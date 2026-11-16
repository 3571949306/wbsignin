#!/usr/bin/env python3
"""从本机 TRAE CN（trae.cn）桌面客户端提取登录凭据与设备签名密钥（Windows 专用）。

背景：TRAE CN 客户端将登录态与设备 P-256 密钥对保存在：
    %APPDATA%\\Trae CN\\User\\globalStorage\\storage.json
使用应用内嵌的 SHA-512 + AES-128-CBC（PKCS#7）加密存储。本脚本借助 Windows 原生
CNG（`bcrypt.dll`）直接解密提取，零第三方依赖。

用法：
  python pull_trae_cred.py                         # 提取并打印脱敏预览
  python pull_trae_cred.py --json                  # 输出完整 JSON 凭据（含敏感令牌与私钥）
  python pull_trae_cred.py --local                 # 直接导入到本机 wbsignin 凭据库
  python pull_trae_cred.py --push --host your-vps  # 提取后经 SSH 推送到服务器
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import socket
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from _remote_push import import_local_with_tempfile, push_via_ssh
from _win_crypto import aes_cbc_decrypt

_HDR_AES = bytes([116, 99, 5, 16, 0, 0])
_HDR_AES_PRIV = bytes([18, 57, 32, 32, 2, 3])

_JHE = bytes(
    [
        82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
        124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
        84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
        8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
    ]
)
_KHE = bytes(
    [
        31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
        96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
        160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
        23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
    ]
)
_ZHE = bytes(
    [
        191, 192, 216, 250, 122, 246, 220, 97, 31, 254, 98, 27, 8, 72, 71, 176,
        135, 99, 96, 18, 127, 101, 203, 104, 211, 102, 191, 125, 37, 72, 150, 156,
        51, 229, 121, 35, 17, 153, 141, 177, 110, 131, 150, 128, 172, 255, 254, 6,
        18, 140, 55, 62, 236, 249, 135, 64, 135, 12, 117, 4, 89, 149, 168, 209,
    ]
)
_GHE = bytes(
    [
        246, 204, 26, 232, 232, 70, 129, 109, 223, 146, 169, 242, 23, 241, 105, 145,
        50, 196, 165, 42, 254, 120, 3, 54, 244, 207, 209, 85, 53, 6, 138, 106,
        175, 148, 31, 204, 186, 186, 165, 182, 87, 142, 49, 10, 39, 110, 26, 154,
        86, 56, 173, 125, 18, 64, 198, 225, 99, 99, 83, 82, 191, 134, 76, 170,
    ]
)


def decrypt_icube_storage_value(b64_str: str) -> Dict[str, Any]:
    """解密 storage.json 中 iCubeAuthInfo://* 字段，返回反序列化对象。"""
    raw = base64.b64decode(b64_str)
    if len(raw) <= 38:
        raise ValueError("iCubeAuthInfo 密文长度无效")
    hdr = raw[:6]
    if hdr == _HDR_AES:
        salt = bytes(a ^ b for a, b in zip(_JHE, _KHE))
    elif hdr == _HDR_AES_PRIV:
        salt = bytes(a ^ b for a, b in zip(_ZHE, _GHE))
    else:
        raise ValueError("未知的 iCubeAuthInfo 魔数头: %s" % hdr.hex())

    seed_key = raw[6:38]
    digest = hashlib.sha512(hashlib.sha512(seed_key).digest() + salt).digest()
    pt = aes_cbc_decrypt(digest[:16], digest[16:32], raw[38:])
    if len(pt) < 64 or hashlib.sha512(pt[64:]).digest() != pt[:64]:
        raise ValueError("iCubeAuthInfo SHA-512 完整性校验失败")
    return json.loads(pt[64:].decode("utf-8"))


def _read_app_meta() -> Dict[str, str]:
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    pj = local / "Programs" / "Trae CN" / "resources" / "app" / "product.json"
    out = {"appVersion": "3.4.18", "clientId": "ono9krqynydwx5"}
    if not pj.is_file():
        return out
    try:
        prod = json.loads(pj.read_text(encoding="utf-8"))
        if prod.get("appVersion"):
            out["appVersion"] = str(prod["appVersion"])
        quality = str(prod.get("quality") or "stable")
        cid = (((prod.get("iCubeApp") or {}).get("authConfig") or {}).get("TRAE") or {}).get(quality)
        if cid:
            out["clientId"] = str(cid)
    except Exception:
        pass
    return out


def _default_label(account: Dict[str, Any], uid: str) -> str:
    ident = (
        str(account.get("nonPlainTextMobile") or "").strip()
        or str(account.get("email") or "").strip()
        or str(account.get("username") or "").strip()
        or uid[:8]
    )
    return f"TRAE CN({ident})" if ident else "TRAE CN"


def extract(custom_name: str = "") -> Optional[Dict[str, Any]]:
    appdata = Path(os.environ.get("APPDATA", ""))
    st_path = appdata / "Trae CN" / "User" / "globalStorage" / "storage.json"
    if not st_path.is_file():
        return None
    try:
        st = json.loads(st_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    raw_auth = st.get("iCubeAuthInfo://icube.cloudide")
    if not isinstance(raw_auth, str) or not raw_auth:
        return None
    auth = decrypt_icube_storage_value(raw_auth)
    token = str(auth.get("token") or "").strip()
    if not token:
        return None

    acc = auth.get("account") if isinstance(auth.get("account"), dict) else {}
    scope = str(acc.get("scope") or "")
    region = str(acc.get("storeRegion") or "")
    if scope and scope != "marscode":
        return None
    if region and region != "CN":
        return None

    uid = str(auth.get("userId") or "").strip()
    meta = _read_app_meta()

    dev_id = ""
    priv_pem = ""
    pub_pem = ""
    prefix = "iCubeAuthInfo://icube-dc:"
    for k, v in st.items():
        if k.startswith(prefix) and isinstance(v, str):
            dev_id = k[len(prefix) :].strip()
            try:
                kp = decrypt_icube_storage_value(v)
                priv_pem = str(kp.get("privateKeyPEM") or "")
                pub_pem = str(kp.get("publicKeyPEM") or "")
            except Exception:
                pass
            break

    device: Dict[str, Any] = {
        "deviceId": dev_id,
        "machineId": str(st.get("telemetry.machineId") or ""),
        "appVersion": meta["appVersion"],
        "clientId": meta["clientId"],
        "osName": "win32",
        "osVersion": platform.release() or "",
        "deviceName": socket.gethostname(),
        "apiHost": str(auth.get("host") or "https://api.trae.cn"),
    }
    if priv_pem and pub_pem:
        device["privateKeyPEM"] = priv_pem
        device["publicKeyPEM"] = pub_pem

    return {
        "provider": "trae-cn",
        "label": custom_name.strip() or _default_label(acc, uid),
        "uid": uid,
        "token": token,
        "refresh_token": str(auth.get("refreshToken") or "").strip(),
        "expires_at": auth.get("expiredAt") or "",
        "refresh_expires_at": auth.get("refreshExpiredAt") or "",
        "device": device,
    }


def _masked_preview(item: Dict[str, Any]) -> str:
    tok = item["token"]
    head = tok[:8] + "..." + tok[-4:] if len(tok) > 16 else "***"
    dev = item.get("device") or {}
    has_key = bool(dev.get("privateKeyPEM") and dev.get("publicKeyPEM"))
    dev_id = str(dev.get("deviceId") or "")
    dev_mask = (dev_id[:4] + "****" + dev_id[-4:]) if len(dev_id) >= 8 else (dev_id or "-")
    return (
        f"[trae-cn] {item['label']}  token={head}  "
        f"exp={str(item.get('expires_at') or '-')[:10]}  "
        f"rt_exp={str(item.get('refresh_expires_at') or '-')[:10]}  "
        f"dev={dev_mask}  ec_key={'OK' if has_key else 'NO'}"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="提取本机 TRAE CN（trae.cn）登录凭据")
    ap.add_argument("--name", default="", help="自定义账号名称")
    ap.add_argument("--json", action="store_true", help="输出完整凭据 JSON（含敏感令牌与私钥）")
    ap.add_argument("--local", action="store_true", help="提取后直接导入到本机 wbsignin 凭据库")
    ap.add_argument("--push", action="store_true", help="提取后经 SSH 推送到服务器")
    ap.add_argument("--host", default="", help="SSH 目标主机名（也可用 WBSIGNIN_SSH_HOST）")
    ap.add_argument("--remote-dir", default="", help="远端 wbsignin 代码目录")
    ap.add_argument("--remote-home", default="", help="远端凭据状态目录")
    args = ap.parse_args()

    item = extract(custom_name=args.name)
    if not item:
        print("未找到可用的 TRAE CN 登录凭据，请先在本机 TRAE CN 客户端登录个人账号。")
        return 1

    if args.json and not args.push and not args.local:
        print(json.dumps(item, ensure_ascii=False, indent=2))
        return 0

    print(_masked_preview(item))

    payload_bytes = json.dumps(item, ensure_ascii=False).encode("utf-8")
    if args.local:
        r = import_local_with_tempfile(
            payload_bytes, ".json", lambda tmp: ["login-trae", "--from-json", tmp]
        )
        print(f"[本机导入 trae-cn] {'成功' if r == 0 else f'失败（退出码 {r}）'}")
        return r

    if args.push:
        r = push_via_ssh(
            host=args.host,
            payload=payload_bytes,
            remote_tmp=f"/tmp/trae_cn_{os.getpid()}.json",
            build_cli_args=lambda q_tmp: f"login-trae --from-json {q_tmp}",
            remote_dir=args.remote_dir,
            remote_home=args.remote_home,
        )
        print(f"[推送 trae-cn] {'成功' if r == 0 else f'失败（退出码 {r}）'}")
        return r

    return 0


if __name__ == "__main__":
    sys.exit(main())
