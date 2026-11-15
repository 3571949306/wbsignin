#!/usr/bin/env python3
"""从本机 Qoder / Qoder CN 桌面客户端提取登录凭据与设备指纹（Windows 专用）。

背景：Qoder 桌面端把 OAuth 登录态加密保存在：
    %APPDATA%\\com.qodercn.app.stable\\auth.v1.dat  （国内版 qoder-cn）
    %APPDATA%\\com.qoder.app.stable\\auth.v1.dat    （国际版 qoder）
使用 Electron safeStorage（DPAPI + AES-256-GCM v10）加密；同时设备指纹由客户端自带的
`umid\\runtime-info.exe` 生成。

依赖：全标准库 + Windows 原生 DPAPI/CNG（无需安装第三方包）。

用法：
  python pull_qoder_cred.py                         # 提取并打印脱敏预览
  python pull_qoder_cred.py --json                  # 输出完整 JSON 凭据（慎用，含敏感令牌）
  python pull_qoder_cred.py --region cn             # 只提取国内版（默认 all）
  python pull_qoder_cred.py --local                 # 直接导入到本机 wbsignin 凭据库
  python pull_qoder_cred.py --push --host your-vps  # 提取后经 SSH 推送到服务器
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from _remote_push import import_local_with_tempfile, push_via_ssh
from _win_crypto import chromium_local_state_key, decrypt_v10


TARGETS = (
    {
        "region": "cn",
        "provider": "qoder-cn",
        "title": "Qoder 国内版",
        "appdata": "com.qodercn.app.stable",
        "program": "Qoder CN",
        "dotdir": ".qoder-cn",
        "umid_env": "0",
        "default_version": "0.5.11",
    },
    {
        "region": "intl",
        "provider": "qoder",
        "title": "Qoder 国际版",
        "appdata": "com.qoder.app.stable",
        "program": "Qoder",
        "dotdir": ".qoder",
        "umid_env": "3",
        "default_version": "0.5.7",
    },
)


def _version_key(name: str) -> Tuple[int, ...]:
    parts: List[int] = []
    for seg in name.split("."):
        try:
            parts.append(int(seg))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _find_umid(spec: Dict[str, str]) -> Tuple[Optional[Path], str]:
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    home = Path.home()
    prog = local / "Programs" / spec["program"]

    candidates: List[Path] = []
    vers_dir = prog / ".qoder-versions"
    if vers_dir.is_dir():
        dirs = [
            d
            for d in vers_dir.iterdir()
            if d.is_dir() and (d / "resources" / "umid" / "runtime-info.exe").is_file()
        ]
        dirs.sort(key=lambda d: _version_key(d.name), reverse=True)
        for d in dirs:
            candidates.append(d / "resources" / "umid" / "runtime-info.exe")

    top_ri = prog / "resources" / "umid" / "runtime-info.exe"
    if top_ri.is_file():
        candidates.append(top_ri)

    dot_bin = home / spec["dotdir"] / ".bin"
    if dot_bin.is_dir():
        for ri in sorted(dot_bin.glob("umid-win32-*/runtime-info.exe"), reverse=True):
            if ri.is_file():
                candidates.append(ri)

    if not candidates:
        return None, spec["default_version"]

    ri = candidates[0]
    version = spec["default_version"]
    manifest = ri.parent.parent / "build-manifest.json"
    if manifest.is_file():
        try:
            pv = json.loads(manifest.read_text(encoding="utf-8")).get("productVersion")
            if pv:
                version = str(pv)
        except Exception:
            pass
    return ri, version


def _collect_device(spec: Dict[str, str], user_dir: Path, uid: str) -> Dict[str, Any]:
    ri, version = _find_umid(spec)
    dev: Dict[str, Any] = {
        "clientType": "10",
        "version": version,
        "machineOS": "x86_64_win32",
    }
    mid_file = user_dir / "auth.machine-id"
    if mid_file.is_file():
        mid = mid_file.read_text(encoding="utf-8", errors="ignore").strip()
        if mid:
            dev["machineId"] = mid
    host = socket.gethostname()
    if host:
        dev["machineHostname"] = host

    if ri is not None:
        try:
            proc = subprocess.run(
                [str(ri), spec["umid_env"], "--account-stdin"],
                input=(json.dumps({"account": uid}) + "\n").encode("utf-8"),
                capture_output=True,
                timeout=15,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                info = json.loads(proc.stdout.decode("utf-8", "replace"))
                for k in ("machineToken", "machineCode", "machineType"):
                    val = str(info.get(k) or "").strip()
                    if val:
                        dev[k] = val
        except Exception as exc:
            print(f"[警告] {spec['title']} runtime-info 执行失败: {exc}", file=sys.stderr)
    return dev


def _default_label(user: Dict[str, Any], uid: str, spec: Dict[str, str]) -> str:
    phone = str(user.get("phone") or "").strip()
    if phone:
        return (phone[:3] + "****" + phone[-4:]) if len(phone) >= 8 else phone
    email = str(user.get("email") or "").strip()
    if email:
        return email
    uname = str(user.get("name") or "").strip()
    if uname:
        return uname
    return f"{spec['title']}({uid[:8]})" if uid else spec["title"]


def extract_one(spec: Dict[str, str], custom_name: str = "") -> Optional[Dict[str, Any]]:
    appdata = Path(os.environ.get("APPDATA", ""))
    user_dir = appdata / spec["appdata"]
    auth_file = user_dir / "auth.v1.dat"
    local_state = user_dir / "Local State"
    if not auth_file.is_file() or not local_state.is_file():
        return None

    key = chromium_local_state_key(user_dir)
    plain = decrypt_v10(auth_file.read_bytes(), key)
    if plain is None:
        raise RuntimeError(f"{spec['title']} 使用了 v20 app-bound 加密，无法离线解密")

    raw = json.loads(plain.decode("utf-8"))
    token = str(raw.get("token") or raw.get("accessToken") or "").strip()
    if not token:
        return None

    user = raw.get("user") if isinstance(raw.get("user"), dict) else {}
    uid = str(user.get("id") or raw.get("uid") or "").strip()
    label = custom_name.strip() or _default_label(user, uid, spec)
    device = _collect_device(spec, user_dir, uid)

    return {
        "region": spec["region"],
        "provider": spec["provider"],
        "label": label,
        "uid": uid,
        "token": token,
        "refresh_token": str(raw.get("refreshToken") or "").strip(),
        "expires_at": raw.get("expiresAt") or "",
        "device": device,
    }


def _masked_preview(item: Dict[str, Any]) -> str:
    tok = item["token"]
    head = tok[:8] + "..." + tok[-4:] if len(tok) > 16 else "***"
    dev = item.get("device") or {}
    has_umid = bool(dev.get("machineToken") and dev.get("machineCode"))
    return (
        f"[{item['provider']}] {item['label']}  "
        f"token={head}  exp={item.get('expires_at') or '-'}  "
        f"ver={dev.get('version', '-')}  umid={'OK' if has_umid else 'NO'}"
    )


def _push_one(
    item: Dict[str, Any],
    host: str = "",
    remote_dir: str = "",
    remote_home: str = "",
) -> int:
    """经单次 SSH 会话把 JSON 写入远端临时文件并执行 login-qoder。"""
    payload_bytes = json.dumps(item, ensure_ascii=False).encode("utf-8")
    remote_tmp = f"/tmp/qoder_{item['region']}_{os.getpid()}.json"
    return push_via_ssh(
        host=host,
        payload=payload_bytes,
        remote_tmp=remote_tmp,
        build_cli_args=lambda q_tmp: (
            f"login-qoder --region {shlex.quote(item['region'])} --from-json {q_tmp}"
        ),
        remote_dir=remote_dir,
        remote_home=remote_home,
    )


def _import_local_one(item: Dict[str, Any]) -> int:
    payload_bytes = json.dumps(item, ensure_ascii=False).encode("utf-8")
    return import_local_with_tempfile(
        payload_bytes,
        ".json",
        lambda tmp_path: ["login-qoder", "--region", item["region"], "--from-json", tmp_path],
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="提取本机 Qoder / Qoder CN 登录凭据")
    ap.add_argument("--region", choices=("all", "cn", "intl"), default="all",
                    help="提取目标：all（默认，国内+国际）、cn 或 intl")
    ap.add_argument("--name", default="", help="自定义账号名称（仅单版本时建议指定）")
    ap.add_argument("--json", action="store_true", help="输出完整凭据 JSON（含敏感令牌）")
    ap.add_argument("--local", action="store_true", help="提取后直接导入到本机 wbsignin 凭据库")
    ap.add_argument("--push", action="store_true", help="提取后经 SSH 推送到服务器")
    ap.add_argument("--host", default="",
                    help="SSH 目标主机名（也可通过环境变量 WBSIGNIN_SSH_HOST 指定）")
    ap.add_argument("--remote-dir", default="",
                    help="远端 wbsignin 代码目录（默认自动探测 ~/.local/share/wbsignin、~/wbsignin、/opt/wbsignin）")
    ap.add_argument("--remote-home", default="",
                    help="远端凭据状态目录（默认 $WBSIGNIN_HOME 或 ~/.wbsignin）")
    args = ap.parse_args()

    selected = [t for t in TARGETS if args.region in ("all", t["region"])]
    found: List[Dict[str, Any]] = []
    for spec in selected:
        item = extract_one(spec, custom_name=args.name if len(selected) == 1 else "")
        if item:
            found.append(item)

    if not found:
        print("未找到可用的 Qoder 登录凭据，请先在本机 Qoder / Qoder CN 客户端登录。")
        return 1

    if args.json and not args.push and not args.local:
        out = found[0] if (len(found) == 1 and args.region != "all") else found
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0

    for item in found:
        print(_masked_preview(item))

    if args.local:
        rc = 0
        for item in found:
            r = _import_local_one(item)
            print(f"[本机导入 {item['provider']}] {'成功' if r == 0 else f'失败（退出码 {r}）'}")
            if r != 0:
                rc = r
        return rc

    if args.push:
        rc = 0
        for item in found:
            r = _push_one(
                item,
                host=args.host,
                remote_dir=args.remote_dir,
                remote_home=args.remote_home,
            )
            print(f"[推送 {item['provider']}] {'成功' if r == 0 else f'失败（退出码 {r}）'}")
            if r != 0:
                rc = r
        return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())
