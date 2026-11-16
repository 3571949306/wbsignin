"""TRAE CN（trae.cn）每日自动签到、积分查询与 OAuth 令牌续期。

协议契约（对齐桌面端行为）：
    POST https://api.trae.cn/trae/api/v2/ug/checkin_credits/status   查询今日签到状态
    POST https://api.trae.cn/trae/api/v2/ug/checkin_credits/claim    领取今日签到积分（幂等）
    POST https://api.trae.cn/trae/api/v2/pay/ide_user_ent_usage        查询总积分与有效期包明细
    POST https://api.trae.cn/cloudide/api/v3/trae/GetUserInfo          校验登录态与脱敏账号标识
    POST https://api.trae.cn/trae/api/v3/oauth/ExchangeToken           RefreshToken + P-256 DeviceProof 续期
"""
from __future__ import annotations

import base64
import datetime
import gzip
import hashlib
import hmac
import json
import re
import secrets
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, Tuple

from . import config, httpc
from .qoder import parse_expires_at
from .tasks import (
    ST_ALREADY,
    ST_FAILED,
    ST_SEASON,
    ST_SIGNED,
    ST_SKIPPED,
    CheckinResult,
    CreditSnapshot,
)

PROVIDER_CN = "trae-cn"
DEFAULT_CLIENT_ID = "ono9krqynydwx5"
DEFAULT_APP_VERSION = "3.4.18"
_APPLOG_CN_AID = 787976
_APPLOG_CN_PACKAGE = "com.trae.app"

_CHECKIN_STATUS_PATH = "/trae/api/v2/ug/checkin_credits/status"
_CHECKIN_CLAIM_PATH = "/trae/api/v2/ug/checkin_credits/claim"
_USAGE_PATH = "/trae/api/v2/pay/ide_user_ent_usage"
_GET_USER_INFO_PATH = "/cloudide/api/v3/trae/GetUserInfo"
_EXCHANGE_TOKEN_PATH = "/trae/api/v3/oauth/ExchangeToken"

_AUTH_CODES = frozenset({1002})
_RT_INVALID_CODES = frozenset({"20324", "20101", "20315", "20125", "20126", "20401", "20403"})

# NIST P-256 曲线参数（用于纯标准库签署 ExchangeToken DeviceProof，无第三方依赖）
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _as_float(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _num_str(v: float) -> str:
    return str(int(v)) if abs(v - int(v)) < 1e-9 else ("%.2f" % v).rstrip("0").rstrip(".")


def _fmt_ms(ms: int) -> str:
    return datetime.datetime.fromtimestamp(ms / 1000.0, tz=config.BJ_TZ).strftime(
        "%Y-%m-%d %H:%M"
    )


def _api_base(device: Optional[Dict[str, Any]] = None) -> str:
    if isinstance(device, dict):
        host = str(device.get("apiHost") or "").strip().rstrip("/")
        if host.startswith("https://"):
            return host
    return config.TRAE_CN_API_BASE


def build_ug_headers(token: str, device: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    dev = device if isinstance(device, dict) else {}
    os_type = str(dev.get("osName") or "win32")
    h: Dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Cloud-IDE-JWT " + token,
        "x-device-type": os_type,
        "x-app-version": str(dev.get("appVersion") or DEFAULT_APP_VERSION),
    }
    did = str(dev.get("ugDeviceId") or dev.get("deviceId") or "").strip()
    if did:
        h["x-device-id"] = did
    if dev.get("deviceBrand"):
        h["x-device-brand"] = str(dev["deviceBrand"]).strip()
    os_ver = str(dev.get("osVersion") or "").strip()
    if os_ver:
        h["x-os-version"] = os_ver
    elif os_type == "win32":
        h["x-os-version"] = "11"
    return h


# ---------- 纯标准库 P-256 ECDSA（ExchangeToken DeviceProof） ----------
def _ec_add(p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    p = _P256_P
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return x3, (lam * (x1 - x3) - y1) % p


def _ec_mul(k: int, pt: Tuple[int, int] = _P256_G) -> Optional[Tuple[int, int]]:
    res: Optional[Tuple[int, int]] = None
    cur: Optional[Tuple[int, int]] = pt
    while k:
        if k & 1:
            res = _ec_add(res, cur)
        cur = _ec_add(cur, cur)
        k >>= 1
    return res


def _parse_pkcs8_ec_privkey(pem: str) -> int:
    b64 = "".join(
        ln.strip()
        for ln in str(pem or "").splitlines()
        if ln.strip() and "BEGIN" not in ln and "END" not in ln
    )
    if not b64:
        raise ValueError("设备私钥 PEM 为空")
    der = base64.b64decode(b64)
    marker = b"\x02\x01\x01\x04\x20"
    pos = der.find(marker)
    if pos >= 0 and pos + len(marker) + 32 <= len(der):
        return int.from_bytes(der[pos + len(marker) : pos + len(marker) + 32], "big")
    idx = der.find(b"\x04\x20")
    if idx >= 0 and idx + 34 <= len(der):
        return int.from_bytes(der[idx + 2 : idx + 34], "big")
    raise ValueError("不支持的 P-256 PKCS#8 私钥格式")


def _der_int(val: int) -> bytes:
    raw = val.to_bytes((val.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return bytes([0x02, len(raw)]) + raw


def sign_p256_sha256(private_key_pem: str, msg: bytes) -> bytes:
    """使用 RFC 6979 确定性 ECDSA-SHA256 对 msg 签名并输出 DER 编码。"""
    d = _parse_pkcs8_ec_privkey(private_key_pem)
    if not (1 <= d < _P256_N):
        raise ValueError("ECDSA 私钥标量超出 P-256 范围")
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big") % _P256_N
    bx = d.to_bytes(32, "big") + z.to_bytes(32, "big")
    v = b"\x01" * 32
    k_mac = hmac.new(b"\x00" * 32, v + b"\x00" + bx, hashlib.sha256).digest()
    v = hmac.new(k_mac, v, hashlib.sha256).digest()
    k_mac = hmac.new(k_mac, v + b"\x01" + bx, hashlib.sha256).digest()
    v = hmac.new(k_mac, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k_mac, v, hashlib.sha256).digest()
        k = int.from_bytes(v, "big")
        if 1 <= k < _P256_N:
            pt = _ec_mul(k)
            r = (pt[0] % _P256_N) if pt else 0
            if r:
                s = (pow(k, -1, _P256_N) * (z + r * d)) % _P256_N
                if s:
                    if s > _P256_N // 2:
                        s = _P256_N - s
                    body = _der_int(r) + _der_int(s)
                    return bytes([0x30, len(body)]) + body
        k_mac = hmac.new(k_mac, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k_mac, v, hashlib.sha256).digest()


def build_device_proof(
    private_key_pem: str,
    client_id: str,
    refresh_token: str,
    timestamp: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    ts = int(time.time()) if timestamp is None else int(timestamp)
    n = secrets.token_hex(16) if nonce is None else str(nonce)
    msg = "\n".join(
        ["POST", _EXCHANGE_TOKEN_PATH, client_id, refresh_token, str(ts), n]
    ).encode("utf-8")
    sig = base64.b64encode(sign_p256_sha256(private_key_pem, msg)).decode("ascii")
    return {"Signature": sig, "Timestamp": ts, "Nonce": n}


def _pem_block(kind: str, der: bytes) -> str:
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {kind}-----\n" + "\n".join(lines) + f"\n-----END {kind}-----\n"


def generate_p256_keypair() -> Tuple[str, str]:
    """纯标准库生成 NIST P-256 PKCS#8 私钥 + SPKI 公钥 PEM（供远端 OAuth 注册设备）。"""
    d = secrets.randbelow(_P256_N - 1) + 1
    pt = _ec_mul(d)
    assert pt is not None
    pub_uncomp = b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
    oid_ecpub = b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
    oid_p256 = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
    alg_id = b"\x30" + bytes([len(oid_ecpub) + len(oid_p256)]) + oid_ecpub + oid_p256
    bitstr = b"\x03" + bytes([len(pub_uncomp) + 1]) + b"\x00" + pub_uncomp
    spki_body = alg_id + bitstr
    spki = b"\x30" + bytes([len(spki_body)]) + spki_body

    priv_b = d.to_bytes(32, "big")
    ec_body = (
        b"\x02\x01\x01\x04\x20"
        + priv_b
        + b"\xa0"
        + bytes([len(oid_p256)])
        + oid_p256
        + b"\xa1"
        + bytes([len(bitstr)])
        + bitstr
    )
    ec_priv = b"\x30" + bytes([len(ec_body)]) + ec_body
    p8_body = b"\x02\x01\x00" + alg_id + b"\x04" + bytes([len(ec_priv)]) + ec_priv
    p8_hdr = b"\x30" + (
        bytes([0x81, len(p8_body)]) if len(p8_body) >= 128 else bytes([len(p8_body)])
    )
    return _pem_block("PRIVATE KEY", p8_hdr + p8_body), _pem_block("PUBLIC KEY", spki)


# ---------- 登录校验与续期 ----------
def verify_token(
    token: str, device: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """校验 TRAE CN Token，返回账号基础信息，失败抛 ApiError。"""
    tok = str(token or "").strip()
    if not tok:
        raise httpc.ApiError(httpc.KIND_AUTH, "缺少 TRAE CN token")
    dev = device if isinstance(device, dict) else {}
    ver = str(dev.get("appVersion") or DEFAULT_APP_VERSION)
    resp = httpc.request(
        "POST",
        _api_base(dev) + _GET_USER_INFO_PATH,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-cloudide-token": tok,
        },
        body={"IDEVersion": ver, "ReqSource": "IDE"},
        retries=2,
    )
    if resp.status in (401, 403):
        raise httpc.ApiError(
            httpc.KIND_AUTH,
            "TRAE CN 登录态无效或已过期（HTTP %s）" % resp.status,
            resp.status,
            resp.payload,
        )
    if resp.status >= 400 or not isinstance(resp.payload, dict):
        raise httpc.ApiError(
            httpc.KIND_BAD_RESPONSE,
            "TRAE CN 校验失败（HTTP %s）" % resp.status,
            resp.status,
            resp.payload,
        )
    meta_err = ((resp.payload.get("ResponseMetadata") or {}).get("Error") or {})
    err_code = str(meta_err.get("Code") or "")
    res = resp.payload.get("Result")
    if err_code in _RT_INVALID_CODES or not isinstance(res, dict) or not res.get("UserID"):
        raise httpc.ApiError(
            httpc.KIND_AUTH,
            "TRAE CN Token 校验未通过%s" % ("（%s）" % err_code if err_code else ""),
            resp.status,
            resp.payload,
        )
    return {
        "uid": str(res.get("UserID") or ""),
        "screen_name": str(res.get("ScreenName") or ""),
        "masked_mobile": str(res.get("NonPlainTextMobile") or ""),
        "masked_email": str(res.get("NonPlainTextEmail") or ""),
        "region": str(res.get("AIRegion") or "CN"),
        "raw": resp.payload,
    }


def needs_refresh(
    token: str, at_exp: int = 0, threshold_seconds: int = 24 * 3600
) -> bool:
    """离 AT 过期不足阈值时返回 True；桌面端自身 ~9 天刷新，这里在最后 24h 兜底。"""
    if not token:
        return True
    if at_exp <= 0:
        return False
    return at_exp - int(time.time()) <= threshold_seconds


def _build_device_info(dev: Dict[str, Any], pub: str) -> Dict[str, Any]:
    ver = str(dev.get("appVersion") or DEFAULT_APP_VERSION)
    return {
        "DeviceID": str(dev.get("deviceId") or ""),
        "MachineID": str(dev.get("machineId") or ""),
        "PlatformCode": "IDE_PC",
        "DeviceType": "PC",
        "DeviceName": str(dev.get("deviceName") or "PC"),
        "DeviceModel": str(dev.get("deviceModel") or ""),
        "ClientVersion": ver,
        "DevicePublicKey": pub,
        "DeviceBrand": str(dev.get("deviceBrand") or ""),
        "DeviceCPU": str(dev.get("deviceCpu") or ""),
        "OSInfo": str(dev.get("osName") or "win32"),
        "OSVersion": str(dev.get("osVersion") or ""),
    }


def _exchange_token_call(
    dev: Dict[str, Any],
    body: Dict[str, Any],
    headers: Dict[str, str],
    fallback_rt: str = "",
) -> Dict[str, Any]:
    resp = httpc.request(
        "POST",
        _api_base(dev) + _EXCHANGE_TOKEN_PATH,
        headers=headers,
        body=body,
        retries=1,
    )
    payload = resp.payload if isinstance(resp.payload, dict) else {}
    meta_err = ((payload.get("ResponseMetadata") or {}).get("Error") or {})
    err_code = str(meta_err.get("Code") or "")
    res = payload.get("Result") if isinstance(payload.get("Result"), dict) else {}
    if resp.status in (401, 403) or err_code in _RT_INVALID_CODES:
        raise httpc.ApiError(
            httpc.KIND_AUTH,
            "TRAE CN OAuth 凭据无效或已过期（%s）"
            % (err_code or ("HTTP %s" % resp.status)),
            resp.status,
            payload,
        )
    new_at = str(res.get("Token") or "").strip()
    if resp.status >= 400 or not new_at:
        raise httpc.ApiError(
            httpc.KIND_SERVER,
            "TRAE CN ExchangeToken 响应异常（HTTP %s）" % resp.status,
            resp.status,
            payload,
        )
    new_rt = str(res.get("RefreshToken") or fallback_rt).strip()
    exp_ts = parse_expires_at(res.get("TokenExpireAt"))
    if not exp_ts and res.get("TokenExpireDuration"):
        exp_ts = int(time.time()) + int(_as_float(res["TokenExpireDuration"]) / 1000)
    return {
        "access_token": new_at,
        "refresh_token": new_rt,
        "at_exp": exp_ts,
        "refresh_exp": parse_expires_at(res.get("RefreshExpireAt")),
    }


def refresh_session(
    refresh_token: str,
    access_token: str = "",
    device: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """调用 /trae/api/v3/oauth/ExchangeToken 续期（需持有设备 P-256 私钥）。"""
    rt = str(refresh_token or "").strip()
    dev = device if isinstance(device, dict) else {}
    priv = str(dev.get("privateKeyPEM") or "")
    pub = str(dev.get("publicKeyPEM") or "")
    if not rt or not priv.strip() or not pub.strip():
        raise httpc.ApiError(
            httpc.KIND_AUTH,
            "缺少 RefreshToken 或设备 P-256 密钥，需在本机重新导入 TRAE CN 凭据",
        )

    client_id = str(dev.get("clientId") or DEFAULT_CLIENT_ID)
    ver = str(dev.get("appVersion") or DEFAULT_APP_VERSION)
    proof = build_device_proof(priv, client_id, rt)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if access_token:
        headers["x-cloudide-token"] = access_token

    return _exchange_token_call(
        dev,
        {
            "ClientID": client_id,
            "ClientSecret": "",
            "RefreshToken": rt,
            "DeviceInfo": _build_device_info(dev, pub),
            "DeviceProof": proof,
            "IDEVersion": ver,
        },
        headers,
        fallback_rt=rt,
    )


# ---------- 纯标准库 AES-128-CBC & CN 设备注册 ----------
_AES_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
_AES_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
_APPLOG_K1 = bytes(
    [
        82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
        124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
        84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
        8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
    ]
)
_APPLOG_K2 = bytes(
    [
        31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
        96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
        160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
        23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
    ]
)
_APPLOG_SECRET_MASK = bytes(a ^ b for a, b in zip(_APPLOG_K1, _APPLOG_K2))


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else ((a << 1) & 0xFF)


def _aes128_expand_key(key: bytes) -> List[bytes]:
    w = list(key)
    for rnd in range(10):
        t0, t1, t2, t3 = w[-4], w[-3], w[-2], w[-1]
        tmp = [
            _AES_SBOX[t1] ^ _AES_RCON[rnd],
            _AES_SBOX[t2],
            _AES_SBOX[t3],
            _AES_SBOX[t0],
        ]
        base = len(w) - 16
        for i in range(4):
            w.append(w[base + i] ^ tmp[i])
        for i in range(4, 16):
            w.append(w[base + i] ^ w[-4])
    return [bytes(w[i : i + 16]) for i in range(0, 176, 16)]


def _aes128_encrypt_block(block: bytes, round_keys: List[bytes]) -> bytes:
    s = [block[i] ^ round_keys[0][i] for i in range(16)]
    for rnd in range(1, 11):
        sb = [_AES_SBOX[x] for x in s]
        sr = [
            sb[0], sb[5], sb[10], sb[15],
            sb[4], sb[9], sb[14], sb[3],
            sb[8], sb[13], sb[2], sb[7],
            sb[12], sb[1], sb[6], sb[11],
        ]
        if rnd < 10:
            mc = []
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = sr[c], sr[c + 1], sr[c + 2], sr[c + 3]
                t = a0 ^ a1 ^ a2 ^ a3
                mc.extend(
                    (
                        a0 ^ t ^ _xtime(a0 ^ a1),
                        a1 ^ t ^ _xtime(a1 ^ a2),
                        a2 ^ t ^ _xtime(a2 ^ a3),
                        a3 ^ t ^ _xtime(a3 ^ a0),
                    )
                )
            sr = mc
        rk = round_keys[rnd]
        s = [sr[i] ^ rk[i] for i in range(16)]
    return bytes(s)


def _aes128_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("AES-128-CBC 密钥与 IV 必须为 16 字节")
    pad = 16 - (len(data) % 16)
    padded = data + bytes([pad]) * pad
    rks = _aes128_expand_key(key)
    prev = iv
    out = bytearray()
    for off in range(0, len(padded), 16):
        blk = bytes(padded[off + i] ^ prev[i] for i in range(16))
        ct = _aes128_encrypt_block(blk, rks)
        out.extend(ct)
        prev = ct
    return bytes(out)


def _tc_applog_encrypt(raw: bytes) -> bytes:
    """按字节桌面端 AppLog tc\\x05\\x10 协议加密 gzip 后的设备注册载荷。"""
    rnd = secrets.token_bytes(32)
    h1 = hashlib.sha512(rnd).digest()
    h2 = hashlib.sha512(h1 + _APPLOG_SECRET_MASK).digest()
    plain = hashlib.sha512(raw).digest() + raw
    ct = _aes128_cbc_encrypt(h2[:16], h2[16:32], plain)
    return b"tc\x05\x10\x00\x00" + rnd + ct


def register_cn_device(app_version: str = DEFAULT_APP_VERSION) -> Dict[str, str]:
    """向 log.snssdk.com 注册并激活独立 TRAE CN (aid=787976) 桌面设备标识。"""
    ver = str(app_version or DEFAULT_APP_VERSION).strip()
    mac = ":".join(f"{b:02x}" for b in (0x02, *secrets.token_bytes(5)))
    pc_uuid = str(uuid.uuid4()).upper()
    pc_serial = secrets.token_hex(8).upper()
    reg_url = config.TRAE_CN_DEVICE_REGISTER_URL + "?" + urllib.parse.urlencode(
        {
            "aid": str(_APPLOG_CN_AID),
            "channel": "stable",
            "os": "Windows",
            "os_version": "10.0.26100",
            "device_platform": "PC",
            "version_code": ver,
        }
    )
    body = {
        "header": {
            "device_id": 0,
            "install_id": 0,
            "os": "Windows",
            "device_platform": "PC",
            "sdk_version": "0.0.2",
            "sdk_version_code": 2,
            "aid": _APPLOG_CN_AID,
            "mc": mac,
            "channel": "stable",
            "package": _APPLOG_CN_PACKAGE,
            "language": "zh-CN",
            "app_version": ver,
            "os_version": "10.0.26100",
            "device_model": "System Product Name",
            "time_zone": 8,
            "tz_name": "Asia/Shanghai",
            "tz_offset": 28800,
            "resolution": "1920x1080",
            "app_region": "CN",
            "app_language": "zh-CN",
            "display_name": "Trae CN",
            "new_user_mode": 0,
            "pc_uuid": pc_uuid,
            "pc_serial": pc_serial,
        },
        "_gen_time": int(time.time()),
        "magic_tag": "ss_app_log",
    }
    enc = _tc_applog_encrypt(gzip.compress(json.dumps(body).encode("utf-8")))
    resp = httpc.request(
        "POST",
        reg_url,
        headers={"Content-Type": "application/json", "User-Agent": "TTNetwork PC"},
        body=enc,
        retries=2,
    )
    payload = resp.payload if isinstance(resp.payload, dict) else {}
    did = str(payload.get("device_id_str") or payload.get("device_id") or "").strip()
    iid = str(payload.get("install_id_str") or payload.get("install_id") or "").strip()
    if resp.status >= 400 or not did or did == "0" or not iid or iid == "0":
        raise httpc.ApiError(
            httpc.KIND_SERVER,
            "向 TRAE CN 注册独立设备标识失败（HTTP %s）" % resp.status,
            resp.status,
            payload,
        )

    act_url = config.TRAE_CN_DEVICE_ACTIVE_URL + "?" + urllib.parse.urlencode(
        {
            "aid": str(_APPLOG_CN_AID),
            "app_name": "Trae CN",
            "version_code": ver,
            "channel": "stable",
            "os": "Windows",
            "device_platform": "PC",
            "device_id": did,
            "iid": iid,
        }
    )
    try:
        httpc.request("POST", act_url, headers={"User-Agent": "TTNetwork PC"}, retries=1)
    except httpc.ApiError:
        pass
    return {
        "deviceId": did,
        "installId": iid,
        "deviceModel": "System Product Name",
        "osVersion": "11",
    }


def oauth_start(callback_origin: str, name: str = "") -> Dict[str, Any]:
    """生成 TRAE CN PKCE 网页授权会话与已注册的独立设备密钥，回调指向 127.0.0.1:<port>/authorize。"""
    m = re.match(r"^https?://(127\.0\.0\.1|localhost):(\d+)$", (callback_origin or "").strip())
    if not m:
        raise httpc.ApiError(
            httpc.KIND_BAD_RESPONSE,
            "无效的本机回调地址（需为 http://127.0.0.1:<端口>）",
        )
    port = m.group(2)
    callback_url = f"http://127.0.0.1:{port}/authorize"

    reg = register_cn_device(DEFAULT_APP_VERSION)
    device_id = reg["deviceId"]
    trace_id = str(uuid.uuid4())
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode("ascii")
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    machine_id = secrets.token_hex(32)
    priv_pem, pub_pem = generate_p256_keypair()

    dev = {
        "deviceId": device_id,
        "installId": reg["installId"],
        "machineId": machine_id,
        "appVersion": DEFAULT_APP_VERSION,
        "clientId": DEFAULT_CLIENT_ID,
        "osName": "win32",
        "osVersion": reg.get("osVersion") or "11",
        "deviceModel": reg.get("deviceModel") or "System Product Name",
        "deviceName": "wbsignin-" + secrets.token_hex(3),
        "apiHost": config.TRAE_CN_API_BASE,
        "privateKeyPEM": priv_pem,
        "publicKeyPEM": pub_pem,
    }
    params = {
        "login_version": "1",
        "auth_from": "trae",
        "login_channel": "native_ide",
        "plugin_version": "local",
        "auth_type": "local",
        "client_id": DEFAULT_CLIENT_ID,
        "redirect": "0",
        "login_trace_id": trace_id,
        "auth_callback_url": callback_url,
        "machine_id": machine_id,
        "device_id": device_id,
        "x_device_id": device_id,
        "x_machine_id": machine_id,
        "x_device_type": "win32",
        "x_app_version": DEFAULT_APP_VERSION,
        "x_app_type": "stable",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = config.TRAE_CN_WEB_ORIGIN + "/authorization?" + urllib.parse.urlencode(params)
    return {
        "trace_id": trace_id,
        "auth_url": auth_url,
        "code_verifier": code_verifier,
        "device": dev,
        "name": (name or "").strip(),
    }


def exchange_auth_code(
    auth_code: str,
    code_verifier: str,
    device: Optional[Dict[str, Any]] = None,
    host: str = "",
) -> Dict[str, Any]:
    """用 OAuth 回调收到的 AuthCode + PKCE CodeVerifier 兑换 Token 与 RefreshToken。"""
    code = str(auth_code or "").strip()
    verifier = str(code_verifier or "").strip()
    dev = dict(device) if isinstance(device, dict) else {}
    pub = str(dev.get("publicKeyPEM") or "")
    if not code or not verifier or not pub.strip():
        raise httpc.ApiError(httpc.KIND_AUTH, "OAuth 授权参数缺失（AuthCode / CodeVerifier）")

    if host:
        h_name = urllib.parse.urlsplit(host).hostname or ""
        if h_name in config.ALLOWED_HOSTS and host.startswith("https://"):
            dev["apiHost"] = host.rstrip("/")

    client_id = str(dev.get("clientId") or DEFAULT_CLIENT_ID)
    ver = str(dev.get("appVersion") or DEFAULT_APP_VERSION)
    res = _exchange_token_call(
        dev,
        {
            "ClientID": client_id,
            "AuthCode": code,
            "CodeVerifier": verifier,
            "DeviceInfo": _build_device_info(dev, pub),
            "IDEVersion": ver,
        },
        {"Content-Type": "application/json", "Accept": "application/json"},
    )
    return {
        "provider": PROVIDER_CN,
        "token": res["access_token"],
        "refresh_token": res["refresh_token"],
        "expires_at": res["at_exp"],
        "device": dev,
    }


# ---------- 签到与积分 ----------
def _handle_ug_error(status: int, payload: Any, fallback: str) -> Optional[CheckinResult]:
    if status in (401, 403):
        return CheckinResult(
            status=ST_SKIPPED,
            kind=httpc.KIND_AUTH,
            detail="TRAE CN 登录态已失效（HTTP %s），请重新导入" % status,
        )
    if not isinstance(payload, dict):
        return CheckinResult(
            status=ST_FAILED,
            kind=httpc.KIND_SERVER if status >= 400 else httpc.KIND_BAD_RESPONSE,
            detail="%s（HTTP %s）" % (fallback, status),
        )
    code = payload.get("code")
    if isinstance(code, bool) or (code is not None and code != 0):
        if code in _AUTH_CODES:
            return CheckinResult(
                status=ST_SKIPPED,
                kind=httpc.KIND_AUTH,
                detail="TRAE CN 登录态已失效（code %s），请重新导入" % code,
                raw=payload,
            )
        if code == 9090:
            return CheckinResult(
                status=ST_SEASON,
                kind=httpc.KIND_SEASON,
                detail="当前无每日签到活动",
                raw=payload,
            )
        if code in (9004, 4001):
            return CheckinResult(
                status=ST_FAILED,
                kind=httpc.KIND_BAD_RESPONSE,
                detail="请求参数无效（缺少有效设备标识 x-device-id）",
                raw=payload,
            )
        if code == 9095:
            return CheckinResult(
                status=ST_ALREADY,
                detail="该设备今日已完成签到",
                raw=payload,
            )
        if code == 9074:
            return CheckinResult(
                status=ST_FAILED,
                kind=httpc.KIND_SERVER,
                detail="设备标识未注册或触发活动风控（code 9074），建议自动重注册设备或稍后重试",
                raw=payload,
            )
        msg = str(payload.get("message") or payload.get("msg") or fallback)
        return CheckinResult(
            status=ST_FAILED,
            kind=httpc.KIND_SERVER,
            detail="%s（code %s）" % (msg, code),
            raw=payload,
        )
    if status >= 400:
        return CheckinResult(
            status=ST_FAILED,
            kind=httpc.KIND_SERVER,
            detail="%s（HTTP %s）" % (fallback, status),
            raw=payload,
        )
    return None


def trae_checkin(
    token: str, device: Optional[Dict[str, Any]] = None
) -> CheckinResult:
    """执行 TRAE CN 每日积分签到（幂等：先查 status，未签再 claim）。"""
    tok = str(token or "").strip()
    if not tok:
        return CheckinResult(
            status=ST_SKIPPED, kind=httpc.KIND_AUTH, detail="缺少 TRAE CN token"
        )
    hdrs = build_ug_headers(tok, device)
    base = config.TRAE_CN_API_BASE
    try:
        resp = httpc.request(
            "POST", base + _CHECKIN_STATUS_PATH, headers=hdrs, body={"req_source": 1}, retries=2
        )
    except httpc.ApiError as exc:
        return CheckinResult(status=ST_FAILED, kind=exc.kind, detail=exc.detail)

    err = _handle_ug_error(resp.status, resp.payload, "查询 TRAE CN 签到状态失败")
    if err is not None:
        return err

    st_payload = resp.payload
    st_data = st_payload.get("data") if isinstance(st_payload.get("data"), dict) else st_payload
    credits = _as_float(st_data.get("credits"))
    if st_data.get("checked_in") is True or st_data.get("did_checked_in") is True:
        return CheckinResult(
            status=ST_ALREADY,
            detail="今日已签到%s" % ("（%s 积分）" % _num_str(credits) if credits > 0 else ""),
            raw=st_payload,
        )
    if st_data.get("enable") is False:
        return CheckinResult(
            status=ST_SEASON,
            kind=httpc.KIND_SEASON,
            detail="当前账号暂不支持每日签到",
            raw=st_payload,
        )

    try:
        cres = httpc.request(
            "POST", base + _CHECKIN_CLAIM_PATH, headers=hdrs, body={"req_source": 1}, retries=1
        )
    except httpc.ApiError as exc:
        return CheckinResult(status=ST_FAILED, kind=exc.kind, detail=exc.detail)

    cerr = _handle_ug_error(cres.status, cres.payload, "TRAE CN 签到领取失败")
    if cerr is not None:
        return cerr

    c_payload = cres.payload
    c_data = c_payload.get("data") if isinstance(c_payload.get("data"), dict) else c_payload
    gained = _as_float(c_data.get("credits") or c_data.get("reward_credits")) or credits
    return CheckinResult(
        status=ST_SIGNED,
        credits_gained=gained,
        detail="签到成功（+%s 积分）" % _num_str(gained) if gained > 0 else "签到成功",
        raw=c_payload,
    )


def trae_credits(
    token: str, device: Optional[Dict[str, Any]] = None
) -> Tuple[CreditSnapshot, Dict[str, Any]]:
    """查询 TRAE CN 当前积分余额、套餐明细与最早到期包。"""
    tok = str(token or "").strip()
    if not tok:
        return CreditSnapshot(error="缺少 TRAE CN token"), {}

    try:
        resp = httpc.request(
            "POST",
            config.TRAE_CN_API_BASE + _USAGE_PATH,
            headers=build_ug_headers(tok, device),
            body={"require_usage": True, "req_source": 1},
            retries=2,
        )
    except httpc.ApiError as exc:
        return CreditSnapshot(error=exc.detail), {}

    if resp.status in (401, 403):
        return CreditSnapshot(error="鉴权失败（HTTP %s）" % resp.status), {}
    if resp.status >= 400 or not isinstance(resp.payload, dict):
        return CreditSnapshot(error="积分查询失败（HTTP %s）" % resp.status), {}

    payload = resp.payload
    code = payload.get("code")
    if code in _AUTH_CODES:
        return CreditSnapshot(error="登录态已失效（code %s）" % code), {}
    if code is not None and code != 0:
        return CreditSnapshot(error="%s（code %s）" % (payload.get("message") or "积分查询失败", code)), {}

    raw_packs = payload.get("user_entitlement_pack_list") or []
    grouped: Dict[str, Dict[str, float]] = {}
    exp_candidates: List[Dict[str, Any]] = []
    is_paid = False

    for p in raw_packs:
        if not isinstance(p, dict):
            continue
        base_info = p.get("entitlement_base_info") if isinstance(p.get("entitlement_base_info"), dict) else {}
        quota = base_info.get("quota") if isinstance(base_info.get("quota"), dict) else {}
        limit = _as_float(quota.get("credits_limit"))
        usage = p.get("usage") if isinstance(p.get("usage"), dict) else {}
        used = _as_float(usage.get("credits_amount"))
        if _as_float(base_info.get("charge_amount")) > 0:
            is_paid = True
        if limit <= 0:
            continue
        rem = max(0.0, limit - used)
        if rem <= 1e-6:
            continue
        name = str(p.get("display_desc") or p.get("group_name") or "积分包").strip()
        grp = grouped.setdefault(name, {"name": name, "total": 0.0, "used": 0.0, "remain": 0.0})
        grp["total"] += limit
        grp["used"] += used
        grp["remain"] += rem

        exp_raw = p.get("expire_time") or base_info.get("end_time") or 0
        try:
            exp_val = int(exp_raw or 0)
        except (TypeError, ValueError):
            exp_val = 0
        if exp_val > 0:
            exp_ms = exp_val * 1000 if exp_val < 10**12 else exp_val
            exp_candidates.append(
                {"ms": exp_ms, "name": name, "remain": rem, "size": limit}
            )

    pkgs = list(grouped.values())
    total_bal = payload.get("total_balance")
    total_remain = (
        float(total_bal)
        if isinstance(total_bal, (int, float))
        else sum(p["remain"] for p in pkgs)
    )
    snap = CreditSnapshot(total_remain=total_remain, packages=pkgs, is_paid=is_paid)

    expiry: Dict[str, Any] = {}
    if exp_candidates:
        soonest = min(exp_candidates, key=lambda c: c["ms"])
        expiry = {
            "ms": soonest["ms"],
            "expire": _fmt_ms(soonest["ms"]),
            "remain": round(soonest["remain"], 2),
            "size": soonest["size"],
            "name": soonest["name"],
        }
    return snap, expiry
