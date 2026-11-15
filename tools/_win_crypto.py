#!/usr/bin/env python3
"""Windows 本地凭据解密工具（DPAPI + Chromium/Electron v10 AES-256-GCM）。

零第三方依赖：优先使用 cryptography（若已安装），否则直接调用 Windows CNG
`bcrypt.dll` 执行 AES-GCM 解密。
"""
from __future__ import annotations

import base64
import ctypes
import json
from ctypes import wintypes
from pathlib import Path
from typing import Optional


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_decrypt(blob: bytes) -> bytes:
    """使用当前 Windows 登录用户上下文解密 DPAPI 数据。"""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_buf = ctypes.create_string_buffer(blob, len(blob))
    in_blob = _DATA_BLOB(len(blob), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = _DATA_BLOB()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
    ):
        raise RuntimeError("DPAPI 解密失败（CryptUnprotectData 返回 0）")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


class _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.ULONG),
        ("dwInfoVersion", wintypes.ULONG),
        ("pbNonce", ctypes.c_void_p),
        ("cbNonce", wintypes.ULONG),
        ("pbAuthData", ctypes.c_void_p),
        ("cbAuthData", wintypes.ULONG),
        ("pbTag", ctypes.c_void_p),
        ("cbTag", wintypes.ULONG),
        ("pbMacContext", ctypes.c_void_p),
        ("cbMacContext", wintypes.ULONG),
        ("cbAAD", wintypes.ULONG),
        ("cbData", ctypes.c_uint64),
        ("dwFlags", wintypes.ULONG),
    ]


def _c_ubyte_array(data: bytes):
    if not data:
        return None
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


def _cng_aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    bcrypt = ctypes.windll.bcrypt
    h_alg = ctypes.c_void_p()
    h_key = ctypes.c_void_p()

    status = bcrypt.BCryptOpenAlgorithmProvider(
        ctypes.byref(h_alg), ctypes.c_wchar_p("AES"), None, 0
    )
    if status != 0:
        raise RuntimeError("BCryptOpenAlgorithmProvider 失败: 0x%08x" % (status & 0xFFFFFFFF))
    try:
        mode_val = ctypes.create_unicode_buffer("ChainingModeGCM")
        status = bcrypt.BCryptSetProperty(
            h_alg,
            ctypes.c_wchar_p("ChainingMode"),
            mode_val,
            ctypes.sizeof(mode_val),
            0,
        )
        if status != 0:
            raise RuntimeError("BCryptSetProperty 失败: 0x%08x" % (status & 0xFFFFFFFF))

        key_buf = _c_ubyte_array(key)
        status = bcrypt.BCryptGenerateSymmetricKey(
            h_alg, ctypes.byref(h_key), None, 0, key_buf, len(key), 0
        )
        if status != 0:
            raise RuntimeError("BCryptGenerateSymmetricKey 失败: 0x%08x" % (status & 0xFFFFFFFF))

        nonce_buf = _c_ubyte_array(nonce)
        tag_buf = _c_ubyte_array(tag)
        ct_buf = _c_ubyte_array(ciphertext)
        pt_buf = (ctypes.c_ubyte * max(1, len(ciphertext)))()
        cb_out = wintypes.ULONG(0)

        info = _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
        info.cbSize = ctypes.sizeof(info)
        info.dwInfoVersion = 1
        info.pbNonce = ctypes.cast(nonce_buf, ctypes.c_void_p)
        info.cbNonce = len(nonce)
        info.pbTag = ctypes.cast(tag_buf, ctypes.c_void_p)
        info.cbTag = len(tag)

        status = bcrypt.BCryptDecrypt(
            h_key,
            ct_buf,
            len(ciphertext),
            ctypes.byref(info),
            None,
            0,
            pt_buf,
            len(ciphertext),
            ctypes.byref(cb_out),
            0,
        )
        if status != 0:
            raise RuntimeError("BCryptDecrypt 失败: 0x%08x" % (status & 0xFFFFFFFF))
        return bytes(pt_buf[: cb_out.value])
    finally:
        if h_key.value:
            bcrypt.BCryptDestroyKey(h_key)
        if h_alg.value:
            bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)


def aes_gcm_decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """解密 Chromium/Electron AES-256-GCM（data = ciphertext || 16B tag）。"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

        return AESGCM(key).decrypt(nonce, data, None)
    except ImportError:
        if len(data) < 16:
            raise ValueError("AES-GCM 密文长度不足 16 字节")
        return _cng_aes_gcm_decrypt(key, nonce, data[:-16], data[-16:])


def chromium_local_state_key(user_data_dir: Path) -> bytes:
    """读取 Chromium/Electron User Data 目录下的 Local State 并解密主密钥。"""
    state = json.loads((user_data_dir / "Local State").read_text(encoding="utf-8"))
    enc = base64.b64decode(state["os_crypt"]["encrypted_key"])
    if not enc.startswith(b"DPAPI"):
        raise RuntimeError("encrypted_key 不是 DPAPI 格式")
    return dpapi_decrypt(enc[5:])


def decrypt_v10(blob: bytes, key: bytes) -> Optional[bytes]:
    """解密 Chromium v10 加密块；遇到 v20 app-bound 加密返回 None。"""
    raw = bytes(blob)
    if raw.startswith(b"v20"):
        return None
    if raw.startswith(b"v10"):
        return aes_gcm_decrypt(key, raw[3:15], raw[15:])
    return raw
