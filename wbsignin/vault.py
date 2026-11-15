"""加密凭据库。

威胁模型（务必读一遍）
----------------------
保护目标：磁盘上的凭据文件被「误拷走」时不至于直接泄露 Refresh Token。
典型场景：备份、网盘同步、误 git add、服务器快照、别人临时拿到文件。

**不承诺**防护以下情形：攻击者已获得该用户的 shell 权限或 root 权限。
理由很直接——解密所需的 passphrase 必须能被本程序读到（环境变量或交互输入），
凡是能读环境变量的进程，也能读 vault 文件。任何声称"脚本本地加密所以绝对安全"
的说法都不成立。

构造说明
--------
KDF：scrypt（N=2^15, r=8, p=1），单次约 32MB 内存开销。
派生 64 字节，前 32 字节为加密密钥 k_enc，后 32 字节为认证密钥 k_mac。

加密：HMAC-SHA256 计数器模式，仅用标准库（不引入 AES 实现，避免自制分组密码）。
    keystream_block(i) = HMAC-SHA256(k_enc, nonce || be64(i))
    ct = pt XOR keystream
nonce 每次写入随机生成 16 字节，绝不复用（复用会直接毁掉该构造的安全性）。

认证：Encrypt-then-MAC
    tag = HMAC-SHA256(k_mac, header || nonce || ct)
校验使用 hmac.compare_digest 做常量时间比较。

为何不用 AES-GCM：标准库无 AES。引入 cryptography 依赖会破坏"零依赖"目标
（服务器 pip 安装需编译或拉 wheel）。此处选 HMAC 作为伪随机函数是标准做法
（HKDF/HMAC-DRBG 同源思路），安全性依赖 HMAC-SHA256 的 PRF 性质，
而非自创密码学原语。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any, Dict

VERSION = 1
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_LEN = 16
NONCE_LEN = 16
KEY_LEN = 32


class VaultError(Exception):
    """凭据库读写失败（密码错误、文件损坏、格式不支持）。"""


# ---------- 密钥派生 ----------
def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int):
    if not passphrase:
        raise VaultError("passphrase 不能为空")
    raw = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=KEY_LEN * 2,
        maxmem=128 * 1024 * 1024,
    )
    return raw[:KEY_LEN], raw[KEY_LEN:]


# ---------- 流加密 ----------
def _keystream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    off = 0
    counter = 0
    while off < len(data):
        block = hmac.new(
            key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        chunk = data[off: off + len(block)]
        for i, b in enumerate(chunk):
            out[off + i] = b ^ block[i]
        off += len(chunk)
        counter += 1
    return bytes(out)


def _header_bytes(meta: Dict[str, Any]) -> bytes:
    """参与 MAC 的头部字段，顺序固定，避免歧义编码。"""
    return "|".join(
        [
            str(meta["v"]),
            meta["kdf"],
            str(meta["n"]),
            str(meta["r"]),
            str(meta["p"]),
            meta["salt"],
        ]
    ).encode("utf-8")


# ---------- 加解密 ----------
def encrypt(payload: Dict[str, Any], passphrase: str) -> Dict[str, Any]:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    k_enc, k_mac = _derive(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)

    plain = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ct = _keystream_xor(k_enc, nonce, plain)

    meta = {
        "v": VERSION,
        "kdf": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "salt": base64.b64encode(salt).decode("ascii"),
        "cipher": "hmac-ctr-sha256",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    tag = hmac.new(
        k_mac, _header_bytes(meta) + nonce + ct, hashlib.sha256
    ).digest()
    meta["tag"] = base64.b64encode(tag).decode("ascii")
    return meta


def decrypt(blob: Dict[str, Any], passphrase: str) -> Dict[str, Any]:
    try:
        if int(blob.get("v", -1)) != VERSION:
            raise VaultError(
                "凭据库版本不支持：%r（本程序支持 v%d）" % (blob.get("v"), VERSION)
            )
        if blob.get("cipher") != "hmac-ctr-sha256":
            raise VaultError("未知的加密构造：%r" % (blob.get("cipher"),))
        salt = base64.b64decode(blob["salt"])
        nonce = base64.b64decode(blob["nonce"])
        ct = base64.b64decode(blob["ct"])
        tag = base64.b64decode(blob["tag"])
    except VaultError:
        raise
    except Exception as exc:
        raise VaultError("凭据库格式损坏：%s" % exc) from exc

    k_enc, k_mac = _derive(
        passphrase, salt, int(blob["n"]), int(blob["r"]), int(blob["p"])
    )
    expect = hmac.new(
        k_mac, _header_bytes(blob) + nonce + ct, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expect, tag):
        raise VaultError(
            "凭据库校验失败：passphrase 不正确，或文件已被篡改/损坏"
        )
    plain = _keystream_xor(k_enc, nonce, ct)
    try:
        return json.loads(plain.decode("utf-8"))
    except Exception as exc:
        raise VaultError("明文解析失败：%s" % exc) from exc


# ---------- 口令来源 ----------
PASSPHRASE_ENV = "WBSIGNIN_PASSPHRASE"


def get_passphrase(confirm: bool = False) -> str:
    """取 passphrase：优先环境变量，其次交互输入。

    环境变量是服务器无人值守部署的唯一可行方式；交互模式用于本机首次设置。
    """
    env = os.environ.get(PASSPHRASE_ENV, "")
    if env:
        return env
    import getpass

    pw = getpass.getpass("凭据库主密码（不会回显）: ")
    if not pw:
        raise VaultError(
            "未提供主密码。无人值守环境请设置环境变量 %s" % PASSPHRASE_ENV
        )
    if confirm:
        again = getpass.getpass("再输入一次确认: ")
        if pw != again:
            raise VaultError("两次输入不一致")
    if len(pw) < 8:
        raise VaultError("主密码过短（至少 8 位）")
    return pw


# ---------- 库对象 ----------
class Vault:
    """凭据库的读写封装。结构：

        {"version": 1, "accounts": {"<phone>": {at, rt, uid, updated, ...}}}
    """

    def __init__(self, path: Path, passphrase: str):
        self.path = Path(path)
        self._passphrase = passphrase

    # -- 读 --
    def load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "accounts": {}}
        try:
            blob = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise VaultError("凭据库无法解析：%s" % exc) from exc
        data = decrypt(blob, self._passphrase)
        data.setdefault("accounts", {})
        return data

    # -- 写 --
    def save(self, data: Dict[str, Any]) -> None:
        blob = encrypt(data, self._passphrase)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # 原子写：临时文件 + rename，避免写入中断导致凭据库损坏
        fd, tmp = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".vault-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(blob, f, ensure_ascii=False, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def exists(self) -> bool:
        return self.path.exists()
