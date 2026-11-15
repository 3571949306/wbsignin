"""离线单元测试：不触网，不需要真实账号。

覆盖三处最容易出错、且一旦出错后果严重的逻辑：
  1. 凭据库加解密与防篡改；
  2. 单写者锁的互斥性；
  3. 错误分类与域名白名单。
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wbsignin import httpc, vault as vaultmod  # noqa: E402
from wbsignin.lock import FileLock, LockTimeout  # noqa: E402


def fake_jwt(claims: dict) -> str:
    """构造仅含 payload 的伪 JWT（本地解析不验签，够用）。"""
    import base64
    import json

    def seg(obj) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(obj).encode()
        ).decode().rstrip("=")

    return "%s.%s.%s" % (seg({"alg": "none"}), seg(claims), "sig")


class TestVault(unittest.TestCase):
    PW = "correct horse battery staple"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "v.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip(self):
        payload = {"version": 1, "accounts": {"13800000000": {"access_token": "AT"}}}
        blob = vaultmod.encrypt(payload, self.PW)
        self.assertEqual(vaultmod.decrypt(blob, self.PW), payload)

    def test_ciphertext_not_plaintext(self):
        payload = {"secret": "SUPER_SECRET_TOKEN_VALUE"}
        blob = vaultmod.encrypt(payload, self.PW)
        self.assertNotIn("SUPER_SECRET_TOKEN_VALUE", str(blob))

    def test_wrong_passphrase(self):
        blob = vaultmod.encrypt({"a": 1}, self.PW)
        with self.assertRaises(vaultmod.VaultError):
            vaultmod.decrypt(blob, "wrong passphrase")

    def test_tamper_detected(self):
        blob = vaultmod.encrypt({"a": 1}, self.PW)
        raw = bytearray(__import__("base64").b64decode(blob["ct"]))
        raw[0] ^= 0x01
        blob["ct"] = __import__("base64").b64encode(bytes(raw)).decode()
        with self.assertRaises(vaultmod.VaultError):
            vaultmod.decrypt(blob, self.PW)

    def test_nonce_unique(self):
        a = vaultmod.encrypt({"x": 1}, self.PW)
        b = vaultmod.encrypt({"x": 1}, self.PW)
        self.assertNotEqual(a["nonce"], b["nonce"])
        self.assertNotEqual(a["ct"], b["ct"])

    def test_file_permissions(self):
        v = vaultmod.Vault(self.path, self.PW)
        v.save({"version": 1, "accounts": {}})
        if os.name == "posix":
            mode = self.path.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
        self.assertEqual(v.load()["accounts"], {})


class TestLock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "l.lock"

    def tearDown(self):
        self.tmp.cleanup()

    def test_exclusive(self):
        a = FileLock(self.path).acquire(timeout=1)
        try:
            with self.assertRaises(LockTimeout):
                FileLock(self.path).acquire(timeout=0.2, poll=0.05)
        finally:
            a.release()
        # 释放后可再次获取
        b = FileLock(self.path).acquire(timeout=1)
        b.release()

    def test_serializes_writers(self):
        """模拟两个实例同时刷新 RT：临界区必须串行，不能交叉。"""
        order = []
        barrier = threading.Barrier(2)

        def worker(name):
            barrier.wait()
            with FileLock(self.path):
                order.append(name + "-in")
                time.sleep(0.15)
                order.append(name + "-out")

        ts = [threading.Thread(target=worker, args=(n,)) for n in ("A", "B")]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        # 必须成对出现，即 A-in,A-out,B-in,B-out 或 B-in,B-out,A-in,A-out
        self.assertEqual(len(order), 4)
        self.assertEqual(order[0][0], order[1][0])
        self.assertEqual(order[2][0], order[3][0])
        self.assertTrue(order[1].endswith("-out"))


class TestHttpc(unittest.TestCase):
    def test_host_whitelist(self):
        with self.assertRaises(httpc.ApiError) as ctx:
            httpc.request("GET", "https://evil.example.com/steal")
        self.assertEqual(ctx.exception.kind, httpc.KIND_BAD_HOST)

    def test_classify_auth(self):
        self.assertEqual(httpc.classify(httpc.Response(401, {}, ""))[0],
                         httpc.KIND_AUTH)
        self.assertEqual(httpc.classify(httpc.Response(403, {}, ""))[0],
                         httpc.KIND_AUTH)

    def test_classify_season(self):
        r = httpc.Response(200, {"code": 41000, "msg": "活动已结束"}, "")
        self.assertEqual(httpc.classify(r)[0], httpc.KIND_SEASON)

    def test_classify_restricted(self):
        r = httpc.Response(200, {"code": 11140, "msg": "账号存在异常行为"}, "")
        self.assertEqual(httpc.classify(r)[0], httpc.KIND_RESTRICTED)

    def test_classify_rate_limit_not_restricted(self):
        r = httpc.Response(200, {"code": 11140, "msg": "请求过于频繁"}, "")
        self.assertEqual(httpc.classify(r)[0], httpc.KIND_RATE_LIMIT)

    def test_classify_channel(self):
        r = httpc.Response(200, {"code": "11-128", "msg": "request illegal"}, "")
        self.assertEqual(httpc.classify(r)[0], httpc.KIND_CHANNEL)

    def test_classify_ok(self):
        self.assertEqual(httpc.classify(httpc.Response(200, {"code": 0}, ""))[0],
                         httpc.KIND_OK)

    def test_jwt_typ_detection(self):
        at = fake_jwt({"sub": "u1", "typ": "Bearer", "exp": 9999999999})
        rt = fake_jwt({"sub": "u1", "typ": "Offline", "exp": 9999999999})
        self.assertEqual(httpc.jwt_typ(at), "Bearer")
        self.assertEqual(httpc.jwt_typ(rt), "Offline")
        self.assertEqual(httpc.jwt_uid(at), "u1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
