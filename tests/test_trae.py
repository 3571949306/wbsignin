"""TRAE CN（trae.cn）协议、纯标准库 P-256 ECDSA 签名、续期与集成离线单元测试。"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from wbsignin import cli, config, httpc, runner, tasks, trae
from wbsignin.auth import Account
from wbsignin.vault import Vault
from wbsignin.web import App


def _resp(payload, status=200):
    return httpc.Response(status=status, payload=payload, text="{}")


def _dummy_p256_pkcs8_pem(d: int = 0x112233445566778899AABBCCDDEEFF01112233445566778899AABBCCDDEEFF01) -> str:
    """构造仅用于单元测试的合法合成 PKCS#8 NIST P-256 EC 私钥 PEM。"""
    priv_bytes = d.to_bytes(32, "big")
    inner_ec = (
        b"\x30\x77"
        b"\x02\x01\x01"
        b"\x04\x20" + priv_bytes
    )
    # 无需真公钥扩展也能满足 parse；补全真实公钥点以模拟完整 PKCS#8
    pub_pt = trae._ec_mul(d)
    assert pub_pt is not None
    pub_uncompressed = b"\x04" + pub_pt[0].to_bytes(32, "big") + pub_pt[1].to_bytes(32, "big")
    oid_p256 = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
    ec_priv = (
        b"\x30" + bytes([3 + 2 + 32 + 2 + len(oid_p256) + 4 + len(pub_uncompressed)])
        + b"\x02\x01\x01\x04\x20" + priv_bytes
        + b"\xa0" + bytes([len(oid_p256)]) + oid_p256
        + b"\xa1" + bytes([len(pub_uncompressed) + 3]) + b"\x03" + bytes([len(pub_uncompressed) + 1]) + b"\x00" + pub_uncompressed
    )
    oid_ecpub = b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
    alg_id = b"\x30" + bytes([len(oid_ecpub) + len(oid_p256)]) + oid_ecpub + oid_p256
    pkcs8_body = b"\x02\x01\x00" + alg_id + b"\x04" + bytes([len(ec_priv)]) + ec_priv
    pkcs8 = b"\x30" + bytes([0x81, len(pkcs8_body)]) + pkcs8_body if len(pkcs8_body) >= 128 else b"\x30" + bytes([len(pkcs8_body)]) + pkcs8_body
    b64 = base64.b64encode(pkcs8).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END PRIVATE KEY-----\n"


def _verify_p256_der(d: int, msg: bytes, sig_der: bytes) -> bool:
    """独立验证 ASN.1 DER P-256 ECDSA 签名在数学上对应 Q = d*G。"""
    if len(sig_der) < 8 or sig_der[0] != 0x30 or sig_der[2] != 0x02:
        return False
    r_len = sig_der[3]
    r = int.from_bytes(sig_der[4 : 4 + r_len], "big")
    s_pos = 4 + r_len
    if sig_der[s_pos] != 0x02:
        return False
    s_len = sig_der[s_pos + 1]
    s = int.from_bytes(sig_der[s_pos + 2 : s_pos + 2 + s_len], "big")
    n = trae._P256_N
    if not (1 <= r < n and 1 <= s < n):
        return False
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big") % n
    w = pow(s, -1, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    q_pt = trae._ec_mul(d)
    p1 = trae._ec_mul(u1)
    p2 = trae._ec_mul(u2, q_pt)  # type: ignore[arg-type]
    pt = trae._ec_add(p1, p2)
    return pt is not None and (pt[0] % n) == r


class TraeHelpersAndCryptoTests(unittest.TestCase):
    def test_config_and_account_roundtrip(self):
        self.assertIn("api.trae.cn", config.ALLOWED_HOSTS)
        self.assertIn("api.trae.com.cn", config.ALLOWED_HOSTS)
        acc = Account.from_dict(
            "trae-cn:u100",
            {
                "provider": "trae-cn",
                "access_token": "tok-1",
                "refresh_token": "rt-1",
                "uid": "u100",
                "at_exp": 1800000000,
                "device": {"deviceId": "dev-1"},
            },
        )
        self.assertTrue(acc.is_trae)
        self.assertFalse(acc.is_qoder)
        self.assertEqual(acc.masked(), "TRAE CN")
        self.assertEqual(acc.to_dict()["device"], {"deviceId": "dev-1"})

    def test_p256_ecdsa_pkcs8_and_device_proof(self):
        d = 0x112233445566778899AABBCCDDEEFF01112233445566778899AABBCCDDEEFF01
        pem = _dummy_p256_pkcs8_pem(d)
        msg = b"POST\n/trae/api/v3/oauth/ExchangeToken\nono9krqynydwx5\nrt-xyz\n1794796800\nnonce123"
        sig = trae.sign_p256_sha256(pem, msg)
        self.assertTrue(_verify_p256_der(d, msg, sig))
        # RFC 6979 确定性：同输入同签名
        self.assertEqual(sig, trae.sign_p256_sha256(pem, msg))

        proof = trae.build_device_proof(pem, "ono9krqynydwx5", "rt-xyz", timestamp=1794796800, nonce="nonce123")
        self.assertEqual(proof["Timestamp"], 1794796800)
        self.assertEqual(proof["Nonce"], "nonce123")
        self.assertTrue(_verify_p256_der(d, msg, base64.b64decode(proof["Signature"])))


class TraeCheckinCreditsAndRefreshTests(unittest.TestCase):
    def test_checkin_claimable_and_already_and_errors(self):
        dev = {"deviceId": "123456", "appVersion": "3.4.18", "osName": "win32"}
        seen_headers = []

        def fake_claimable(method, url, headers=None, body=None, **kw):
            seen_headers.append(headers or {})
            if url.endswith("/checkin_credits/status"):
                return _resp({"code": 0, "enable": True, "checked_in": False, "credits": 200})
            if url.endswith("/checkin_credits/claim"):
                return _resp({"code": 0, "message": "success"})
            raise AssertionError(url)

        with patch("wbsignin.httpc.request", side_effect=fake_claimable):
            r = trae.trae_checkin("jwt-abc", dev)
        self.assertEqual(r.status, tasks.ST_SIGNED)
        self.assertEqual(r.credits_gained, 200.0)
        self.assertEqual(seen_headers[0]["Authorization"], "Cloud-IDE-JWT jwt-abc")
        self.assertEqual(seen_headers[0]["x-device-id"], "123456")

        # 已签到时不请求 claim
        with patch(
            "wbsignin.httpc.request",
            return_value=_resp({"code": 0, "enable": True, "checked_in": True, "credits": 200}),
        ) as m:
            r_alr = trae.trae_checkin("jwt-abc", dev)
        self.assertEqual(r_alr.status, tasks.ST_ALREADY)
        self.assertEqual(m.call_count, 1)

        # 设备重复签到 code=9095 -> ST_ALREADY
        with patch(
            "wbsignin.httpc.request",
            side_effect=[
                _resp({"code": 0, "enable": True, "checked_in": False, "credits": 200}),
                _resp({"code": 9095, "message": "device checked in"}),
            ],
        ):
            r_9095 = trae.trae_checkin("jwt-abc", dev)
        self.assertEqual(r_9095.status, tasks.ST_ALREADY)

        # 活动关闭 code=9090 -> ST_SEASON；鉴权失败 code=1002 -> KIND_AUTH
        with patch("wbsignin.httpc.request", return_value=_resp({"code": 9090})):
            r_9090 = trae.trae_checkin("jwt-abc", dev)
        self.assertEqual(r_9090.status, tasks.ST_SEASON)

        with patch("wbsignin.httpc.request", return_value=_resp({"code": 1002})):
            r_1002 = trae.trae_checkin("jwt-abc", dev)
        self.assertEqual(r_1002.status, tasks.ST_SKIPPED)
        self.assertEqual(r_1002.kind, httpc.KIND_AUTH)

    def test_credits_grouping_and_earliest_expiry(self):
        exp1 = int(datetime.datetime(2026, 12, 12, 22, 1, tzinfo=config.BJ_TZ).timestamp())
        exp2 = int(datetime.datetime(2026, 12, 13, 10, 0, tzinfo=config.BJ_TZ).timestamp())
        payload = {
            "total_balance": 2249.63,
            "user_entitlement_pack_list": [
                {
                    "display_desc": "会员 Lite",
                    "expire_time": exp1,
                    "usage": {"credits_amount": 550.3744},
                    "entitlement_base_info": {"charge_amount": 990, "quota": {"credits_limit": 2000}},
                },
                {
                    "display_desc": "每月登录赠送",
                    "expire_time": exp1 - 86400,
                    "usage": {"credits_amount": 500},
                    "entitlement_base_info": {"charge_amount": 0, "quota": {"credits_limit": 500}},
                },
                {
                    "display_desc": "签到奖励",
                    "expire_time": exp2,
                    "usage": {"credits_amount": None},
                    "entitlement_base_info": {"charge_amount": 0, "quota": {"credits_limit": 200}},
                },
                {
                    "display_desc": "签到奖励",
                    "expire_time": exp2 + 86400,
                    "usage": {"credits_amount": 0},
                    "entitlement_base_info": {"charge_amount": 0, "quota": {"credits_limit": 200}},
                },
            ],
        }
        with patch("wbsignin.httpc.request", return_value=_resp(payload)):
            snap, exp = trae.trae_credits("jwt-abc", {"deviceId": "123"})
        self.assertEqual(snap.total_remain, 2249.63)
        self.assertTrue(snap.is_paid)
        self.assertEqual(len(snap.packages), 2)
        self.assertEqual(exp["name"], "会员 Lite")
        self.assertEqual(exp["expire"], "2026-12-12 22:01")
        self.assertEqual(exp["ms"], exp1 * 1000)

    def test_runner_refresh_all_for_trae(self):
        pem = _dummy_p256_pkcs8_pem()
        soon = int(time.time()) + 3600
        future_iso = "2026-12-01T00:00:00Z"

        with tempfile.TemporaryDirectory() as d:
            home_dir = Path(d)
            with patch.dict("os.environ", {"WBSIGNIN_HOME": str(home_dir)}):
                vault = Vault(home_dir / "vault.json", "pass-trae-test-123")
                acc = Account(
                    phone="trae-cn:u100",
                    provider="trae-cn",
                    access_token="old-tok",
                    refresh_token="old-rt",
                    uid="u100",
                    at_exp=soon,
                    label="TRAE 测试",
                    device={"deviceId": "dev-1", "privateKeyPEM": pem, "publicKeyPEM": "PUB_PEM"},
                )
                vault.save({"version": 1, "accounts": {acc.phone: acc.to_dict()}})
                accounts = runner.load_accounts(vault)

                def fake_exchange(method, url, headers=None, body=None, **kw):
                    self.assertIn("/trae/api/v3/oauth/ExchangeToken", url)
                    self.assertEqual(body["RefreshToken"], "old-rt")
                    self.assertTrue(body["DeviceProof"]["Signature"])
                    return _resp(
                        {
                            "Result": {
                                "Token": "new-tok",
                                "RefreshToken": "new-rt",
                                "TokenExpireAt": future_iso,
                                "RefreshExpireAt": "2027-05-08T00:00:00Z",
                            }
                        }
                    )

                with patch("wbsignin.httpc.request", side_effect=fake_exchange):
                    errs = runner.refresh_all(accounts, vault)
                self.assertEqual(errs, {})
                reloaded = runner.load_accounts(vault)["trae-cn:u100"]
                self.assertEqual(reloaded.access_token, "new-tok")
                self.assertEqual(reloaded.refresh_token, "new-rt")
                self.assertGreater(reloaded.at_exp, soon)


class TraeCliAndWebIntegrationTests(unittest.TestCase):
    def test_cli_web_login_trae_and_signin_run(self):
        with tempfile.TemporaryDirectory() as d:
            home_dir = Path(d)
            cred_file = home_dir / "trae.json"
            cred_file.write_text(
                json.dumps(
                    {
                        "provider": "trae-cn",
                        "token": "jwt-trae-1",
                        "refresh_token": "rt-trae-1",
                        "expires_at": "2026-11-23T01:27:44.178Z",
                        "device": {"deviceId": "dev-99", "machineId": "m-99"},
                    }
                ),
                encoding="utf-8",
            )

            def fake_req(method, url, headers=None, body=None, **kw):
                if "/trae/GetUserInfo" in url:
                    return _resp({"Result": {"UserID": "2068001", "NonPlainTextMobile": "138******00", "AIRegion": "CN"}})
                if "/checkin_credits/status" in url:
                    return _resp({"code": 0, "enable": True, "checked_in": False, "credits": 200})
                if "/checkin_credits/claim" in url:
                    return _resp({"code": 0, "message": "success"})
                if "/ide_user_ent_usage" in url:
                    return _resp(
                        {
                            "total_balance": 2449.63,
                            "user_entitlement_pack_list": [
                                {
                                    "display_desc": "签到奖励",
                                    "expire_time": 1797115452,
                                    "usage": {"credits_amount": 0},
                                    "entitlement_base_info": {"quota": {"credits_limit": 200}},
                                }
                            ],
                        }
                    )
                raise AssertionError("unexpected url: " + url)

            with patch.dict(
                "os.environ",
                {"WBSIGNIN_HOME": str(home_dir), "WBSIGNIN_PASSPHRASE": "p-test-trae-123"},
            ):
                with patch("wbsignin.httpc.request", side_effect=fake_req):
                    rc = cli.main(["login-trae", "--from-json", str(cred_file)])
                    self.assertEqual(rc, 0)

                    vault = Vault(config.vault_path(), "p-test-trae-123")
                    app = App(vault)
                    res = app.do_signin()
                    self.assertEqual(res["failed"], 0)
                    self.assertEqual(res["rows"][0]["provider"], "trae-cn")
                    self.assertEqual(res["rows"][0]["status"], "SIGNED")
                    self.assertEqual(res["rows"][0]["credit"], "2449.6")

                    # 再跑一次 Web login 应按 UserID 去重更新
                    up = app.do_login_trae(token="jwt-trae-2", name="TRAE 主号")
                    self.assertEqual(up["masked"], "TRAE 主号")
                    saved = vault.load()["accounts"]
                    self.assertEqual(len(saved), 1)
                    self.assertIn("trae-cn:2068001", saved)

    def test_generate_p256_keypair_and_oauth_multi_account_callback(self):
        import urllib.parse

        priv, pub = trae.generate_p256_keypair()
        self.assertIn("BEGIN PRIVATE KEY", priv)
        self.assertIn("BEGIN PUBLIC KEY", pub)
        d = trae._parse_pkcs8_ec_privkey(priv)
        msg = b"POST\n/trae/api/v3/oauth/ExchangeToken\ncid\nrt\n1700000000\nn"
        self.assertTrue(_verify_p256_der(d, msg, trae.sign_p256_sha256(priv, msg)))

        with self.assertRaises(httpc.ApiError):
            trae.oauth_start("https://evil.example.com:8787")

        with tempfile.TemporaryDirectory() as d_dir:
            home_dir = Path(d_dir)
            with patch.dict("os.environ", {"WBSIGNIN_HOME": str(home_dir)}):
                vault = Vault(home_dir / "vault.json", "pass-oauth-123")
                app = App(vault)

                # 先模拟已存在一个主号，验证网页授权能追加第 2 个小号并带独立 deviceId
                vault.save(
                    {
                        "version": 1,
                        "accounts": {
                            "trae-cn:1001": Account(
                                phone="trae-cn:1001", provider="trae-cn",
                                access_token="tok-1", uid="1001", label="TRAE-1",
                                device={"deviceId": "dev-111"},
                            ).to_dict()
                        },
                    }
                )

                started = app.do_trae_oauth_start("http://localhost:8787", name="TRAE-2号")
                tid = started["trace_id"]
                parsed = urllib.parse.urlparse(started["auth_url"])
                q = dict(urllib.parse.parse_qsl(parsed.query))
                self.assertEqual(q["auth_callback_url"], "http://127.0.0.1:8787/authorize")
                self.assertEqual(q["code_challenge_method"], "S256")
                self.assertEqual(q["login_trace_id"], tid)

                def fake_req(method, url, headers=None, body=None, **kw):
                    if "/trae/api/v3/oauth/ExchangeToken" in url:
                        self.assertEqual(body["AuthCode"], "ac-xyz")
                        self.assertTrue(body["CodeVerifier"])
                        self.assertEqual(body["DeviceInfo"]["DevicePublicKey"], app._trae_oauth_sessions[tid]["device"]["publicKeyPEM"])
                        return _resp(
                            {
                                "Result": {
                                    "Token": "tok-2",
                                    "RefreshToken": "rt-2",
                                    "TokenExpireAt": "2026-12-01T00:00:00Z",
                                    "RefreshExpireAt": "2027-06-01T00:00:00Z",
                                }
                            }
                        )
                    if "/trae/GetUserInfo" in url:
                        return _resp({"Result": {"UserID": "2002", "NonPlainTextMobile": "139******88", "AIRegion": "CN"}})
                    if "/ide_user_ent_usage" in url:
                        return _resp({"total_balance": 1500, "user_entitlement_pack_list": []})
                    raise AssertionError("unexpected url: " + url)

                cb_query = urllib.parse.urlencode(
                    {
                        "isRedirect": "true",
                        "scope": "marscode",
                        "authCodeInfo": json.dumps({"AuthCode": "ac-xyz"}),
                        "loginTraceID": tid,
                        "host": "https://api.trae.cn",
                    }
                )
                with patch("wbsignin.httpc.request", side_effect=fake_req):
                    html_out = app.do_trae_oauth_callback(cb_query)
                self.assertIn("TRAE CN 授权成功", html_out)
                st = app.do_trae_oauth_status(tid)
                self.assertEqual(st["status"], "done")
                self.assertEqual(st["masked"], "TRAE-2号")

                # 重放同一个 trace_id 回调必须被拒绝
                replay = app.do_trae_oauth_callback(cb_query)
                self.assertIn("无效或已过期", replay)

                saved = vault.load()["accounts"]
                self.assertEqual(len(saved), 2)
                self.assertIn("trae-cn:1001", saved)
                self.assertIn("trae-cn:2002", saved)
                self.assertNotEqual(saved["trae-cn:2002"]["device"]["deviceId"], "dev-111")


if __name__ == "__main__":
    unittest.main(verbosity=2)
