"""豆包模块离线测试：Cookie 规整、设备标识派生（不触网）。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wbsignin import doubao  # noqa: E402


class TestNormalizeCookie(unittest.TestCase):
    def test_strip_prefix(self):
        self.assertEqual(
            doubao.normalize_cookie("Cookie: a=b; c=d"), "a=b; c=d"
        )
        self.assertEqual(
            doubao.normalize_cookie("cookie: a=b"), "a=b"
        )

    def test_collapse_newlines(self):
        raw = "a=b;\n c=d;\r\ne=f"
        self.assertEqual(doubao.normalize_cookie(raw), "a=b; c=d; e=f")

    def test_normalize_separators(self):
        self.assertEqual(doubao.normalize_cookie("a=b;c=d; e=f "), "a=b; c=d; e=f")

    def test_empty(self):
        self.assertEqual(doubao.normalize_cookie(""), "")
        self.assertEqual(doubao.normalize_cookie("  Cookie:  "), "")


class TestDeviceIds(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(doubao.device_ids("seed1"), doubao.device_ids("seed1"))

    def test_distinct(self):
        a = doubao.device_ids("seed1")
        b = doubao.device_ids("seed2")
        self.assertNotEqual(a, b)

    def test_format(self):
        d = doubao.device_ids("anyseed")
        self.assertTrue(d["device_id"].startswith("4"))
        self.assertEqual(len(d["device_id"]), 16)
        self.assertTrue(d["device_id"].isdigit())
        self.assertTrue(d["web_id"].startswith("76"))
        self.assertEqual(len(d["web_id"]), 19)
        self.assertTrue(d["web_id"].isdigit())
        self.assertEqual(d["tea_uuid"], d["device_id"])
        self.assertEqual(d["fp"], "verify_" + d["device_id"])

    def test_api_url_desktop_params(self):
        import urllib.parse
        from wbsignin import config

        u = doubao._api_url(config.DOUBAO_DETAIL_URL, "seed1")
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(u).query))
        self.assertEqual(q["aid"], "582478")
        self.assertEqual(q["real_aid"], "582478")
        self.assertEqual(q["doubao_device_platform"], "desktop")
        self.assertEqual(q["runtime_version"], "3.44.9")
        self.assertEqual(q["region"], "CN")
        self.assertEqual(q["fp"], "verify_" + q["device_id"])
        self.assertEqual(doubao._headers("sid=1").get("Agw-Js-Conv"), "str")


class OverseasFallbackTests(unittest.TestCase):
    def _resp(self, payload, status=200):
        from wbsignin import httpc

        return httpc.Response(status=status, payload=payload, text="{}")

    def test_quota_records_pagination_and_today(self):
        from unittest.mock import patch
        import datetime
        from wbsignin import config

        today_ms = int(datetime.datetime.now(config.BJ_TZ).timestamp() * 1000)
        old_ms = today_ms - 3 * 86400 * 1000
        pages = [
            self._resp(
                {
                    "code": 0,
                    "data": {
                        "has_more": True,
                        "next_cursor": "c2",
                        "records": [
                            {"amount": 200, "task_code": "daily_signin", "create_time_ms": today_ms},
                            {"amount": 300, "task_code": "bonus", "create_time_ms": old_ms},
                        ],
                    },
                }
            ),
            self._resp(
                {
                    "code": 0,
                    "data": {
                        "has_more": False,
                        "records": [
                            {"amount": 500, "task_code": "daily_signin", "create_time_ms": old_ms},
                        ],
                    },
                }
            ),
        ]
        with patch("wbsignin.httpc.request", side_effect=pages) as m:
            res = doubao.doubao_quota_records("sessionid=abc", seed="s1")
        self.assertTrue(res["auth"])
        self.assertEqual(res["total_amount"], 1000)
        self.assertTrue(res["checked_in"])
        self.assertEqual(m.call_count, 2)

    def test_status_code2_overseas_fallback(self):
        from unittest.mock import patch

        def fake_req(method, url, headers=None, body=None, **kw):
            if "/v3/detail/" in url:
                return self._resp({"code": 2, "data": None, "message": "campaign not found"})
            if "/landing/checkin" in url:
                return self._resp(
                    {"code": 0, "data": {"idempotent": True, "continuous_days": 7, "reward_amount": 200}}
                )
            if "/subscription/overview/" in url:
                return self._resp(
                    {
                        "code": 0,
                        "data": {
                            "quota_balance_overview": {
                                "total_remaining_amount": "8,754",
                                "top_items": [
                                    {
                                        "display_name": "标准套餐",
                                        "end_time": 1796290560301,
                                        "total_amount": "9,000",
                                        "used_amount": "1,007",
                                    }
                                ],
                            },
                            "package_entitlement_groups": [
                                {
                                    "entitlements": [
                                        {
                                            "display": {"title": "标准套餐"},
                                            "end_time": 1796290560301,
                                            "total_amount": "9,000",
                                            "used_amount": "1,007",
                                        }
                                    ]
                                }
                            ],
                            "incentive_quota_section": {
                                "window_limit_groups": [
                                    {
                                        "feature_group_name": "活动赠送额度",
                                        "window_limits": [
                                            {"total_amount": "3,500", "used_amount": "2,739"}
                                        ],
                                    }
                                ]
                            },
                            "current_subscription": {"sku_key": "doubao_personal_std", "is_gift": True, "agreement_price": 0},
                        },
                    }
                )
            raise AssertionError("unexpected url: " + url)

        with patch("wbsignin.httpc.request", side_effect=fake_req):
            st = doubao.doubao_status("sessionid=abc; uid_tt=u1", seed="s1")
        self.assertTrue(st["auth"])
        self.assertTrue(st["checked_in"])
        self.assertEqual(st["continuous_days"], 7)
        self.assertEqual(st["total_amount"], 8754.0)

    def test_doubao_credits_and_expiry(self):
        from unittest.mock import patch

        payload = {
            "code": 0,
            "data": {
                "quota_balance_overview": {
                    "total_remaining_amount": "8,754",
                    "top_items": [
                        {"display_name": "活动赠送额度", "end_time": 1797042505102, "total_amount": "200", "used_amount": "39"},
                        {"display_name": "标准套餐", "end_time": 1796290560301, "total_amount": "9,000", "used_amount": "1,007"},
                    ],
                },
                "package_entitlement_groups": [
                    {"entitlements": [{"display": {"title": "标准套餐"}, "end_time": 1796290560301, "total_amount": "9,000", "used_amount": "1,007"}]}
                ],
                "incentive_quota_section": {
                    "window_limit_groups": [
                        {"feature_group_name": "活动赠送额度", "window_limits": [{"total_amount": "3,500", "used_amount": "2,739"}]}
                    ]
                },
                "current_subscription": {"sku_key": "doubao_personal_std", "is_gift": True, "agreement_price": 0},
            },
        }
        with patch("wbsignin.httpc.request", return_value=self._resp(payload)):
            snap, exp = doubao.doubao_credits("sessionid=abc", seed="s1")
        self.assertEqual(snap.total_remain, 8754.0)
        self.assertEqual(len(snap.packages), 2)
        self.assertFalse(snap.is_paid)
        lines = snap.lines()
        self.assertIn("标准套餐 剩余 7993", lines[0])
        self.assertIn("活动赠送额度 剩余 761", lines[1])
        self.assertEqual(exp["name"], "标准套餐")
        self.assertEqual(exp["ms"], 1796290560301)

    def test_checkin_states_signed_already_notask_and_expired(self):
        from unittest.mock import patch

        ov_ok = self._resp(
            {
                "code": 0,
                "data": {
                    "quota_balance_overview": {"total_remaining_amount": "3,700"},
                    "current_subscription": {},
                },
            }
        )
        detail_pending = self._resp(
            {
                "code": 0,
                "data": {
                    "tasks": [
                        {
                            "task_kind": "daily_signin",
                            "daily_checkin": {
                                "checked_in_today": False,
                                "continuous_days": 7,
                                "reward": {"reward_amount": 200},
                            },
                        }
                    ]
                },
            }
        )
        with patch(
            "wbsignin.httpc.request",
            side_effect=[
                detail_pending,
                self._resp({"code": 0, "data": {"idempotent": False, "continuous_days": 8, "reward_amount": 200}}),
                ov_ok,
            ],
        ):
            r1 = doubao.doubao_checkin("sessionid=abc", seed="s1")
        self.assertEqual(r1["state"], doubao.ST_SIGNED)
        self.assertEqual(r1["reward_amount"], 200)
        self.assertEqual(r1["continuous_days"], 8)
        self.assertEqual(r1["total_amount"], 3700.0)

        # overview 失败时应回退到 quota/records
        with patch(
            "wbsignin.httpc.request",
            side_effect=[
                detail_pending,
                self._resp({"code": 0, "data": {"idempotent": True, "continuous_days": 7}}),
                self._resp({"code": 500}, status=500),
                self._resp({"code": 0, "data": {"has_more": False, "records": [{"amount": 3500}]}}),
            ],
        ):
            r2 = doubao.doubao_checkin("sessionid=abc", seed="s1")
        self.assertEqual(r2["state"], doubao.ST_ALREADY)
        self.assertEqual(r2["total_amount"], 3500)

        with patch(
            "wbsignin.httpc.request",
            return_value=self._resp({"code": 0, "data": {"tasks": [{"task_kind": "other_task"}]}}),
        ):
            r3 = doubao.doubao_checkin("sessionid=abc", seed="s1")
        self.assertEqual(r3["state"], doubao.ST_NO_TASK)
        self.assertEqual(r3["kinds"], ["other_task"])

        with patch(
            "wbsignin.httpc.request",
            return_value=self._resp({"code": doubao.LOGIN_INVALID, "msg": "not login"}),
        ):
            r4 = doubao.doubao_checkin("sessionid=abc", seed="s1")
        self.assertEqual(r4["state"], doubao.ST_FAILED)
        self.assertTrue(r4.get("auth_expired"))

    def test_checkin_detail_already_short_circuit(self):
        from unittest.mock import patch

        called = []

        def fake_req(method, url, **kw):
            called.append(url)
            if "/v3/detail/" in url:
                return self._resp(
                    {
                        "code": 0,
                        "data": {
                            "tasks": [
                                {
                                    "task_kind": "daily_signin",
                                    "daily_checkin": {
                                        "checked_in_today": True,
                                        "continuous_days": 7,
                                        "reward": {"reward_amount": 400},
                                    },
                                }
                            ]
                        },
                    }
                )
            if "/landing/checkin" in url:
                raise AssertionError("already checked in should not call /landing/checkin")
            if "/subscription/overview/" in url:
                return self._resp({"code": 0, "data": {"quota_balance_overview": {"total_remaining_amount": "8,754"}}})
            raise AssertionError("unexpected url: " + url)

        with patch("wbsignin.httpc.request", side_effect=fake_req):
            r = doubao.doubao_checkin("sessionid=abc", seed="s1")
        self.assertEqual(r["state"], doubao.ST_ALREADY)
        self.assertEqual(r["continuous_days"], 7)
        self.assertEqual(r["total_amount"], 8754.0)
        self.assertFalse(any("/landing/checkin" in u for u in called))

    def test_checkin_daily_signin_present_710010702_is_failed(self):
        from unittest.mock import patch

        def fake_req(method, url, **kw):
            if "/v3/detail/" in url:
                return self._resp(
                    {
                        "code": 0,
                        "data": {
                            "tasks": [
                                {
                                    "task_kind": "daily_signin",
                                    "daily_checkin": {
                                        "checked_in_today": False,
                                        "continuous_days": 7,
                                        "reward": {"reward_amount": 400},
                                    },
                                }
                            ]
                        },
                    }
                )
            if "/landing/checkin" in url:
                return self._resp({"code": doubao.NO_ACTIVITY, "message": "系统错误"})
            raise AssertionError("unexpected url: " + url)

        with patch("wbsignin.httpc.request", side_effect=fake_req):
            r = doubao.doubao_checkin("sessionid=abc", seed="s1")
        self.assertEqual(r["state"], doubao.ST_FAILED)
        self.assertEqual(r.get("upstream_code"), doubao.NO_ACTIVITY)
        self.assertIn("daily_signin", r["error"])
        self.assertIn("710010702", r["error"])

    def test_checkin_code2_overseas_710010702_with_records_history(self):
        import datetime
        from unittest.mock import patch
        from wbsignin import config

        old_dt = datetime.datetime.now(config.BJ_TZ) - datetime.timedelta(days=2)
        old_ms = int(old_dt.timestamp() * 1000)
        expected_date = old_dt.strftime("%Y-%m-%d")

        def fake_req(method, url, **kw):
            if "/v3/detail/" in url:
                return self._resp({"code": 2, "data": None, "message": "campaign not found"})
            if "/quota/records/" in url:
                return self._resp(
                    {
                        "code": 0,
                        "data": {
                            "has_more": False,
                            "records": [
                                {"amount": 200, "task_code": "daily_signin", "create_time_ms": old_ms}
                            ],
                        },
                    }
                )
            if "/landing/checkin" in url:
                return self._resp({"code": doubao.NO_ACTIVITY, "message": "系统错误"})
            raise AssertionError("unexpected url: " + url)

        with patch("wbsignin.httpc.request", side_effect=fake_req):
            r = doubao.doubao_checkin("sessionid=abc", seed="s1")
        self.assertEqual(r["state"], doubao.ST_FAILED)
        self.assertEqual(r.get("upstream_code"), doubao.NO_ACTIVITY)
        self.assertIn(expected_date, r["error"])
        self.assertIn("710010702", r["error"])
        self.assertIn("WBSIGNIN_DOUBAO_PROXY", r["error"])

        # 若海外场景下 quota/records 显示今日已签，直接返回 ST_ALREADY 且不再打 /landing/checkin
        today_ms = int(datetime.datetime.now(config.BJ_TZ).timestamp() * 1000)

        def fake_req_today(method, url, **kw):
            if "/v3/detail/" in url:
                return self._resp({"code": 2, "data": None})
            if "/quota/records/" in url:
                return self._resp(
                    {
                        "code": 0,
                        "data": {
                            "has_more": False,
                            "records": [
                                {"amount": 400, "task_code": "daily_signin", "create_time_ms": today_ms}
                            ],
                        },
                    }
                )
            if "/subscription/overview/" in url:
                return self._resp({"code": 0, "data": {"quota_balance_overview": {"total_remaining_amount": "9,154"}}})
            raise AssertionError("unexpected url: " + url)

        with patch("wbsignin.httpc.request", side_effect=fake_req_today):
            r_today = doubao.doubao_checkin("sessionid=abc", seed="s1")
        self.assertEqual(r_today["state"], doubao.ST_ALREADY)
        self.assertEqual(r_today["total_amount"], 9154.0)

    def test_status_code2_fallback_auth_when_landing_710010702(self):
        from unittest.mock import patch

        def fake_req(method, url, **kw):
            if "/v3/detail/" in url:
                return self._resp({"code": 2, "data": None, "message": "campaign not found"})
            if "/landing/checkin" in url:
                return self._resp({"code": doubao.NO_ACTIVITY, "message": "系统错误"})
            if "/quota/records/" in url:
                return self._resp({"code": 0, "data": {"has_more": False, "records": [{"amount": 200}]}})
            if "/subscription/overview/" in url:
                return self._resp({"code": 0, "data": {"quota_balance_overview": {"total_remaining_amount": "8,754"}}})
            raise AssertionError("unexpected url: " + url)

        with patch("wbsignin.httpc.request", side_effect=fake_req):
            st = doubao.doubao_status("sessionid=abc; uid_tt=u1", seed="s1")
        self.assertTrue(st["auth"])
        self.assertFalse(st["checked_in"])
        self.assertEqual(st["total_amount"], 8754.0)
        self.assertIn("710010702", st["claim_error"])

    def test_proxy_forwarding_and_scheme_validation(self):
        import os
        from unittest.mock import patch
        from wbsignin import config, httpc

        seen_kwargs = {}

        def fake_req(method, url, **kw):
            seen_kwargs.update(kw)
            return self._resp({"code": 0, "data": {}})

        with patch.dict(os.environ, {"WBSIGNIN_DOUBAO_PROXY": "http://127.0.0.1:7890"}):
            with patch("wbsignin.httpc.request", side_effect=fake_req):
                doubao._post(config.DOUBAO_DETAIL_URL, "sid=1", {"campaign_group_code": "x"})
        self.assertEqual(seen_kwargs.get("proxy_url"), "http://127.0.0.1:7890")

        with self.assertRaises(httpc.ApiError) as ctx:
            httpc.request("POST", config.DOUBAO_DETAIL_URL, proxy_url="socks5://127.0.0.1:1080")
        self.assertEqual(ctx.exception.kind, httpc.KIND_BAD_HOST)

    def test_runner_work_doubao_keeps_credits_on_checkin_failure(self):
        from unittest.mock import patch
        from wbsignin import httpc, runner
        from wbsignin.auth import Account

        acc = Account(phone="doubao:seed1", provider="doubao", cookie="sessionid=1", uid="seed1", label="豆包主号")

        def fake_req(method, url, **kw):
            if "/v3/detail/" in url:
                return self._resp({"code": 2, "data": None})
            if "/quota/records/" in url:
                return self._resp({"code": 0, "data": {"has_more": False, "records": []}})
            if "/landing/checkin" in url:
                return self._resp({"code": doubao.NO_ACTIVITY, "message": "系统错误"})
            if "/subscription/overview/" in url:
                return self._resp(
                    {
                        "code": 0,
                        "data": {
                            "quota_balance_overview": {
                                "total_remaining_amount": "8,754",
                                "top_items": [
                                    {"display_name": "标准套餐", "end_time": 1796290560301, "total_amount": "9,000", "used_amount": "246"}
                                ],
                            },
                            "package_entitlement_groups": [
                                {"entitlements": [{"display": {"title": "标准套餐"}, "end_time": 1796290560301, "total_amount": "9,000", "used_amount": "246"}]}
                            ],
                        },
                    }
                )
            raise AssertionError("unexpected url: " + url)

        with patch("wbsignin.httpc.request", side_effect=fake_req):
            out = runner._work_doubao(acc, want_credits=True)
        self.assertEqual(out.checkin.status, runner.ST_FAILED)
        self.assertEqual(out.checkin.kind, httpc.KIND_SERVER)
        self.assertIsNotNone(out.credits)
        self.assertEqual(out.credits.total_remain, 8754.0)
        self.assertEqual(out.expiry.get("name"), "标准套餐")

        with patch("wbsignin.httpc.request", return_value=self._resp({"code": doubao.LOGIN_INVALID, "msg": "expired"})):
            out_exp = runner._work_doubao(acc, want_credits=True)
        self.assertEqual(out_exp.checkin.status, runner.ST_FAILED)
        self.assertEqual(out_exp.checkin.kind, httpc.KIND_AUTH)
        self.assertIsNone(out_exp.credits)

    def test_cookie_uid_and_upsert_dedup(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from wbsignin.runner import upsert_doubao_account
        from wbsignin.vault import Vault

        self.assertEqual(doubao.cookie_uid("a=1; uid_tt=abc123; sid_tt=x"), "abc123")
        with tempfile.TemporaryDirectory() as d:
            vault = Vault(Path(d) / "vault.json", "test-passphrase-123")

            def fake_req(method, url, **kw):
                if "/v3/detail/" in url:
                    return self._resp({"code": 2, "data": None})
                if "/landing/checkin" in url:
                    return self._resp({"code": 0, "data": {"idempotent": True, "continuous_days": 7}})
                if "/subscription/overview/" in url:
                    return self._resp({"code": 0, "data": {"quota_balance_overview": {"total_remaining_amount": "8,754"}}})
                raise AssertionError(url)

            with patch("wbsignin.httpc.request", side_effect=fake_req):
                r1 = upsert_doubao_account(vault, "sessionid=s1; uid_tt=u1", name="豆包主号")
                r2 = upsert_doubao_account(vault, "sessionid=s2; uid_tt=u1", name="", default_name="豆包-默认")
                r3 = upsert_doubao_account(vault, "sessionid=s3; uid_tt=u2", name="", default_name="豆包-小号")

            saved = vault.load()["accounts"]
            self.assertEqual(len(saved), 2)
            self.assertEqual(r1["key"], r2["key"])
            self.assertEqual(saved[r1["key"]]["label"], "豆包主号")
            self.assertIn("s2", saved[r1["key"]]["cookie"])
            self.assertEqual(saved[r3["key"]]["label"], "豆包-小号")

    def test_doubao_qr_flow_and_redirect_whitelist(self):
        import http.cookiejar
        import tempfile
        import urllib.request
        from pathlib import Path
        from unittest.mock import patch
        from wbsignin import httpc
        from wbsignin.vault import Vault
        from wbsignin.web import App

        handler = httpc._WhitelistedRedirectHandler()
        orig_req = urllib.request.Request("https://accounts.doubao.com/x")
        with self.assertRaises(httpc.ApiError) as ctx:
            handler.redirect_request(orig_req, None, 302, "Found", {}, "https://evil.example.com/steal")
        self.assertEqual(ctx.exception.kind, httpc.KIND_BAD_HOST)

        def _add_cookie(jar, name, val, domain=".doubao.com"):
            jar.set_cookie(
                http.cookiejar.Cookie(
                    version=0, name=name, value=val, port=None, port_specified=False,
                    domain=domain, domain_specified=True, domain_initial_dot=True,
                    path="/", path_specified=True, secure=True, expires=None,
                    discard=True, comment=None, comment_url=None, rest={},
                )
            )

        states = iter(["new", "scanned", "confirmed"])

        def fake_cookie_get(url, jar, headers=None, **kw):
            if "/get_qrcode/" in url:
                return self._resp({"message": "success", "data": {"qrcode": "AAA=", "token": "qr-tok-1", "expire_time": 1800000000}})
            if "/check_qrconnect/" in url:
                st = next(states)
                if st == "confirmed":
                    return self._resp({"message": "success", "data": {"status": "confirmed", "redirect_url": "https://www.doubao.com/sso"}})
                return self._resp({"message": "success", "data": {"status": st}})
            if url == "https://www.doubao.com/sso":
                _add_cookie(jar, "sessionid", "sid-qr-99")
                _add_cookie(jar, "uid_tt", "uid-qr-99")
                return self._resp({"ok": True})
            raise AssertionError("unexpected qr url: " + url)

        def fake_api_req(method, url, **kw):
            if "/v3/detail/" in url:
                return self._resp({"code": 2, "data": None})
            if "/landing/checkin" in url:
                return self._resp({"code": 0, "data": {"idempotent": True, "continuous_days": 3}})
            if "/subscription/overview/" in url:
                return self._resp({"code": 0, "data": {"quota_balance_overview": {"total_remaining_amount": "600"}}})
            raise AssertionError("unexpected api url: " + url)

        with tempfile.TemporaryDirectory() as d:
            vault = Vault(Path(d) / "vault.json", "test-qr-pass-123")
            app = App(vault)
            with patch("wbsignin.httpc.cookie_session_get", side_effect=fake_cookie_get):
                with patch("wbsignin.httpc.request", side_effect=fake_api_req):
                    started = app.do_doubao_qr_start(name="扫码小号")
                    self.assertTrue(started["qrcode"].startswith("data:image/png;base64,"))
                    p1 = app.do_doubao_qr_poll(started["session_id"])
                    self.assertEqual(p1["status"], "new")
                    p2 = app.do_doubao_qr_poll(started["session_id"])
                    self.assertEqual(p2["status"], "scanned")
                    p3 = app.do_doubao_qr_poll(started["session_id"])
                    self.assertEqual(p3["status"], "done")
                    self.assertEqual(p3["masked"], "扫码小号")
                    # 会话完成后应从内存中移除，再次轮询报 expired
                    p4 = app.do_doubao_qr_poll(started["session_id"])
                    self.assertEqual(p4["status"], "expired")

            saved = vault.load()["accounts"]
            self.assertEqual(len(saved), 1)
            k = next(iter(saved))
            self.assertEqual(saved[k]["label"], "扫码小号")
            self.assertIn("sessionid=sid-qr-99", saved[k]["cookie"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
