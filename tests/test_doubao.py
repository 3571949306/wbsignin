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
        # 参考实现实际生成 '76' + 8 位单数字 = 10 位（注释里的"18位"是笔误）
        self.assertTrue(d["web_id"].startswith("76"))
        self.assertEqual(len(d["web_id"]), 10)
        self.assertEqual(len(d["tea_uuid"]), 16)
        self.assertTrue(d["web_id"].isdigit())
        self.assertTrue(d["tea_uuid"].isdigit())


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
        with patch(
            "wbsignin.httpc.request",
            side_effect=[
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
            return_value=self._resp({"code": doubao.NO_ACTIVITY, "msg": "no activity"}),
        ):
            r3 = doubao.doubao_checkin("sessionid=abc", seed="s1")
        self.assertEqual(r3["state"], doubao.ST_NO_TASK)

        with patch(
            "wbsignin.httpc.request",
            return_value=self._resp({"code": doubao.LOGIN_INVALID, "msg": "not login"}),
        ):
            r4 = doubao.doubao_checkin("sessionid=abc", seed="s1")
        self.assertEqual(r4["state"], doubao.ST_FAILED)
        self.assertTrue(r4.get("auth_expired"))

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
