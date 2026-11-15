"""Qoder / Qoder CN 协议、账户模型、Schedule 与 Web API 离线单元测试。"""
from __future__ import annotations

import datetime
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wbsignin import config, httpc, qoder, schedule, tasks
from wbsignin.auth import Account
from wbsignin.vault import Vault
from wbsignin.web import App


def _resp(payload, status=200):
    return httpc.Response(status=status, payload=payload, text="{}")


class QoderRoundAndHelpersTests(unittest.TestCase):
    def test_endpoints_and_round_boundary(self):
        self.assertEqual(qoder.base_url("qoder"), config.QODER_INTL_BASE)
        self.assertEqual(qoder.base_url("qoder-cn"), config.QODER_CN_BASE)
        self.assertEqual(qoder.normalize_provider("cn"), "qoder-cn")
        self.assertEqual(qoder.normalize_provider("intl"), "qoder")

        before_10 = datetime.datetime(2026, 11, 15, 9, 59, 59, tzinfo=config.BJ_TZ)
        at_10 = datetime.datetime(2026, 11, 15, 10, 0, 0, tzinfo=config.BJ_TZ)
        self.assertEqual(
            qoder.current_round_start_ts(before_10.timestamp()),
            datetime.datetime(2026, 11, 14, 10, 0, 0, tzinfo=config.BJ_TZ).timestamp(),
        )
        self.assertEqual(
            qoder.current_round_start_ts(at_10.timestamp()),
            at_10.timestamp(),
        )

    def test_headers_include_device_fields(self):
        h = qoder.build_headers(
            "dt-tok",
            {
                "version": "0.5.11",
                "machineId": "mid-1",
                "machineHostname": "host-1",
                "machineToken": "mt-1",
                "machineCode": "mc-1",
                "machineType": "windows",
            },
        )
        self.assertEqual(h["Authorization"], "Bearer dt-tok")
        self.assertEqual(h["Cosy-Version"], "0.5.11")
        self.assertEqual(h["Cosy-MachineId"], "mid-1")
        self.assertEqual(h["Cosy-MachineToken"], "mt-1")
        self.assertEqual(h["Cosy-MachineCode"], "mc-1")
        self.assertEqual(h["Cosy-MachineType"], "windows")

    def test_schedule_contains_both_daily_runs(self):
        txt = schedule.systemd_timer()
        self.assertIn("08,10:17:00", txt)
        wtxt = schedule.systemd_web_service(port=9090)
        self.assertIn("web --host 127.0.0.1 --port 9090", wtxt)
        self.assertIn("Restart=on-failure", wtxt)

    def test_account_qoder_roundtrip(self):
        acc = Account.from_dict(
            "qoder-cn:uid1",
            {
                "provider": "qoder-cn",
                "access_token": "dt-1",
                "refresh_token": "rt-1",
                "uid": "uid1",
                "label": "138****0000",
                "device": {"machineCode": "abc"},
            },
        )
        self.assertTrue(acc.is_qoder)
        self.assertFalse(acc.is_workbuddy)
        self.assertEqual(acc.masked(), "138****0000")
        d = acc.to_dict()
        self.assertEqual(d["device"], {"machineCode": "abc"})


class QoderCheckinAndCreditsTests(unittest.TestCase):
    def test_pat_exchange_and_checkin_claimable(self):
        now = datetime.datetime(2026, 11, 15, 10, 17, 0, tzinfo=config.BJ_TZ).timestamp()
        calls = []

        def fake_req(method, url, headers=None, body=None, **kw):
            calls.append((method, url, headers, body))
            if url.endswith("/api/v1/jobToken/exchange"):
                return _resp({"token": "jt-short"})
            if "/sash/api/v1/me/campaigns" in url and method == "GET":
                return _resp(
                    {
                        "uid": "u-cn",
                        "campaigns": [
                            {
                                "campaignId": "daily-100",
                                "actionType": "CLAIM_BENEFIT",
                                "claimStatus": "CLAIMABLE",
                                "startAt": int((now - 1000) * 1000),
                                "endAt": int((now + 3600) * 1000),
                                "benefit": {"amount": 100},
                            }
                        ],
                    }
                )
            if url.endswith("/daily-100/claim") and method == "POST":
                return _resp({"status": "CLAIMED", "benefit": {"amount": 100}})
            raise AssertionError("unexpected call: " + url)

        with patch("wbsignin.httpc.request", side_effect=fake_req):
            res = qoder.qoder_checkin("pt-pat", provider="qoder-cn", now_ts=now)

        self.assertEqual(res.status, tasks.ST_SIGNED)
        self.assertEqual(res.credits_gained, 100.0)
        self.assertEqual(calls[1][2]["Authorization"], "Bearer jt-short")

    def test_checkin_already_and_prev_round(self):
        now = datetime.datetime(2026, 11, 15, 8, 17, 0, tzinfo=config.BJ_TZ).timestamp()
        cur_start = datetime.datetime(2026, 11, 14, 10, 0, 0, tzinfo=config.BJ_TZ).timestamp()
        older_start = datetime.datetime(2026, 11, 13, 10, 0, 0, tzinfo=config.BJ_TZ).timestamp()
        cur_payload = {
            "campaigns": [
                {
                    "campaignId": "c1",
                    "actionType": "CLAIM_BENEFIT",
                    "claimStatus": "CLAIMED",
                    "startAt": int(cur_start * 1000),
                    "endAt": int((now + 3600) * 1000),
                    "benefit": {"amount": 100},
                }
            ]
        }
        with patch("wbsignin.httpc.request", return_value=_resp(cur_payload)):
            res_cur = qoder.qoder_checkin("dt-1", provider="qoder", now_ts=now)
        self.assertEqual(res_cur.status, tasks.ST_ALREADY)
        self.assertIn("今日已签到", res_cur.detail)

        prev_payload = {
            "campaigns": [
                {
                    "campaignId": "c0",
                    "actionType": "CLAIM_BENEFIT",
                    "claimStatus": "CLAIMED",
                    "startAt": int(older_start * 1000),
                    "endAt": int((now + 3600) * 1000),
                    "benefit": {"amount": 100},
                }
            ]
        }
        with patch("wbsignin.httpc.request", return_value=_resp(prev_payload)):
            res_prev = qoder.qoder_checkin("dt-1", provider="qoder", now_ts=now)
        self.assertEqual(res_prev.status, tasks.ST_ALREADY)
        self.assertIn("上轮已领", res_prev.detail)

    def test_checkin_no_campaign_and_401(self):
        with patch("wbsignin.httpc.request", return_value=_resp({"campaigns": []})):
            r1 = qoder.qoder_checkin("dt-1", provider="qoder")
        self.assertEqual(r1.status, tasks.ST_SEASON)

        with patch("wbsignin.httpc.request", return_value=_resp({"error": "unauthorized"}, status=401)):
            r2 = qoder.qoder_checkin("dt-1", provider="qoder")
        self.assertEqual(r2.status, tasks.ST_SKIPPED)
        self.assertEqual(r2.kind, httpc.KIND_AUTH)

    def test_qoder_credits_quota_and_expiry(self):
        exp_ms = 1796832000000
        with patch(
            "wbsignin.httpc.request",
            return_value=_resp(
                {
                    "userType": "personal_standard",
                    "userQuota": {"total": 2000, "used": 2000, "remaining": 0},
                    "addOnQuota": {"total": 800, "used": 587, "remaining": 213},
                    "expiresAt": exp_ms,
                }
            ),
        ):
            snap, expiry = qoder.qoder_credits("dt-1", provider="qoder-cn")
        self.assertEqual(snap.total_remain, 213.0)
        self.assertEqual(len(snap.packages), 2)
        self.assertFalse(snap.is_paid)
        self.assertEqual(expiry["ms"], exp_ms)
        self.assertEqual(expiry["remain"], 213.0)

        with patch(
            "wbsignin.httpc.request",
            return_value=_resp(
                {
                    "userType": "free",
                    "userQuota": {"total": 2000, "used": 0, "remaining": 2000},
                    "addOnQuota": {"total": 0, "used": 0, "remaining": 0},
                    "expiresAt": 4102444800000,
                }
            ),
        ):
            snap2, expiry2 = qoder.qoder_credits("dt-1", provider="qoder")
        self.assertEqual(snap2.total_remain, 2000.0)
        self.assertEqual(expiry2, {})


class WebQoderIntegrationTests(unittest.TestCase):
    def test_do_login_qoder_json_and_do_credit(self):
        with tempfile.TemporaryDirectory() as d:
            vault = Vault(Path(d) / "vault.json", "test-passphrase-123")
            app = App(vault)

            def fake_req(method, url, headers=None, body=None, **kw):
                if "/sash/api/v1/me/campaigns" in url:
                    return _resp({"uid": "u-123456", "campaigns": []})
                if "/api/v2/quota/usage" in url:
                    return _resp(
                        {
                            "userType": "free",
                            "userQuota": {"total": 2000, "used": 100, "remaining": 1900},
                            "addOnQuota": {"total": 300, "used": 0, "remaining": 300},
                            "expiresAt": 1796832000000,
                        }
                    )
                raise AssertionError("unexpected url: " + url)

            raw_json = '{"region":"cn","token":"dt-test","label":"Qoder测试","device":{"version":"0.5.11"}}'
            with patch("wbsignin.httpc.request", side_effect=fake_req):
                out = app.do_login_qoder(region="cn", token=raw_json)
                credits = app.do_credit()

            self.assertEqual(out["provider"], "qoder-cn")
            self.assertEqual(out["masked"], "Qoder测试")
            self.assertEqual(out["credit"], "2200")
            self.assertEqual(credits["items"]["Qoder测试"]["total"], "2200")

    def test_cli_login_qoder_from_json_respects_intl_region(self):
        from wbsignin.cli import build_parser

        args = build_parser().parse_args(["login-qoder", "--from-json", "x.json"])
        self.assertIsNone(args.region)


if __name__ == "__main__":
    unittest.main(verbosity=2)
