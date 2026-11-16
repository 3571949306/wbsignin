"""本地 Web 仪表盘（零依赖，仅监听 127.0.0.1）。

安全模型
--------
- 只绑定 127.0.0.1，公网无法直接访问；通过 SSH 隧道使用：
      ssh -L 8787:127.0.0.1:8787 <your-server>
  然后浏览器打开 http://127.0.0.1:8787
- 所有写操作要求自定义头 `X-Requested-With: wbsignin`，跨域页面无法携带该头
  （会先触发 CORS 预检而被拒绝），以此挡住"恶意网页对本机端口发请求"这类 CSRF。
- 主密码只在服务进程内存里，由启动时的环境变量注入，不经过浏览器、不写日志。

能力边界：这是「管理面板」而非「常驻监控」。签到、积分、登录走的是与 CLI
完全相同的函数，保证行为一致、锁语义不变。
"""
from __future__ import annotations

import datetime
import html
import json
import os
import re
import secrets
import subprocess
import threading
import time
import urllib.parse
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from . import config, httpc
from .auth import login, send_sms
from .lock import is_locked
from .runner import (
    load_accounts,
    load_state,
    run,
    upsert_doubao_account,
    upsert_trae_account,
)
from .tasks import ST_ALREADY, ST_SIGNED, query_credits
from .vault import Vault

_INDEX = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")
_LOG = deque(maxlen=400)  # (时间, 文本)


def _log(msg: str) -> None:
    _LOG.append((time.strftime("%H:%M:%S"), msg))


def _fmt_ts(ts: int) -> str:
    if not ts:
        return "-"
    import datetime

    return datetime.datetime.fromtimestamp(ts, tz=config.BJ_TZ).strftime("%Y-%m-%d %H:%M")


def _num(v) -> str:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    return str(int(f)) if abs(f - int(f)) < 1e-9 else ("%.1f" % f)


class App:
    _SESSION_TTL = 600.0

    def __init__(self, vault: Vault, jobs: int = 0):
        self.vault = vault
        self.jobs = jobs
        self._credits: Dict[str, Any] = {}
        self._login_lock = threading.Lock()
        self._db_qr_sessions: Dict[str, Dict[str, Any]] = {}
        self._trae_oauth_sessions: Dict[str, Dict[str, Any]] = {}

    def _prune_sessions(self, store: Dict[str, Dict[str, Any]]) -> None:
        now = time.time()
        expired = [k for k, v in store.items() if now - v.get("created", 0) > self._SESSION_TTL]
        for k in expired:
            store.pop(k, None)

    def _cache_upsert_credit(self, res: Dict[str, Any]) -> None:
        snap = res.get("snap")
        if snap and not snap.error:
            self._credits[res["key"]] = {
                "total": _num(snap.total_remain),
                "lines": snap.lines(),
                "paid": snap.is_paid,
            }

    # ---------- 数据访问 ----------
    def _accounts(self) -> Dict[str, Any]:
        return load_accounts(self.vault)

    def state(self) -> Dict[str, Any]:
        accounts = self._accounts()
        # 每次请求都实时读 state.json：定时任务是独立进程，它刚写入的结果
        # 若不重读，长驻的 Web 进程无法感知（只能在重启后生效）。
        st = load_state()
        persisted = st.get("accounts") or {}
        items = []
        for phone in sorted(accounts):
            a = accounts[phone]
            credit = self._credits.get(phone)
            ent = persisted.get(phone) or {}
            if credit is None and isinstance(ent.get("credit"), dict):
                credit = ent["credit"]
                self._credits[phone] = credit
            items.append(
                {
                    "phone": phone,
                    "masked": a.masked(),
                    "provider": a.provider,
                    "uid": (a.uid or "")[:8],
                    "at_exp": _fmt_ts(a.at_exp),
                    "at_exp_soon": bool(a.at_exp) and a.at_exp - time.time() < 3 * 86400,
                    "updated": a.updated,
                    "last_error": a.last_error,
                    "credit": credit,
                    "expiry": ent.get("expiry") or {},
                    "signin": ent.get("signin", ""),
                    "ok": bool(ent.get("ok")),
                }
            )
        return {
            "accounts": items,
            "count": len(items),
            "locked": is_locked(config.lock_path()),
            "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tzone": "Asia/Shanghai",
            "next_run": next_timer_run(),
            "last_run": {
                "updated": st.get("updated", ""),
                "one_line": st.get("one_line", ""),
            },
        }

    def do_signin(self) -> Dict[str, Any]:
        _log("开始签到")
        report = run(self.vault, want_credits=True, jobs=self.jobs or 0,
                     log=_log)
        _log("签到完成：%s" % report.one_line())
        rows = []
        for o in report.outcomes:
            has_balance = bool(o.credits) and not o.credits.error and (
                bool(o.credits.packages) or o.provider in ("doubao", "qoder", "qoder-cn", "trae-cn")
            )
            rows.append(
                {
                    "masked": o.masked,
                    "provider": o.provider,
                    "ok": o.ok,
                    "status": o.checkin.status if o.checkin else "SKIPPED",
                    "summary": o.checkin.summary() if o.checkin else (o.refresh_error or "未执行"),
                    "refresh_error": o.refresh_error,
                    "credit": _num(o.credits.total_remain) if has_balance else None,
                    "hint": o.hint,
                }
            )
            if has_balance:
                self._credits[o.phone] = {
                    "total": _num(o.credits.total_remain),
                    "lines": o.credits.lines(),
                    "paid": o.credits.is_paid,
                }
        return {
            "rows": rows,
            "one_line": report.one_line(),
            "failed": report.failed,
        }

    def do_credit(self) -> Dict[str, Any]:
        from . import doubao, qoder, trae

        accounts = self._accounts()
        out = {}
        for phone in sorted(accounts):
            a = accounts[phone]
            if a.is_doubao:
                snap, _exp = doubao.doubao_credits(a.cookie, a.uid or "")
                key_label = a.masked()
            elif a.is_qoder:
                snap, _exp = qoder.qoder_credits(a.access_token, a.provider, a.device)
                key_label = a.masked()
            elif a.is_trae:
                snap, _exp = trae.trae_credits(a.access_token, a.device)
                key_label = a.masked()
            else:
                snap = query_credits(a.access_token, a.uid)
                key_label = _mask(phone)

            if snap.error:
                out[key_label] = {"error": snap.error}
                continue
            self._credits[phone] = {
                "total": _num(snap.total_remain),
                "lines": snap.lines(),
                "paid": snap.is_paid,
            }
            out[key_label] = self._credits[phone]
        _log("积分/额度已刷新")
        return {"items": out}

    def do_sms(self, phone: str) -> Dict[str, Any]:
        info = send_sms(phone)
        _log("已向 %s 发送验证码" % _mask(phone))
        return {"expires_in": info["expires_in"]}

    def do_login(self, phone: str, code: str) -> Dict[str, Any]:
        got = login(phone, code)
        data = self.vault.load()
        from .auth import Account

        acc = Account.from_dict(phone, data.get("accounts", {}).get(phone, {}))
        acc.access_token = got["access_token"]
        acc.refresh_token = got["refresh_token"]
        acc.uid = got["uid"]
        acc.at_exp = int(got.get("at_exp") or 0)
        acc.updated = time.strftime("%Y-%m-%d %H:%M:%S")
        acc.last_error = ""
        data.setdefault("accounts", {})[phone] = acc.to_dict()
        self.vault.save(data)
        _log("账号 %s 登录成功" % _mask(phone))
        return {"masked": _mask(phone), "uid": (acc.uid or "")[:8]}

    def do_remove(self, phone: str) -> Dict[str, Any]:
        data = self.vault.load()
        removed = data.get("accounts", {}).pop(phone, None)
        if removed is not None:
            self.vault.save(data)
            self._credits.pop(phone, None)
            _log("已移除账号 %s" % _mask(phone))
            return {"removed": True}
        return {"removed": False}

    def do_login_doubao(self, cookie_raw: str, name: str) -> Dict[str, Any]:
        res = upsert_doubao_account(self.vault, cookie_raw, name=name)
        snap = res.get("snap")
        if snap and not snap.error:
            self._credits[res["key"]] = {
                "total": _num(snap.total_remain),
                "lines": snap.lines(),
                "paid": snap.is_paid,
            }
        _log("豆包账号 %s 已添加" % res["masked"])
        return {
            "masked": res["masked"],
            "continuous_days": res.get("continuous_days", 0),
            "total_amount": res.get("total_amount", 0),
        }

    def do_login_qoder(
        self,
        region: str = "cn",
        token: str = "",
        name: str = "",
        refresh_token: str = "",
        device: Any = None,
        uid: str = "",
        expires_at: Any = None,
    ) -> Dict[str, Any]:
        from . import qoder
        from .auth import Account

        raw_tok = str(token or "").strip()
        payload_in: Dict[str, Any] = {}
        if raw_tok.startswith("{"):
            try:
                parsed = json.loads(raw_tok)
            except ValueError as exc:
                raise httpc.ApiError(httpc.KIND_BAD_RESPONSE, "JSON 解析失败：%s" % exc)
            if not isinstance(parsed, dict):
                raise httpc.ApiError(httpc.KIND_BAD_RESPONSE, "凭据 JSON 必须为对象")
            payload_in = parsed
            raw_tok = str(
                payload_in.get("token") or payload_in.get("access_token") or ""
            ).strip()

        if not raw_tok:
            raise httpc.ApiError(httpc.KIND_BAD_RESPONSE, "Token 不能为空")

        eff_region = str(payload_in.get("region") or region or "cn")
        provider = qoder.normalize_provider(eff_region)
        rt = str(
            refresh_token
            or payload_in.get("refresh_token")
            or payload_in.get("refreshToken")
            or ""
        ).strip()
        dev = (
            device
            if isinstance(device, dict)
            else (
                payload_in.get("device")
                if isinstance(payload_in.get("device"), dict)
                else {}
            )
        )
        eff_uid = str(uid or payload_in.get("uid") or "").strip()
        eff_name = str(
            name or payload_in.get("label") or payload_in.get("name") or ""
        ).strip()
        exp_ts = qoder.parse_expires_at(
            expires_at
            or payload_in.get("expires_at")
            or payload_in.get("expiresAt")
        )

        campaigns_payload = qoder.verify_token(raw_tok, provider, dev)
        eff_uid = eff_uid or str(campaigns_payload.get("uid") or "").strip()
        snap, _ = qoder.qoder_credits(raw_tok, provider, dev)
        label = eff_name or "%s(%s)" % (
            qoder.provider_label(provider),
            (eff_uid or "default")[:8],
        )
        key = "%s:%s" % (provider, eff_uid or label)

        data = self.vault.load()
        acc = Account.from_dict(key, data.get("accounts", {}).get(key, {}))
        acc.provider = provider
        acc.access_token = raw_tok
        acc.refresh_token = rt
        acc.uid = eff_uid
        acc.at_exp = exp_ts
        acc.label = label
        acc.device = dev
        acc.updated = time.strftime("%Y-%m-%d %H:%M:%S")
        acc.last_error = ""
        data.setdefault("accounts", {})[key] = acc.to_dict()
        self.vault.save(data)
        if not snap.error:
            self._credits[key] = {
                "total": _num(snap.total_remain),
                "lines": snap.lines(),
                "paid": snap.is_paid,
            }
        _log("%s 账号 %s 已添加" % (qoder.provider_label(provider), label))
        return {
            "masked": label,
            "provider": provider,
            "credit": _num(snap.total_remain) if not snap.error else None,
        }

    def do_login_trae(
        self,
        token: str = "",
        name: str = "",
        refresh_token: str = "",
        device: Any = None,
        uid: str = "",
        expires_at: Any = None,
    ) -> Dict[str, Any]:
        res = upsert_trae_account(
            self.vault,
            token,
            name=name,
            refresh_token=refresh_token,
            device=device,
            uid=uid,
            expires_at=expires_at,
        )
        snap = res.get("snap")
        if snap and not snap.error:
            self._credits[res["key"]] = {
                "total": _num(snap.total_remain),
                "lines": snap.lines(),
                "paid": snap.is_paid,
            }
        _log("TRAE CN 账号 %s 已添加" % res["masked"])
        return {
            "masked": res["masked"],
            "provider": res["provider"],
            "credit": res.get("credit"),
        }

    # ---------- 豆包无头扫码登录 ----------
    def do_doubao_qr_start(self, name: str = "") -> Dict[str, Any]:
        from . import doubao

        started = doubao.qr_start()
        sid = secrets.token_hex(16)
        with self._login_lock:
            self._prune_sessions(self._db_qr_sessions)
            self._db_qr_sessions[sid] = {
                "token": started["token"],
                "jar": started["jar"],
                "name": (name or "").strip(),
                "created": time.time(),
            }
        return {
            "session_id": sid,
            "qrcode": started["qrcode"],
            "expire_time": started.get("expire_time", 0),
        }

    def do_doubao_qr_poll(self, session_id: str, name: str = "") -> Dict[str, Any]:
        from . import doubao

        sid = str(session_id or "").strip()
        with self._login_lock:
            self._prune_sessions(self._db_qr_sessions)
            sess = self._db_qr_sessions.get(sid)
        if not sess:
            return {"status": "expired", "error": "扫码会话已过期，请刷新二维码"}

        polled = doubao.qr_poll(sess["token"], sess["jar"])
        st = polled.get("status")
        if st in ("new", "scanned"):
            return {"status": st}
        if st in ("refused", "expired", "error"):
            with self._login_lock:
                self._db_qr_sessions.pop(sid, None)
            return {"status": st, "error": polled.get("error", "扫码失败")}
        if st == "confirmed":
            with self._login_lock:
                self._db_qr_sessions.pop(sid, None)
            eff_name = (name or "").strip() or sess.get("name", "")
            res = upsert_doubao_account(
                self.vault,
                polled["cookie"],
                name=eff_name,
                default_name="豆包",
            )
            self._cache_upsert_credit(res)
            _log("豆包账号 %s 扫码登录成功" % res["masked"])
            return {
                "status": "done",
                "masked": res["masked"],
                "continuous_days": res.get("continuous_days", 0),
                "total_amount": res.get("total_amount", 0),
            }
        return {"status": "error", "error": "未知扫码状态"}

    # ---------- TRAE CN 网页授权登录 ----------
    def do_trae_oauth_start(self, origin: str, name: str = "") -> Dict[str, Any]:
        from . import trae

        sess = trae.oauth_start(origin, name=name)
        trace_id = sess["trace_id"]
        with self._login_lock:
            self._prune_sessions(self._trae_oauth_sessions)
            self._trae_oauth_sessions[trace_id] = {
                "status": "pending",
                "code_verifier": sess["code_verifier"],
                "device": sess["device"],
                "name": sess["name"],
                "created": time.time(),
            }
        return {"trace_id": trace_id, "auth_url": sess["auth_url"]}

    def do_trae_oauth_status(self, trace_id: str) -> Dict[str, Any]:
        tid = str(trace_id or "").strip()
        with self._login_lock:
            self._prune_sessions(self._trae_oauth_sessions)
            sess = self._trae_oauth_sessions.get(tid)
            if not sess:
                return {"status": "expired", "error": "授权会话已过期，请重新发起"}
            out: Dict[str, Any] = {"status": sess["status"]}
            if sess["status"] == "done" and isinstance(sess.get("result"), dict):
                out.update(sess["result"])
            elif sess["status"] == "error":
                out["error"] = sess.get("error", "授权失败")
            return out

    def do_trae_oauth_callback(self, query_str: str) -> str:
        from . import trae

        qs = urllib.parse.parse_qs(query_str or "", keep_blank_values=True)
        trace_id = (qs.get("loginTraceID") or qs.get("login_trace_id") or [""])[0].strip()
        with self._login_lock:
            self._prune_sessions(self._trae_oauth_sessions)
            sess = self._trae_oauth_sessions.get(trace_id)
            if not sess or sess.get("status") != "pending":
                return _oauth_result_html(False, "授权会话无效或已过期", "请返回 wbsignin 控制台重新发起授权。", "")
            sess["status"] = "processing"

        auth_code = ""
        raw_info = (qs.get("authCodeInfo") or [""])[0].strip()
        if raw_info:
            try:
                parsed = json.loads(raw_info)
                if isinstance(parsed, dict):
                    auth_code = str(parsed.get("AuthCode") or parsed.get("authCode") or "").strip()
            except ValueError:
                pass
        if not auth_code:
            auth_code = (qs.get("AuthCode") or qs.get("code") or [""])[0].strip()

        if not auth_code:
            err_msg = (qs.get("error_msg") or qs.get("error_code") or ["未收到 AuthCode"])[0]
            with self._login_lock:
                sess["status"] = "error"
                sess["error"] = "授权未完成：%s" % err_msg
            return _oauth_result_html(False, "TRAE CN 授权未完成", str(err_msg), trace_id)

        try:
            exchanged = trae.exchange_auth_code(
                auth_code,
                sess["code_verifier"],
                sess["device"],
                host=(qs.get("host") or [""])[0],
            )
            res = upsert_trae_account(self.vault, exchanged, name=sess.get("name", ""))
            self._cache_upsert_credit(res)
            with self._login_lock:
                sess["status"] = "done"
                sess["result"] = {"masked": res["masked"], "credit": res.get("credit")}
            _log("TRAE CN 账号 %s 网页授权成功" % res["masked"])
            credit_txt = "（剩余 %s 积分）" % res["credit"] if res.get("credit") is not None else ""
            return _oauth_result_html(
                True,
                "TRAE CN 授权成功",
                "账号 %s 已添加到服务器%s，可关闭此页面。" % (res["masked"], credit_txt),
                trace_id,
            )
        except Exception as exc:
            detail = exc.detail if isinstance(exc, httpc.ApiError) else str(exc)[:200]
            with self._login_lock:
                sess["status"] = "error"
                sess["error"] = detail
            return _oauth_result_html(False, "TRAE CN 导入失败", detail, trace_id)


def _oauth_result_html(ok: bool, title: str, detail: str, trace_id: str) -> str:
    msg_json = json.dumps({"type": "wbsignin-trae-oauth", "ok": ok, "trace_id": trace_id})
    color = "#3fb96f" if ok else "#e5534b"
    icon = "✓" if ok else "✕"
    close_btn = (
        '<button onclick="window.close()" style="margin-top:18px;padding:9px 20px;border:none;'
        'border-radius:8px;background:#4f7cff;color:#fff;cursor:pointer;font-size:14px">关闭窗口</button>'
    )
    return (
        "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
        "<title>%s</title></head>"
        "<body style='margin:0;background:#101014;color:#e6e6eb;font:15px/1.6 -apple-system,Segoe UI,sans-serif;"
        "display:flex;align-items:center;justify-content:center;min-height:100vh'>"
        "<div style='background:#17171c;border:1px solid #2a2a33;border-radius:12px;padding:28px 32px;"
        "max-width:420px;text-align:center'>"
        "<div style='font-size:32px;color:%s;margin-bottom:8px'>%s</div>"
        "<h2 style='margin:0 0 8px;font-size:18px'>%s</h2>"
        "<p style='margin:0;color:#9a9aa5;font-size:13px'>%s</p>%s</div>"
        "<script>try{if(window.opener){window.opener.postMessage(%s,'*');}}catch(e){}</script>"
        "</body></html>"
        % (html.escape(title), color, icon, html.escape(title), html.escape(detail), close_btn, msg_json)
    )


def _mask(phone: str) -> str:
    return (phone[:3] + "****" + phone[-4:]) if len(phone) >= 8 else phone


# ---------- 定时器下次触发时间 ----------
_NEXT_CACHE: Dict[str, Any] = {"ts": 0.0, "value": ""}


def _query_next_timer_run() -> str:
    """读 systemd 定时器的 NextElapseUSecRealtime，返回北京时间字符串。

    定时器带 300s 随机延迟，真实触发时间只有 systemd 知道，故不自行推算。
    失败（无 systemd / 未装 timer）返回空字符串，前端按「未启用」处理。
    """
    try:
        env = dict(os.environ)
        env.setdefault("XDG_RUNTIME_DIR", "/run/user/%d" % os.getuid())
        out = subprocess.run(
            ["systemctl", "--user", "show", "wbsignin.timer",
             "--property=NextElapseUSecRealtime", "--value"],
            capture_output=True, text=True, timeout=5, env=env,
        )
        val = out.stdout.strip()
        if not val or val == "infinity":
            return ""
        # systemctl 返回的是人类可读时间（如 "Mon 2026-11-16 08:17:22 CST"）
        m = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2})", val)
        if m:
            return m.group(1)
        if val.isdigit():  # 兜底：部分环境返回微秒时间戳
            return datetime.datetime.fromtimestamp(
                int(val) / 1e6, tz=config.BJ_TZ
            ).strftime("%Y-%m-%d %H:%M")
        return ""
    except Exception:
        return ""


def next_timer_run() -> str:
    now = time.time()
    if now - _NEXT_CACHE["ts"] < 60:
        return _NEXT_CACHE["value"]
    _NEXT_CACHE["ts"] = now
    _NEXT_CACHE["value"] = _query_next_timer_run()
    return _NEXT_CACHE["value"]


# ---------- HTTP 处理 ----------
def _app_ctx() -> App:
    return _SINGLETON["app"]


def _send(handler, obj: Any, status: int = 200) -> None:
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _send_html(handler, html: str) -> None:
    body = html.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = "wbsignin/0.1"

    def log_message(self, *args):  # 静默访问日志，输出走应用内 ring buffer
        pass

    # -- 工具 --
    def _body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _is_local(self) -> bool:
        return self.client_address[0] in ("127.0.0.1", "::1", "localhost")

    def _is_same_origin(self) -> bool:
        # CSRF 防护：写操作要求自定义头（跨域无法携带）
        return self.headers.get("X-Requested-With") == "wbsignin"

    # -- 路由 --
    def do_GET(self):  # noqa: N802
        if not self._is_local():
            self.send_error(403)
            return
        path, _, query = self.path.partition("?")
        if path in ("/", "/index.html"):
            _send_html(self, _INDEX)
        elif path == "/api/state":
            _send(self, _app_ctx().state())
        elif path == "/api/log":
            _send(self, {"lines": list(_LOG)})
        elif path == "/api/trae-oauth/status":
            tid = (urllib.parse.parse_qs(query).get("trace_id") or [""])[0]
            _send(self, _app_ctx().do_trae_oauth_status(tid))
        elif path == "/authorize":
            _send_html(self, _app_ctx().do_trae_oauth_callback(query))
        else:
            self.send_error(404)

    def do_POST(self):  # noqa: N802
        if not self._is_local() or not self._is_same_origin():
            self.send_error(403)
            return
        app = _app_ctx()
        path = self.path.split("?", 1)[0]
        body = self._body()
        try:
            if path == "/api/signin":
                _send(self, app.do_signin())
            elif path == "/api/credit":
                _send(self, app.do_credit())
            elif path == "/api/sms":
                _send(self, app.do_sms(str(body.get("phone") or "").strip()))
            elif path == "/api/login":
                phone = str(body.get("phone") or "").strip()
                code = str(body.get("code") or "").strip()
                if not phone or not code:
                    _send(self, {"ok": False, "error": "手机号和验证码不能为空"}, 400)
                    return
                _send(self, app.do_login(phone, code))
            elif path == "/api/login-doubao":
                cookie = str(body.get("cookie") or "").strip()
                name = str(body.get("name") or "").strip()
                _send(self, app.do_login_doubao(cookie, name))
            elif path == "/api/doubao-qr/start":
                _send(self, app.do_doubao_qr_start(name=str(body.get("name") or "").strip()))
            elif path == "/api/doubao-qr/poll":
                _send(
                    self,
                    app.do_doubao_qr_poll(
                        session_id=str(body.get("session_id") or "").strip(),
                        name=str(body.get("name") or "").strip(),
                    ),
                )
            elif path == "/api/login-qoder":
                _send(
                    self,
                    app.do_login_qoder(
                        region=str(body.get("region") or "cn"),
                        token=str(body.get("token") or body.get("access_token") or ""),
                        name=str(body.get("name") or body.get("label") or ""),
                        refresh_token=str(body.get("refresh_token") or body.get("refreshToken") or ""),
                        device=body.get("device"),
                        uid=str(body.get("uid") or ""),
                        expires_at=body.get("expires_at") or body.get("expiresAt"),
                    ),
                )
            elif path == "/api/login-trae":
                _send(
                    self,
                    app.do_login_trae(
                        token=str(body.get("token") or body.get("access_token") or ""),
                        name=str(body.get("name") or body.get("label") or ""),
                        refresh_token=str(body.get("refresh_token") or body.get("refreshToken") or ""),
                        device=body.get("device"),
                        uid=str(body.get("uid") or ""),
                        expires_at=body.get("expires_at") or body.get("expiresAt") or body.get("expiredAt"),
                    ),
                )
            elif path == "/api/trae-oauth/start":
                _send(
                    self,
                    app.do_trae_oauth_start(
                        origin=str(body.get("origin") or "").strip(),
                        name=str(body.get("name") or "").strip(),
                    ),
                )
            elif path == "/api/remove":
                _send(self, app.do_remove(str(body.get("phone") or "").strip()))
            else:
                self.send_error(404)
        except httpc.ApiError as exc:
            _send(self, {"ok": False, "kind": exc.kind, "error": exc.detail}, 400)
        except Exception as exc:  # 防御：单次请求异常不拖垮服务
            _send(self, {"ok": False, "error": str(exc)[:200]}, 500)


_SINGLETON: Dict[str, Any] = {}


def serve(vault: Vault, host: str = "127.0.0.1", port: int = 8787, jobs: int = 0) -> None:
    _SINGLETON["app"] = App(vault, jobs=jobs)
    httpd = ThreadingHTTPServer((host, port), Handler)
    _log("仪表盘已启动：http://%s:%d" % (host, port))
    _log("通过 SSH 隧道访问：ssh -L %d:127.0.0.1:%d <your-server>" % (port, port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
