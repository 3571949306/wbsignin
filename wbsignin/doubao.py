"""豆包（doubao.com）每日签到领体验额度。

协议契约：
    POST /alice/ug/campaign/v3/detail/       任务面板（国内 IP 可用；海外 IP 返回 code=2）
    POST /alice/ug/campaign/landing/checkin  领取（服务端幂等；710010702 表示活动未开放或上游异常）
    POST /alice/commerce/sale/subscription/overview/  真实剩余额度与到期明细（国内/海外 IP 均可用）
    POST /alice/ug/campaign/quota/records/           激励额度流水与历史签到日期（国内/海外 IP 均可用）

鉴权：纯 doubao.com 会话 Cookie；请求必须携带「豆包电脑版 desktop webview」的
完整客户端参数（aid=582478、runtime_version=3.44.9、region=CN 等）与确定性
device_id / web_id / tea_uuid / fp 才会稳定命中 PC 签到活动与任务面板。

参与门槛：仅个人账号。工作版 / 企业账号在 v3/detail 返回 code=0 但 tasks 中无 daily_signin；
个人账号若遇到 /landing/checkin 返回 710010702「系统错误」，属上游活动服务故障，不能误判为无签到任务。
"""
from __future__ import annotations

import datetime
import hashlib
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from . import config, httpc
from .tasks import CreditSnapshot

CAMPAIGN_GROUP = "pc_incentive_task_mvp_v3"
LOGIN_INVALID = 710012001  # 会话过期 / Cookie 失效
NO_ACTIVITY = 710010702    # 活动未开放或上游活动服务系统错误

CLIENT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) DoubaoDesktop/2.35.12 Chrome/147.0.7727.149 Safari/537.36"
)

COMMON_PARAMS = {
    "version_code": "20800",
    "language": "zh",
    "device_platform": "web",
    "doubao_device_platform": "desktop",
    "aid": "582478",
    "real_aid": "582478",
    "pkg_type": "release_version",
    "pc_version": "2.35.12",
    "doubao_pc_version": "2.35.12",
    "samantha_web": "1",
    "web_platform": "desktop",
    "use-olympus-account": "1",
    "web_tab_id": "0",
    "region": "CN",
    "sys_region": "CN",
    "runtime": "web",
    "runtime_version": "3.44.9",
    "client_platform": "pc_client",
    "chromium_version": "147.0.7727.149",
    "channel": "win",
}

# 状态（对齐 runner 的签到状态词汇，便于前端复用）
ST_SIGNED = "SIGNED"
ST_ALREADY = "ALREADY"
ST_NO_TASK = "NO_TASK"
ST_FAILED = "FAILED"


def normalize_cookie(raw: str) -> str:
    """规整用户粘贴的 Cookie：去掉 'Cookie:' 前缀、折叠换行、统一分隔符。"""
    return (
        str(raw or "")
        .replace("\ufeff", "")
        .replace("Cookie:", "")
        .replace("cookie:", "")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("; ", ";")
        .replace(";", "; ")
        .replace("  ", " ")
        .strip()
        .rstrip(";")
        .strip()
    )


def cookie_uid(cookie: str) -> str:
    """从 Cookie 头中提取稳定的豆包用户标识（uid_tt / uid_tt_ss）。"""
    found: Dict[str, str] = {}
    for seg in str(cookie or "").split(";"):
        if "=" not in seg:
            continue
        k, v = seg.split("=", 1)
        k = k.strip()
        if k in ("uid_tt", "uid_tt_ss") and v.strip():
            found[k] = v.strip()
    return found.get("uid_tt") or found.get("uid_tt_ss") or ""


def device_ids(seed: str) -> Dict[str, str]:
    """按账号 seed 派生稳定的桌面端设备参数（每号恒定、账号间互异）。"""
    h = hashlib.sha256(("doubao-dev:" + (seed or "anonymous")).encode("utf-8")).digest()
    device_id = "4" + "".join(str(b % 10) for b in h[:15])
    web_id = "76" + "".join(str(b % 10) for b in h[15:32])
    return {
        "device_id": device_id,
        "web_id": web_id,
        "tea_uuid": device_id,
        "fp": "verify_" + device_id,
    }


def _api_url(base: str, seed: str) -> str:
    params: Dict[str, str] = dict(COMMON_PARAMS)
    params.update(device_ids(seed))
    return base + "?" + urllib.parse.urlencode(params)


def _headers(cookie: str) -> Dict[str, str]:
    return {
        "Cookie": cookie,
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Referer": "https://www.doubao.com/pc/agent-explore",
        "Origin": "https://www.doubao.com",
        "Agw-Js-Conv": "str",
        "User-Agent": CLIENT_UA,
    }


def _post(
    url_base: str,
    cookie: str,
    body: Dict[str, Any],
    seed: str = "",
    retries: int = 2,
) -> httpc.Response:
    """发送豆包 POST JSON 请求，按需附带 WBSIGNIN_DOUBAO_PROXY。"""
    kwargs: Dict[str, Any] = {
        "headers": _headers(cookie),
        "body": body,
        "retries": retries,
    }
    proxy = config.doubao_proxy()
    if proxy:
        kwargs["proxy_url"] = proxy
    return httpc.request("POST", _api_url(url_base, seed), **kwargs)


def _code_int(payload: Any) -> Any:
    code = payload.get("code") if isinstance(payload, dict) else None
    try:
        return int(code)
    except (TypeError, ValueError):
        return code


def _msg(payload: Any) -> str:
    if isinstance(payload, dict):
        return str(payload.get("msg") or payload.get("message") or "未知错误")
    return "响应非 JSON"


def _beijing_today() -> str:
    import datetime

    return datetime.datetime.now(tz=config.BJ_TZ).strftime("%Y-%m-%d")


def _ms_to_bj_date(ms: Any) -> str:
    import datetime

    val = _int(ms)
    if val <= 0:
        return ""
    return datetime.datetime.fromtimestamp(val / 1000.0, tz=config.BJ_TZ).strftime(
        "%Y-%m-%d"
    )


# ---------- 额度记录（无海外 IP 限制） ----------
def doubao_quota_records(cookie: str, seed: str = "") -> Dict[str, Any]:
    """查询豆包激励额度流水（合计总额度 + 今日签到记录）。

    与 /v3/detail/ 不同，/quota/records/ 对海外服务器 IP 同样放行。
    """
    cursor = ""
    total = 0
    today = _beijing_today()
    checked_today = False
    latest_signin_date = ""
    last_amount = 0

    for _ in range(5):
        try:
            resp = _post(
                config.DOUBAO_QUOTA_RECORDS_URL,
                cookie,
                {"cursor": cursor, "page_size": 100},
                seed=seed,
            )
        except httpc.ApiError as exc:
            return {"auth": False, "code": None, "error": exc.detail}

        payload = resp.payload
        if not isinstance(payload, dict):
            return {
                "auth": False,
                "code": "HTTP %s" % resp.status,
                "error": "响应非 JSON",
            }
        code = _code_int(payload)
        if code == LOGIN_INVALID:
            return {
                "auth": False,
                "code": code,
                "error": "豆包登录已过期（Cookie 失效）",
            }
        if code != 0:
            return {
                "auth": False,
                "code": code,
                "error": _msg(payload) + "（code %s）" % code,
            }

        data = payload.get("data") or {}
        records = [r for r in (data.get("records") or []) if isinstance(r, dict)]
        for r in records:
            amt = _int(r.get("amount"))
            total += amt
            if r.get("task_code") == "daily_signin":
                d = _ms_to_bj_date(r.get("create_time_ms"))
                if d and not latest_signin_date:
                    latest_signin_date = d
                    last_amount = amt
                if d == today:
                    checked_today = True

        if not data.get("has_more"):
            break
        nxt = str(data.get("next_cursor") or data.get("cursor") or "")
        if not nxt or nxt == cursor:
            break
        cursor = nxt

    return {
        "auth": True,
        "code": 0,
        "total_amount": total,
        "checked_in": checked_today,
        "latest_signin_date": latest_signin_date,
        "reward_amount": last_amount or 200,
    }


def _fetch_detail(cookie: str, seed: str = "") -> Dict[str, Any]:
    """请求 /alice/ug/campaign/v3/detail/ 并统一解析 code / payload。"""
    try:
        resp = _post(
            config.DOUBAO_DETAIL_URL,
            cookie,
            {"campaign_group_code": CAMPAIGN_GROUP},
            seed=seed,
        )
    except httpc.ApiError as exc:
        return {"ok": False, "code": None, "error": exc.detail}

    payload = resp.payload
    if not isinstance(payload, dict):
        return {
            "ok": False,
            "code": "HTTP %s" % resp.status,
            "error": "响应非 JSON",
        }
    return {"ok": True, "code": _code_int(payload), "payload": payload}


def _extract_daily_task(data: Dict[str, Any]) -> Tuple[Optional[dict], List[str]]:
    tasks: List[dict] = [t for t in (data.get("tasks") or []) if isinstance(t, dict)]
    task = next((t for t in tasks if t.get("task_kind") == "daily_signin"), None)
    kinds = sorted({str(t.get("task_kind")) for t in tasks if t.get("task_kind")})
    return task, kinds


def _resolve_credits(
    cookie: str,
    seed: str = "",
    rec: Optional[Dict[str, Any]] = None,
) -> Tuple[Any, CreditSnapshot, Dict[str, Any]]:
    snap, expiry = doubao_credits(cookie, seed)
    if not snap.error:
        return snap.total_remain, snap, expiry
    if rec is None:
        rec = doubao_quota_records(cookie, seed)
    total: Any = rec.get("total_amount", 0) if rec.get("auth") else 0
    return total, snap, expiry


def _claim_landing(cookie: str, seed: str = "") -> Dict[str, Any]:
    """调用服务端幂等签到端点 /alice/ug/campaign/landing/checkin。"""
    try:
        resp = _post(
            config.DOUBAO_CHECKIN_URL,
            cookie,
            {"scene": CAMPAIGN_GROUP},
            seed=seed,
        )
    except httpc.ApiError as exc:
        return {"state": ST_FAILED, "error": exc.detail}

    payload = resp.payload
    if not isinstance(payload, dict):
        return {"state": ST_FAILED, "error": "签到接口返回无法解析"}

    code = _code_int(payload)
    if code == LOGIN_INVALID:
        return {
            "state": ST_FAILED,
            "code": code,
            "error": "豆包登录已过期",
            "auth_expired": True,
        }
    if code == NO_ACTIVITY:
        msg = _msg(payload) or "上游活动接口异常"
        return {
            "state": ST_FAILED,
            "code": code,
            "upstream_code": code,
            "error": "%s（code %s）" % (msg, code),
        }
    if code != 0:
        return {
            "state": ST_FAILED,
            "code": code,
            "error": _msg(payload) + "（code %s）" % code,
        }

    d = payload.get("data") or {}
    amount = _int(d.get("reward_amount")) or 200
    days = _int(d.get("continuous_days"))
    if d.get("idempotent") is True:
        return {
            "state": ST_ALREADY,
            "continuous_days": days,
            "reward_amount": amount,
        }
    return {
        "state": ST_SIGNED,
        "reward_amount": amount,
        "continuous_days": days,
    }


# ---------- 状态查询 ----------
def doubao_status(cookie: str, seed: str = "") -> Dict[str, Any]:
    """查任务面板：签到状态 + 总体验额度。

    注：/v3/detail/ 对海外出口 IP 会返回 code=2 (campaign not found)，
    此时降级结合 /quota/records/ 与 /landing/checkin + /subscription/overview/ 确认 Cookie
    有效性及余额；若 /quota/records/ 已确认会话有效，即使签到端点返回 710010702
    也仍视为 auth=True，保证本地/服务端导入与刷新 Cookie 不受上游活动故障阻塞。
    """
    det = _fetch_detail(cookie, seed)
    if not det["ok"]:
        return {"auth": False, "code": det["code"], "error": det["error"]}

    code = det["code"]
    payload = det["payload"]
    if code == LOGIN_INVALID:
        return {"auth": False, "code": code, "error": "豆包登录已过期（Cookie 失效）"}

    if code == 2:
        claim = _claim_landing(cookie, seed)
        if claim.get("auth_expired"):
            return {
                "auth": False,
                "code": LOGIN_INVALID,
                "error": claim.get("error", "豆包登录已过期"),
            }
        if claim.get("state") in (ST_SIGNED, ST_ALREADY):
            total, _snap, _exp = _resolve_credits(cookie, seed)
            return {
                "auth": True,
                "code": 0,
                "checked_in": True,
                "just_signed": claim.get("state") == ST_SIGNED,
                "continuous_days": claim.get("continuous_days", 0),
                "reward_amount": claim.get("reward_amount", 200),
                "total_amount": total,
            }
        rec = doubao_quota_records(cookie, seed)
        if rec.get("code") == LOGIN_INVALID:
            return {"auth": False, "code": LOGIN_INVALID, "error": "豆包登录已过期（Cookie 失效）"}
        if rec.get("auth"):
            # /landing/checkin 返回 710010702 等错误时，仍以 quota/records 放行有效 Cookie
            total, _snap, _exp = _resolve_credits(cookie, seed, rec=rec)
            return {
                "auth": True,
                "code": 0,
                "checked_in": bool(rec.get("checked_in")),
                "continuous_days": 0,
                "reward_amount": rec.get("reward_amount", 200),
                "total_amount": total,
                "claim_error": claim.get("error", ""),
            }
        return {
            "auth": False,
            "code": code,
            "error": claim.get("error") or rec.get("error") or "活动面板不可用（code 2）",
        }

    if code != 0:
        return {"auth": False, "code": code, "error": _msg(payload) + "（code %s）" % code}

    data = payload.get("data") or {}
    task, kinds = _extract_daily_task(data)
    if task is None:
        return {"auth": True, "code": code, "no_task": True, "kinds": kinds}

    c = task.get("daily_checkin") or {}
    reward = c.get("reward") or {}
    snap, _exp = doubao_credits(cookie, seed)
    real_total: Any = (
        snap.total_remain
        if not snap.error
        else _int((data.get("progress") or {}).get("total_amount"))
    )
    return {
        "auth": True,
        "code": code,
        "checked_in": c.get("checked_in_today") is True,
        "continuous_days": _int(c.get("continuous_days")),
        "reward_amount": _int(reward.get("reward_amount")),
        "total_amount": real_total,
    }


def _int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _parse_amount(v: Any) -> float:
    if v is None:
        return 0.0
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).replace(",", "").strip()
    if not s:
        return 0.0
    try:
        return float(s)
    except ValueError:
        return 0.0


def _fmt_ms(ms: int) -> str:
    return datetime.datetime.fromtimestamp(ms / 1000.0, tz=config.BJ_TZ).strftime(
        "%Y-%m-%d %H:%M"
    )


def doubao_credits(
    cookie: str, seed: str = ""
) -> Tuple[CreditSnapshot, Dict[str, Any]]:
    """查询豆包真实剩余额度明细与最近到期信息（国内/海外 IP 均可用）。"""
    try:
        resp = _post(
            config.DOUBAO_OVERVIEW_URL,
            cookie,
            {"product_line": "membership"},
            seed=seed,
        )
    except httpc.ApiError as exc:
        return CreditSnapshot(error=exc.detail), {}

    payload = resp.payload
    if not isinstance(payload, dict):
        return CreditSnapshot(error="额度接口返回非 JSON（HTTP %s）" % resp.status), {}

    code = _code_int(payload)
    if code == LOGIN_INVALID:
        return CreditSnapshot(error="豆包登录已过期（Cookie 失效）"), {}
    if code != 0:
        return CreditSnapshot(error=_msg(payload) + "（code %s）" % code), {}

    data = payload.get("data") or {}
    qbo = data.get("quota_balance_overview") if isinstance(data.get("quota_balance_overview"), dict) else {}

    pkgs: List[Dict[str, Any]] = []
    # 1. 套餐额度（package_entitlement_groups -> entitlements，回退 window_limit_section）
    pkg_groups = [
        g for g in (data.get("package_entitlement_groups") or []) if isinstance(g, dict)
    ]
    for grp in pkg_groups:
        for ent in (grp.get("entitlements") or []):
            if not isinstance(ent, dict):
                continue
            tot = _parse_amount(ent.get("total_amount"))
            used = _parse_amount(ent.get("used_amount"))
            rem = max(0.0, tot - used)
            title = str((ent.get("display") or {}).get("title") or "主套餐")
            pkgs.append({"name": title, "total": tot, "used": used, "remain": rem})

    if not pkgs:
        wls = data.get("window_limit_section") if isinstance(data.get("window_limit_section"), dict) else {}
        for grp in (wls.get("window_limit_groups") or []):
            if not isinstance(grp, dict):
                continue
            for wl in (grp.get("window_limits") or []):
                if not isinstance(wl, dict):
                    continue
                tot = _parse_amount(wl.get("total_amount"))
                used = _parse_amount(wl.get("used_amount"))
                pkgs.append(
                    {
                        "name": str(grp.get("feature_group_name") or "主套餐"),
                        "total": tot,
                        "used": used,
                        "remain": max(0.0, tot - used),
                    }
                )

    # 2. 活动赠送额度（incentive_quota_section）
    iqs = data.get("incentive_quota_section") if isinstance(data.get("incentive_quota_section"), dict) else {}
    for grp in (iqs.get("window_limit_groups") or []):
        if not isinstance(grp, dict):
            continue
        for wl in (grp.get("window_limits") or []):
            if not isinstance(wl, dict):
                continue
            tot = _parse_amount(wl.get("total_amount"))
            used = _parse_amount(wl.get("used_amount"))
            pkgs.append(
                {
                    "name": str(grp.get("feature_group_name") or "活动赠送额度"),
                    "total": tot,
                    "used": used,
                    "remain": max(0.0, tot - used),
                }
            )

    if not pkgs and isinstance(qbo.get("summaries"), list):
        for s in qbo["summaries"]:
            if not isinstance(s, dict):
                continue
            rem = _parse_amount(s.get("remaining_amount"))
            pkgs.append(
                {"name": str(s.get("title") or "额度"), "total": rem, "used": 0.0, "remain": rem}
            )

    has_qbo_total = qbo.get("total_remaining_amount") is not None
    total_remain = (
        _parse_amount(qbo.get("total_remaining_amount"))
        if has_qbo_total
        else sum(p.get("remain", 0.0) for p in pkgs)
    )

    sub = data.get("current_subscription") if isinstance(data.get("current_subscription"), dict) else {}
    is_paid = (
        bool(sub.get("sku_key"))
        and not bool(sub.get("is_gift"))
        and _parse_amount(sub.get("agreement_price")) > 0
    )

    # 3. 最近到期额度包（从未耗尽条目中取最近 end_time）
    exp_candidates: List[Dict[str, Any]] = []
    for item in (qbo.get("top_items") or []):
        if isinstance(item, dict):
            exp_candidates.append(
                {
                    "end_time": _int(item.get("end_time")),
                    "total": _parse_amount(item.get("total_amount")),
                    "used": _parse_amount(item.get("used_amount")),
                    "name": str(item.get("display_name") or "额度"),
                }
            )
    for grp in pkg_groups:
        for ent in (grp.get("entitlements") or []):
            if isinstance(ent, dict):
                exp_candidates.append(
                    {
                        "end_time": _int(ent.get("end_time")),
                        "total": _parse_amount(ent.get("total_amount")),
                        "used": _parse_amount(ent.get("used_amount")),
                        "name": str((ent.get("display") or {}).get("title") or "标准套餐"),
                    }
                )
    for ent in (data.get("incentive_quota_entitlements") or []):
        if isinstance(ent, dict):
            exp_candidates.append(
                {
                    "end_time": _int(ent.get("end_time")),
                    "total": _parse_amount(ent.get("total_amount")),
                    "used": _parse_amount(ent.get("used_amount")),
                    "name": str((ent.get("display") or {}).get("title") or "活动赠送额度"),
                }
            )

    active_exp = [
        c for c in exp_candidates if c["end_time"] > 0 and (c["total"] - c["used"]) > 1e-9
    ]
    expiry: Dict[str, Any] = {}
    if active_exp:
        soonest = min(active_exp, key=lambda c: c["end_time"])
        rem = max(0.0, soonest["total"] - soonest["used"])
        expiry = {
            "ms": soonest["end_time"],
            "expire": _fmt_ms(soonest["end_time"]),
            "remain": rem,
            "size": soonest["total"],
            "name": soonest["name"],
        }

    return (
        CreditSnapshot(total_remain=total_remain, packages=pkgs, is_paid=is_paid),
        expiry,
    )


def _checkin_success(
    state: str,
    cookie: str,
    seed: str,
    days: int,
    amount: int,
    rec: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    total, snap, expiry = _resolve_credits(cookie, seed, rec=rec)
    out: Dict[str, Any] = {
        "state": state,
        "continuous_days": days,
        "total_amount": total,
        "snap": snap,
        "expiry": expiry,
    }
    if state == ST_SIGNED:
        out["reward_amount"] = amount or 200
    elif amount:
        out["reward_amount"] = amount
    return out


# ---------- 签到 ----------
def doubao_checkin(cookie: str, seed: str = "") -> Dict[str, Any]:
    """签到主流程：先查 /v3/detail/ 任务面板，再按状态调用 /landing/checkin 与 overview。"""
    det = _fetch_detail(cookie, seed)
    if not det["ok"]:
        return {"state": ST_FAILED, "error": det["error"]}

    code = det["code"]
    payload = det["payload"]
    if code == LOGIN_INVALID:
        return {
            "state": ST_FAILED,
            "code": code,
            "error": "豆包登录已过期（Cookie 失效）",
            "auth_expired": True,
        }

    if code == 0:
        data = payload.get("data") or {}
        task, kinds = _extract_daily_task(data)
        if task is None:
            return {
                "state": ST_NO_TASK,
                "error": "该账号没有可领的每日签到任务",
                "kinds": kinds,
            }
        c = task.get("daily_checkin") or {}
        reward = c.get("reward") or {}
        days = _int(c.get("continuous_days"))
        amount = _int(reward.get("reward_amount")) or 200
        if c.get("checked_in_today") is True:
            return _checkin_success(ST_ALREADY, cookie, seed, days, amount)

        claim = _claim_landing(cookie, seed)
        c_state = claim.get("state")
        if c_state in (ST_SIGNED, ST_ALREADY):
            return _checkin_success(
                c_state,
                cookie,
                seed,
                claim.get("continuous_days") or days or (1 if c_state == ST_SIGNED else 0),
                claim.get("reward_amount") or amount,
            )
        if claim.get("upstream_code") == NO_ACTIVITY:
            claim = dict(claim)
            claim["error"] = (
                "存在每日签到任务（daily_signin，今日 +%d 额度），"
                "但签到接口返回 710010702 系统错误（豆包服务端故障）" % amount
            )
        return claim

    if code == 2:
        rec = doubao_quota_records(cookie, seed)
        if rec.get("code") == LOGIN_INVALID:
            return {
                "state": ST_FAILED,
                "code": LOGIN_INVALID,
                "error": "豆包登录已过期（Cookie 失效）",
                "auth_expired": True,
            }
        if rec.get("auth") and rec.get("checked_in"):
            return _checkin_success(
                ST_ALREADY,
                cookie,
                seed,
                0,
                _int(rec.get("reward_amount")) or 200,
                rec=rec,
            )
        claim = _claim_landing(cookie, seed)
        c_state = claim.get("state")
        if c_state in (ST_SIGNED, ST_ALREADY):
            return _checkin_success(
                c_state,
                cookie,
                seed,
                claim.get("continuous_days") or (1 if c_state == ST_SIGNED else 0),
                claim.get("reward_amount") or 200,
                rec=rec if rec.get("auth") else None,
            )
        if claim.get("upstream_code") == NO_ACTIVITY:
            hist = (
                "（最近签到日期 %s）" % rec.get("latest_signin_date")
                if rec.get("auth") and rec.get("latest_signin_date")
                else ""
            )
            claim = dict(claim)
            claim["error"] = (
                "海外 IP 受限（v3/detail code 2）且签到接口返回 710010702%s；"
                "建议在本地运行或配置 WBSIGNIN_DOUBAO_PROXY" % hist
            )
        return claim

    return {
        "state": ST_FAILED,
        "code": code,
        "error": _msg(payload) + "（code %s）" % code,
    }
