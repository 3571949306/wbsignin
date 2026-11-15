"""豆包（doubao.com）每日签到领体验额度。

协议契约整理自 CreditDaddy / dsh-checkin-all（均为 MIT）的实测：
    POST /alice/ug/campaign/v3/detail/       任务面板（含今日签到状态、总额度）
    POST /alice/ug/campaign/landing/checkin  领取（+200 额度/天，服务端幂等）

鉴权：纯 doubao.com 会话 Cookie，无 a_bogus / msToken 请求签名；但服务端按
客户端环境放行，请求必须携带「豆包电脑版 webview」的请求形状：
    - UA 带 DoubaoDesktop 标识
    - URL 带 version_code / device_platform=web / aid 等平台参数
    - web_id / tea_uuid 按账号 seed 确定性派生（每号一台稳定「设备」）
    - device_id 留空（实测可过）

参与门槛：仅个人账号。工作版（DoubaoWork）/ 飞书企业账号的任务面板里没有
「每日签到」任务，服务端会回 710010702「系统错误」。
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
NO_ACTIVITY = 710010702    # Cookie 有效，但该账号没有可领的签到活动

CLIENT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) DoubaoDesktop/2.32.6 Chrome/147.0.7727.149 Safari/537.36"
)

COMMON_PARAMS = {
    "version_code": "20800",
    "language": "zh",
    "device_platform": "web",
    "doubao_device_platform": "web",
    "aid": "497858",
    "real_aid": "497858",
    "pkg_type": "release_version",
    "pc_version": "2.32.6",
    "doubao_pc_version": "5.72.66",
    "samantha_web": "1",
    "web_platform": "desktop",
    "use-olympus-account": "1",
    "web_tab_id": "0",
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
    """按账号 seed 派生稳定的 web_id / tea_uuid（每号恒定、账号间互异）。"""
    h = hashlib.sha256(("doubao-dev:" + (seed or "anonymous")).encode("utf-8")).digest()
    web_id = "76" + "".join(str(b % 10) for b in h[:8])
    tea_uuid = "".join(str(b % 10) for b in h[8:16]).ljust(16, "7")
    return {"web_id": web_id, "tea_uuid": tea_uuid}


def _api_url(base: str, seed: str) -> str:
    params: Dict[str, str] = dict(COMMON_PARAMS)
    params.update(device_ids(seed))
    params.update({"device_id": "", "region": "", "sys_region": ""})
    return base + "?" + urllib.parse.urlencode(params)


def _headers(cookie: str) -> Dict[str, str]:
    return {
        "Cookie": cookie,
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Referer": "https://www.doubao.com/pc/agent-explore",
        "Origin": "https://www.doubao.com",
        "User-Agent": CLIENT_UA,
    }


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
            resp = httpc.request(
                "POST",
                _api_url(config.DOUBAO_QUOTA_RECORDS_URL, seed),
                headers=_headers(cookie),
                body={"cursor": cursor, "page_size": 100},
                retries=2,
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


def _claim_landing(cookie: str, seed: str = "") -> Dict[str, Any]:
    """调用服务端幂等签到端点 /alice/ug/campaign/landing/checkin。"""
    try:
        resp = httpc.request(
            "POST",
            _api_url(config.DOUBAO_CHECKIN_URL, seed),
            headers=_headers(cookie),
            body={"scene": CAMPAIGN_GROUP},
            retries=2,
        )
    except httpc.ApiError as exc:
        return {"state": ST_FAILED, "error": exc.detail}

    payload = resp.payload
    if not isinstance(payload, dict):
        return {"state": ST_FAILED, "error": "签到接口返回无法解析"}

    code = _code_int(payload)
    if code == LOGIN_INVALID:
        return {"state": ST_FAILED, "error": "豆包登录已过期", "auth_expired": True}
    if code == NO_ACTIVITY:
        return {"state": ST_NO_TASK, "error": "该账号没有可领的签到活动"}
    if code != 0:
        return {"state": ST_FAILED, "error": _msg(payload) + "（code %s）" % code}

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
    此时自动降级为幂等 /landing/checkin + /quota/records/ 组合获取状态与总额度。
    """
    try:
        resp = httpc.request(
            "POST", _api_url(config.DOUBAO_DETAIL_URL, seed),
            headers=_headers(cookie),
            body={"campaign_group_code": CAMPAIGN_GROUP},
            retries=2,
        )
    except httpc.ApiError as exc:
        return {"auth": False, "code": None, "error": exc.detail}

    payload = resp.payload
    if not isinstance(payload, dict):
        return {"auth": False, "code": "HTTP %s" % resp.status, "error": "响应非 JSON"}

    code = _code_int(payload)
    if code == LOGIN_INVALID:
        return {"auth": False, "code": code, "error": "豆包登录已过期（Cookie 失效）"}
    if code == 2:
        # 海外服务器 IP 被 /v3/detail/ 地域过滤，走无地域限制的幂等 checkin + overview 真实余额
        claim = _claim_landing(cookie, seed)
        if claim.get("state") == ST_NO_TASK:
            return {"auth": True, "code": 0, "no_task": True, "kinds": []}
        if claim.get("state") not in (ST_SIGNED, ST_ALREADY):
            return {
                "auth": False,
                "code": code,
                "error": claim.get("error", "活动面板不可用（code 2）"),
            }
        snap, _exp = doubao_credits(cookie, seed)
        if not snap.error:
            total: Any = snap.total_remain
        else:
            rec = doubao_quota_records(cookie, seed)
            total = rec.get("total_amount", 0) if rec.get("auth") else 0
        return {
            "auth": True,
            "code": 0,
            "checked_in": True,
            "just_signed": claim.get("state") == ST_SIGNED,
            "continuous_days": claim.get("continuous_days", 0),
            "reward_amount": claim.get("reward_amount", 200),
            "total_amount": total,
        }
    if code != 0:
        return {"auth": False, "code": code, "error": _msg(payload) + "（code %s）" % code}

    data = payload.get("data") or {}
    tasks: List[dict] = [t for t in (data.get("tasks") or []) if isinstance(t, dict)]
    task = next((t for t in tasks if t.get("task_kind") == "daily_signin"), None)
    if task is None:
        kinds = sorted({str(t.get("task_kind")) for t in tasks if t.get("task_kind")})
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
        resp = httpc.request(
            "POST",
            _api_url(config.DOUBAO_OVERVIEW_URL, seed),
            headers=_headers(cookie),
            body={"product_line": "membership"},
            retries=2,
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


# ---------- 签到 ----------
def doubao_checkin(cookie: str, seed: str = "") -> Dict[str, Any]:
    """签到主流程：优先调幂等签到接口并结合 overview 返回真实剩余额度。"""
    claim = _claim_landing(cookie, seed)
    state = claim.get("state")
    if state in (ST_FAILED, ST_NO_TASK):
        return claim

    snap, expiry = doubao_credits(cookie, seed)
    if not snap.error:
        total: Any = snap.total_remain
    else:
        rec = doubao_quota_records(cookie, seed)
        total = rec.get("total_amount", 0) if rec.get("auth") else 0

    if state == ST_ALREADY:
        return {
            "state": ST_ALREADY,
            "continuous_days": claim.get("continuous_days", 0),
            "total_amount": total,
            "snap": snap,
            "expiry": expiry,
        }

    amount = claim.get("reward_amount", 200) or 200
    days = claim.get("continuous_days", 0) or 1
    return {
        "state": ST_SIGNED,
        "reward_amount": amount,
        "continuous_days": days,
        "total_amount": total,
        "snap": snap,
        "expiry": expiry,
    }
