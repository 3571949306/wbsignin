"""Qoder（国际版 qoder / 国内版 qoder-cn）每日自动签到与配额查询。

协议契约：
    GET  {base}/sash/api/v1/me/campaigns?clientType=10   活动列表
    POST {base}/sash/api/v1/me/campaigns/{id}/claim       领取每日 Credits（幂等）
    GET  {base}/api/v2/quota/usage                        配额与 Credits 余额
    POST {base}/api/v1/jobToken/exchange                  PAT (pt-...) 兑换短期 token
    POST {base}/api/v1/deviceToken/refresh                设备 OAuth 令牌续期（尽力尝试）

端点：
    国际版（qoder）   : https://openapi.qoder.sh
    国内版（qoder-cn）: https://openapi.qoder.com.cn

每天活动刷新时间为北京时间 10:00（每轮从当日 10:00 至次日 09:59）。
"""
from __future__ import annotations

import datetime
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from . import config, httpc
from .tasks import (
    ST_ALREADY,
    ST_FAILED,
    ST_RETRY,
    ST_SEASON,
    ST_SIGNED,
    ST_SKIPPED,
    CheckinResult,
    CreditSnapshot,
)

PROVIDER_INTL = "qoder"
PROVIDER_CN = "qoder-cn"

_CAMPAIGNS_PATH = "/sash/api/v1/me/campaigns?clientType=10"
_CLAIM_PATH_TMPL = "/sash/api/v1/me/campaigns/%s/claim"
_QUOTA_PATH = "/api/v2/quota/usage"
_EXCHANGE_PATH = "/api/v1/jobToken/exchange"
_REFRESH_PATH = "/api/v1/deviceToken/refresh"

# 9999-12-31 永不过期占位值（毫秒），大于此阈值视为无到期日
_FOREVER_MS = 4102444800000

_REFRESH_HOUR_BJ = 10


def base_url(provider: str) -> str:
    return config.QODER_CN_BASE if provider == PROVIDER_CN else config.QODER_INTL_BASE


def provider_label(provider: str) -> str:
    return "Qoder国内" if provider == PROVIDER_CN else "Qoder国际"


def normalize_provider(region: str) -> str:
    r = str(region or "cn").strip().lower()
    return PROVIDER_CN if r in ("cn", "qoder-cn") else PROVIDER_INTL


def parse_expires_at(exp_raw: Any) -> int:
    """将毫秒/秒时间戳或 ISO 时间字符串解析为 Unix 秒（解析失败返回 0）。"""
    ts = _epoch_sec(exp_raw)
    return int(ts) if ts > 0 else 0


def _apply_device_headers(
    headers: Dict[str, str], dev: Dict[str, Any], include_basic: bool = True
) -> None:
    keys = (
        ("version", "Cosy-Version"),
        ("machineOS", "Cosy-MachineOS"),
    ) if include_basic else ()
    keys = keys + (
        ("machineId", "Cosy-MachineId"),
        ("machineHostname", "Cosy-MachineHostname"),
        ("machineToken", "Cosy-MachineToken"),
        ("machineCode", "Cosy-MachineCode"),
        ("machineType", "Cosy-MachineType"),
    )
    for k, hdr in keys:
        val = str(dev.get(k) or "").strip()
        if val:
            headers[hdr] = val


def _epoch_sec(v: Any) -> float:
    if isinstance(v, (int, float)) and v > 0:
        return v / 1000.0 if v >= 1e12 else float(v)
    if isinstance(v, str) and v.strip():
        s = v.strip()
        try:
            n = float(s)
            return n / 1000.0 if n >= 1e12 else n
        except ValueError:
            pass
        try:
            iso = s.replace("Z", "+00:00")
            return datetime.datetime.fromisoformat(iso).timestamp()
        except ValueError:
            return 0.0
    return 0.0


def current_round_start_ts(now_ts: Optional[float] = None) -> float:
    """计算当前 Qoder 活动轮次的起点时间戳（北京时间每日 10:00）。"""
    now_dt = datetime.datetime.fromtimestamp(
        now_ts if now_ts is not None else time.time(), tz=config.BJ_TZ
    )
    today_10 = now_dt.replace(hour=_REFRESH_HOUR_BJ, minute=0, second=0, microsecond=0)
    if now_dt >= today_10:
        return today_10.timestamp()
    return (today_10 - datetime.timedelta(days=1)).timestamp()


def build_headers(
    token: str, device: Optional[Dict[str, Any]] = None
) -> Dict[str, str]:
    dev = device if isinstance(device, dict) else {}
    h: Dict[str, str] = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "User-Agent": "Qoder",
        "Cosy-ClientType": str(dev.get("clientType") or "10"),
        "Cosy-Version": str(dev.get("version") or "0.5.7"),
        "Cosy-MachineOS": str(dev.get("machineOS") or "x86_64_win32"),
    }
    _apply_device_headers(h, dev, include_basic=False)
    return h


def verify_token(
    token: str,
    provider: str = PROVIDER_INTL,
    device: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """校验 Qoder Token（含 PAT 兑换），返回 /campaigns 响应字典，失败抛 ApiError。"""
    active_tok = resolve_token(token, provider)
    resp = httpc.request(
        "GET",
        base_url(provider) + _CAMPAIGNS_PATH,
        headers=build_headers(active_tok, device),
        retries=2,
    )
    if resp.status in (401, 403):
        raise httpc.ApiError(
            httpc.KIND_AUTH,
            "Token 无效或已过期（HTTP %s）" % resp.status,
            resp.status,
            resp.payload,
        )
    if resp.status >= 400 or not isinstance(resp.payload, dict):
        raise httpc.ApiError(
            httpc.KIND_BAD_RESPONSE,
            "Qoder 校验失败（HTTP %s）" % resp.status,
            resp.status,
            resp.payload,
        )
    return resp.payload


def exchange_pat(pat: str, provider: str = PROVIDER_INTL) -> str:
    """PAT (pt-...) 兑换短期 job token (jt-...)。"""
    url = base_url(provider) + _EXCHANGE_PATH
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "qodercli/1.0.0",
        "Cosy-Version": "1.0.0",
        "Cosy-ClientType": "5",
    }
    resp = httpc.request("POST", url, headers=headers, body={"personal_token": pat}, retries=2)
    if resp.status in (401, 403):
        raise httpc.ApiError(httpc.KIND_AUTH, "Qoder PAT 无效或已过期（HTTP %s）" % resp.status, resp.status, resp.payload)
    if resp.status >= 400 or not isinstance(resp.payload, dict):
        raise httpc.ApiError(httpc.KIND_SERVER, "PAT 兑换失败（HTTP %s）" % resp.status, resp.status, resp.payload)
    tok = resp.payload.get("token") or ""
    if not tok:
        raise httpc.ApiError(httpc.KIND_BAD_RESPONSE, "PAT 兑换响应缺少 token", resp.status, resp.payload)
    return str(tok)


def resolve_token(token: str, provider: str = PROVIDER_INTL) -> str:
    tok = str(token or "").strip()
    if not tok:
        raise httpc.ApiError(httpc.KIND_AUTH, "缺少 Qoder token")
    if tok.startswith("pt-"):
        return exchange_pat(tok, provider)
    return tok


def refresh_device_token(
    refresh_token: str,
    provider: str = PROVIDER_INTL,
    device: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, str]]:
    """尽力尝试用 refresh_token 刷新设备 token；服务端拒绝时返回 None。"""
    rt = str(refresh_token or "").strip()
    if not rt:
        return None
    dev = device if isinstance(device, dict) else {}
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Qoder/claim",
        "Cosy-ClientType": str(dev.get("clientType") or "10"),
    }
    _apply_device_headers(headers, dev, include_basic=True)
    try:
        resp = httpc.request(
            "POST",
            base_url(provider) + _REFRESH_PATH,
            headers=headers,
            body={"refresh_token": rt},
            retries=1,
        )
    except httpc.ApiError:
        return None
    if resp.status != 200 or not isinstance(resp.payload, dict):
        return None
    data = resp.payload
    tok = data.get("token") or data.get("accessToken") or data.get("access_token") or ""
    if not tok:
        return None
    return {
        "access_token": str(tok),
        "refresh_token": str(data.get("refreshToken") or data.get("refresh_token") or rt),
        "expires_at": str(data.get("expiresAt") or data.get("expires_at") or ""),
    }


def _campaigns_from_payload(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    raw = payload.get("campaigns")
    if raw is None and isinstance(payload.get("data"), dict):
        raw = payload["data"].get("campaigns")
    if not isinstance(raw, list):
        return []
    return [c for c in raw if isinstance(c, dict)]


def _in_window(c: Dict[str, Any], now_ts: float) -> bool:
    start = _epoch_sec(c.get("startAt") if c.get("startAt") is not None else c.get("beginAt"))
    end = _epoch_sec(c.get("endAt"))
    if start > 0 and now_ts < start:
        return False
    if end > 0 and now_ts > end:
        return False
    return True


def _benefit_amount(c: Dict[str, Any]) -> float:
    b = c.get("benefit")
    if isinstance(b, dict):
        try:
            return float(b.get("amount") or 0)
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def _num_str(v: float) -> str:
    return str(int(v)) if abs(v - int(v)) < 1e-9 else ("%.1f" % v)


def qoder_checkin(
    token: str,
    provider: str = PROVIDER_INTL,
    device: Optional[Dict[str, Any]] = None,
    now_ts: Optional[float] = None,
) -> CheckinResult:
    """查询活动并领取 Qoder 每日 Credits。"""
    try:
        active_tok = resolve_token(token, provider)
    except httpc.ApiError as exc:
        return CheckinResult(
            status=ST_SKIPPED if exc.kind == httpc.KIND_AUTH else ST_FAILED,
            kind=exc.kind,
            detail=exc.detail,
        )

    base = base_url(provider)
    hdrs = build_headers(active_tok, device)
    try:
        resp = httpc.request("GET", base + _CAMPAIGNS_PATH, headers=hdrs, retries=2)
    except httpc.ApiError as exc:
        return CheckinResult(
            status=ST_RETRY if exc.kind == httpc.KIND_NETWORK else ST_FAILED,
            kind=exc.kind,
            detail="查询活动失败：%s" % exc.detail,
        )

    if resp.status in (401, 403):
        return CheckinResult(
            status=ST_SKIPPED,
            kind=httpc.KIND_AUTH,
            detail="Qoder 登录态已失效（HTTP %s），需重新导入" % resp.status,
        )
    if resp.status >= 400 or not isinstance(resp.payload, dict):
        return CheckinResult(
            status=ST_RETRY if resp.status >= 500 else ST_FAILED,
            kind=httpc.KIND_SERVER,
            detail="活动接口异常（HTTP %s）" % resp.status,
        )

    now = now_ts if now_ts is not None else time.time()
    campaigns = _campaigns_from_payload(resp.payload)
    benefits = [c for c in campaigns if c.get("actionType") == "CLAIM_BENEFIT"]
    claimable = [
        c for c in benefits if c.get("claimStatus") == "CLAIMABLE" and _in_window(c, now)
    ]

    if claimable:
        gained = 0.0
        replayed_only = True
        errors: List[str] = []
        for c in claimable:
            cid = str(c.get("campaignId") or c.get("id") or "")
            if not cid:
                continue
            claim_url = base + (_CLAIM_PATH_TMPL % urllib.parse.quote(cid, safe=""))
            try:
                cres = httpc.request("POST", claim_url, headers=hdrs, body={}, retries=2)
            except httpc.ApiError as exc:
                errors.append(exc.detail)
                continue
            if cres.status in (401, 403):
                return CheckinResult(
                    status=ST_SKIPPED,
                    kind=httpc.KIND_AUTH,
                    detail="Qoder 登录态已失效（HTTP %s）" % cres.status,
                )
            if cres.status >= 400 or not isinstance(cres.payload, dict):
                errors.append("HTTP %s" % cres.status)
                continue
            body = cres.payload.get("data") if isinstance(cres.payload.get("data"), dict) else cres.payload
            if body.get("replayed") is True:
                continue
            if body.get("status") == "CLAIMED" or body.get("success") is True or cres.status == 200:
                replayed_only = False
                amt = _benefit_amount(body) or _benefit_amount(c) or 100.0
                gained += amt
            else:
                errors.append(str(body.get("message") or "未确认领取"))

        if gained > 0 or not replayed_only:
            return CheckinResult(
                status=ST_SIGNED,
                credits_gained=gained,
                detail="签到成功（+%s Credits）" % _num_str(gained),
                raw=resp.payload,
            )
        if not errors:
            amt = _benefit_amount(claimable[0]) or 100.0
            return CheckinResult(
                status=ST_ALREADY,
                detail="今日已签到（已领 %s Credits）" % _num_str(amt),
                raw=resp.payload,
            )
        return CheckinResult(
            status=ST_FAILED,
            kind=httpc.KIND_SERVER,
            detail="领取失败：%s" % "；".join(errors),
        )

    claimed = [
        c for c in benefits if c.get("claimStatus") == "CLAIMED" and _in_window(c, now)
    ]
    if claimed:
        amt = _benefit_amount(claimed[0]) or 100.0
        start = _epoch_sec(claimed[0].get("startAt") or claimed[0].get("beginAt"))
        round_start = current_round_start_ts(now)
        if start > 0 and start < round_start:
            return CheckinResult(
                status=ST_ALREADY,
                detail="上轮已领 %s Credits（今日新一轮 10:00 开启）" % _num_str(amt),
                raw=resp.payload,
            )
        return CheckinResult(
            status=ST_ALREADY,
            detail="今日已签到（已领 %s Credits）" % _num_str(amt),
            raw=resp.payload,
        )

    if not benefits:
        return CheckinResult(
            status=ST_SEASON,
            kind=httpc.KIND_SEASON,
            detail="当前无每日签到活动",
            raw=resp.payload,
        )

    return CheckinResult(
        status=ST_ALREADY,
        detail="今日已签到或活动未开启",
        raw=resp.payload,
    )


def _as_float(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _fmt_ms(ms: int) -> str:
    return datetime.datetime.fromtimestamp(ms / 1000.0, tz=config.BJ_TZ).strftime(
        "%Y-%m-%d %H:%M"
    )


def qoder_credits(
    token: str,
    provider: str = PROVIDER_INTL,
    device: Optional[Dict[str, Any]] = None,
) -> Tuple[CreditSnapshot, Dict[str, Any]]:
    """查询 Qoder 配额余额与最近到期时间。"""
    try:
        active_tok = resolve_token(token, provider)
    except httpc.ApiError as exc:
        return CreditSnapshot(error=exc.detail), {}

    url = base_url(provider) + _QUOTA_PATH
    try:
        resp = httpc.request("GET", url, headers=build_headers(active_tok, device), retries=2)
    except httpc.ApiError as exc:
        return CreditSnapshot(error=exc.detail), {}

    if resp.status in (401, 403):
        return CreditSnapshot(error="鉴权失败（HTTP %s）" % resp.status), {}
    if resp.status >= 400 or not isinstance(resp.payload, dict):
        return CreditSnapshot(error="配额查询失败（HTTP %s）" % resp.status), {}

    data = resp.payload
    uq = data.get("userQuota") if isinstance(data.get("userQuota"), dict) else {}
    aq = data.get("addOnQuota") if isinstance(data.get("addOnQuota"), dict) else {}

    u_total = _as_float(uq.get("total"))
    u_used = _as_float(uq.get("used"))
    u_rem = _as_float(uq.get("remaining"))

    a_total = _as_float(aq.get("total"))
    a_used = _as_float(aq.get("used"))
    a_rem = _as_float(aq.get("remaining"))

    user_type = str(data.get("userType") or "")
    is_paid = user_type not in ("", "free", "personal_standard", "trial")

    pkgs: List[Dict[str, Any]] = []
    if u_total > 0 or u_rem > 0:
        pkgs.append({"total": u_total, "used": u_used, "remain": u_rem})
    if a_total > 0 or a_rem > 0:
        pkgs.append({"total": a_total, "used": a_used, "remain": a_rem})

    snap = CreditSnapshot(
        total_remain=u_rem + a_rem,
        packages=pkgs,
        is_paid=is_paid,
    )

    expiry: Dict[str, Any] = {}
    exp_raw = data.get("expiresAt")
    try:
        exp_ms = int(exp_raw or 0)
    except (TypeError, ValueError):
        exp_ms = 0
    if 0 < exp_ms < 10**12:
        exp_ms *= 1000
    if 0 < exp_ms < _FOREVER_MS:
        expiry = {
            "ms": exp_ms,
            "expire": _fmt_ms(exp_ms),
            "remain": snap.total_remain,
            "size": u_total + a_total,
            "name": user_type or provider_label(provider),
        }

    return snap, expiry
