"""签到与积分查询。

签到采用「先查状态、再领取」的幂等流程：已签则直接跳过，不重复请求领取接口。
这样即使一天跑多次、或换机器补跑，也不会重复领取。
"""
from __future__ import annotations

import datetime
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import config, httpc
from .auth import api_headers

# 结果状态
ST_SIGNED = "SIGNED"          # 本次领取成功
ST_ALREADY = "ALREADY"        # 今天已签到（幂等命中）
ST_SEASON = "SEASON"          # 活动未开启 / 已结束
ST_RETRY = "RETRY"            # 瞬时失败，可重试
ST_FAILED = "FAILED"          # 明确失败
ST_SKIPPED = "SKIPPED"        # 未执行（凭据不可用等）


@dataclass
class CheckinResult:
    status: str
    kind: str = httpc.KIND_OK
    detail: str = ""
    streak_days: int = 0
    total_credits: float = 0.0
    credits_gained: float = 0.0
    activity_name: str = ""
    end_time: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        if self.status == ST_SIGNED:
            tail = []
            if self.streak_days:
                tail.append("连签 %d 天" % self.streak_days)
            if self.credits_gained:
                tail.append("本次 +%s" % _num(self.credits_gained))
            if self.total_credits:
                tail.append("活动累计 %s" % _num(self.total_credits))
            return "签到成功" + ("（%s）" % "，".join(tail) if tail else "")
        if self.status == ST_ALREADY:
            tail = []
            if self.streak_days:
                tail.append("连签 %d 天" % self.streak_days)
            if self.total_credits:
                tail.append("活动累计 %s" % _num(self.total_credits))
            return "今日已签到" + ("（%s）" % "，".join(tail) if tail else "")
        if self.status == ST_SEASON:
            return "签到活动未开启或已结束%s" % (
                "（%s）" % self.activity_name if self.activity_name else ""
            )
        return self.detail or self.status


def _num(v: Any) -> str:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    return str(int(f)) if abs(f - int(f)) < 1e-9 else ("%.1f" % f)


def _payload_data(resp: httpc.Response) -> Dict[str, Any]:
    p = resp.payload
    if isinstance(p, dict):
        d = p.get("data")
        if isinstance(d, dict):
            return d
    return {}


# ---------- 签到 ----------
def checkin_status(access_token: str, uid: str = "") -> httpc.Response:
    return httpc.request(
        "POST", config.CHECKIN_STATUS_URL,
        headers=api_headers(access_token, uid), body={},
    )


def do_checkin(access_token: str, uid: str = "") -> httpc.Response:
    return httpc.request(
        "POST", config.CHECKIN_URL,
        headers=api_headers(access_token, uid), body={},
    )


def run_checkin(access_token: str, uid: str = "") -> CheckinResult:
    # 1) 查状态
    try:
        resp = checkin_status(access_token, uid)
    except httpc.ApiError as exc:
        return CheckinResult(
            status=ST_RETRY if exc.kind == httpc.KIND_NETWORK else ST_SKIPPED,
            kind=exc.kind, detail="状态查询失败：%s" % exc.detail,
        )

    kind, detail = httpc.classify(resp)
    if kind != httpc.KIND_OK:
        return CheckinResult(
            status=ST_RETRY if kind in (httpc.KIND_SERVER, httpc.KIND_NETWORK) else ST_FAILED,
            kind=kind, detail="状态查询失败：%s" % detail,
        )

    data = _payload_data(resp)
    result = CheckinResult(
        status=ST_SEASON,
        activity_name=str(data.get("activity_name") or ""),
        end_time=str(data.get("end_time") or ""),
        streak_days=_as_int(data.get("streak_days")),
        total_credits=_as_float(data.get("total_credits")),
        raw=data,
    )

    if data.get("active") is False:
        result.status = ST_SEASON
        result.detail = "签到活动未开启"
        return result

    if data.get("today_checked_in") in (True, 1, "1", "true"):
        result.status = ST_ALREADY
        return result

    # 2) 领取。签到是幂等的，允许对瞬时 404 / 5xx / 网络错误做一次退避重试。
    claim = None
    ckind = httpc.KIND_OK
    cdetail = ""
    for attempt in (1, 2):
        try:
            claim = do_checkin(access_token, uid)
        except httpc.ApiError as exc:
            if exc.kind == httpc.KIND_NETWORK:
                if attempt == 1:
                    time.sleep(2)
                    continue
                # 结果未知，标记待重试而非失败，避免误判断签
                result.status = ST_RETRY
                result.kind = exc.kind
                result.detail = "领取请求异常（结果未知，稍后重试）：%s" % exc.detail
                return result
            raise
        ckind, cdetail = httpc.classify(claim)
        # 瞬时失败判定：404（服务端瞬时路由抖动）/ 5xx / 500+10001 稍后重试
        transient = (
            claim.status == 404
            or (500 <= claim.status < 600)
            or (ckind == httpc.KIND_SERVER and _code_of(claim) in (10001, "10001"))
        )
        if transient and attempt == 1:
            time.sleep(2)
            continue
        break

    cdata = _payload_data(claim)

    if ckind == httpc.KIND_SEASON:
        result.status = ST_SEASON
        result.detail = cdetail
        return result
    if ckind != httpc.KIND_OK:
        retryable = ckind == httpc.KIND_SERVER and _code_of(claim) in (10001, "10001")
        result.status = ST_RETRY if retryable else ST_FAILED
        result.kind = ckind
        result.detail = "签到失败：%s" % cdetail
        return result

    result.status = ST_SIGNED
    result.credits_gained = _as_float(
        cdata.get("credits") or cdata.get("credit") or cdata.get("award_credits")
    )
    # 领取后回读一次状态，用服务端口径确认，而不是仅凭 HTTP 200 断言成功
    try:
        recheck = checkin_status(access_token, uid)
        if httpc.classify(recheck)[0] == httpc.KIND_OK:
            rdata = _payload_data(recheck)
            result.streak_days = _as_int(rdata.get("streak_days")) or result.streak_days
            result.total_credits = _as_float(rdata.get("total_credits")) or result.total_credits
            if rdata.get("today_checked_in") in (True, 1, "1", "true"):
                pass
            else:
                result.status = ST_RETRY
                result.detail = "领取请求已发送，但回读状态未确认（稍后重试）"
    except httpc.ApiError:
        pass  # 回读失败不影响已领取事实，交由下次运行确认
    return result


def _code_of(resp: httpc.Response) -> Any:
    if isinstance(resp.payload, dict):
        return resp.payload.get("code")
    return None


def _as_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _as_float(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


# ---------- 积分 ----------
@dataclass
class CreditSnapshot:
    total_remain: float = 0.0
    packages: List[Dict[str, Any]] = field(default_factory=list)
    is_paid: Optional[bool] = None
    error: str = ""

    def lines(self) -> List[str]:
        out = []
        for i, p in enumerate(self.packages):
            name = str(p.get("name") or "") or ("主套餐" if i == 0 else "加量包%d" % i)
            out.append(
                "%s 剩余 %s（共 %s，已用 %s）"
                % (
                    name,
                    _num(p.get("remain", 0)),
                    _num(p.get("total", 0)),
                    _num(p.get("used", 0)),
                )
            )
        return out


def query_credits(access_token: str, uid: str = "") -> CreditSnapshot:
    try:
        resp = httpc.request(
            "POST", config.CREDIT_SUMMARY_URL,
            headers=api_headers(access_token, uid), body={},
        )
    except httpc.ApiError as exc:
        return CreditSnapshot(error=exc.detail)

    kind, detail = httpc.classify(resp)
    if kind != httpc.KIND_OK:
        return CreditSnapshot(error=detail)

    data = _payload_data(resp)
    snap = CreditSnapshot(is_paid=data.get("IsPaidUser"))
    for p in data.get("Packages") or []:
        if not isinstance(p, dict):
            continue
        remain = _as_float(p.get("CycleRemainCapacity"))
        total = _as_float(p.get("CycleTotalCapacity"))
        used = _as_float(p.get("CycleUsedCapacity"))
        snap.total_remain += remain
        snap.packages.append({"remain": remain, "total": total, "used": used})
    return snap


# ---------- 积分到期 ----------
def _fmt_ms(ms: int) -> str:
    import datetime

    return datetime.datetime.fromtimestamp(ms / 1000, tz=config.BJ_TZ).strftime(
        "%Y-%m-%d %H:%M"
    )


def _parse_cycle_time(raw: str) -> int:
    """把 CycleEndTime（"YYYY-MM-DD HH:MM:SS"）转毫秒。失败返回 0。"""
    import datetime

    try:
        dt = datetime.datetime.strptime(raw[:19], "%Y-%m-%d %H:%M:%S")
        return int(dt.replace(tzinfo=config.BJ_TZ).timestamp() * 1000)
    except Exception:
        return 0


def query_expiry(access_token: str, uid: str = "") -> Dict[str, Any]:
    """查询最近到期的积分。

    数据来自 /billing/meter/get-user-resource，每个积分包带 DeductionEndTime
    （积分可使用的截止时间）与 CycleEndTime。只统计剩余>0 的包，返回最早到期者。
    订阅/体验版套餐的 DeductionEndTime 通常是很远的未来（表示不随周期清零），
    因此「最近到期」自然落到有实效的裂变包/权益包上。
    """
    try:
        resp = httpc.request(
            "POST", config.RESOURCE_URL,
            headers=api_headers(access_token, uid), body={},
        )
    except httpc.ApiError as exc:
        return {"error": exc.detail}
    kind, detail = httpc.classify(resp)
    if kind != httpc.KIND_OK:
        return {"error": detail}

    data = _payload_data(resp)
    accs = ((data.get("Response") or {}).get("Data") or {}).get("Accounts") or []
    soonest: Dict[str, Any] = {}
    for x in accs:
        if not isinstance(x, dict):
            continue
        remain = _as_float(x.get("CapacityRemain", x.get("CycleCapacityRemain", 0)))
        if remain <= 0:
            continue
        ded = x.get("DeductionEndTime")
        try:
            ded_ms = int(ded) if ded else 0
        except (TypeError, ValueError):
            ded_ms = 0
        if not ded_ms:
            ded_ms = _parse_cycle_time(str(x.get("CycleEndTime") or ""))
        if not ded_ms:
            continue
        if not soonest or ded_ms < soonest.get("ms", 0):
            soonest = {
                "ms": ded_ms,
                "expire": _fmt_ms(ded_ms),
                "remain": remain,
                "size": _as_float(x.get("CapacitySize", x.get("CycleCapacitySize", 0))),
                "name": str(
                    x.get("PackageName") or x.get("SubProductName") or "积分包"
                )[:20],
            }
    if not soonest:
        return {"expire": "", "remain": 0, "name": "", "ms": 0}
    return soonest


# ---------- 时间辅助 ----------
def beijing_now() -> datetime.datetime:
    return datetime.datetime.now(tz=config.BJ_TZ)


def activity_hint(end_time: str) -> str:
    """活动到期预警：不足 7 天或已过期时提示，避免收入静默断档。"""
    raw = (end_time or "").strip()
    if len(raw) < 19:
        return ""
    try:
        end = datetime.datetime.strptime(raw[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ""
    now = beijing_now().replace(tzinfo=None)
    days = (end - now).total_seconds() / 86400.0
    if days < 0:
        return "签到活动已到期"
    if days <= 7:
        return "签到活动 %d 天后结束" % max(1, int(days))
    return ""
