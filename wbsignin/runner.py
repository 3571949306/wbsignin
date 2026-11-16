"""多账号执行编排。

三个阶段，顺序是刻意的：

  阶段 1（串行 + 持锁）  续期所有需要续期的账号，并立即写回凭据库。
  阶段 2（并发，不加锁）  只读凭据做签到 / 积分查询，不触碰凭据库。
  阶段 3（串行 + 持锁）  统一写回最后一次错误信息与时间戳。

这样拆分的原因：RT 轮换必须在单写者锁内完成（否则多实例互相踢掉），
而签到是纯 IO 等待，可以并发以缩短总耗时。并发度默认很小——线程而非进程，
每个线程只是等在 socket 上，内存开销可忽略，符合「少占系统」的要求。
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import config, httpc
from .auth import Account, needs_refresh, refresh
from .lock import FileLock
from .tasks import (
    ST_ALREADY,
    ST_FAILED,
    ST_RETRY,
    ST_SIGNED,
    ST_SKIPPED,
    CheckinResult,
    CreditSnapshot,
    activity_hint,
    query_credits,
    query_expiry,
    run_checkin,
)
from .vault import Vault


@dataclass
class AccountOutcome:
    phone: str
    uid: str = ""
    provider: str = "workbuddy"
    label: str = ""
    checkin: Optional[CheckinResult] = None
    credits: Optional[CreditSnapshot] = None
    expiry: Dict[str, Any] = field(default_factory=dict)
    refresh_error: str = ""
    hint: str = ""
    note: str = ""

    @property
    def masked(self) -> str:
        if self.label:
            return self.label
        p = self.phone or ""
        return p[:3] + "****" + p[-4:] if len(p) >= 8 else p

    @property
    def ok(self) -> bool:
        if self.refresh_error:
            return False
        if self.checkin is None:
            return False
        return self.checkin.status in (ST_SIGNED, ST_ALREADY)


@dataclass
class RunReport:
    started: str = ""
    finished: str = ""
    outcomes: List[AccountOutcome] = field(default_factory=list)
    jobs: int = 1

    @property
    def signed(self) -> int:
        return sum(1 for o in self.outcomes if o.checkin and o.checkin.status == ST_SIGNED)

    @property
    def already(self) -> int:
        return sum(1 for o in self.outcomes if o.checkin and o.checkin.status == ST_ALREADY)

    @property
    def failed(self) -> int:
        return sum(1 for o in self.outcomes if not o.ok)

    @property
    def total_gained(self) -> float:
        return sum(
            (o.checkin.credits_gained if o.checkin else 0.0) for o in self.outcomes
        )

    def one_line(self) -> str:
        parts = []
        if self.signed:
            parts.append("新签 %d" % self.signed)
        if self.already:
            parts.append("已签 %d" % self.already)
        if self.failed:
            parts.append("异常 %d" % self.failed)
        body = "，".join(parts) if parts else "无账号"
        gained = self.total_gained
        if gained:
            body += "，本次共 +%s 积分" % (int(gained) if gained == int(gained) else gained)
        return body


def load_accounts(vault: Vault) -> Dict[str, Account]:
    data = vault.load()
    raw = data.get("accounts") or {}
    return {phone: Account.from_dict(phone, d) for phone, d in raw.items()}


def persist(vault: Vault, accounts: Dict[str, Account]) -> None:
    """直接写盘，不先读盘。

    每次 vault.load() 都要跑一遍 scrypt（约 100ms CPU + 32MB 瞬时内存），
    在已有完整账号表时再读一次纯属浪费——尤其在低配 VPS 上。
    """
    vault.save(
        {
            "version": 1,
            "accounts": {p: a.to_dict() for p, a in accounts.items()},
        }
    )


def save_accounts(vault: Vault, accounts: Dict[str, Account]) -> None:
    """合并式保存：保留库中已有但本次未涉及的账号。"""
    data = vault.load()
    merged = {
        p: Account.from_dict(p, d) for p, d in (data.get("accounts") or {}).items()
    }
    merged.update(accounts)
    persist(vault, merged)


# ---------- 运行结果持久化 ----------
# 定时任务（独立进程）跑完后把「签到结论 + 积分明细」写入 state.json，
# Web 仪表盘进程启动时读取它做初始展示，避免每次打开都空白、必须手动刷新。
def _num(v: Any) -> str:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    return str(int(f)) if abs(f - int(f)) < 1e-9 else ("%.1f" % f)


def load_state() -> Dict[str, Any]:
    try:
        return json.loads(config.state_path().read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(data: Dict[str, Any]) -> None:
    p = config.state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".state-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def persist_run_state(report: "RunReport") -> None:
    """把本次运行结果落盘为 state.json（含积分/额度快照）。"""
    accounts: Dict[str, Any] = {}
    for o in report.outcomes:
        entry: Dict[str, Any] = {
            "ok": o.ok,
            "provider": o.provider,
            "signin": o.checkin.summary() if o.checkin else (o.refresh_error or "未执行"),
        }
        if o.credits and not o.credits.error:
            entry["credit"] = {
                "total": _num(o.credits.total_remain),
                "lines": o.credits.lines(),
                "paid": o.credits.is_paid,
            }
        if o.expiry:
            entry["expiry"] = o.expiry
        accounts[o.phone] = entry
    save_state(
        {
            "updated": report.finished or time.strftime("%Y-%m-%d %H:%M:%S"),
            "one_line": report.one_line(),
            "accounts": accounts,
        }
    )


# ---------- 阶段 1：续期 ----------
def refresh_all(
    accounts: Dict[str, Account],
    vault: Vault,
    log: Callable[[str], None] = lambda s: None,
) -> Dict[str, str]:
    """串行续期。返回 {phone: 错误信息}（仅记录失败项）。

    锁在整段续期期间持有：即便两个实例同时启动，第二个会排队，
    拿到锁后读到的是已经轮换过的新 RT，不会用旧 RT 去刷新。
    """
    errors: Dict[str, str] = {}
    pending = [
        a for a in accounts.values()
        if a.is_workbuddy and needs_refresh(a.access_token)
    ]
    if not pending:
        return errors

    with FileLock(config.lock_path()):
        # 重新读一次：可能已被前一个持锁实例更新
        fresh = load_accounts(vault)
        for acc in pending:
            cur = fresh.get(acc.phone)
            if cur is None:
                continue
            if not needs_refresh(cur.access_token):
                acc.access_token = cur.access_token
                acc.refresh_token = cur.refresh_token
                acc.uid = cur.uid or acc.uid
                acc.at_exp = cur.at_exp
                continue
            try:
                got = refresh(cur.refresh_token, cur.access_token)
            except httpc.ApiError as exc:
                errors[acc.phone] = exc.detail
                cur.last_error = "%s %s" % (exc.kind, exc.detail)
                fresh[acc.phone] = cur
                continue
            cur.access_token = got["access_token"]
            cur.refresh_token = got["refresh_token"]
            cur.uid = got.get("uid") or cur.uid
            cur.at_exp = int(got.get("at_exp") or 0)
            cur.updated = time.strftime("%Y-%m-%d %H:%M:%S")
            cur.last_error = ""
            fresh[acc.phone] = cur

            acc.access_token = cur.access_token
            acc.refresh_token = cur.refresh_token
            acc.uid = cur.uid
            acc.at_exp = cur.at_exp
            log("  ↻ %s 令牌已续期" % acc.masked())
            # 每成功一个立即落盘：即便后续崩溃，已轮换的 RT 也不会丢
            persist(vault, fresh)
    return errors


# ---------- 阶段 2：签到 / 积分 ----------
def _work_doubao(acc: Account, want_credits: bool = True) -> AccountOutcome:
    from . import doubao

    out = AccountOutcome(phone=acc.phone, uid=acc.uid, provider=acc.provider,
                         label=acc.masked())
    if not acc.cookie:
        out.refresh_error = "缺少豆包 Cookie，需重新登录"
        return out
    r = doubao.doubao_checkin(acc.cookie, acc.uid or "")
    if r.get("state") == doubao.ST_SIGNED:
        amt = int(r.get("reward_amount", 0) or 0)
        out.checkin = CheckinResult(
            status=ST_SIGNED,
            credits_gained=float(amt),
            detail="签到成功 +%d 额度（连续 %d 天）"
            % (amt, r.get("continuous_days", 0)),
        )
    elif r.get("state") == doubao.ST_ALREADY:
        out.checkin = CheckinResult(
            status=ST_ALREADY,
            detail="今日已签到（连续 %d 天）" % r.get("continuous_days", 0),
        )
    elif r.get("state") == doubao.ST_NO_TASK:
        out.checkin = CheckinResult(
            status=ST_SKIPPED,
            kind=httpc.KIND_NOT_CLAIMABLE,
            detail="该账号无签到任务",
        )
        out.note = "；".join(r.get("kinds", []))
    else:
        kind = httpc.KIND_AUTH if r.get("auth_expired") else httpc.KIND_SERVER
        out.checkin = CheckinResult(
            status=ST_FAILED,
            kind=kind,
            detail=r.get("error", "签到失败"),
        )
    if want_credits and not r.get("auth_expired"):
        snap = r.get("snap")
        exp = r.get("expiry")
        if isinstance(snap, CreditSnapshot) and not snap.error:
            out.credits = snap
            if isinstance(exp, dict):
                out.expiry = exp
        elif r.get("total_amount") is not None and r.get("state") in (
            doubao.ST_SIGNED,
            doubao.ST_ALREADY,
        ):
            out.credits = CreditSnapshot(total_remain=float(r["total_amount"]))
        elif not isinstance(snap, CreditSnapshot):
            snap, exp = doubao.doubao_credits(acc.cookie, acc.uid or "")
            out.credits = snap
            if isinstance(exp, dict) and not snap.error:
                out.expiry = exp
    return out


def upsert_doubao_account(
    vault: Vault, cookie_raw: str, name: str = "", default_name: str = "豆包"
) -> Dict[str, Any]:
    """校验并保存/按 uid_tt 去重更新豆包账号。"""
    import hashlib
    import secrets

    from . import doubao

    cookie = doubao.normalize_cookie(cookie_raw)
    if not cookie:
        raise httpc.ApiError(httpc.KIND_BAD_RESPONSE, "Cookie 不能为空")

    uid_tt = doubao.cookie_uid(cookie)
    data = vault.load()
    accounts_map = data.setdefault("accounts", {})
    req_name = (name or "").strip()

    matched_key = ""
    matched_dict: Dict[str, Any] = {}
    for k, d in accounts_map.items():
        if not isinstance(d, dict) or d.get("provider") != "doubao":
            continue
        existing_uid = doubao.cookie_uid(str(d.get("cookie") or ""))
        if uid_tt and existing_uid == uid_tt:
            matched_key, matched_dict = k, d
            break
    if not matched_key and req_name:
        for k, d in accounts_map.items():
            if not isinstance(d, dict) or d.get("provider") != "doubao":
                continue
            if str(d.get("label") or "").strip() == req_name:
                matched_key, matched_dict = k, d
                break

    seed = (
        str(matched_dict.get("uid") or "").strip()
        or (
            hashlib.sha256(("doubao:" + uid_tt).encode("utf-8")).hexdigest()[:12]
            if uid_tt
            else secrets.token_hex(6)
        )
    )
    st = doubao.doubao_status(cookie, seed)
    if not st.get("auth"):
        raise httpc.ApiError(
            httpc.KIND_AUTH, "Cookie 无效：%s" % (st.get("error", "未知"))
        )
    if st.get("no_task"):
        kinds = "、".join(st.get("kinds", []))
        raise httpc.ApiError(
            httpc.KIND_NOT_CLAIMABLE,
            "该账号没有「每日签到」任务（工作版/企业账号无此玩法）%s"
            % ("；现有任务：" + kinds if kinds else ""),
        )

    key = matched_key or ("doubao:" + seed[:12])
    acc = Account.from_dict(key, matched_dict)
    label = req_name or (acc.label or "").strip() or (default_name or "").strip() or "豆包"
    acc.provider = "doubao"
    acc.cookie = cookie
    acc.uid = seed
    acc.label = label
    acc.updated = time.strftime("%Y-%m-%d %H:%M:%S")
    acc.last_error = ""
    accounts_map[key] = acc.to_dict()
    vault.save(data)

    snap, exp = doubao.doubao_credits(cookie, seed)
    total = snap.total_remain if not snap.error else st.get("total_amount", 0)
    return {
        "key": key,
        "masked": label,
        "continuous_days": st.get("continuous_days", 0),
        "total_amount": total,
        "snap": snap,
        "expiry": exp,
    }


def _work_qoder(acc: Account, want_credits: bool) -> AccountOutcome:
    from . import qoder

    out = AccountOutcome(phone=acc.phone, uid=acc.uid, provider=acc.provider,
                         label=acc.masked())
    if not acc.access_token:
        out.refresh_error = "缺少 Qoder token，需重新导入"
        return out
    out.checkin = qoder.qoder_checkin(acc.access_token, acc.provider, acc.device)
    if want_credits:
        snap, exp = qoder.qoder_credits(acc.access_token, acc.provider, acc.device)
        out.credits = snap
        out.expiry = exp
    return out


def _work(acc: Account, want_credits: bool) -> AccountOutcome:
    if acc.is_doubao:
        return _work_doubao(acc, want_credits)
    if acc.is_qoder:
        return _work_qoder(acc, want_credits)
    out = AccountOutcome(phone=acc.phone, uid=acc.uid, provider=acc.provider,
                         label=acc.masked())
    if not acc.access_token:
        out.refresh_error = "缺少 access_token，需重新登录"
        return out
    try:
        out.checkin = run_checkin(acc.access_token, acc.uid)
    except httpc.ApiError as exc:
        out.checkin = CheckinResult(status=ST_SKIPPED, kind=exc.kind,
                                    detail=exc.detail)
    if out.checkin:
        out.hint = activity_hint(out.checkin.end_time)
    if want_credits:
        try:
            out.credits = query_credits(acc.access_token, acc.uid)
        except httpc.ApiError as exc:
            out.credits = CreditSnapshot(error=exc.detail)
        try:
            out.expiry = query_expiry(acc.access_token, acc.uid)
        except httpc.ApiError as exc:
            out.expiry = {"error": exc.detail}
    return out


def run(
    vault: Vault,
    want_credits: bool = True,
    jobs: int = 1,
    log: Callable[[str], None] = lambda s: None,
) -> RunReport:
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    accounts = load_accounts(vault)
    report = RunReport(started=started, jobs=max(1, jobs))

    if not accounts:
        report.finished = time.strftime("%Y-%m-%d %H:%M:%S")
        return report

    errs = refresh_all(accounts, vault, log)

    # 阶段 2：只读凭据，可并发
    order: List[Account] = sorted(accounts.values(), key=lambda a: a.phone)
    results: Dict[str, AccountOutcome] = {}
    n = len(order)
    workers = max(1, min(jobs, n))

    if workers == 1:
        for acc in order:
            results[acc.phone] = _work(acc, want_credits)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_work, a, want_credits): a for a in order}
            for fut in as_completed(futs):
                acc = futs[fut]
                try:
                    results[acc.phone] = fut.result()
                except Exception as exc:  # 单账号异常不拖垮整批
                    o = AccountOutcome(phone=acc.phone, uid=acc.uid)
                    o.checkin = CheckinResult(
                        status=ST_FAILED, detail="未预期异常：%s" % str(exc)[:120]
                    )
                    results[acc.phone] = o

    report.outcomes = [results[p] for p in sorted(results)]

    # 阶段 3：写回错误状态（持锁，避免与并发的另一个实例互相覆盖）
    for out in report.outcomes:
        if out.phone in errs:
            out.refresh_error = errs[out.phone]
    try:
        with FileLock(config.lock_path()):
            fresh = load_accounts(vault)
            for out in report.outcomes:
                cur = fresh.get(out.phone)
                if cur is None:
                    continue
                if out.refresh_error:
                    cur.last_error = out.refresh_error
                elif out.checkin and out.checkin.status in (ST_SIGNED, ST_ALREADY):
                    cur.last_error = ""
                elif out.checkin and out.checkin.detail:
                    cur.last_error = "%s %s" % (out.checkin.kind, out.checkin.detail)
                fresh[out.phone] = cur
            persist(vault, fresh)
    except Exception as exc:
        log("  ⚠ 状态回写失败（不影响本次领取结果）：%s" % str(exc)[:100])

    report.finished = time.strftime("%Y-%m-%d %H:%M:%S")
    if want_credits:
        try:
            persist_run_state(report)
        except Exception as exc:
            log("  ⚠ 结果持久化失败（不影响领取）：%s" % str(exc)[:100])
    return report
