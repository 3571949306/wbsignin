"""命令行入口。"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional

from . import __version__, config, httpc, schedule
from .auth import Account, login, send_sms
from .lock import FileLock, LockTimeout, is_locked
from .runner import load_accounts, refresh_all, run, save_accounts
from .tasks import ST_ALREADY, ST_SIGNED, query_credits
from .vault import Vault, VaultError, get_passphrase

MARK = {"ok": "[+]", "bad": "[-]", "warn": "[!]", "dot": "[·]"}


def _say(msg: str = "") -> None:
    print(msg, flush=True)


def _open_vault(confirm: bool = False) -> Vault:
    return Vault(config.vault_path(), get_passphrase(confirm=confirm))


# ---------- login ----------
def cmd_login(args) -> int:
    vault = _open_vault(confirm=not vault_exists())
    phone = (args.phone or "").strip() or input("手机号: ").strip()
    if not phone:
        _say("%s 手机号不能为空" % MARK["bad"])
        return 2

    code = args.code or ""
    if not code:
        info = send_sms(phone)
        _say("%s 验证码已发送（%d 秒内有效）" % (MARK["ok"], info["expires_in"]))
        code = input("验证码: ").strip()
    if not code:
        _say("%s 验证码不能为空" % MARK["bad"])
        return 2

    got = login(phone, code)
    data = vault.load()
    acc = Account.from_dict(phone, data.get("accounts", {}).get(phone, {}))
    acc.access_token = got["access_token"]
    acc.refresh_token = got["refresh_token"]
    acc.uid = got["uid"]
    acc.at_exp = int(got.get("at_exp") or 0)
    acc.updated = time.strftime("%Y-%m-%d %H:%M:%S")
    acc.last_error = ""
    data.setdefault("accounts", {})[phone] = acc.to_dict()
    vault.save(data)

    exp = _fmt_ts(acc.at_exp)
    _say("%s 登录成功：%s（uid=%s，AT 到期 %s）"
         % (MARK["ok"], acc.masked(), (acc.uid or "?")[:8], exp))
    _say("    凭据已加密写入 %s" % vault.path)
    return 0


def cmd_login_doubao(args) -> int:
    """添加豆包账号：粘贴 doubao.com 会话 Cookie。"""
    from .runner import upsert_doubao_account

    vault = _open_vault(confirm=not vault_exists())
    cookie_raw = args.cookie
    if args.cookie_file:
        from pathlib import Path

        cookie_raw = Path(args.cookie_file).read_text(encoding="utf-8")
    name = (args.name or "").strip()
    if not name and not args.cookie_file and not args.cookie:
        name = input("账号名称（用于区分，如「豆包主号」）: ").strip()
    if not cookie_raw:
        cookie_raw = input(
            "粘贴 doubao.com 的 Cookie（浏览器 F12→Network 里复制）: ").strip()

    _say("%s 正在校验 Cookie ..." % MARK["dot"])
    try:
        res = upsert_doubao_account(
            vault,
            cookie_raw,
            name=name,
            default_name=(getattr(args, "default_name", "") or "").strip() or "豆包",
        )
    except httpc.ApiError as exc:
        _say("%s %s" % (MARK["bad"] if exc.kind != httpc.KIND_NOT_CLAIMABLE else MARK["warn"], exc.detail))
        return 1

    _say("%s 豆包账号「%s」已保存（连续 %d 天，剩余额度 %s）"
         % (MARK["ok"], res["masked"], res.get("continuous_days", 0),
            _num(res.get("total_amount", 0))))
    return 0


def cmd_login_qoder(args) -> int:
    """添加 Qoder（国际版 / 国内版）账号。"""
    import datetime

    from . import qoder

    vault = _open_vault(confirm=not vault_exists())

    payload: dict = {}
    if args.from_json:
        payload = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            _say("%s JSON 内容必须为对象" % MARK["bad"])
            return 2

    region = args.region or payload.get("region") or "cn"
    provider = qoder.normalize_provider(region)
    token = (args.token or payload.get("token") or payload.get("access_token") or "").strip()
    if not token:
        token = input("Qoder Token（dt-... 或 pt-... PAT）: ").strip()
    if not token:
        _say("%s Token 不能为空" % MARK["bad"])
        return 2

    rt = (args.refresh_token or payload.get("refresh_token") or payload.get("refreshToken") or "").strip()
    device = payload.get("device") if isinstance(payload.get("device"), dict) else {}
    if args.device_json:
        device = json.loads(args.device_json)

    uid = str(payload.get("uid") or "").strip()
    name = (args.name or payload.get("label") or payload.get("name") or "").strip()
    exp_ts = qoder.parse_expires_at(payload.get("expires_at") or payload.get("expiresAt"))

    _say("%s 正在校验 %s 凭据 ..." % (MARK["dot"], qoder.provider_label(provider)))
    try:
        resp_payload = qoder.verify_token(token, provider, device)
    except httpc.ApiError as exc:
        _say("%s 校验失败：%s" % (MARK["bad"], exc.detail))
        return 1

    uid = uid or str(resp_payload.get("uid") or "")
    snap, _ = qoder.qoder_credits(token, provider, device)
    if not name:
        name = "%s(%s)" % (qoder.provider_label(provider), (uid or "default")[:8])
    key = "%s:%s" % (provider, uid or name)

    data = vault.load()
    acc = Account.from_dict(key, data.get("accounts", {}).get(key, {}))
    acc.provider = provider
    acc.access_token = token
    acc.refresh_token = rt
    acc.uid = uid
    acc.at_exp = exp_ts
    acc.label = name
    acc.device = device
    acc.updated = time.strftime("%Y-%m-%d %H:%M:%S")
    acc.last_error = ""
    data.setdefault("accounts", {})[key] = acc.to_dict()
    vault.save(data)

    _say(
        "%s %s「%s」已添加（剩余 %s Credits）"
        % (MARK["ok"], qoder.provider_label(provider), name, _num(snap.total_remain))
    )
    return 0


def cmd_login_trae(args) -> int:
    """导入 TRAE CN（trae.cn）凭据：支持 Token 或 pull_trae_cred.py --json 输出。"""
    from .runner import upsert_trae_account

    vault = _open_vault()
    payload: Any = ""
    if args.from_json:
        raw_text = Path(args.from_json).expanduser().read_text(encoding="utf-8")
        try:
            parsed = json.loads(raw_text)
        except ValueError as exc:
            _say("%s JSON 文件解析失败：%s" % (MARK["bad"], exc))
            return 2
        if not isinstance(parsed, dict):
            _say("%s 凭据 JSON 必须为对象" % MARK["bad"])
            return 2
        payload = parsed
    elif args.token:
        payload = args.token.strip()
    else:
        payload = input("TRAE CN Token（或凭据 JSON）: ").strip()

    if not payload:
        _say("%s Token 不能为空" % MARK["bad"])
        return 2

    device = json.loads(args.device_json) if args.device_json else None
    _say("%s 正在校验 TRAE CN 凭据 ..." % MARK["dot"])
    res = upsert_trae_account(
        vault,
        payload,
        name=(args.name or "").strip(),
        refresh_token=(args.refresh_token or "").strip(),
        device=device,
    )
    credit_str = res["credit"] if res.get("credit") is not None else "-"
    _say("%s TRAE CN「%s」已添加（剩余 %s 积分）" % (MARK["ok"], res["masked"], credit_str))
    return 0


def vault_exists() -> bool:
    return config.vault_path().exists()


# ---------- accounts / status ----------
def cmd_accounts(args) -> int:
    vault = _open_vault()
    accounts = load_accounts(vault)
    if not accounts:
        _say("%s 尚未登录任何账号，先执行：wbsignin login" % MARK["warn"])
        return 1
    _say("共 %d 个账号（凭据库：%s）" % (len(accounts), vault.path))
    _say("")
    _say("%-13s %-9s %-12s %s" % ("账号", "类型", "到期/标识", "状态"))
    for phone in sorted(accounts):
        a = accounts[phone]
        state = "正常"
        if a.last_error:
            state = a.last_error[:40]
        elif not a.access_token and not a.cookie:
            state = "缺少凭据"
        if a.is_doubao:
            mark = "豆包"
            expire = a.uid[:8] if a.uid else "-"
        elif a.is_qoder:
            mark = "Qoder国内" if a.provider == "qoder-cn" else "Qoder国际"
            expire = _fmt_ts(a.at_exp) if a.at_exp else (a.uid[:8] or "-")
        elif a.is_trae:
            mark = "TRAE CN"
            expire = _fmt_ts(a.at_exp) if a.at_exp else (a.uid[:8] or "-")
        else:
            mark = "WorkBuddy"
            expire = _fmt_ts(a.at_exp)
        _say("%-18s %-10s %-12s %s" % (a.masked(), mark, expire, state))
    return 0


def cmd_status(args) -> int:
    rc = cmd_accounts(args)
    _say("")
    busy = is_locked(config.lock_path())
    _say("凭据库锁：%s" % ("被占用（另一个实例正在运行）" if busy else "空闲"))
    return rc


# ---------- signin ----------
def cmd_signin(args) -> int:
    vault = _open_vault()
    accounts = load_accounts(vault)
    if not accounts:
        _say("%s 尚未登录任何账号，先执行：wbsignin login" % MARK["warn"])
        return 1

    quiet = args.quiet
    jobs = args.jobs if args.jobs and args.jobs > 0 else min(4, len(accounts))

    def log(s: str) -> None:
        if not quiet:
            _say(s)

    try:
        report = run(vault, want_credits=not args.no_credits, jobs=jobs, log=log)
    except LockTimeout as exc:
        _say("%s 另一个实例正在运行，本次跳过：%s" % (MARK["warn"], exc))
        return 3

    if not quiet:
        _say("")
    for o in report.outcomes:
        if o.refresh_error:
            _say("%s %-13s 续期失败：%s" % (MARK["bad"], o.masked, o.refresh_error))
            continue
        c = o.checkin
        if c is None:
            _say("%s %-13s 未执行" % (MARK["warn"], o.masked))
            continue
        mark = MARK["ok"] if c.status in (ST_SIGNED, ST_ALREADY) else MARK["bad"]
        line = "%s %-13s %s" % (mark, o.masked, c.summary())
        if o.credits and not o.credits.error and (
            o.credits.packages or o.provider in ("doubao", "qoder", "qoder-cn", "trae-cn")
        ):
            unit = "额度" if o.provider == "doubao" else ("Credits" if o.provider.startswith("qoder") else "积分")
            line += "｜剩余%s %s" % (unit, _num(o.credits.total_remain))
        _say(line)
        if o.hint:
            _say("    %s %s" % (MARK["warn"], o.hint))
        if o.credits and o.credits.error:
            _say("    查询失败：%s" % o.credits.error)

    _say("")
    _say("小结：%s" % report.one_line())
    return 0 if report.failed == 0 else 1


# ---------- credit ----------
def cmd_credit(args) -> int:
    from . import doubao

    vault = _open_vault()
    accounts = load_accounts(vault)
    if args.phone:
        accounts = {p: a for p, a in accounts.items() if p == args.phone}
    if not accounts:
        _say("%s 没有匹配的账号" % MARK["warn"])
        return 1

    # 先确保 WorkBuddy / TRAE CN 令牌可用（临期则续期）
    refreshable = {p: a for p, a in accounts.items() if a.is_workbuddy or a.is_trae}
    if refreshable:
        refresh_all(refreshable, vault, lambda s: _say(s))

    from . import qoder, trae

    rc = 0
    for phone in sorted(accounts):
        a = accounts[phone]
        if a.is_doubao:
            snap, exp = doubao.doubao_credits(a.cookie, a.uid or "")
            unit = "额度"
        elif a.is_qoder:
            snap, exp = qoder.qoder_credits(a.access_token, a.provider, a.device)
            unit = " Credits"
        elif a.is_trae:
            snap, exp = trae.trae_credits(a.access_token, a.device)
            unit = "积分"
        else:
            snap, exp = query_credits(a.access_token, a.uid), {}
            unit = "积分合计"

        if snap.error:
            _say("%s %-18s 查询失败：%s" % (MARK["bad"], a.masked(), snap.error))
            rc = 1
            continue
        tail = "｜到期 %s" % exp["expire"] if exp.get("expire") else ("（付费）" if a.is_workbuddy and snap.is_paid else "")
        _say("%s %-18s 剩余%s %s%s"
             % (MARK["ok"], a.masked(), unit, _num(snap.total_remain), tail))
        for line in snap.lines():
            _say("    %s" % line)
    return rc


# ---------- doctor ----------
def cmd_doctor(args) -> int:
    """环境与连通性自检。只输出脱敏信息，绝不打印令牌。"""
    _say("环境")
    _say("  python      %s" % sys.version.split()[0])
    _say("  平台        %s" % sys.platform)
    _say("  状态目录    %s" % config.home())
    _say("  凭据库      %s（%s）"
         % (config.vault_path(), "存在" if vault_exists() else "不存在"))
    _say("  时区        Asia/Shanghai（脚本内部强制，不依赖系统 TZ）")
    _say("  当前北京时间 %s" % time.strftime("%Y-%m-%d %H:%M:%S",
                                            time.localtime(time.time() + 0)))

    _say("")
    _say("凭据库")
    try:
        vault = _open_vault()
        accounts = load_accounts(vault)
        _say("  可解密     是（共 %d 个账号）" % len(accounts))
        for phone in sorted(accounts):
            a = accounts[phone]
            _say("    %-13s uid=%s AT到期=%s"
                 % (a.masked(), (a.uid or "-")[:8], _fmt_ts(a.at_exp)))
    except VaultError as exc:
        _say("  可解密     否 —— %s" % exc)
        return 1

    _say("")
    _say("网络连通性（仅握手，不提交任何凭据）")
    ok = True
    for host in ("www.workbuddy.cn", "copilot.tencent.com", "www.doubao.com", "openapi.qoder.sh", "openapi.qoder.com.cn", "api.trae.cn", "api.trae.com.cn"):
        try:
            import socket

            t0 = time.time()
            with socket.create_connection((host, 443), timeout=8):
                pass
            _say("  %-22s 可达（%.0f ms）" % (host, (time.time() - t0) * 1000))
        except Exception as exc:
            ok = False
            _say("  %-22s 不可达：%s" % (host, str(exc)[:60]))
    if not ok:
        _say("  %s 境外服务器访问腾讯域名可能受限，建议用 curl -I 复测" % MARK["warn"])
    return 0 if ok else 1


# ---------- schedule ----------
def cmd_schedule(args) -> int:
    with_web = bool(getattr(args, "with_web", False))
    web_port = int(getattr(args, "web_port", 8787) or 8787)
    if args.print or not schedule.has_systemd():
        _say("# 方式 A：systemd 用户级定时器（推荐，支持开机补跑）")
        _say("# 将下面两个文件分别写入：")
        _say("#   ~/.config/systemd/user/%s.service" % schedule.SERVICE_NAME)
        _say("#   ~/.config/systemd/user/%s.timer" % schedule.SERVICE_NAME)
        if with_web:
            _say("#   ~/.config/systemd/user/%s.service" % schedule.WEB_SERVICE_NAME)
        _say("# 然后执行：systemctl --user daemon-reload && "
             "systemctl --user enable --now %s.timer" % schedule.SERVICE_NAME)
        _say("")
        _say(schedule.systemd_service().rstrip())
        _say("")
        _say(schedule.systemd_timer(args.calendar).rstrip())
        if with_web:
            _say("")
            _say(schedule.systemd_web_service(port=web_port).rstrip())
        _say("")
        _say("# 方式 B：cron")
        _say(schedule.cron_line(args.at))
        return 0

    env = schedule.write_env_file()
    files = schedule.install_user_timer(
        args.calendar, with_web=with_web, web_port=web_port
    )
    _say("%s 已安装 systemd 用户定时器%s"
         % (MARK["ok"], "（含 Web 控制台服务）" if with_web else ""))
    for f in files:
        _say("    %s" % f)
    _say("    触发时间 %s（随机延迟 ≤300s，错过后开机补跑）" % args.calendar)
    if with_web:
        _say("    Web 控制台：127.0.0.1:%d" % web_port)
    _say("")
    _say("%s 还需把主密码写进 %s，否则定时任务无法解密凭据库：" % (MARK["warn"], env))
    _say("    WBSIGNIN_PASSPHRASE=<你的主密码>")
    _say("    chmod 600 %s" % env)
    _say("  并执行：systemctl --user restart %s.timer" % schedule.SERVICE_NAME)
    _say("  验证：systemctl --user list-timers | grep wbsignin")
    return 0


# ---------- web ----------
def cmd_web(args) -> int:
    from . import web
    from .vault import Vault, get_passphrase

    vault = Vault(config.vault_path(), get_passphrase())
    _say("%s 启动本地仪表盘（仅监听 127.0.0.1，公网不可达）" % MARK["ok"])
    _say("   浏览器访问：http://%s:%d" % (args.host, args.port))
    _say("   若在服务器上，先在本机建隧道：")
    _say("     ssh -L %d:127.0.0.1:%d <your-server>" % (args.port, args.port))
    _say("   按 Ctrl+C 退出")
    web.serve(vault, host=args.host, port=args.port, jobs=args.jobs)
    return 0


# ---------- 辅助 ----------
def _fmt_ts(ts: int) -> str:
    if not ts:
        return "-"
    import datetime

    return datetime.datetime.fromtimestamp(ts, tz=config.BJ_TZ).strftime("%m-%d %H:%M")


def _num(v) -> str:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    return str(int(f)) if abs(f - int(f)) < 1e-9 else ("%.1f" % f)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wbsignin",
        description="WorkBuddy / 豆包 / Qoder / TRAE CN 多账号自动签到（零依赖，可在无 GUI 服务器运行）",
    )
    p.add_argument("-V", "--version", action="version", version="wbsignin " + __version__)
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("login", help="短信登录并保存账号（可重复执行以添加多账号）")
    sp.add_argument("phone", nargs="?", help="手机号；省略则交互输入")
    sp.add_argument("--code", help="短信验证码；省略则发送后交互输入")
    sp.set_defaults(func=cmd_login)

    sp = sub.add_parser("login-doubao", help="添加豆包账号（粘贴 doubao.com Cookie）")
    sp.add_argument("name", nargs="?", help="账号名称；省略则交互输入或保留已有名称")
    sp.add_argument("--default-name", help="仅新增账号时使用的默认名称（按 uid_tt 去重）")
    sp.add_argument("--cookie", help="doubao.com 会话 Cookie")
    sp.add_argument("--cookie-file", help="从文件读取 Cookie（避免出现在命令行）")
    sp.set_defaults(func=cmd_login_doubao)

    sp = sub.add_parser("login-qoder", help="添加 Qoder（国际版 / 国内版）账号")
    sp.add_argument("name", nargs="?", help="账号名称；省略则自动生成")
    sp.add_argument("--region", choices=("cn", "intl", "qoder", "qoder-cn"), default=None,
                    help="版本：cn（国内版，默认）或 intl（国际版）")
    sp.add_argument("--token", help="Qoder access token（dt-...）或个人访问令牌（pt-...）")
    sp.add_argument("--refresh-token", help="可选 refreshToken")
    sp.add_argument("--device-json", help="可选设备风控 JSON 字符串")
    sp.add_argument("--from-json", help="从 JSON 文件导入完整 Qoder 凭据（含设备标识）")
    sp.set_defaults(func=cmd_login_qoder)

    sp = sub.add_parser("login-trae", help="添加 TRAE CN（trae.cn）账号")
    sp.add_argument("name", nargs="?", help="账号名称；省略则自动生成")
    sp.add_argument("--token", help="TRAE CN access token（Cloud-IDE-JWT）")
    sp.add_argument("--refresh-token", help="可选 RefreshToken")
    sp.add_argument("--device-json", help="可选设备标识 JSON 字符串")
    sp.add_argument("--from-json", help="从 JSON 文件导入完整 TRAE CN 凭据（含 P-256 密钥对）")
    sp.set_defaults(func=cmd_login_trae)

    sp = sub.add_parser("accounts", help="列出已保存账号")
    sp.set_defaults(func=cmd_accounts)

    sp = sub.add_parser("status", help="账号状态 + 凭据库锁状态")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("signin", help="对所有账号执行签到")
    sp.add_argument("--jobs", type=int, default=0,
                    help="并发度，默认 min(4, 账号数)；1 表示完全串行")
    sp.add_argument("--no-credits", action="store_true", help="跳过积分查询，进一步省流量")
    sp.add_argument("--quiet", action="store_true", help="只输出结果行，适合定时任务")
    sp.set_defaults(func=cmd_signin)

    sp = sub.add_parser("credit", help="查看积分")
    sp.add_argument("--phone", help="只看指定账号")
    sp.set_defaults(func=cmd_credit)

    sp = sub.add_parser("doctor", help="环境与连通性自检（输出已脱敏）")
    sp.set_defaults(func=cmd_doctor)

    sp = sub.add_parser("schedule", help="安装/打印定时任务")
    sp.add_argument("--at", default="08:17", help="cron 时间 HH:MM，默认 08:17")
    sp.add_argument("--calendar", default="*-*-* 08,10:17:00",
                    help="systemd OnCalendar 表达式")
    sp.add_argument("--with-web", action="store_true",
                    help="同时安装并启动 wbsignin-web.service（Web 控制台常驻）")
    sp.add_argument("--web-port", type=int, default=8787,
                    help="wbsignin-web 监听端口，默认 8787")
    sp.add_argument("--print", action="store_true", help="只打印配置，不安装")
    sp.set_defaults(func=cmd_schedule)

    sp = sub.add_parser("web", help="启动本地 Web 仪表盘（仅监听 127.0.0.1）")
    sp.add_argument("--host", default="127.0.0.1", help="监听地址，默认 127.0.0.1")
    sp.add_argument("--port", type=int, default=8787, help="端口，默认 8787")
    sp.add_argument("--jobs", type=int, default=0, help="签到并发度，默认 min(4, 账号数)")
    sp.set_defaults(func=cmd_web)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except VaultError as exc:
        _say("%s %s" % (MARK["bad"], exc))
        return 2
    except httpc.ApiError as exc:
        _say("%s %s：%s" % (MARK["bad"], exc.kind, exc.detail))
        return 1
    except KeyboardInterrupt:
        _say("\n已中断")
        return 130
