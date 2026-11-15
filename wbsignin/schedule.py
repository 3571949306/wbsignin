"""定时器生成与安装（systemd timer 优先，其次 cron）。

选 systemd timer 而非 cron 的原因：Persistent=true 可以在机器关机/休眠错过
触发点后，开机补跑一次——对"签到不能断"这个需求是直接收益。cron 没有这个语义。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

SERVICE_NAME = "wbsignin"
WEB_SERVICE_NAME = "wbsignin-web"


def _python() -> str:
    return sys.executable or "/usr/bin/python3"


def _code_root() -> Path:
    """包所在目录的父目录，用作 WorkingDirectory / PYTHONPATH。"""
    return Path(__file__).resolve().parent.parent


def _pythonpath_line() -> str:
    """若是 git clone 部署（包不在 site-packages 内），显式给出 PYTHONPATH。

    否则 systemd 的干净环境下 `-m wbsignin` 会 ImportError——这是
    裸机部署最常见的坑，提前处理掉。
    """
    root = _code_root()
    try:
        import site

        for sp in site.getsitepackages() + [site.getusersitepackages()]:
            if str(root).startswith(str(sp)):
                return ""
    except Exception:
        pass
    return "Environment=PYTHONPATH=%s\n" % root


def _env_file_hint() -> str:
    return "EnvironmentFile=%s\n" % (_default_home() / "vault.env")


def _default_home() -> Path:
    return Path(os.environ.get("WBSIGNIN_HOME", "") or (Path.home() / ".wbsignin"))


def systemd_service(exec_args: str = "signin --quiet") -> str:
    home = _default_home()
    return (
        "[Unit]\n"
        "Description=wbsignin multi-account daily check-in\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "Environment=PYTHONUNBUFFERED=1\n"
        "Environment=TZ=Asia/Shanghai\n"
        "Environment=WBSIGNIN_HOME=%s\n"
        "%s"
        "%s"
        "WorkingDirectory=%s\n"
        "ExecStart=%s -m wbsignin %s\n"
        "Nice=10\n"
        "IOSchedulingClass=idle\n"
        "MemoryMax=192M\n"
        "NoNewPrivileges=true\n"
        "PrivateTmp=true\n"
        % (home, _env_file_hint(), _pythonpath_line(), _code_root(),
           _python(), exec_args)
    )


def systemd_timer(on_calendar: str = "*-*-* 08,10:17:00", persistent: bool = True) -> str:
    return (
        "[Unit]\n"
        "Description=Daily schedule for wbsignin\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=%s\n"
        "RandomizedDelaySec=300\n"
        "Persistent=%s\n"
        "Unit=%s.service\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
        % (on_calendar, "true" if persistent else "false", SERVICE_NAME)
    )


def systemd_web_service(host: str = "127.0.0.1", port: int = 8787) -> str:
    """生成 Web 控制台常驻 systemd 用户服务单元（仅绑定本地回环地址）。"""
    home = _default_home()
    return (
        "[Unit]\n"
        "Description=wbsignin local web dashboard\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "Environment=PYTHONUNBUFFERED=1\n"
        "Environment=TZ=Asia/Shanghai\n"
        "Environment=WBSIGNIN_HOME=%s\n"
        "%s"
        "%s"
        "WorkingDirectory=%s\n"
        "ExecStart=%s -m wbsignin web --host %s --port %d\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "MemoryMax=192M\n"
        "NoNewPrivileges=true\n"
        "PrivateTmp=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
        % (home, _env_file_hint(), _pythonpath_line(), _code_root(),
           _python(), host, int(port))
    )


def cron_line(on_calendar: str = "08:17") -> str:
    try:
        hh, mm = on_calendar.split(":")[0:2]
    except ValueError:
        hh, mm = "8", "17"
    home = _default_home()
    return (
        "%s %s * * * TZ=Asia/Shanghai WBSIGNIN_HOME=%s %s -m wbsignin signin --quiet "
        ">> %s/signin.log 2>&1\n"
        % (int(mm), int(hh), home, _python(), home)
    )


def has_systemd() -> bool:
    return bool(shutil.which("systemctl")) and Path("/run/systemd/system").exists()


def install_user_timer(
    on_calendar: str = "*-*-* 08,10:17:00",
    with_web: bool = False,
    web_port: int = 8787,
) -> List[Path]:
    """安装到当前用户的 systemd（无需 root）。返回写入的文件路径。"""
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    svc = unit_dir / ("%s.service" % SERVICE_NAME)
    tmr = unit_dir / ("%s.timer" % SERVICE_NAME)
    svc.write_text(systemd_service(), encoding="utf-8")
    tmr.write_text(systemd_timer(on_calendar), encoding="utf-8")
    written = [svc, tmr]
    if with_web:
        wsvc = unit_dir / ("%s.service" % WEB_SERVICE_NAME)
        wsvc.write_text(systemd_web_service(port=web_port), encoding="utf-8")
        written.append(wsvc)
    _run(["systemctl", "--user", "daemon-reload"])
    _run(["systemctl", "--user", "enable", "--now", "%s.timer" % SERVICE_NAME])
    if with_web:
        _run(["systemctl", "--user", "enable", "--now", "%s.service" % WEB_SERVICE_NAME])
        _run(["systemctl", "--user", "restart", "%s.service" % WEB_SERVICE_NAME])
    return written


def _run(cmd: List[str]) -> Optional[int]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode
    except Exception:
        return None


def write_env_file(passphrase_placeholder: str = "CHANGE_ME") -> Path:
    """生成 systemd EnvironmentFile 模板（权限 600）。"""
    home = _default_home()
    path = home / "vault.env"
    if path.exists():
        return path
    path.write_text(
        "WBSIGNIN_HOME=%s\nWBSIGNIN_PASSPHRASE=%s\n"
        % (home, passphrase_placeholder),
        encoding="utf-8",
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path
