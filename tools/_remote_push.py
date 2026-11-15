#!/usr/bin/env python3
"""将本地提取的凭据安全推送到远端服务器或导入本机凭据库（零第三方依赖）。"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, List


def push_via_ssh(
    host: str,
    payload: bytes,
    remote_tmp: str,
    build_cli_args: Callable[[str], str],
    remote_dir: str = "",
    remote_home: str = "",
) -> int:
    """经单次 SSH 会话写入 077 临时文件并执行远端 wbsignin 子命令（含 255 断线重试）。"""
    eff_host = (host or "").strip() or os.environ.get("WBSIGNIN_SSH_HOST", "").strip()
    if not eff_host:
        print(
            "[错误] 未指定远端 SSH 主机：请传入 --host <ssh主机名> 或设置环境变量 WBSIGNIN_SSH_HOST",
            file=sys.stderr,
        )
        return 2

    eff_dir = (remote_dir or "").strip() or os.environ.get("WBSIGNIN_REMOTE_DIR", "").strip()
    eff_home = (remote_home or "").strip() or os.environ.get("WBSIGNIN_REMOTE_HOME", "").strip()

    q_tmp = shlex.quote(remote_tmp)
    q_dir = shlex.quote(eff_dir)
    q_home = shlex.quote(eff_home)
    cli_args = build_cli_args(q_tmp)

    cmd = (
        f"umask 077 && cat > {q_tmp} && "
        f'WBS_HOME="${{WBSIGNIN_HOME:-$HOME/.wbsignin}}"; '
        f'if [ -n {q_home} ]; then WBS_HOME={q_home}; fi; '
        f'export WBSIGNIN_HOME="$WBS_HOME"; '
        f'if [ -f "$WBS_HOME/vault.env" ]; then set -a && . "$WBS_HOME/vault.env" && set +a; fi; '
        f'if [ -n {q_home} ]; then export WBSIGNIN_HOME={q_home}; fi; '
        f"WBS_DIR={q_dir}; "
        f'if [ -z "$WBS_DIR" ]; then '
        f'  for d in "$HOME/.local/share/wbsignin" "$HOME/wbsignin" "/opt/wbsignin"; do '
        f'    if [ -d "$d/wbsignin" ]; then WBS_DIR="$d"; break; fi; '
        f"  done; "
        f"fi; "
        f'if [ -n "$WBS_DIR" ]; then cd "$WBS_DIR" && python3 -m wbsignin {cli_args} < /dev/null; '
        f"elif command -v wbsignin >/dev/null 2>&1; then wbsignin {cli_args} < /dev/null; "
        f'else echo "未找到远端 wbsignin 安装目录，请先运行 install.sh 或通过 --remote-dir 指定" >&2; rm -f {q_tmp}; exit 1; fi; '
        f"rc=$?; rm -f {q_tmp}; exit $rc"
    )

    rc = 1
    for attempt in range(3):
        proc = subprocess.run(["ssh", eff_host, cmd], input=payload)
        rc = proc.returncode
        if rc != 255:
            return rc
        if attempt < 2:
            time.sleep(2)
    return rc


def import_local_with_tempfile(
    payload: bytes,
    suffix: str,
    build_cli_args: Callable[[str], List[str]],
) -> int:
    """将凭据写入仅当前用户可读的临时文件并调用本机 `python -m wbsignin`。"""
    repo_root = Path(__file__).resolve().parent.parent
    env = dict(os.environ)
    vault_env = (
        Path(env.get("WBSIGNIN_HOME", "") or (Path.home() / ".wbsignin")) / "vault.env"
    )
    if not env.get("WBSIGNIN_PASSPHRASE") and vault_env.is_file():
        for line in vault_env.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env.setdefault(k.strip(), v.strip())

    fd, tmp_name = tempfile.mkstemp(prefix="wbs_import_", suffix=suffix)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fp:
            fp.write(payload)
        cmd = [sys.executable, "-m", "wbsignin", *build_cli_args(str(tmp_path))]
        return subprocess.run(cmd, cwd=str(repo_root), env=env).returncode
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass
