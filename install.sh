#!/usr/bin/env bash
# wbsignin Linux / macOS 一键安装与升级脚本（零第三方依赖）
#
# 用法：
#   curl -fsSL https://raw.githubusercontent.com/3571949306/wbsignin/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/3571949306/wbsignin/main/install.sh | bash -s -- --with-web
#   WBSIGNIN_PASSPHRASE='your-strong-passphrase' bash install.sh --with-web
set -euo pipefail

DEFAULT_REPO="https://github.com/3571949306/wbsignin.git"
DEFAULT_BRANCH="main"
DEFAULT_ARCHIVE_TMPL="https://github.com/3571949306/wbsignin/archive/refs/heads/%s.tar.gz"

REPO_URL="${WBSIGNIN_REPO:-$DEFAULT_REPO}"
BRANCH="${WBSIGNIN_BRANCH:-$DEFAULT_BRANCH}"
INSTALL_DIR="${WBSIGNIN_INSTALL_DIR:-}"
HOME_DIR="${WBSIGNIN_HOME:-$HOME/.wbsignin}"
PY="${PYTHON:-}"
PASS="${WBSIGNIN_PASSPHRASE:-}"
CALENDAR="${WBSIGNIN_CALENDAR:-*-*-* 08,10:17:00}"
WITH_WEB=0
WEB_PORT="${WBSIGNIN_WEB_PORT:-8787}"
NO_TIMER=0
NO_RC=0
YES=0

say() { printf '%s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die() { printf '\n[x] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
wbsignin 一键安装脚本

选项：
  --dir <path>         源码安装目录（默认：本地仓库内为当前目录，远程安装为 ~/.local/share/wbsignin）
  --home <path>        凭据与状态目录（默认：~/.wbsignin）
  --with-web           同时安装并启动 systemd 用户级 Web 控制台（127.0.0.1:8787）
  --web-port <port>    Web 控制台端口（默认：8787）
  --calendar <expr>    systemd OnCalendar 表达式（默认：*-*-* 08,10:17:00）
  --no-timer           跳过定时任务安装
  --no-rc              不修改 ~/.bashrc / ~/.zshrc / ~/.profile
  --repo <url>         Git 仓库地址
  --branch <name>      分支名（默认：main）
  --passphrase <pw>    直接指定凭据库主密码（更推荐用环境变量 WBSIGNIN_PASSPHRASE）
  -y, --yes            无交互模式（未设置密码且无现有 vault.env 时自动生成随机主密码）
  -h, --help           显示此帮助
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) INSTALL_DIR="$2"; shift 2 ;;
    --home) HOME_DIR="$2"; shift 2 ;;
    --repo) REPO_URL="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --passphrase) PASS="$2"; shift 2 ;;
    --calendar) CALENDAR="$2"; shift 2 ;;
    --with-web) WITH_WEB=1; shift ;;
    --web-port) WEB_PORT="$2"; shift 2 ;;
    --no-timer) NO_TIMER=1; shift ;;
    --no-rc) NO_RC=1; shift ;;
    -y|--yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数: $1（用 --help 查看用法）" ;;
  esac
done

# 探测是否已在克隆好的仓库内部执行
SRC_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  CANDIDATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ -f "$CANDIDATE/pyproject.toml" ] && [ -d "$CANDIDATE/wbsignin" ]; then
    SRC_DIR="$CANDIDATE"
  fi
elif [ -f "./pyproject.toml" ] && [ -d "./wbsignin" ]; then
  SRC_DIR="$(pwd)"
fi

if [ -z "$INSTALL_DIR" ]; then
  if [ -n "$SRC_DIR" ]; then
    INSTALL_DIR="$SRC_DIR"
  else
    INSTALL_DIR="$HOME/.local/share/wbsignin"
  fi
fi

say "== 1/6 检查 Python 环境 =="
if [ -z "$PY" ]; then
  for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
      if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
        PY="$(command -v "$cand")"
        break
      fi
    fi
  done
fi
[ -n "$PY" ] || die "未找到 Python 3.8+，请先安装 python3"
PY_VER="$("$PY" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
say "  Python $PY_VER ($PY)"

say "== 2/6 准备程序源码 =="
if [ -n "$SRC_DIR" ] && [ "$INSTALL_DIR" = "$SRC_DIR" ]; then
  say "  使用本地目录: $INSTALL_DIR"
elif [ -n "$SRC_DIR" ] && [ "$INSTALL_DIR" != "$SRC_DIR" ]; then
  mkdir -p "$INSTALL_DIR"
  cp -a "$SRC_DIR/wbsignin" "$SRC_DIR/tools" "$SRC_DIR/tests" "$SRC_DIR/pyproject.toml" "$SRC_DIR/README.md" "$SRC_DIR/LICENSE" "$SRC_DIR/install.sh" "$SRC_DIR/deploy.sh" "$INSTALL_DIR/"
  say "  已复制源码至: $INSTALL_DIR"
elif [ -d "$INSTALL_DIR/.git" ] && command -v git >/dev/null 2>&1; then
  say "  更新已有仓库: $INSTALL_DIR"
  git -C "$INSTALL_DIR" pull --ff-only || warn "git pull 未能快进更新，保留当前代码继续配置"
elif command -v git >/dev/null 2>&1; then
  mkdir -p "$(dirname "$INSTALL_DIR")"
  say "  克隆仓库: $REPO_URL ($BRANCH) -> $INSTALL_DIR"
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
else
  # 无 git 时通过标准库 urllib + tarfile 拉取 GitHub 源码归档
  mkdir -p "$INSTALL_DIR"
  ARCHIVE_URL="$(printf "$DEFAULT_ARCHIVE_TMPL" "$BRANCH")"
  say "  未检测到 git，下载源码压缩包: $ARCHIVE_URL"
  "$PY" - "$ARCHIVE_URL" "$INSTALL_DIR" <<'PYEOF'
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

url, dst = sys.argv[1], Path(sys.argv[2])
with tempfile.TemporaryDirectory() as tmp:
    tgz = Path(tmp) / "src.tar.gz"
    req = urllib.request.Request(url, headers={"User-Agent": "wbsignin-installer"})
    with urllib.request.urlopen(req, timeout=60) as resp, open(tgz, "wb") as out:
        shutil.copyfileobj(resp, out)
    with tarfile.open(tgz, "r:gz") as tf:
        members = tf.getmembers()
        if hasattr(tarfile, "data_filter"):
            tf.extractall(tmp, filter="data")
        else:
            tf.extractall(tmp)
    roots = [p for p in Path(tmp).iterdir() if p.is_dir()]
    if not roots:
        raise RuntimeError("源码归档为空")
    src_root = roots[0]
    for item in src_root.iterdir():
        target = dst / item.name
        if target.exists():
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
        shutil.move(str(item), str(target))
PYEOF
fi

say "== 3/6 准备状态目录与主密码 =="
mkdir -p "$HOME_DIR"
chmod 700 "$HOME_DIR"
say "  状态目录: $HOME_DIR (700)"

ENV_FILE="$HOME_DIR/vault.env"
GENERATED_PASS=0
if [ -n "$PASS" ]; then
  [ ${#PASS} -ge 8 ] || die "主密码至少 8 位"
elif [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  set -a; . "$ENV_FILE"; set +a
  PASS="${WBSIGNIN_PASSPHRASE:-}"
  if [ -n "$PASS" ]; then
    say "  复用现有主密码配置: $ENV_FILE"
  fi
fi

if [ -z "$PASS" ]; then
  if [ "$YES" -eq 1 ]; then
    PASS="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(18))')"
    GENERATED_PASS=1
  elif [ -t 0 ]; then
    read -r -s -p "  设置凭据库主密码（至少 8 位）: " PASS; echo
    read -r -s -p "  再输入一次确认: " PASS2; echo
    [ "$PASS" = "$PASS2" ] || die "两次输入不一致"
  elif [ -r /dev/tty ]; then
    read -r -s -p "  设置凭据库主密码（至少 8 位）: " PASS </dev/tty; echo >/dev/tty
    read -r -s -p "  再输入一次确认: " PASS2 </dev/tty; echo >/dev/tty
    [ "$PASS" = "$PASS2" ] || die "两次输入不一致"
  else
    die "无法在非交互管道读取主密码。请用 WBSIGNIN_PASSPHRASE='你的密码' curl ... | bash 或加 --yes 自动生成。"
  fi
fi
[ ${#PASS} -ge 8 ] || die "主密码至少 8 位"

umask 077
printf 'WBSIGNIN_HOME=%s\nWBSIGNIN_PASSPHRASE=%s\n' "$HOME_DIR" "$PASS" > "$ENV_FILE"
chmod 600 "$ENV_FILE"
say "  凭据环境已写入: $ENV_FILE (600)"
if [ "$GENERATED_PASS" -eq 1 ]; then
  say "  已自动生成随机主密码并保存于 $ENV_FILE（请妥善备份，切勿泄露）"
fi

say "== 4/6 安装命令行入口 =="
if [ "$(id -u)" -eq 0 ] && [ -w /usr/local/bin ]; then
  BIN_DIR="/usr/local/bin"
else
  BIN_DIR="$HOME/.local/bin"
fi
mkdir -p "$BIN_DIR"
WRAPPER="$BIN_DIR/wbsignin"
cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
WBSIGNIN_HOME="\${WBSIGNIN_HOME:-$HOME_DIR}"
export WBSIGNIN_HOME
if [ -z "\${WBSIGNIN_PASSPHRASE:-}" ] && [ -f "\$WBSIGNIN_HOME/vault.env" ]; then
  set -a
  # shellcheck disable=SC1090
  . "\$WBSIGNIN_HOME/vault.env"
  set +a
fi
PYTHONPATH="$INSTALL_DIR\${PYTHONPATH:+:\$PYTHONPATH}" exec "$PY" -m wbsignin "\$@"
EOF
chmod 755 "$WRAPPER"
say "  CLI 命令已安装: $WRAPPER"

if [ "$NO_RC" -eq 0 ] && [ "$BIN_DIR" = "$HOME/.local/bin" ]; then
  for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [ -f "$rc" ] && ! grep -q '\.local/bin' "$rc" 2>/dev/null; then
      printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$rc"
      say "  已将 ~/.local/bin 加入 $rc"
    fi
  done
fi

say "== 5/6 环境与连通性自检 =="
cd "$INSTALL_DIR"
"$WRAPPER" doctor || true

say "== 6/6 安装定时任务 =="
if [ "$NO_TIMER" -eq 1 ]; then
  say "  已按 --no-timer 跳过定时任务安装"
elif command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  if [ -z "${XDG_RUNTIME_DIR:-}" ] && [ -d "/run/user/$(id -u)" ]; then
    export XDG_RUNTIME_DIR="/run/user/$(id -u)"
  fi
  SCHED_ARGS=(--calendar "$CALENDAR")
  if [ "$WITH_WEB" -eq 1 ]; then
    SCHED_ARGS+=(--with-web --web-port "$WEB_PORT")
  fi
  "$WRAPPER" schedule "${SCHED_ARGS[@]}" || warn "systemd 用户单元启用失败（若当前为 su/容器环境请检查 loginctl/dbus）"
  if command -v loginctl >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    say "  若注销 SSH 后需保持后台定时器常驻，建议执行: sudo loginctl enable-linger $USER"
  fi
else
  warn "未检测到运行中的 systemd，输出 cron 配置供手动加入 crontab -e："
  "$WRAPPER" schedule --print | grep -A1 '方式 B' || true
fi

say ""
say "== 安装完成 =="
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say "当前会话若找不到 wbsignin，请先执行: export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
say "添加账号："
say "  WorkBuddy（短信登录）: wbsignin login"
say "  豆包（粘贴 Cookie）  : wbsignin login-doubao"
say "  Qoder（国内/国际）   : wbsignin login-qoder --region cn   # 或 intl"
say "（Windows 本机可通过 tools/pull_doubao_cookie.py --push / tools/pull_qoder_cred.py --push 一键提取推送）"
say ""
say "立即验证签到与额度："
say "  wbsignin signin"
say "  wbsignin credit"
if [ "$WITH_WEB" -eq 1 ]; then
  say ""
  say "打开 Web 控制台（本地浏览器）："
  say "  ssh -L $WEB_PORT:127.0.0.1:$WEB_PORT <your-server>"
  say "  然后访问 http://127.0.0.1:$WEB_PORT"
fi
