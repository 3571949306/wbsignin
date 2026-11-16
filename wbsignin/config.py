"""全局配置：接口端点、路径、常量。

说明：端点契约来自对公开实现的核对（见 README 的「协议来源」一节）。
这里集中定义，便于官方改版时单点修改。
"""
from __future__ import annotations

import os
from pathlib import Path

# ---------- 接口端点 ----------
BASE = "https://www.workbuddy.cn"
SEND_SMS_URL = BASE + "/v2/plugin/login/send-sms"
LOGIN_URL = BASE + "/v2/plugin/login/token"
REFRESH_URL = "https://copilot.tencent.com/v2/plugin/auth/token/refresh"
REFRESH_DOMAIN = "www.workbuddy.cn"

CHECKIN_STATUS_URL = BASE + "/v2/billing/meter/checkin-activity-status"
CHECKIN_URL = BASE + "/v2/billing/meter/daily-checkin"
CREDIT_SUMMARY_URL = BASE + "/billing/meter/get-user-resource-summary"
RESOURCE_URL = BASE + "/billing/meter/get-user-resource"

# 豆包（doubao.com）
DOUBAO_DETAIL_URL = "https://www.doubao.com/alice/ug/campaign/v3/detail/"
DOUBAO_LANDING_GET_URL = "https://www.doubao.com/alice/ug/campaign/landing/get"
DOUBAO_CHECKIN_URL = "https://www.doubao.com/alice/ug/campaign/landing/checkin"
DOUBAO_QUOTA_RECORDS_URL = "https://www.doubao.com/alice/ug/campaign/quota/records/"
DOUBAO_OVERVIEW_URL = "https://www.doubao.com/alice/commerce/sale/subscription/overview/"
DOUBAO_PASSPORT_QRCODE_URL = "https://accounts.doubao.com/passport/web/get_qrcode/"
DOUBAO_PASSPORT_CHECK_URL = "https://accounts.doubao.com/passport/web/check_qrconnect/"


def doubao_proxy() -> str:
    """可选的豆包专用国内代理（环境变量 WBSIGNIN_DOUBAO_PROXY）。"""
    return os.environ.get("WBSIGNIN_DOUBAO_PROXY", "").strip()

# Qoder（国际版 / 国内版）
QODER_INTL_BASE = "https://openapi.qoder.sh"
QODER_CN_BASE = "https://openapi.qoder.com.cn"

# TRAE CN（trae.cn）
TRAE_CN_API_BASE = "https://api.trae.cn"
TRAE_CN_LOGIN_CHECK_BASE = "https://api.trae.com.cn"
TRAE_CN_WEB_ORIGIN = "https://www.trae.cn"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/138.0.7204.251 Safari/537.36"
)

# 允许访问的域名白名单。任何非白名单地址一律拒绝，避免凭据被转发。
ALLOWED_HOSTS = frozenset(
    {
        "www.workbuddy.cn",
        "copilot.tencent.com",
        "www.codebuddy.cn",
        "www.doubao.com",
        "accounts.doubao.com",
        "openapi.qoder.sh",
        "openapi.qoder.com.cn",
        "api.trae.cn",
        "api.trae.com.cn",
    }
)

REQUEST_TIMEOUT = 25
MAX_RETRIES = 3
RETRY_GAP = 2.0

# ---------- 路径 ----------
def home() -> Path:
    """状态目录。WBSIGNIN_HOME 优先，否则 ~/.wbsignin。"""
    raw = os.environ.get("WBSIGNIN_HOME", "").strip()
    p = Path(raw).expanduser() if raw else Path.home() / ".wbsignin"
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass
    return p


def vault_path() -> Path:
    return home() / "vault.json"


def lock_path() -> Path:
    return home() / "vault.lock"


def state_path() -> Path:
    return home() / "state.json"


# ---------- 时区 ----------
# 签到活动、连签天数均以北京时间（UTC+8）为准。
# 服务器默认 UTC 时若直接取本地日期，会在每日 00:00-08:00 之间算错一天。
try:
    from zoneinfo import ZoneInfo

    BJ_TZ = ZoneInfo("Asia/Shanghai")
except Exception:  # pragma: no cover - 老版本或缺少 tzdata
    from datetime import timedelta, timezone

    BJ_TZ = timezone(timedelta(hours=8))
