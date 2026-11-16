"""HTTP 客户端与错误分类。

两条硬性约束
------------
1. **域名白名单**：只允许访问 ALLOWED_HOSTS 内的地址。这防止了任何形式的
   凭据转发——即使上游响应里塞了一个第三方 URL，也不会被请求。
2. **强制 TLS 校验**：使用 urllib 默认的证书校验，不提供关闭开关。
   （部分现成脚本用 verify=False 换取"能跑通"，代价是中间人可直接拿到 Token，
   不值得。）

错误分类的意义
--------------
现有工具普遍只回一行 JSON 字符串，断签后无法定位原因。这里把失败拆成
可判定的类别，每类对应明确的处置动作（重试 / 跳过该账号 / 人工重新登录）。
"""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from . import config

# ---------- 错误类别 ----------
KIND_OK = "OK"
KIND_NETWORK = "NETWORK"            # 连不上 / 超时
KIND_SERVER = "SERVER"              # 5xx 重试后仍失败
KIND_AUTH = "AUTH"                  # 401 / 403：登录态失效，需重新登录
KIND_RESTRICTED = "RESTRICTED"      # 11140 + 限制文案：账号级风控
KIND_CHANNEL = "CHANNEL"            # 11-128：渠道指纹被拒
KIND_RATE_LIMIT = "RATE_LIMIT"      # 限流
KIND_SEASON = "SEASON"              # 41000 / active=false：活动未开或已结束
KIND_NOT_CLAIMABLE = "NOT_CLAIMABLE"  # 40901：暂不可领取
KIND_BAD_HOST = "BAD_HOST"          # 非白名单域名（内部防误用）
KIND_BAD_RESPONSE = "BAD_RESPONSE"  # 响应不是预期 JSON

SKIP_ACCOUNT = {KIND_AUTH, KIND_RESTRICTED, KIND_CHANNEL}


class ApiError(Exception):
    def __init__(self, kind: str, detail: str, status: Optional[int] = None,
                 payload: Any = None):
        super().__init__("%s: %s" % (kind, detail))
        self.kind = kind
        self.detail = detail
        self.status = status
        self.payload = payload

    @property
    def skip_account(self) -> bool:
        return self.kind in SKIP_ACCOUNT


@dataclass
class Response:
    status: int
    payload: Any
    text: str

    def json(self) -> Any:
        return self.payload


# ---------- 请求 ----------
def _check_host(url: str) -> None:
    host = urllib.parse.urlsplit(url).hostname or ""
    if host not in config.ALLOWED_HOSTS:
        raise ApiError(
            KIND_BAD_HOST,
            "拒绝访问非白名单域名 %r（允许：%s）"
            % (host, ", ".join(sorted(config.ALLOWED_HOSTS))),
        )


def new_message_id() -> str:
    """官方请求级 ID：32 hex，前 12 位为毫秒时间戳。"""
    return "%012x%s" % (int(time.time() * 1000), uuid.uuid4().hex[:20])


def _open_url(req: urllib.request.Request, timeout: float, proxy_url: str = ""):
    proxy = (proxy_url or "").strip()
    if not proxy:
        return urllib.request.urlopen(req, timeout=timeout)
    parsed = urllib.parse.urlsplit(proxy)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ApiError(KIND_BAD_HOST, "不支持的代理地址：%r（仅支持 http/https）" % proxy)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )
    return opener.open(req, timeout=timeout)


def request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Any = None,
    timeout: float = config.REQUEST_TIMEOUT,
    retries: int = config.MAX_RETRIES,
    gap: float = config.RETRY_GAP,
    proxy_url: str = "",
) -> Response:
    """发请求。仅对「网络错误 / 5xx」重试，4xx 一律不重试。"""
    _check_host(url)
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")

    last: Optional[Exception] = None
    resp: Optional[Response] = None
    for attempt in range(1, max(1, retries) + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with _open_url(req, timeout=timeout, proxy_url=proxy_url) as fp:
                raw = fp.read()
                status = fp.status
            resp = _parse(status, raw)
            if 500 <= status < 600 and attempt < retries:
                last = ApiError(KIND_SERVER, "HTTP %d" % status, status)
                time.sleep(gap * attempt)
                continue
            return resp
        except urllib.error.HTTPError as exc:
            raw = b""
            try:
                raw = exc.read()
            except Exception:
                pass
            parsed = _parse(exc.code, raw)
            if 500 <= exc.code < 600 and attempt < retries:
                last = ApiError(KIND_SERVER, "HTTP %d" % exc.code, exc.code)
                time.sleep(gap * attempt)
                continue
            # 4xx 立即返回，交由上层分类
            return parsed
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
            last = exc
            if attempt < retries:
                time.sleep(gap * attempt)
            continue

    raise ApiError(
        KIND_NETWORK,
        "网络请求失败（已重试 %d 次）：%s" % (retries, _short(last)),
    )


def _short(exc: Any) -> str:
    text = str(exc or "").strip()
    return text[:160] if text else exc.__class__.__name__


def _parse(status: int, raw: bytes) -> Response:
    text = ""
    payload: Any = None
    try:
        text = raw.decode("utf-8", "replace")
        payload = json.loads(text) if text.strip() else {}
    except Exception:
        payload = None
    return Response(status=status, payload=payload, text=text[:4000])


# ---------- 分类 ----------
def _code(payload: Any) -> Any:
    if isinstance(payload, dict):
        c = payload.get("code")
        return c
    return None


def _msg(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("msg", "message", "displayMsg", "displayTips"):
            v = payload.get(key)
            if v:
                return str(v)
    return ""


def code_ok(code: Any) -> bool:
    return code in (0, 200, "0", "200", None)


def classify(resp: Response) -> Tuple[str, str]:
    """返回 (kind, 人类可读说明)。"""
    st = resp.status
    payload = resp.payload
    code = _code(payload)
    msg = _msg(payload)

    blob = json.dumps(payload, ensure_ascii=False).lower() if payload is not None else ""
    if code == "11-128" or "11-128" in blob[:400]:
        return KIND_CHANNEL, "渠道指纹被拒（11-128），非登录失效；建议降低频率"

    if code in (11140, "11140"):
        low = " ".join(
            str(payload.get(k) or "") for k in ("msg", "message", "displayMsg", "displayTips")
        ).lower() if isinstance(payload, dict) else ""
        rate = ("rate limit", "rate-limiting", "too many requests",
                "请求过于频繁", "限流")
        if any(m in low for m in rate):
            return KIND_RATE_LIMIT, "请求过于频繁（11140 限流）"
        restrict = ("account restricted", "account is restricted",
                    "account has been restricted", "restricted account",
                    "account illegal", "unusual activity",
                    "账号受限", "账号被限制", "账号存在异常行为", "账号异常",
                    "账号非法", "账户受限", "账户被限制", "账户存在异常行为",
                    "账户异常", "账户非法", "已被限制使用")
        if any(m in low for m in restrict):
            return KIND_RESTRICTED, "账号受限（11140）：%s" % (msg or "上游限制")
        return KIND_SERVER, "业务码 11140：%s" % (msg or "未明确")

    if st == 401 or code in (401, "401", 40100, "40100"):
        return KIND_AUTH, "登录态失效（401）：需重新登录该账号"
    if st == 403:
        return KIND_AUTH, "禁止访问（403）：登录态或权限异常"
    if st == 429:
        return KIND_RATE_LIMIT, "限流（HTTP 429），稍后重试"
    if code in (41000, "41000"):
        return KIND_SEASON, "活动未开始或已结束（41000）"
    if code in (40901, "40901"):
        return KIND_NOT_CLAIMABLE, "任务暂不可领取（40901）"
    if 500 <= st < 600:
        return KIND_SERVER, "服务端错误 HTTP %s" % st
    if payload is None:
        return KIND_BAD_RESPONSE, "响应非 JSON（HTTP %s）：%s" % (st, resp.text[:120])
    if not (200 <= st < 300):
        return KIND_SERVER, "HTTP %s %s" % (st, msg)
    if not code_ok(code):
        return KIND_SERVER, "业务码 %s：%s" % (code, msg or "未明确")
    return KIND_OK, ""


# ---------- JWT ----------
def jwt_claims(token: str) -> Dict[str, Any]:
    """本地解 JWT payload（不验签，仅用于读 sub / exp / typ）。"""
    try:
        seg = (token or "").split(".")
        if len(seg) != 3:
            return {}
        s = seg[1]
        s += "=" * (4 - len(s) % 4)
        import base64

        data = json.loads(base64.urlsafe_b64decode(s))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def jwt_uid(token: str) -> str:
    return str(jwt_claims(token).get("sub") or "")


def jwt_exp(token: str) -> int:
    try:
        return int(jwt_claims(token).get("exp") or 0)
    except Exception:
        return 0


def jwt_typ(token: str) -> str:
    """Bearer=AT，Offline=RT。用于自动纠正用户粘反的令牌。"""
    return str(jwt_claims(token).get("typ") or "")
