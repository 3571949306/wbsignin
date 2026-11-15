"""登录与令牌刷新。

登录走官方插件接口，服务端直接下发明文 JWT，因此**不需要桌面客户端**。
这是本工具能跑在无 GUI 服务器上的根本原因（读取客户端凭据那条路走不通：
新版客户端把凭据改为 AES-256-GCM 信封，解密密钥只驻留客户端进程内存）。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from . import config, httpc


# ---------- 请求头 ----------
def _base_headers(referer_path: str = "/") -> Dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Origin": config.BASE,
        "Referer": config.BASE + referer_path,
        "User-Agent": config.USER_AGENT,
    }


def api_headers(access_token: str, uid: str = "") -> Dict[str, str]:
    h = _base_headers("/profile/growth-center")
    h["Authorization"] = "Bearer " + access_token
    real_uid = uid or httpc.jwt_uid(access_token)
    if real_uid:
        h["X-User-Id"] = real_uid
    return h


# ---------- 登录 ----------
def send_sms(phone: str) -> Dict[str, Any]:
    """发送短信验证码。失败时抛出 ApiError。"""
    resp = httpc.request(
        "POST", config.SEND_SMS_URL, headers=_base_headers("/"),
        body={"phone": phone}, retries=1,
    )
    kind, detail = httpc.classify(resp)
    if kind != httpc.KIND_OK:
        raise httpc.ApiError(kind, detail, resp.status, resp.payload)
    if not httpc.code_ok(httpc._code(resp.payload)):
        raise httpc.ApiError(
            httpc.KIND_SERVER,
            "验证码发送失败：%s" % (httpc._msg(resp.payload) or "未知原因"),
            resp.status, resp.payload,
        )
    data = (resp.payload or {}).get("data") or {}
    return {"expires_in": int(data.get("expires_in") or 300)}


def login(phone: str, sms_code: str) -> Dict[str, Any]:
    """手机号 + 验证码登录，返回 {access_token, refresh_token, uid, exp}。"""
    resp = httpc.request(
        "POST", config.LOGIN_URL, headers=_base_headers("/"),
        body={"login_method": "phone", "phone": phone, "sms_code": sms_code},
        retries=1,
    )
    kind, detail = httpc.classify(resp)
    if kind != httpc.KIND_OK:
        raise httpc.ApiError(kind, detail, resp.status, resp.payload)
    payload = resp.payload or {}
    if not httpc.code_ok(payload.get("code")):
        raise httpc.ApiError(
            httpc.KIND_SERVER,
            "登录失败：%s（验证码可能已过期或输入有误）"
            % (httpc._msg(payload) or "未知原因"),
            resp.status, payload,
        )
    data = payload.get("data") or {}
    at = data.get("accessToken") or data.get("access_token") or ""
    rt = data.get("refreshToken") or data.get("refresh_token") or ""
    if not at or not rt:
        raise httpc.ApiError(
            httpc.KIND_BAD_RESPONSE,
            "登录响应缺少 accessToken / refreshToken",
            resp.status, payload,
        )
    _sanity(at, rt, phone)
    return {
        "access_token": at,
        "refresh_token": rt,
        "uid": httpc.jwt_uid(at),
        "at_exp": httpc.jwt_exp(at),
    }


def _sanity(at: str, rt: str, phone: str) -> None:
    """粘错位置是最常见的失败原因，这里直接给出准确诊断而不是让上游报错。"""
    if httpc.jwt_typ(at) == "Offline" or httpc.jwt_typ(rt) == "Bearer":
        raise httpc.ApiError(
            httpc.KIND_BAD_RESPONSE,
            "AT / RT 顺序反了（AT 应为 typ=Bearer，RT 应为 typ=Offline）",
        )
    if phone and not httpc.jwt_uid(at):
        raise httpc.ApiError(httpc.KIND_BAD_RESPONSE, "AT 中缺少 sub，凭据不可用")


# ---------- 刷新 ----------
def refresh(refresh_token: str, access_token: str = "") -> Dict[str, Any]:
    """用 RT 换新 AT。返回 {access_token, refresh_token, uid, at_exp}。

    注意：服务端会轮换 RT，调用方**必须**把返回的新 RT 立即持久化，
    否则旧 RT 作废后无法再续期。本函数不负责加锁，锁由调用层（runner）持有。
    """
    headers = {
        "X-Refresh-Token": refresh_token,
        "X-Auth-Refresh-Source": "plugin",
        "Content-Type": "application/json",
        "X-Request-ID": httpc.new_message_id(),
        "X-Domain": config.REFRESH_DOMAIN,
    }
    if access_token:
        headers["Authorization"] = "Bearer " + access_token
        uid = httpc.jwt_uid(access_token)
        if uid:
            headers["X-User-Id"] = uid

    resp = httpc.request(
        "POST", config.REFRESH_URL, headers=headers, body={}, retries=2
    )
    kind, detail = httpc.classify(resp)
    if kind != httpc.KIND_OK:
        raise httpc.ApiError(kind, detail, resp.status, resp.payload)
    payload = resp.payload or {}
    if not httpc.code_ok(payload.get("code")):
        raise httpc.ApiError(
            httpc.KIND_AUTH,
            "续期失败：%s（RT 可能已被其他工具轮换或已过期）"
            % (httpc._msg(payload) or "未知原因"),
            resp.status, payload,
        )
    data = payload.get("data") or {}
    new_at = data.get("accessToken") or ""
    new_rt = data.get("refreshToken") or refresh_token
    if not new_at:
        raise httpc.ApiError(
            httpc.KIND_BAD_RESPONSE, "续期响应缺少 accessToken", resp.status, payload
        )
    return {
        "access_token": new_at,
        "refresh_token": new_rt,
        "uid": httpc.jwt_uid(new_at),
        "at_exp": httpc.jwt_exp(new_at),
    }


def needs_refresh(at: str, threshold_seconds: int = 24 * 3600) -> bool:
    """AT 缺失、无法解析 exp、或即将过期 → 需要续期。

    阈值取 24 小时：给定时任务留出足够的容错窗口（某天任务失败，
    第二天仍在有效期内，不会因为差几小时而断签）。
    """
    if not at:
        return True
    exp = httpc.jwt_exp(at)
    if not exp:
        return True
    return exp - int(time.time()) <= threshold_seconds


@dataclass
class Account:
    phone: str  # 唯一键：WorkBuddy 用手机号，豆包用「doubao:<seed>」，Qoder 用「qoder:<uid>」或「qoder-cn:<uid>」
    provider: str = "workbuddy"  # "workbuddy" | "doubao" | "qoder" | "qoder-cn"
    access_token: str = ""
    refresh_token: str = ""
    cookie: str = ""   # 豆包专用：doubao.com 会话 Cookie
    uid: str = ""      # WorkBuddy：JWT sub；豆包：设备指纹 seed；Qoder：userId
    at_exp: int = 0
    updated: str = ""
    last_error: str = ""
    label: str = ""    # 展示名（豆包 / Qoder 用）
    device: Dict[str, Any] = field(default_factory=dict)  # Qoder 设备风控标识（Cosy-*）

    @classmethod
    def from_dict(cls, phone: str, d: Dict[str, Any]) -> "Account":
        dev = d.get("device")
        return cls(
            phone=phone,
            provider=str(d.get("provider") or "workbuddy"),
            access_token=str(d.get("access_token") or ""),
            refresh_token=str(d.get("refresh_token") or ""),
            cookie=str(d.get("cookie") or ""),
            uid=str(d.get("uid") or ""),
            at_exp=int(d.get("at_exp") or 0),
            updated=str(d.get("updated") or ""),
            last_error=str(d.get("last_error") or ""),
            label=str(d.get("label") or ""),
            device=dict(dev) if isinstance(dev, dict) else {},
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "provider": self.provider,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "cookie": self.cookie,
            "uid": self.uid,
            "at_exp": self.at_exp,
            "updated": self.updated,
            "last_error": self.last_error,
            "label": self.label,
        }
        if self.device:
            out["device"] = self.device
        return out

    @property
    def is_doubao(self) -> bool:
        return self.provider == "doubao"

    @property
    def is_qoder(self) -> bool:
        return self.provider in ("qoder", "qoder-cn")

    @property
    def is_workbuddy(self) -> bool:
        return self.provider == "workbuddy"

    def masked(self) -> str:
        if self.label:
            return self.label
        if self.is_doubao:
            return "豆包"
        if self.is_qoder:
            return "Qoder国内" if self.provider == "qoder-cn" else "Qoder国际"
        p = self.phone or ""
        return p[:3] + "****" + p[-4:] if len(p) >= 8 else p
