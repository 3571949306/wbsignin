"""wbsignin — WorkBuddy / 豆包 / Qoder 多账号自动签到（本地 / 服务器通用，零第三方依赖）。

设计目标：
  1. 凭据加密存储（scrypt + HMAC-CTR + EtM），而非明文 JSON 落盘；
  2. 刷新令牌（RT）单写者串行化，避免多实例并发轮换互相踢下线；
  3. 失败按结构化错误分类输出，便于诊断断签原因；
  4. 内置零依赖 CLI、systemd/cron 定时任务与本地 Web 控制台（127.0.0.1）。
"""

__version__ = "0.2.0"

__all__ = ["__version__"]
