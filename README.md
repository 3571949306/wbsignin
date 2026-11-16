# wbsignin

**WorkBuddy / 豆包（Doubao）/ Qoder（国内版 & 国际版）/ TRAE CN** 多账号每日自动签到与剩余额度查询工具。  
全 Python 标准库编写，**零第三方依赖**，原生支持无图形界面（Headless）的 Linux 云服务器与 Windows 本机部署。

```
$ wbsignin signin
[+] 138****0001       今日已签到（连签 12 天，活动累计 1200）｜剩余积分 1925
[+] 豆包主号          今日已签到｜剩余额度 8754
[+] 138****0002       今日已签到｜剩余Credits 213
[+] user@example.com  今日已签到｜剩余Credits 1274

小结：已签 4
```

---

## 支持平台与能力

| 平台 | 登录/导入方式 | 签到与查询能力 |
|---|---|---|
| **WorkBuddy** | 短信验证码登录（纯 HTTP，无需桌面客户端） | 幂等每日签到、AT/RT 自动滚动刷新、剩余积分包与最早到期时间 |
| **豆包（doubao.com）** | 会话 Cookie 粘贴，或 Windows 本机一键提取（多浏览器 & 多 Profile） | 自动兼容海外服务器 IP 降级策略、查询真实实时剩余额度（套餐 + 活动赠送）与到期时间 |
| **Qoder 国内版**（`qoder-cn`） | PAT（`pt-...`）/ 客户端凭据提取（含设备风控标识） | 每日北京时间 10:00 轮次自动领取 100 Credits、剩余 Credits 与到期时间 |
| **Qoder 国际版**（`qoder`） | 同上（支持 `openapi.qoder.sh` 与 `openapi.qoder.com.cn` 并存） | 同上 |
| **TRAE CN**（`trae-cn`） | 客户端凭据提取（含 P-256 设备签名密钥，零依赖解密） | 每日积分自动签到、总余额/有效期包明细，临期自动通过 P-256 DeviceProof 续期 |

## 工程设计亮点

| 问题 | 常见脚本做法 | 本项目实现 |
|---|---|---|
| 凭据落盘安全性 | 明文 JSON | `scrypt` 派生密钥 + `HMAC-SHA256` 计数器流加密 + Encrypt-then-MAC（文件权限 `0600`） |
| 多实例刷新 Token 互踢 | 无锁并发覆盖，静默失效 | 独立锁文件（`flock` / `msvcrt`）串行化「读 RT → 刷新 → 写回」；每成功一个立即原子落盘 |
| 失败诊断 | 只抛通用报错 | 结构化错误分类（`AUTH` / `RESTRICTED` / `CHANNEL` / `RATE_LIMIT` / `SEASON` / `NOT_CLAIMABLE`） |
| 凭据转发风险 | 不校验目标域名 | 域名白名单 `ALLOWED_HOSTS` + 强制 TLS 证书校验（无跳过开关） |
| 多端管理体验 | 仅命令行 | 内置暗色 Web 控制台（仅监听 `127.0.0.1`，通过 SSH 隧道访问，带 CSRF 防护） |

---

## 一键安装

只需 **Python 3.8+**，无需 `pip install` 任何第三方依赖。

### Linux / macOS 服务器一键部署

```bash
# 安装代码、创建加密凭据环境、注册 wbsignin 命令与每天 08:17 / 10:17 systemd 定时器
curl -fsSL https://raw.githubusercontent.com/3571949306/wbsignin/main/install.sh | bash
```

可选同时启用 **Web 控制台常驻服务**（推荐，只监听 `127.0.0.1:8787`）：

```bash
curl -fsSL https://raw.githubusercontent.com/3571949306/wbsignin/main/install.sh | bash -s -- --with-web
```

<details>
<summary>无交互部署 / 本地克隆安装 / 自定义参数</summary>

```bash
# 方式 1：预先传入主密码（适合自动化脚本）
WBSIGNIN_PASSPHRASE='your-strong-passphrase' \
  curl -fsSL https://raw.githubusercontent.com/3571949306/wbsignin/main/install.sh | bash -s -- --with-web

# 方式 2：克隆仓库后本地安装
git clone https://github.com/3571949306/wbsignin.git && cd wbsignin
bash install.sh --with-web

# 查看全部安装选项
bash install.sh --help
```

</details>

### Windows 一键安装

在 PowerShell 中执行：

```powershell
irm https://raw.githubusercontent.com/3571949306/wbsignin/main/install.ps1 | iex
```

如需同时注册 Windows 每日定时任务（08:17 & 10:17）：

```powershell
git clone https://github.com/3571949306/wbsignin.git
cd wbsignin
.\install.ps1 -InstallTask
```

### Python 包方式安装（可选）

```bash
pip install git+https://github.com/3571949306/wbsignin.git
```

---

## 添加账号与使用

### 1. 添加 WorkBuddy 账号（短信登录）

```bash
wbsignin login
```

按提示输入手机号并接收短信验证码。多次执行可添加多个账号，不会覆盖前一个。

### 2. 添加豆包账号（支持多账号自动识别）

在服务器终端手动粘贴 Cookie：

```bash
wbsignin login-doubao
```

**Windows 本机一键提取并推送（推荐）**：  
使用零依赖脚本 [pull_doubao_cookie.py](tools/pull_doubao_cookie.py)，会自动扫描本机豆包客户端全部 Profile（`Default`、`Profile *`）以及 Chrome / Edge / Brave 中的会话 Cookie，并按 `uid_tt` 自动去重：

```powershell
# 预览本机发现的全部豆包账号
python tools/pull_doubao_cookie.py

# 直接导入到本机 wbsignin
python tools/pull_doubao_cookie.py --local

# 一键推送到远端 Linux 服务器（按 uid_tt 去重更新）
python tools/pull_doubao_cookie.py --push --host <your-server>
```

> 说明：
> - 仅豆包个人账号拥有 `daily_signin` 每日签到任务；工作版 / 飞书企业账号在 `/v3/detail/` 返回的 `tasks` 中无此任务。
> - 客户端参数已对齐豆包电脑版桌面端请求特征（`aid=582478`、`runtime_version=3.44.9`、`doubao_device_platform=desktop` 与确定性 `device_id` / `web_id` / `fp`）；当系统处于正在运行的 `Default\Network\Cookies` 被锁定时，关闭豆包桌面端后即可读取该配置档。
> - 若服务器位于海外，`/v3/detail/` 会返回 `code=2` 地域限制，程序将结合 `/quota/records/`、`/landing/checkin` 与 `/subscription/overview/` 保留余额、到期时间及最近签到记录；如上游 `/landing/checkin` 返回 `710010702` 系统错误，将明确报告为活动故障并继续保留真实余额，也可通过环境变量 `WBSIGNIN_DOUBAO_PROXY=http://127.0.0.1:PORT`（支持 `http`/`https` 代理）经国内出口代理访问豆包接口。

### 3. 添加 Qoder 账号（国内版 & 国际版）

支持粘贴 `pt-...` 个人访问令牌（PAT）或客户端完整凭据：

```bash
wbsignin login-qoder --region cn     # 国内版
wbsignin login-qoder --region intl   # 国际版
```

**Windows 本机一键提取客户端凭据与设备指纹并推送**：  
使用 [pull_qoder_cred.py](tools/pull_qoder_cred.py)（同时读取 `umid/runtime-info.exe` 生成设备风控头）：

```powershell
# 预览本机已登录的 Qoder 国内版 / 国际版凭据
python tools/pull_qoder_cred.py

# 直接导入本机 wbsignin
python tools/pull_qoder_cred.py --local

# 一键推送到远端 Linux 服务器
python tools/pull_qoder_cred.py --push --host <your-server>
```

### 4. 添加 TRAE CN 账号（trae.cn）

支持从命令行导入或使用 [pull_trae_cred.py](tools/pull_trae_cred.py) 直接解密本机 TRAE CN 桌面端凭据与 P-256 设备密钥：

```powershell
# 预览本机已登录的 TRAE CN 凭据（全脱敏）
python tools/pull_trae_cred.py

# 直接导入到本机 wbsignin
python tools/pull_trae_cred.py --local

# 一键推送到远端 Linux 服务器（含自动续期所需的 P-256 设备私钥）
python tools/pull_trae_cred.py --push --host <your-server>
```

---

## 日常命令

```bash
wbsignin accounts              # 列出已保存账号、类型、到期日及状态
wbsignin status                # 同上 + 凭据库文件锁占用情况
wbsignin signin                # 执行全部账号签到与余额快照刷新
wbsignin signin --jobs 1       # 串行执行，进一步降低占用
wbsignin signin --quiet        # 精简输出，适合定时任务日志
wbsignin credit                # 查询各账号详细剩余积分 / 额度 / Credits 明细与到期日
wbsignin doctor                # 环境、凭据库解密与 7 个上游域名 HTTPS 连通性自检（全脱敏）
```

---

## Web 仪表盘（可选）

仅监听 **`127.0.0.1`**，公网不可直接访问；支持查看账号状态、剩余额度与悬停明细、触发立即签到、添加 WorkBuddy / 豆包 / Qoder / TRAE CN 账号、查看实时日志：

```bash
# 1. 手动启动（或安装时加 --with-web 自动常驻）
wbsignin web --port 8787

# 2. 若部署在云服务器上，在本地建立 SSH 端口转发隧道
ssh -L 8787:127.0.0.1:8787 <your-server>
```

随后在本地浏览器访问：`http://127.0.0.1:8787`。

---

## 定时任务与调度说明

默认 `OnCalendar=*-*-* 08,10:17:00`（北京时间 08:17 与 10:17 各执行一次，带 `<=300s` 随机延迟并启用 `Persistent=true`）：
- **08:17** 覆盖 WorkBuddy 与豆包的每日首轮签到；
- **10:17** 覆盖 Qoder（北京时间 10:00 刷新活动轮次）当轮领取，兼作前轮补偿（所有平台均为幂等接口，重复跑只记录 `今日已签到`）。

管理定时任务：

```bash
wbsignin schedule --with-web               # 重新生成并启用定时器 + Web 服务
systemctl --user list-timers | grep wbsignin
sudo loginctl enable-linger "$USER"        # 注销 SSH 后保持用户级服务持续运行
```

---

## 安全说明

1. **本地加密边界**：凭据库采用 `scrypt` + `HMAC-SHA256` Encrypt-then-MAC 加密保存（`~/.wbsignin/vault.json`，权限 `0600`），防止备份、网盘误同步、镜像快照等场景泄露明文；无法对抗已经获得同用户 shell / `root` 权限的本地攻击者。
2. **主密码与 Env 文件**：自动运行所需的主密码保存在 `~/.wbsignin/vault.env`（`0600`），切勿提交到仓库或公开分享。
3. **Refresh Token 竞争**：本机通过文件锁串行化刷新；避免同一 WorkBuddy 账号在多个无关客户端高频竞争刷新 RT。
4. **脱敏约定**：`doctor`、`accounts` 及仓库中的测试/工具默认不打印敏感凭据与私人主机名；提交 PR 前请确认没有带入任何真实手机号、邮箱、Cookie、Token 或服务器地址。

---

## 目录结构

```text
wbsignin/
  install.sh               Linux / macOS 一键安装脚本
  install.ps1              Windows 一键安装脚本
  deploy.sh                兼容旧脚本的部署入口（转发至 install.sh）
  pyproject.toml           Python 包元数据与 CLI 入口
  wbsignin/
    config.py              接口端点、白名单域名与北京时间时区配置
    vault.py               加密凭据库（scrypt + HMAC-CTR + EtM）
    lock.py                单写者文件锁（flock / msvcrt）
    httpc.py               标准库 HTTP 客户端、白名单校验、错误分类与 JWT 解析
    auth.py                WorkBuddy 短信登录、令牌刷新与统一 Account 模型
    tasks.py               WorkBuddy 签到与积分/到期解析
    doubao.py              豆包签到、海外 IP 降级策略与实时剩余额度查询
    qoder.py               Qoder 国内版 / 国际版 PAT 兑换、签到与配额查询
    trae.py                TRAE CN 签到、积分包查询与纯标准库 P-256 续期
    runner.py              多账号并发编排、凭据去重与状态快照持久化
    schedule.py            systemd timer / web service 与 cron 生成
    web.py                 仅限本机的零依赖 HTTP API 与控制台后端
    static/index.html      Web 控制台前端页面
    cli.py                 命令行主入口
  tools/
    _win_crypto.py         Windows DPAPI + CNG AES-GCM / AES-CBC 解密（零依赖）
    _remote_push.py        通用 SSH 安全推送与本机导入辅助
    pull_doubao_cookie.py  Windows 豆包多 Profile Cookie 提取工具
    pull_qoder_cred.py     Windows Qoder / Qoder CN 凭据与设备指纹提取工具
    pull_trae_cred.py      Windows TRAE CN 凭据与 P-256 设备密钥提取工具
  tests/
    test_core.py           加解密、锁竞争、HTTP 白名单与错误分类单测
    test_doubao.py         豆包 Cookie、海外回退、实时额度与去重单测
    test_qoder.py          Qoder 协议、轮次边界、配额与 Web 集成单测
    test_trae.py           TRAE CN 协议、P-256 签名、续期与集成单测
```

## 单元测试

```bash
python3 -m unittest discover -s tests -v
```

51 项离线单元测试全部不触网即可验证核心加解密、互斥锁、错误分类、豆包、Qoder 与 TRAE CN 协议兼容逻辑。

## 协议致谢与声明

- 接口协议契约仅作学习与互操作研究整理，代码由本项目独立实现，部分 WorkBuddy / 豆包协议参考了公开 MIT 实现（详见 `LICENSE`）。
- 本项目与腾讯 WorkBuddy / CodeBuddy、字节跳动豆包、TRAE、Qoder 官方无任何从属或关联关系；使用前请自行遵守相关服务条款。

## License

MIT — 见 [LICENSE](LICENSE)。
