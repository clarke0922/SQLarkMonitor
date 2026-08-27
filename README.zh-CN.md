# SQLark Monitor

[English](README.md) | 简体中文

面向测试部门的软件与基础设施资产台账。支持应用系统、代码/制品平台、自动化平台、数据库、服务器和其他资产，提供自动健康检查、到期提醒、站内告警、邮件与飞书通知、RBAC 和 CSV 导出。

设计参考了 [Snipe-IT](https://github.com/grokability/snipe-it) 的资产台账、负责人和生命周期思路，但采用轻量 Node.js + SQLite 实现，更适合 GitLab、Nexus、OA、数据库与服务器等电子资产。Snipe-IT 为 AGPL-3.0；本项目未复制其源代码。

## 语言

界面默认使用英语。首次加载时会读取浏览器/系统语言；检测到 `zh` 语言环境时自动切换为简体中文，其他语言和未知语言均回退到英语。用户填写的资产数据和可编辑门户内容不会被翻译。

## 本地运行

```powershell
Copy-Item .env.example .env
npm.cmd install
npm.cmd start
```

访问 <http://localhost:3000>，初始账号 `admin`，密码由 `ADMIN_PASSWORD` 配置（示例为 `Admin@123456`）。首次登录后请在“用户管理”中修改管理员密码；生产环境务必修改 `JWT_SECRET`。

## `.env` 配置与维护

首次运行先从模板创建本地配置：

```powershell
Copy-Item .env.example .env
```

| 配置项 | 用途 | 维护建议 |
|---|---|---|
| `PORT` | Web 服务端口 | 默认 `3000` |
| `DATA_DIR` | SQLite、备份等数据目录 | 生产环境使用持久化磁盘并定期备份 |
| `JWT_SECRET` | 登录令牌签名密钥 | 生产环境改为随机长字符串，泄露后立即轮换 |
| `ADMIN_PASSWORD` | 首次初始化管理员密码 | 首次登录后在用户管理中修改 |
| `CHECK_INTERVAL_MINUTES` | 自动巡检间隔（分钟） | 根据资产数量调整 |
| `CHECK_TIMEOUT_MS` | 单次巡检超时（毫秒） | 默认 `5000` |
| `FAILURE_THRESHOLD` | 连续失败多少次后标记离线 | 默认 `3` |
| `LOGIN_MAX_ATTEMPTS` | 账号锁定前允许的连续失败次数 | 默认 `5` |
| `ACCOUNT_LOCK_MINUTES` | 账号锁定时间（分钟） | 默认 `15` |
| `LOGIN_RATE_LIMIT` | 同一 IP 每15分钟登录次数上限 | 默认 `20` |
| `AUTO_BACKUP_ENABLED` | 是否启用自动备份 | `true` 或 `false` |
| `AUTO_BACKUP_CRON` | 自动备份 Cron 表达式 | 默认每天凌晨2点 |
| `BACKUP_RETENTION` | 自动备份保留份数 | 默认 `14` |
| `DB_CHECK_PROFILES_JSON` | 数据库专项检查账号配置 | 使用单行合法 JSON，资产只保存 `profile://配置名` |
| `SMTP_*`、`ALERT_RECIPIENTS` | 邮件告警配置 | 未配置时不发送邮件 |
| `FEISHU_WEBHOOK_URL` | 飞书群自定义机器人 Webhook | 未配置时不发送飞书告警 |
| `FEISHU_WEBHOOK_SECRET` | 飞书机器人签名密钥 | 建议在机器人安全设置中启用签名校验 |

数据库检查配置完整示例：

```env
DB_CHECK_PROFILES_JSON={"mysql_qa":{"username":"sqlark_monitor","password":"实际密码"},"postgres_qa":{"username":"sqlark_monitor","password":"实际密码"},"sqlserver_qa":{"username":"sqlark_monitor","password":"实际密码"},"oracle_qa":{"username":"sqlark_monitor","password":"实际密码"}}
```

新增资产时分别引用 `profile://mysql_qa`、`profile://postgres_qa`、`profile://sqlserver_qa` 或 `profile://oracle_qa`。修改 `.env` 后必须重启服务才能生效。

维护规则：

- `.env` 包含密码和密钥，禁止提交到 Git；仓库只维护不含真实凭据的 `.env.example`。
- 数据库巡检账号只授予登录和版本查询所需的最小权限，不使用管理员或业务账号。
- 人员离职、密码泄露或密钥到期时，更新 `.env` 中对应配置并重启服务；资产中的 `profile://` 引用通常无需修改。
- 新增配置项时同步更新 `.env.example` 和本章节，但示例值不得包含真实地址、账号、密码或 Token。

### 密码库

管理员可以在“密码库”菜单中新增数据库巡检凭据，无需重启服务。每条配置包含配置名、用户名、密码和说明，资产使用 `profile://配置名` 引用。密码使用由 `JWT_SECRET` 派生的密钥进行 AES-256-GCM 加密，保存后 API 和页面均不会回显。必须保持并安全备份 `JWT_SECRET`；更换该值会导致已保存的凭据无法解密。

管理后台中的同名凭据优先于 `DB_CHECK_PROFILES_JSON`，`.env` 保留为默认值和应急配置。仍被资产引用的凭据不能删除；凭据变更和删除会写入审计日志，并包含在新创建的 SQLite 备份中。

### 飞书告警

在飞书群中添加“自定义机器人”，复制 Webhook；建议开启签名校验，然后配置：

```env
FEISHU_WEBHOOK_URL=https://open.feishu.cn/open-apis/bot/v2/hook/请替换
FEISHU_WEBHOOK_SECRET=请替换为签名密钥
```

也可以由管理员进入“飞书配置”菜单维护 Webhook、签名密钥并发送测试消息，保存后立即生效，无需重启。管理后台配置优先于 `.env`；点击“恢复 .env 默认值”可清除后台覆盖。Webhook Token 和签名密钥不会回显，并使用由 `JWT_SECRET` 派生的密钥加密保存。

新产生的资产离线、证书到期和维护/许可到期告警会推送到飞书。同一资产同一类型的未解决告警不会重复发送。

## 部署方式

应用要求 Node.js 20 或更高版本。无论使用哪种部署方式，都应先从 `.env.example` 创建 `.env`，替换 `JWT_SECRET` 和 `ADMIN_PASSWORD`，将 `data` 目录放在持久化存储中，并且只向可信网络或 HTTPS 反向代理开放 3000 端口。

### Windows

在项目目录中通过 PowerShell 运行：

```powershell
Copy-Item .env.example .env
npm.cmd ci --omit=dev
npm.cmd start
```

如需开机自动运行且不保留终端窗口，请在管理员 PowerShell 中注册计划任务：

```powershell
$project = (Get-Location).Path
$npm = (Get-Command npm.cmd).Source
$action = New-ScheduledTaskAction -Execute $npm -Argument 'start' -WorkingDirectory $project
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName SQLarkMonitor -Action $action -Trigger $trigger -User SYSTEM -RunLevel Highest
Start-ScheduledTask -TaskName SQLarkMonitor
```

使用 `Get-ScheduledTask -TaskName SQLarkMonitor` 查看状态，通过 `Stop-ScheduledTask` 和 `Start-ScheduledTask` 停止或启动。升级代码后运行 `npm.cmd ci --omit=dev` 并重启任务。请安全备份 `.env`，并复制完整的 `data` 目录，包括其中的 `backups` 子目录。

### Linux（systemd）

将项目放到 `/opt/sqlark-monitor`，然后安装生产依赖：

```bash
cd /opt/sqlark-monitor
cp .env.example .env
npm ci --omit=dev
sudo useradd --system --home /opt/sqlark-monitor --shell /usr/sbin/nologin sqlark 2>/dev/null || true
sudo chown -R sqlark:sqlark /opt/sqlark-monitor
```

创建 `/etc/systemd/system/sqlark-monitor.service`：

```ini
[Unit]
Description=SQLark Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sqlark
WorkingDirectory=/opt/sqlark-monitor
EnvironmentFile=/opt/sqlark-monitor/.env
ExecStart=/usr/bin/npm start
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

使用 `command -v npm` 确认 npm 路径，必要时调整 `ExecStart`，然后启用服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sqlark-monitor
sudo systemctl status sqlark-monitor
sudo journalctl -u sqlark-monitor -f
```

升级时先停止服务，更新代码并运行 `npm ci --omit=dev`，然后重新启动。需要持久化并备份 `/opt/sqlark-monitor/data`，同时通过 `chmod 600` 等方式限制 `/opt/sqlark-monitor/.env` 的访问权限。

### Docker Compose

仓库中的 Compose 文件会构建镜像、映射 3000 端口、加载 `.env`、自动重启容器，并将 SQLite 数据持久化到 `./data`：

```bash
cp .env.example .env
docker compose up -d --build
docker compose ps
docker compose logs -f sqlark-monitor
```

使用 `docker compose up -d --build` 升级并重启，使用 `docker compose down` 停止。除非确定需要删除持久化数据，否则不要添加 `--volumes`。请安全备份 `.env` 和宿主机上的 `data` 目录。

## CSV / Excel 批量导入

在“资产台账”点击“下载导入模板”，填写后通过“批量导入”上传 `.csv` 或 `.xlsx` 文件。系统会先预览并校验全部行；只有整批数据都通过校验后才会以事务方式写入，单次最多1000条、文件最大5MB。

## 自动化测试

```powershell
npm.cmd test
```

测试会启动随机本地端口并使用独立临时 SQLite 数据库，不会修改正式数据。GitHub Actions 会在推送到 `main` 或创建 Pull Request 时自动运行全部测试。

## 登录安全

登录使用一次性图形验证码；同一账号连续失败达到 `LOGIN_MAX_ATTEMPTS` 后会锁定 `ACCOUNT_LOCK_MINUTES` 分钟，同一 IP 每15分钟最多尝试 `LOGIN_RATE_LIMIT` 次。管理员可以在“用户管理”查看失败次数并手工解锁账号。

用户密码必须为8–128位，并包含大写字母、小写字母、数字和特殊字符。

## 数据库备份与恢复

管理员可在“备份与恢复”中创建、下载、上传、恢复和删除 SQLite 备份。恢复前会校验数据库完整性、必要数据表、外键和管理员账号，并自动创建恢复前快照；业务数据在单个事务中恢复，失败时整体回滚。自动备份由 `AUTO_BACKUP_ENABLED`、`AUTO_BACKUP_CRON` 和 `BACKUP_RETENTION` 控制，默认每天凌晨2点执行并保留14份自动备份。

健康检查支持 HTTP/HTTPS、TCP，以及 MySQL、PostgreSQL、SQL Server、Oracle 的真实登录与版本查询。数据库资产只保存 `profile://配置名`，账号密码通过 `.env` 提供，不写入 SQLite。MySQL、PostgreSQL、SQL Server、Oracle 默认端口分别为 3306、5432、1433、1521；Oracle 的“数据库名/服务名”填写 Service Name。配置方法见上方的 `.env` 配置与维护章节。

## 支持项目

如果 SQLark Monitor 对你的团队有所帮助，欢迎通过微信自愿打赏，支持项目持续维护和改进。感谢每一份支持，也感谢你的使用与反馈。

<img src="assets/wechat-donate.jpg" alt="微信打赏二维码" width="320">
