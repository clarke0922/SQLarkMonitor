# SQLark Monitor

[English](README.md) | 简体中文

面向测试部门的软件与基础设施资产台账。支持应用系统、代码/制品平台、自动化平台、数据库、服务器和其他资产，提供自动健康检查、到期提醒、站内告警、邮件与飞书通知、RBAC 和 CSV 导出。

设计参考了 [Snipe-IT](https://github.com/grokability/snipe-it) 的资产台账、负责人和生命周期思路，但采用轻量 Node.js + SQLite 实现，更适合 GitLab、Nexus、OA、数据库与服务器等电子资产。Snipe-IT 为 AGPL-3.0；本项目未复制其源代码。

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

### 飞书告警

在飞书群中添加“自定义机器人”，复制 Webhook；建议开启签名校验，然后配置：

```env
FEISHU_WEBHOOK_URL=https://open.feishu.cn/open-apis/bot/v2/hook/请替换
FEISHU_WEBHOOK_SECRET=请替换为签名密钥
```

也可以由管理员进入“飞书配置”菜单维护 Webhook、签名密钥并发送测试消息，保存后立即生效，无需重启。管理后台配置优先于 `.env`；点击“恢复 .env 默认值”可清除后台覆盖。Webhook Token 和签名密钥不会回显，并使用由 `JWT_SECRET` 派生的密钥加密保存。

新产生的资产离线、证书到期和维护/许可到期告警会推送到飞书。同一资产同一类型的未解决告警不会重复发送。

## Docker

```bash
cp .env.example .env
docker compose up -d --build
```

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
