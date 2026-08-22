# SQLark Monitor

面向测试部门的软件与基础设施资产台账。支持应用系统、代码/制品平台、自动化平台、数据库、服务器和其他资产，提供自动健康检查、到期提醒、站内告警、邮件通知、RBAC 和 CSV 导出。

设计参考了 [Snipe-IT](https://github.com/grokability/snipe-it) 的资产台账、负责人和生命周期思路，但采用轻量 Node.js + SQLite 实现，更适合 GitLab、Nexus、OA、数据库与服务器等电子资产。Snipe-IT 为 AGPL-3.0；本项目未复制其源代码。

## 本地运行

```powershell
Copy-Item .env.example .env
npm.cmd install
npm.cmd start
```

访问 <http://localhost:3000>，初始账号 `admin`，密码由 `ADMIN_PASSWORD` 配置（示例为 `Admin@123456`）。首次登录后请在“用户管理”中修改管理员密码；生产环境务必修改 `JWT_SECRET`。

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

## 数据库备份与恢复

管理员可在“备份与恢复”中创建、下载、上传、恢复和删除 SQLite 备份。恢复前会校验数据库完整性、必要数据表、外键和管理员账号，并自动创建恢复前快照；业务数据在单个事务中恢复，失败时整体回滚。自动备份由 `AUTO_BACKUP_ENABLED`、`AUTO_BACKUP_CRON` 和 `BACKUP_RETENTION` 控制，默认每天凌晨2点执行并保留14份自动备份。

健康检查支持 HTTP/HTTPS 和 TCP。密码、Token 等敏感内容不要录入，只填写公司密码库或 Vault 的引用地址。
