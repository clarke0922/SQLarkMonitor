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

健康检查支持 HTTP/HTTPS 和 TCP。密码、Token 等敏感内容不要录入，只填写公司密码库或 Vault 的引用地址。
