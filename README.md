# SQLark Monitor

English | [简体中文](README.zh-CN.md)

An asset inventory and health monitoring platform for QA departments. It manages applications, source and artifact platforms, automation systems, databases, servers, and other digital assets, with automated health checks, expiration reminders, in-app alerts, email and Feishu notifications, RBAC, and CSV export.

The design borrows asset ownership and lifecycle concepts from [Snipe-IT](https://github.com/grokability/snipe-it), while using a lightweight Node.js and SQLite implementation suited to GitLab, Nexus, OA systems, databases, and servers. Snipe-IT is licensed under AGPL-3.0; this project does not copy its source code.

## Local setup

```powershell
Copy-Item .env.example .env
npm.cmd install
npm.cmd start
```

Open <http://localhost:3000>. The initial username is `admin`; its password is configured through `ADMIN_PASSWORD` (the example value is `Admin@123456`). Change the administrator password in User Management after the first login, and always replace `JWT_SECRET` in production.

## `.env` configuration and maintenance

Create the local configuration from the template before the first run:

```powershell
Copy-Item .env.example .env
```

| Variable | Purpose | Maintenance guidance |
|---|---|---|
| `PORT` | Web service port | Defaults to `3000` |
| `DATA_DIR` | Directory for SQLite data and backups | Use persistent storage and back it up regularly in production |
| `JWT_SECRET` | Login token signing secret | Use a long random value in production and rotate it after exposure |
| `ADMIN_PASSWORD` | Initial administrator password | Change it in User Management after the first login |
| `CHECK_INTERVAL_MINUTES` | Automatic check interval in minutes | Tune it for the number of assets |
| `CHECK_TIMEOUT_MS` | Timeout for one check in milliseconds | Defaults to `5000` |
| `FAILURE_THRESHOLD` | Consecutive failures before an asset is marked offline | Defaults to `3` |
| `LOGIN_MAX_ATTEMPTS` | Consecutive login failures before account lockout | Defaults to `5` |
| `ACCOUNT_LOCK_MINUTES` | Account lock duration in minutes | Defaults to `15` |
| `LOGIN_RATE_LIMIT` | Login attempts per IP in a 15-minute window | Defaults to `20` |
| `AUTO_BACKUP_ENABLED` | Enables automatic backups | `true` or `false` |
| `AUTO_BACKUP_CRON` | Automatic backup cron expression | Defaults to 2:00 AM every day |
| `BACKUP_RETENTION` | Number of automatic backups to retain | Defaults to `14` |
| `DB_CHECK_PROFILES_JSON` | Credentials for database-specific checks | Use valid single-line JSON; assets store only `profile://name` |
| `SMTP_*`, `ALERT_RECIPIENTS` | Email alert settings | Email is disabled when unset |
| `FEISHU_WEBHOOK_URL` | Feishu custom bot webhook | Feishu alerts are disabled when unset |
| `FEISHU_WEBHOOK_SECRET` | Feishu bot signing secret | Enabling signature verification is recommended |

Complete database profile example:

```env
DB_CHECK_PROFILES_JSON={"mysql_qa":{"username":"sqlark_monitor","password":"replace-me"},"postgres_qa":{"username":"sqlark_monitor","password":"replace-me"},"sqlserver_qa":{"username":"sqlark_monitor","password":"replace-me"},"oracle_qa":{"username":"sqlark_monitor","password":"replace-me"}}
```

Reference these profiles from assets as `profile://mysql_qa`, `profile://postgres_qa`, `profile://sqlserver_qa`, or `profile://oracle_qa`. Restart the service after changing `.env`.

Maintenance rules:

- `.env` contains passwords and secrets. Never commit it; only maintain `.env.example` with non-sensitive placeholders.
- Grant database monitoring accounts only the minimum permissions required to log in and query version information. Do not use administrator or application accounts.
- When staff leave, credentials leak, or secrets expire, update the matching `.env` profile and restart the service. The asset's `profile://` reference usually does not need to change.
- When adding a variable, update both `.env.example` and this section without including real addresses, usernames, passwords, or tokens.

### Feishu alerts

Add a custom bot to a Feishu group, copy its webhook, enable signature verification if possible, and configure:

```env
FEISHU_WEBHOOK_URL=https://open.feishu.cn/open-apis/bot/v2/hook/replace-me
FEISHU_WEBHOOK_SECRET=replace-with-signing-secret
```

Administrators can also manage the webhook and signing secret and send a test message from the Feishu Settings page. Changes take effect immediately without a restart. Admin settings override `.env`; use “Restore `.env` defaults” to remove the override. Webhook tokens and signing secrets are never returned to the browser and are encrypted with a key derived from `JWT_SECRET`.

New asset-offline, certificate-expiration, and maintenance/license-expiration alerts are sent to Feishu. An unresolved alert of the same type for the same asset is not sent repeatedly.

## Docker

```bash
cp .env.example .env
docker compose up -d --build
```

## CSV / Excel bulk import

On Asset Inventory, download the import template and upload a completed `.csv` or `.xlsx` file through Bulk Import. The system previews and validates every row before writing the entire batch in one transaction. Each import supports up to 1,000 rows and a 5 MB file.

## Automated tests

```powershell
npm.cmd test
```

Tests start the application on a random local port with an isolated temporary SQLite database, leaving production data untouched. GitHub Actions runs the full suite on pushes to `main` and on pull requests.

## Login security

Login uses a one-time CAPTCHA. An account is locked for `ACCOUNT_LOCK_MINUTES` after `LOGIN_MAX_ATTEMPTS` consecutive failures, and each IP is limited to `LOGIN_RATE_LIMIT` attempts per 15 minutes. Administrators can inspect failed attempts and unlock accounts in User Management.

User passwords must be 8–128 characters and contain uppercase and lowercase letters, a number, and a special character.

## Database backup and restore

Administrators can create, download, upload, restore, and delete SQLite backups from Backup & Restore. Before restoration, the system verifies database integrity, required tables, foreign keys, and an active administrator account, then creates a pre-restore snapshot. Business data is restored in one transaction and fully rolled back on failure. Automatic backups are controlled by `AUTO_BACKUP_ENABLED`, `AUTO_BACKUP_CRON`, and `BACKUP_RETENTION`; by default, they run daily at 2:00 AM and retain 14 automatic backups.

Health checks support HTTP/HTTPS, TCP, and authenticated version queries for MySQL, PostgreSQL, SQL Server, and Oracle. Database assets store only `profile://name`; credentials come from `.env` and are never written to SQLite. The default ports are 3306, 5432, 1433, and 1521 respectively. For Oracle, enter the Service Name in the database/service-name field.
