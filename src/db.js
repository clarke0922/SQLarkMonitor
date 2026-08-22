const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const dataDir = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'sqlark.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','editor','viewer')), active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
  category TEXT NOT NULL, environment TEXT NOT NULL DEFAULT '测试',
  owner TEXT NOT NULL, department TEXT DEFAULT '测试部',
  url TEXT, host TEXT, port INTEGER, protocol TEXT NOT NULL DEFAULT 'none',
  status TEXT NOT NULL DEFAULT 'unknown', enabled INTEGER NOT NULL DEFAULT 1,
  description TEXT, secret_ref TEXT, tags TEXT,
  certificate_expires_at TEXT, maintenance_expires_at TEXT,
  last_checked_at TEXT, last_latency_ms INTEGER, last_error TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER NOT NULL,
  type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at TEXT, FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT,
  action TEXT NOT NULL, target_type TEXT NOT NULL, target_id INTEGER,
  detail TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS portal_settings (
  id INTEGER PRIMARY KEY CHECK(id=1),
  login_title TEXT NOT NULL,
  login_subtitle TEXT NOT NULL,
  home_markdown TEXT NOT NULL,
  links_json TEXT NOT NULL DEFAULT '[]',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

db.prepare(`INSERT OR IGNORE INTO portal_settings(id,login_title,login_subtitle,home_markdown,links_json)
  VALUES(1,?,?,?,?)`).run(
  'SQLark Monitor',
  '测试资产台账与内部系统导航',
  '# SQLark 测试部门工作台\n\n欢迎使用测试资产门户。你可以在这里维护常用系统入口、值班说明、测试规范和团队公告。\n\n## 使用提示\n\n- 从下方快捷入口访问 GitLab、Nexus、OA 和自动化测试平台\n- 在“资产台账”登记系统、数据库和服务器\n- 管理员或维护者可点击右上角“编辑首页”更新本页',
  JSON.stringify([
    { name: 'GitLab', url: 'https://gitlab.com', description: '代码仓库与 CI/CD' },
    { name: 'Nexus', url: 'https://help.sonatype.com/en/sonatype-nexus-repository.html', description: '制品与依赖仓库' }
  ])
);

const portalColumns = db.prepare('PRAGMA table_info(portal_settings)').all().map(column => column.name);
if (!portalColumns.includes('login_html')) {
  db.exec("ALTER TABLE portal_settings ADD COLUMN login_html TEXT NOT NULL DEFAULT '<h1>SQLark 测试资源导航</h1><p>统一访问测试部门的代码仓库、制品平台、自动化测试环境和内部系统。</p><h2>使用说明</h2><ul><li>使用右侧账号登录后维护资产和查看预警</li><li>常用系统可从下方快捷入口直接访问</li><li>如需开通权限，请联系测试部门管理员</li></ul>'");
}

if (!db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
  const password = process.env.ADMIN_PASSWORD || 'Admin@123456';
  db.prepare('INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)')
    .run('admin', bcrypt.hashSync(password, 12), '系统管理员', 'admin');
}

module.exports = db;
