const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const db = require('./db');

const timeoutMs = Number(process.env.CHECK_TIMEOUT_MS || 5000);
const threshold = Number(process.env.FAILURE_THRESHOLD || 3);
let running = false;
let notificationFetch = fetch;
const databaseProtocols = new Set(['mysql', 'postgresql', 'sqlserver', 'oracle']);

function databaseProfiles() {
  try { return JSON.parse(process.env.DB_CHECK_PROFILES_JSON || '{}'); }
  catch { throw new Error('DB_CHECK_PROFILES_JSON 不是有效的 JSON'); }
}

function databaseProfile(asset) {
  const match = /^profile:\/\/([A-Za-z0-9_-]+)$/.exec(asset.secret_ref || '');
  if (!match) throw new Error('数据库凭据引用格式无效');
  const stored = db.prepare('SELECT username,password_encrypted FROM credential_profiles WHERE name=?').get(match[1]);
  if (stored) return { username:stored.username, password:decryptSecret(stored.password_encrypted) };
  const profile = databaseProfiles()[match[1]];
  if (!profile?.username || !profile?.password) throw new Error(`未找到数据库检查配置：${match[1]}`);
  return profile;
}

let databaseAdapters = {
  mysql: async (asset, profile) => {
    const mysql = require('mysql2/promise');
    const connection = await mysql.createConnection({ host:asset.host, port:Number(asset.port), user:profile.username, password:profile.password, database:asset.database_name, connectTimeout:timeoutMs, ssl:profile.ssl });
    try { const [rows] = await connection.query('SELECT VERSION() AS version'); return `MySQL ${rows[0].version}`; }
    finally { await connection.end(); }
  },
  postgresql: async (asset, profile) => {
    const { Client } = require('pg');
    const client = new Client({ host:asset.host, port:Number(asset.port), user:profile.username, password:profile.password, database:asset.database_name, connectionTimeoutMillis:timeoutMs, statement_timeout:timeoutMs, ssl:profile.ssl || false });
    await client.connect();
    try { const result = await client.query('SHOW server_version'); return `PostgreSQL ${result.rows[0].server_version}`; }
    finally { await client.end(); }
  },
  sqlserver: async (asset, profile) => {
    const sql = require('mssql');
    const pool = new sql.ConnectionPool({ server:asset.host, port:Number(asset.port), user:profile.username, password:profile.password, database:asset.database_name, connectionTimeout:timeoutMs, requestTimeout:timeoutMs, options:{ encrypt:profile.encrypt === true, trustServerCertificate:profile.trustServerCertificate !== false } });
    await pool.connect();
    try { const result = await pool.request().query('SELECT CAST(SERVERPROPERTY(\'ProductVersion\') AS varchar(128)) AS version'); return `SQL Server ${result.recordset[0].version}`; }
    finally { await pool.close(); }
  },
  oracle: async (asset, profile) => {
    const oracledb = require('oracledb');
    const connection = await oracledb.getConnection({ user:profile.username, password:profile.password, connectString:`${asset.host}:${asset.port}/${asset.database_name}` });
    connection.callTimeout = timeoutMs;
    try { const result = await connection.execute("SELECT banner FROM v$version WHERE banner LIKE 'Oracle Database%' AND ROWNUM = 1"); return result.rows?.[0]?.[0] || 'Oracle Database 可用'; }
    finally { await connection.close(); }
  }
};

async function databaseCheck(asset) {
  return databaseAdapters[asset.protocol](asset, databaseProfile(asset));
}

function tcpCheck(host, port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port: Number(port), timeout: timeoutMs });
    socket.once('connect', () => { socket.destroy(); resolve(); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error('连接超时')); });
    socket.once('error', reject);
  });
}

async function httpCheck(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), redirect: 'follow' });
  if (response.status >= 500) throw new Error(`HTTP ${response.status}`);
}

function certificateExpiry(url) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:') return resolve(null);
      const socket = tls.connect({ host: parsed.hostname, port: parsed.port || 443, servername: parsed.hostname, rejectUnauthorized: false, timeout: timeoutMs }, () => {
        const cert = socket.getPeerCertificate(); socket.end(); resolve(cert.valid_to ? new Date(cert.valid_to).toISOString() : null);
      });
      socket.on('error', () => resolve(null)); socket.on('timeout', () => { socket.destroy(); resolve(null); });
    } catch { resolve(null); }
  });
}

async function sendMail(subject, text) {
  if (!process.env.SMTP_HOST || !process.env.ALERT_RECIPIENTS) return;
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 25),
    secure: process.env.SMTP_SECURE === 'true',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
  });
  await transport.sendMail({ from: process.env.SMTP_FROM, to: process.env.ALERT_RECIPIENTS, subject, text });
}

function encryptionKey() { return crypto.createHash('sha256').update(process.env.JWT_SECRET || 'dev-only-secret-change-me').digest(); }
function encryptSecret(value) {
  if (!value) return null;
  const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',encryptionKey(),iv),encrypted=Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);
  return `v1:${iv.toString('base64')}:${cipher.getAuthTag().toString('base64')}:${encrypted.toString('base64')}`;
}
function decryptSecret(value) {
  if (!value) return '';
  const [version,iv,tag,encrypted]=value.split(':');
  if(version!=='v1'||!iv||!tag||!encrypted)throw new Error('加密凭据无法解密');
  const decipher=crypto.createDecipheriv('aes-256-gcm',encryptionKey(),Buffer.from(iv,'base64'));decipher.setAuthTag(Buffer.from(tag,'base64'));
  return Buffer.concat([decipher.update(Buffer.from(encrypted,'base64')),decipher.final()]).toString('utf8');
}
function feishuConfig() {
  const row=db.prepare('SELECT feishu_override,feishu_enabled,feishu_webhook_url,feishu_secret_encrypted FROM portal_settings WHERE id=1').get();
  if(row?.feishu_override)return{source:'database',enabled:row.feishu_enabled===1,url:row.feishu_webhook_url?decryptSecret(row.feishu_webhook_url):(process.env.FEISHU_WEBHOOK_URL||''),secret:row.feishu_secret_encrypted?decryptSecret(row.feishu_secret_encrypted):(process.env.FEISHU_WEBHOOK_SECRET||'')};
  return{source:process.env.FEISHU_WEBHOOK_URL?'env':'none',enabled:!!process.env.FEISHU_WEBHOOK_URL,url:process.env.FEISHU_WEBHOOK_URL||'',secret:process.env.FEISHU_WEBHOOK_SECRET||''};
}

async function sendFeishu(subject, text) {
  const config=feishuConfig();
  if (!config.enabled || !config.url) return false;
  const url = new URL(config.url);
  if (url.protocol !== 'https:' || !['open.feishu.cn','open.larksuite.com'].includes(url.hostname) || !url.pathname.startsWith('/open-apis/bot/v2/hook/')) throw new Error('飞书 Webhook 地址无效');
  const body = { msg_type:'text', content:{ text:`${subject}\n${text}` } };
  if (config.secret) {
    body.timestamp = Math.floor(Date.now() / 1000);
    body.sign = crypto.createHmac('sha256', `${body.timestamp}\n${config.secret}`).update('').digest('base64');
  }
  const response = await notificationFetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body), signal:AbortSignal.timeout(timeoutMs) });
  if (!response.ok) throw new Error(`飞书通知 HTTP ${response.status}`);
  const result = await response.json();
  if ((result.code != null && result.code !== 0) || (result.StatusCode != null && result.StatusCode !== 0)) throw new Error(`飞书通知失败：${result.msg || result.StatusMessage || '未知错误'}`);
  return true;
}

function openAlert(asset, type, severity, message) {
  const exists = db.prepare("SELECT id FROM alerts WHERE asset_id=? AND type=? AND status='open'").get(asset.id, type);
  if (exists) return;
  db.prepare('INSERT INTO alerts(asset_id,type,severity,message) VALUES(?,?,?,?)').run(asset.id, type, severity, message);
  const subject = `[SQLark资产预警] ${asset.name}`;
  sendMail(subject, message).catch(console.error);
  sendFeishu(subject, message).catch(console.error);
}

function resolveAlert(assetId, type) {
  db.prepare("UPDATE alerts SET status='resolved',resolved_at=CURRENT_TIMESTAMP WHERE asset_id=? AND type=? AND status='open'").run(assetId, type);
}

async function checkAsset(asset) {
  const started = Date.now();
  try {
    let detail = null;
    if (asset.protocol === 'http') await httpCheck(asset.url);
    else if (asset.protocol === 'tcp') await tcpCheck(asset.host, asset.port);
    else if (databaseProtocols.has(asset.protocol)) detail = await databaseCheck(asset);
    else return;
    const certExpiry = asset.protocol === 'http' ? await certificateExpiry(asset.url) : null;
    db.prepare(`UPDATE assets SET status='online',consecutive_failures=0,last_checked_at=CURRENT_TIMESTAMP,
      last_latency_ms=?,last_error=NULL,last_check_detail=?,certificate_expires_at=COALESCE(?,certificate_expires_at),updated_at=CURRENT_TIMESTAMP WHERE id=?`)
      .run(Date.now() - started, detail, certExpiry, asset.id);
    resolveAlert(asset.id, 'offline');
  } catch (error) {
    const failures = asset.consecutive_failures + 1;
    const status = failures >= threshold ? 'offline' : asset.status;
    db.prepare('UPDATE assets SET status=?,consecutive_failures=?,last_checked_at=CURRENT_TIMESTAMP,last_error=?,last_check_detail=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?')
      .run(status, failures, String(error.message).slice(0, 500), asset.id);
    if (failures >= threshold) openAlert(asset, 'offline', 'critical', `${asset.name} 连续 ${failures} 次健康检查失败：${error.message}`);
  }
}

function checkExpirations(asset) {
  const now = Date.now(); const days30 = now + 30 * 86400000;
  for (const [field, type, label] of [['certificate_expires_at','certificate','证书'], ['maintenance_expires_at','maintenance','维护/许可']]) {
    const value = asset[field];
    if (value && new Date(value).getTime() <= days30) {
      openAlert(asset, type, new Date(value).getTime() <= now ? 'critical' : 'warning', `${asset.name} 的${label}将在 ${value.slice(0,10)} 到期`);
    } else resolveAlert(asset.id, type);
  }
}

async function runChecks() {
  if (running) return; running = true;
  try {
    const assets = db.prepare('SELECT * FROM assets WHERE enabled=1').all();
    for (const asset of assets) { checkExpirations(asset); await checkAsset(asset); }
  } finally { running = false; }
}

function setDatabaseAdaptersForTest(overrides) { databaseAdapters = { ...databaseAdapters, ...overrides }; }
function setNotificationFetchForTest(fetcher) { notificationFetch = fetcher; }

module.exports = { runChecks, sendFeishu, feishuConfig, encryptSecret, decryptSecret, setDatabaseAdaptersForTest, setNotificationFetchForTest };
