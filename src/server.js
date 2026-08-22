require('dotenv').config({ quiet: true });
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
const db = require('./db');
const { runChecks } = require('./monitor');

const app = express();
const secret = process.env.JWT_SECRET || 'dev-only-secret-change-me';
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace(/^Bearer /, '');
    req.user = jwt.verify(token, secret); next();
  } catch { res.status(401).json({ error: '登录已失效，请重新登录' }); }
}
const allow = (...roles) => (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: '无权执行此操作' });
function audit(user, action, targetType, targetId, detail = '') {
  db.prepare('INSERT INTO audit_logs(user_id,username,action,target_type,target_id,detail) VALUES(?,?,?,?,?,?)')
    .run(user.id, user.username, action, targetType, targetId || null, detail);
}

app.post('/api/login', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE username=? AND active=1').get(req.body.username);
  if (!user || !bcrypt.compareSync(req.body.password || '', user.password_hash)) return res.status(401).json({ error: '用户名或密码错误' });
  const profile = { id: user.id, username: user.username, displayName: user.display_name, role: user.role };
  res.json({ token: jwt.sign(profile, secret, { expiresIn: '12h' }), user: profile });
});

app.get('/api/portal/public', (req, res) => {
  const row = db.prepare('SELECT login_title,login_subtitle,login_html,links_json FROM portal_settings WHERE id=1').get();
  res.json({ ...row, links: JSON.parse(row.links_json || '[]'), links_json: undefined });
});

app.get('/api/me', auth, (req, res) => res.json(req.user));
app.get('/api/dashboard', auth, (req, res) => {
  const totals = db.prepare(`SELECT COUNT(*) total, SUM(status='online') online, SUM(status='offline') offline,
    SUM(status='unknown') unknown FROM assets`).get();
  const categories = db.prepare('SELECT category name,COUNT(*) value FROM assets GROUP BY category ORDER BY value DESC').all();
  const alerts = db.prepare("SELECT COUNT(*) total,SUM(severity='critical') critical FROM alerts WHERE status='open'").get();
  res.json({ totals, categories, alerts });
});
app.get('/api/portal', auth, (req, res) => {
  const row = db.prepare('SELECT * FROM portal_settings WHERE id=1').get();
  res.json({ ...row, links: JSON.parse(row.links_json || '[]'), links_json: undefined });
});
app.put('/api/portal', auth, allow('admin','editor'), (req, res) => {
  const { login_title, login_subtitle, home_markdown, links } = req.body;
  if (!login_title?.trim() || !login_subtitle?.trim() || !home_markdown?.trim() || !Array.isArray(links))
    return res.status(400).json({ error: '登录标题、说明和首页内容不能为空' });
  if (links.length > 100) return res.status(400).json({ error: '快捷入口最多100个' });
  for (const link of links) {
    if (!link.name?.trim() || !/^https?:\/\//i.test(link.url || '')) return res.status(400).json({ error: '每个入口都需要名称和有效的 HTTP/HTTPS 地址' });
  }
  db.prepare(`UPDATE portal_settings SET login_title=?,login_subtitle=?,home_markdown=?,links_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=1`)
    .run(login_title.trim(),login_subtitle.trim(),home_markdown,JSON.stringify(links));
  audit(req.user,'update','portal',1,'编辑首页与登录页'); res.json({ok:true});
});
function sanitizeRichHtml(input) {
  return String(input || '')
    .replace(/<\/?(?:script|style|iframe|object|embed|form|input|button|textarea|select|svg|math)[^>]*>/gi, '')
    .replace(/\son\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/\s(?:style|class|id)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/href\s*=\s*["']?\s*(?:javascript|data):[^\s>"']*/gi, 'href="#"');
}
app.put('/api/portal/login', auth, allow('admin'), (req, res) => {
  const { login_title, login_subtitle, login_html } = req.body;
  if (!login_title?.trim() || !login_subtitle?.trim() || !login_html?.trim()) return res.status(400).json({error:'登录页标题、说明和正文不能为空'});
  const safeHtml = sanitizeRichHtml(login_html).slice(0, 50000);
  db.prepare('UPDATE portal_settings SET login_title=?,login_subtitle=?,login_html=?,updated_at=CURRENT_TIMESTAMP WHERE id=1')
    .run(login_title.trim(),login_subtitle.trim(),safeHtml);
  audit(req.user,'update','login_page',1,'发布登录页面'); res.json({ok:true});
});

app.get('/api/assets', auth, (req, res) => {
  const q = `%${req.query.q || ''}%`; const category = req.query.category || '';
  res.json(db.prepare(`SELECT * FROM assets WHERE (name LIKE ? OR owner LIKE ? OR host LIKE ? OR tags LIKE ?)
    AND (?='' OR category=?) ORDER BY updated_at DESC`).all(q,q,q,q,category,category));
});

function assetValues(body) {
  const validCategories = ['应用系统','代码/制品平台','自动化平台','数据库','服务器','其他'];
  if (!body.name?.trim() || !body.owner?.trim()) throw new Error('资产名称和负责人必填');
  if (!validCategories.includes(body.category)) throw new Error('资产分类无效');
  if (body.protocol === 'http' && !/^https?:\/\//i.test(body.url || '')) throw new Error('HTTP 检查需要有效 URL');
  if (body.protocol === 'tcp' && (!body.host || !Number(body.port))) throw new Error('TCP 检查需要主机和端口');
  return [body.name.trim(), body.category, body.environment || '测试', body.owner.trim(), body.department || '测试部',
    body.url || null, body.host || null, body.port ? Number(body.port) : null, body.protocol || 'none', body.description || null,
    body.secret_ref || null, body.tags || null, body.maintenance_expires_at || null, body.enabled === false ? 0 : 1];
}

app.post('/api/assets', auth, allow('admin','editor'), (req, res) => {
  try {
    const result = db.prepare(`INSERT INTO assets(name,category,environment,owner,department,url,host,port,protocol,description,secret_ref,tags,maintenance_expires_at,enabled)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(...assetValues(req.body));
    audit(req.user, 'create', 'asset', result.lastInsertRowid, req.body.name); res.status(201).json({ id: result.lastInsertRowid });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.put('/api/assets/:id', auth, allow('admin','editor'), (req, res) => {
  try {
    db.prepare(`UPDATE assets SET name=?,category=?,environment=?,owner=?,department=?,url=?,host=?,port=?,protocol=?,description=?,secret_ref=?,tags=?,maintenance_expires_at=?,enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
      .run(...assetValues(req.body), req.params.id);
    audit(req.user, 'update', 'asset', Number(req.params.id), req.body.name); res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete('/api/assets/:id', auth, allow('admin'), (req, res) => {
  const asset = db.prepare('SELECT name FROM assets WHERE id=?').get(req.params.id);
  if (!asset) return res.status(404).json({ error: '资产不存在' });
  audit(req.user, 'delete', 'asset', Number(req.params.id), asset.name);
  db.prepare('DELETE FROM assets WHERE id=?').run(req.params.id); res.json({ ok: true });
});

app.post('/api/checks/run', auth, allow('admin','editor'), async (req, res) => { await runChecks(); audit(req.user,'check','assets',null); res.json({ ok:true }); });
app.get('/api/alerts', auth, (req, res) => res.json(db.prepare(`SELECT alerts.*,assets.name asset_name FROM alerts JOIN assets ON assets.id=alerts.asset_id
  WHERE alerts.status='open' ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END,alerts.created_at DESC`).all()));
app.post('/api/alerts/:id/resolve', auth, allow('admin','editor'), (req, res) => {
  db.prepare("UPDATE alerts SET status='resolved',resolved_at=CURRENT_TIMESTAMP WHERE id=?").run(req.params.id);
  audit(req.user,'resolve','alert',Number(req.params.id)); res.json({ok:true});
});
app.get('/api/audit', auth, allow('admin'), (req, res) => res.json(db.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200').all()));
app.get('/api/users', auth, allow('admin'), (req, res) => res.json(db.prepare('SELECT id,username,display_name,role,active,created_at FROM users ORDER BY id').all()));
app.post('/api/users', auth, allow('admin'), (req, res) => {
  const { username, display_name, role, password } = req.body;
  if (!/^\w{3,32}$/.test(username || '') || !display_name || !['admin','editor','viewer'].includes(role) || String(password || '').length < 10)
    return res.status(400).json({ error: '用户名需为3-32位字母数字下划线，密码至少10位' });
  try { const r=db.prepare('INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)').run(username,bcrypt.hashSync(password,12),display_name,role); audit(req.user,'create','user',r.lastInsertRowid,username); res.status(201).json({id:r.lastInsertRowid}); }
  catch { res.status(409).json({ error: '用户名已存在' }); }
});
app.put('/api/users/:id', auth, allow('admin'), (req, res) => {
  const { display_name, role, active, password } = req.body;
  if (!display_name || !['admin','editor','viewer'].includes(role)) return res.status(400).json({error:'用户资料无效'});
  if (Number(req.params.id)===req.user.id && active===false) return res.status(400).json({error:'不能停用当前账号'});
  if (password && String(password).length<10) return res.status(400).json({error:'密码至少10位'});
  db.prepare(`UPDATE users SET display_name=?,role=?,active=?,password_hash=CASE WHEN ?='' THEN password_hash ELSE ? END WHERE id=?`)
    .run(display_name,role,active===false?0:1,password||'',password?bcrypt.hashSync(password,12):'',req.params.id);
  audit(req.user,'update','user',Number(req.params.id)); res.json({ok:true});
});
app.get('/api/assets.csv', auth, (req, res) => {
  const rows = db.prepare('SELECT name,category,environment,owner,department,url,host,port,status,tags,maintenance_expires_at FROM assets ORDER BY id').all();
  const headers = Object.keys(rows[0] || {name:'',category:'',environment:'',owner:'',department:'',url:'',host:'',port:'',status:'',tags:'',maintenance_expires_at:''});
  const quote = v => `"${String(v ?? '').replaceAll('"','""')}"`;
  const csv = '\uFEFF' + [headers.join(','), ...rows.map(r => headers.map(h => quote(r[h])).join(','))].join('\r\n');
  res.type('text/csv').attachment('sqlark-assets.csv').send(csv);
});

const minutes = Math.max(1, Number(process.env.CHECK_INTERVAL_MINUTES || 5));
cron.schedule(`*/${minutes} * * * *`, () => runChecks().catch(console.error));
const port = Number(process.env.PORT || 3000);
app.listen(port, () => { console.log(`SQLark Monitor: http://localhost:${port}`); runChecks().catch(console.error); });
