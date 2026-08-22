require('dotenv').config({ quiet: true });
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
const ExcelJS = require('exceljs');
const multer = require('multer');
const { Readable } = require('stream');
const crypto = require('crypto');
const fs = require('fs');
const { rateLimit } = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const db = require('./db');
const { runChecks, sendFeishu, feishuConfig, encryptSecret } = require('./monitor');
const backups = require('./backup');

const app = express();
const secret = process.env.JWT_SECRET || 'dev-only-secret-change-me';
const loginMaxAttempts = Math.max(3, Number(process.env.LOGIN_MAX_ATTEMPTS || 5));
const accountLockMinutes = Math.max(1, Number(process.env.ACCOUNT_LOCK_MINUTES || 15));
const loginRateLimit = Math.max(loginMaxAttempts + 1, Number(process.env.LOGIN_RATE_LIMIT || 20));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 1 } });
const backupUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024, files: 1 } });
const captchaChallenges = new Map();
const captchaChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: loginRateLimit, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: '登录尝试过于频繁，请15分钟后重试' } });
const captchaLimiter = rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: '验证码请求过于频繁，请稍后重试' } });

function captchaHash(id, answer) { return crypto.createHmac('sha256', secret).update(`${id}:${String(answer).toUpperCase()}`).digest('hex'); }
function escapeSvg(value) { return String(value).replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&apos;'}[character])); }
function createCaptcha() {
  const id = crypto.randomUUID();
  const answer = process.env.NODE_ENV === 'test' ? 'TEST12' : Array.from({length:6},()=>captchaChars[crypto.randomInt(captchaChars.length)]).join('');
  captchaChallenges.set(id, { hash:captchaHash(id,answer), expiresAt:Date.now()+5*60*1000 });
  const glyphs = [...answer].map((char,index)=>`<text x="${20+index*24}" y="39" transform="rotate(${crypto.randomInt(-12,13)} ${20+index*24} 39)">${escapeSvg(char)}</text>`).join('');
  const lines = Array.from({length:5},()=>`<line x1="${crypto.randomInt(0,180)}" y1="${crypto.randomInt(0,55)}" x2="${crypto.randomInt(0,180)}" y2="${crypto.randomInt(0,55)}"/>`).join('');
  const svg=`<svg xmlns="http://www.w3.org/2000/svg" width="180" height="55" viewBox="0 0 180 55"><rect width="180" height="55" rx="8" fill="#f1f4fb"/><g stroke="#9eabd1" stroke-width="1">${lines}</g><g font-family="monospace" font-size="27" font-weight="700" fill="#26355a">${glyphs}</g></svg>`;
  return {id,image:`data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`};
}
function verifyCaptcha(id, answer) {
  const challenge=captchaChallenges.get(id); captchaChallenges.delete(id);
  if(!challenge||challenge.expiresAt<Date.now()||!answer)return false;
  const actual=captchaHash(id,answer); return crypto.timingSafeEqual(Buffer.from(actual),Buffer.from(challenge.hash));
}
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
function validPassword(password) { return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,128}$/.test(String(password || '')); }
const passwordRuleMessage = '密码需为8-128位，并包含大写字母、小写字母、数字和特殊字符';

app.get('/api/captcha', captchaLimiter, (req,res)=>{
  const now=Date.now(); for(const [id,value] of captchaChallenges)if(value.expiresAt<now)captchaChallenges.delete(id);
  res.set('Cache-Control','no-store').json(createCaptcha());
});
app.post('/api/login', loginLimiter, (req, res) => {
  if(!verifyCaptcha(req.body.captcha_id,req.body.captcha_answer))return res.status(400).json({error:'验证码错误或已失效',code:'CAPTCHA_INVALID'});
  const user = db.prepare('SELECT * FROM users WHERE username=? AND active=1').get(req.body.username);
  if(user?.locked_until&&new Date(user.locked_until).getTime()>Date.now()){
    const retryAfterSeconds=Math.ceil((new Date(user.locked_until).getTime()-Date.now())/1000);
    return res.status(423).json({error:`账号已锁定，请在 ${Math.ceil(retryAfterSeconds/60)} 分钟后重试`,code:'ACCOUNT_LOCKED',retryAfterSeconds});
  }
  const passwordMatches=user?bcrypt.compareSync(req.body.password||'',user.password_hash):bcrypt.compareSync(req.body.password||'','$2b$12$uP4J5Dwjhnakz1Iul7l0nexPc/n5jUmnmSlzwxE5PMyYQXoe1LgRG');
  if(!user||!passwordMatches){
    if(user){const attempts=user.failed_attempts+1;const locked=attempts>=loginMaxAttempts;const lockedUntil=locked?new Date(Date.now()+accountLockMinutes*60*1000).toISOString():null;db.prepare('UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?').run(attempts,lockedUntil,user.id);audit({id:user.id,username:user.username},locked?'login_locked':'login_failed','user',user.id,`连续失败 ${attempts} 次`);if(locked)return res.status(423).json({error:`密码连续错误${loginMaxAttempts}次，账号已锁定${accountLockMinutes}分钟`,code:'ACCOUNT_LOCKED',retryAfterSeconds:accountLockMinutes*60});}
    return res.status(401).json({error:'用户名或密码错误',code:'INVALID_CREDENTIALS'});
  }
  db.prepare('UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=?').run(user.id);
  const profile = { id: user.id, username: user.username, displayName: user.display_name, role: user.role };
  audit(profile,'login_success','user',user.id,'登录成功');
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
  return sanitizeHtml(String(input || ''), {
    allowedTags: ['h1','h2','h3','p','br','ul','ol','li','blockquote','pre','code','strong','b','em','i','u','s','a','hr'],
    allowedAttributes: { a: ['href','title','target','rel'] },
    allowedSchemes: ['http','https','mailto'],
    allowedSchemesByTag: { a: ['http','https','mailto'] },
    allowProtocolRelative: false,
    transformTags: {
      a: (tagName, attribs) => ({ tagName, attribs: { ...attribs, target: '_blank', rel: 'noopener noreferrer' } })
    },
    disallowedTagsMode: 'discard',
    enforceHtmlBoundary: true
  });
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

const importColumns = [
  ['name','资产名称'],['category','资产分类'],['environment','所属环境'],['owner','负责人'],['department','部门'],
  ['protocol','检查方式'],['url','访问URL'],['host','主机地址'],['port','端口'],['tags','标签'],
  ['database_name','数据库名/服务名'],['maintenance_expires_at','维护/许可到期日'],['secret_ref','密码库引用'],['description','说明'],['enabled','启用巡检']
];
const headerAliases = new Map(importColumns.flatMap(([key,label]) => [[key,key],[label,key]]));

function normalizeImportRow(raw, rowNumber) {
  const row = {};
  for (const [header, value] of Object.entries(raw)) {
    const key = headerAliases.get(String(header).trim());
    if (key) row[key] = value == null ? '' : String(value).trim();
  }
  row.category ||= '其他'; row.environment ||= '测试'; row.department ||= '测试部'; row.protocol ||= 'none';
  row.enabled = !['否','false','0','停用'].includes(String(row.enabled || '是').toLowerCase());
  row.port = row.port ? Number(row.port) : null;
  row.maintenance_expires_at = row.maintenance_expires_at ? String(row.maintenance_expires_at).slice(0,10) : null;
  const errors = [];
  try { assetValues(row); } catch (error) { errors.push(error.message); }
  return { rowNumber, data: row, errors };
}

async function parseImportFile(file) {
  if (!file) throw new Error('请选择 CSV 或 Excel 文件');
  const extension = String(file.originalname).toLowerCase().split('.').pop();
  if (!['csv','xlsx'].includes(extension)) throw new Error('仅支持 .csv 和 .xlsx 文件');
  const workbook = new ExcelJS.Workbook();
  if (extension === 'csv') await workbook.csv.read(Readable.from(file.buffer));
  else await workbook.xlsx.load(file.buffer);
  const sheet = workbook.worksheets[0];
  if (!sheet || sheet.rowCount < 2) throw new Error('文件中没有可导入的数据');
  const headers = sheet.getRow(1).values.slice(1).map(value => String(value || '').trim());
  if (!headers.some(header => headerAliases.has(header))) throw new Error('表头不匹配，请先下载导入模板');
  const rows = [];
  sheet.eachRow((excelRow, number) => {
    if (number === 1) return;
    const raw = {}; let hasValue = false;
    headers.forEach((header,index) => { const value=excelRow.getCell(index+1).value; const cellValue=value?.text ?? value?.result ?? value; const normalized=cellValue instanceof Date?cellValue.toISOString().slice(0,10):cellValue; raw[header]=normalized; if(normalized!==null&&normalized!==undefined&&String(normalized).trim()!=='')hasValue=true; });
    if (hasValue) rows.push(normalizeImportRow(raw, number));
  });
  if (rows.length > 1000) throw new Error('单次最多导入1000条资产');
  const existing = new Set(db.prepare('SELECT lower(name) name FROM assets').all().map(item => item.name));
  const seen = new Set();
  for (const item of rows) {
    const name = String(item.data.name || '').toLowerCase();
    if (name && (existing.has(name) || seen.has(name))) item.errors.push('资产名称已存在');
    seen.add(name);
  }
  return rows;
}

app.get('/api/assets/import/template', auth, allow('admin','editor'), async (req, res) => {
  const workbook = new ExcelJS.Workbook(); const sheet = workbook.addWorksheet('资产导入模板');
  sheet.columns = importColumns.map(([key,label]) => ({ header: label, key, width: Math.max(14,label.length*2+4) }));
  sheet.getRow(1).font = { bold:true, color:{argb:'FFFFFFFF'} }; sheet.getRow(1).fill = { type:'pattern',pattern:'solid',fgColor:{argb:'FF4666F6'} };
  sheet.addRow({ name:'示例：测试 GitLab',category:'代码/制品平台',environment:'测试',owner:'张三',department:'测试部',protocol:'http',url:'https://gitlab.example.com',tags:'核心,代码仓库',maintenance_expires_at:'2027-12-31',secret_ref:'vault://sqlark/gitlab',description:'请删除示例行后填写',enabled:'是' });
  sheet.views = [{state:'frozen',ySplit:1}]; sheet.autoFilter = {from:'A1',to:'O1'};
  const buffer = await workbook.xlsx.writeBuffer();
  res.attachment('sqlark-assets-import-template.xlsx').type('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet').send(Buffer.from(buffer));
});

app.post('/api/assets/import/preview', auth, allow('admin','editor'), upload.single('file'), async (req, res) => {
  try { const rows=await parseImportFile(req.file); res.json({rows,total:rows.length,valid:rows.filter(x=>!x.errors.length).length,errors:rows.filter(x=>x.errors.length).length}); }
  catch(error){res.status(400).json({error:error.message});}
});

app.post('/api/assets/import', auth, allow('admin','editor'), (req, res) => {
  const rows = Array.isArray(req.body.rows) ? req.body.rows : [];
  if (!rows.length || rows.length > 1000) return res.status(400).json({error:'导入数据为空或超过1000条'});
  const normalized = rows.map((row,index)=>normalizeImportRow(row,index+2));
  const existing = new Set(db.prepare('SELECT lower(name) name FROM assets').all().map(item=>item.name)); const seen=new Set();
  for(const item of normalized){const name=String(item.data.name||'').toLowerCase();if(name&&(existing.has(name)||seen.has(name)))item.errors.push('资产名称已存在');seen.add(name);}
  const invalid = normalized.filter(item=>item.errors.length);
  if(invalid.length) return res.status(400).json({error:'导入数据校验失败，未写入任何资产',rows:normalized});
  const insert = db.prepare(`INSERT INTO assets(name,category,environment,owner,department,url,host,port,protocol,database_name,description,secret_ref,tags,maintenance_expires_at,enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const transaction = db.transaction(items=>{for(const item of items)insert.run(...assetValues(item.data));});
  transaction(normalized); audit(req.user,'import','assets',null,`批量导入 ${normalized.length} 条资产`); res.status(201).json({imported:normalized.length});
});

function assetValues(body) {
  const validCategories = ['应用系统','代码/制品平台','自动化平台','数据库','服务器','其他'];
  if (!body.name?.trim() || !body.owner?.trim()) throw new Error('资产名称和负责人必填');
  if (!validCategories.includes(body.category)) throw new Error('资产分类无效');
  if (body.protocol === 'http' && !/^https?:\/\//i.test(body.url || '')) throw new Error('HTTP 检查需要有效 URL');
  if (body.protocol === 'tcp' && (!body.host || !Number(body.port))) throw new Error('TCP 检查需要主机和端口');
  const databaseProtocols=['mysql','postgresql','sqlserver','oracle'];
  if(databaseProtocols.includes(body.protocol)&&(!body.host||!body.database_name))throw new Error('数据库检查需要主机地址和数据库名/服务名');
  if(databaseProtocols.includes(body.protocol)&&!/^profile:\/\/[A-Za-z0-9_-]+$/.test(body.secret_ref||''))throw new Error('数据库检查需要 profile://配置名 格式的凭据引用');
  const defaultPorts={mysql:3306,postgresql:5432,sqlserver:1433,oracle:1521};
  if(databaseProtocols.includes(body.protocol)&&!body.port)body.port=defaultPorts[body.protocol];
  return [body.name.trim(), body.category, body.environment || '测试', body.owner.trim(), body.department || '测试部',
    body.url || null, body.host || null, body.port ? Number(body.port) : null, body.protocol || 'none', body.database_name || null, body.description || null,
    body.secret_ref || null, body.tags || null, body.maintenance_expires_at || null, body.enabled === false ? 0 : 1];
}

app.post('/api/assets', auth, allow('admin','editor'), (req, res) => {
  try {
    const result = db.prepare(`INSERT INTO assets(name,category,environment,owner,department,url,host,port,protocol,database_name,description,secret_ref,tags,maintenance_expires_at,enabled)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(...assetValues(req.body));
    audit(req.user, 'create', 'asset', result.lastInsertRowid, req.body.name); res.status(201).json({ id: result.lastInsertRowid });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.put('/api/assets/:id', auth, allow('admin','editor'), (req, res) => {
  try {
    db.prepare(`UPDATE assets SET name=?,category=?,environment=?,owner=?,department=?,url=?,host=?,port=?,protocol=?,database_name=?,description=?,secret_ref=?,tags=?,maintenance_expires_at=?,enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
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
function auditQuery(query, includePaging = true) {
  const conditions=[];const params=[];
  if(query.q){conditions.push('(username LIKE ? OR action LIKE ? OR detail LIKE ?)');const value=`%${String(query.q).slice(0,100)}%`;params.push(value,value,value);}
  if(query.username){conditions.push('username=?');params.push(String(query.username).slice(0,100));}
  if(query.action){conditions.push('action=?');params.push(String(query.action).slice(0,100));}
  if(query.target_type){conditions.push('target_type=?');params.push(String(query.target_type).slice(0,100));}
  if(/^\d{4}-\d{2}-\d{2}$/.test(query.date_from||'')){conditions.push('date(created_at)>=date(?)');params.push(query.date_from);}
  if(/^\d{4}-\d{2}-\d{2}$/.test(query.date_to||'')){conditions.push('date(created_at)<=date(?)');params.push(query.date_to);}
  const where=conditions.length?`WHERE ${conditions.join(' AND ')}`:'';
  const page=Math.max(1,Number(query.page)||1),pageSize=Math.min(100,Math.max(10,Number(query.page_size)||25));
  const total=db.prepare(`SELECT COUNT(*) total FROM audit_logs ${where}`).get(...params).total;
  const sql=`SELECT * FROM audit_logs ${where} ORDER BY created_at DESC,id DESC${includePaging?' LIMIT ? OFFSET ?':''}`;
  const rows=includePaging?db.prepare(sql).all(...params,pageSize,(page-1)*pageSize):db.prepare(`${sql} LIMIT 50000`).all(...params);
  return{rows,total,page,pageSize,totalPages:Math.max(1,Math.ceil(total/pageSize))};
}
app.get('/api/audit', auth, allow('admin'), (req,res)=>{
  const result=auditQuery(req.query);
  result.facets={
    users:db.prepare("SELECT DISTINCT username value FROM audit_logs WHERE username IS NOT NULL AND username<>'' ORDER BY username").all().map(row=>row.value),
    actions:db.prepare('SELECT DISTINCT action value FROM audit_logs ORDER BY action').all().map(row=>row.value),
    targetTypes:db.prepare('SELECT DISTINCT target_type value FROM audit_logs ORDER BY target_type').all().map(row=>row.value)
  };
  res.json(result);
});
function csvSafe(value){const text=String(value??'');const safe=/^[=+\-@\t\r]/.test(text)?`'${text}`:text;return`"${safe.replaceAll('"','""')}"`;}
app.get('/api/audit.csv', auth, allow('admin'), (req,res)=>{
  const result=auditQuery(req.query,false);const headers=['时间','用户','动作','对象类型','对象ID','详情'];
  const csv='\uFEFF'+[headers.map(csvSafe).join(','),...result.rows.map(row=>[row.created_at,row.username,row.action,row.target_type,row.target_id,row.detail].map(csvSafe).join(','))].join('\r\n');
  audit(req.user,'export','audit_log',null,`导出 ${result.rows.length} 条审计日志`);
  res.type('text/csv').attachment('sqlark-audit-logs.csv').send(csv);
});
app.get('/api/users', auth, allow('admin'), (req, res) => res.json(db.prepare('SELECT id,username,display_name,role,active,failed_attempts,locked_until,created_at FROM users ORDER BY id').all()));
app.get('/api/settings/feishu', auth, allow('admin'), (req,res)=>{
  const config=feishuConfig();
  res.json({source:config.source,enabled:config.enabled,webhook_configured:!!config.url,secret_configured:!!config.secret});
});
app.put('/api/settings/feishu', auth, allow('admin'), (req,res)=>{
  try{
    if(req.body.use_env){db.prepare('UPDATE portal_settings SET feishu_override=0,feishu_webhook_url=NULL,feishu_secret_encrypted=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=1').run();audit(req.user,'update','feishu_settings',1,'恢复 .env 默认配置');return res.json({ok:true});}
    const current=db.prepare('SELECT feishu_webhook_url,feishu_secret_encrypted FROM portal_settings WHERE id=1').get();
    const webhook=String(req.body.webhook_url||'').trim();
    if(webhook){const url=new URL(webhook);if(url.protocol!=='https:'||!['open.feishu.cn','open.larksuite.com'].includes(url.hostname)||!url.pathname.startsWith('/open-apis/bot/v2/hook/'))return res.status(400).json({error:'请输入有效的飞书群机器人 Webhook 地址'});}
    const encryptedWebhook=webhook?encryptSecret(webhook):current.feishu_webhook_url;
    const encrypted=req.body.clear_secret?null:(req.body.secret?encryptSecret(String(req.body.secret)):current.feishu_secret_encrypted);
    db.prepare('UPDATE portal_settings SET feishu_override=1,feishu_enabled=?,feishu_webhook_url=?,feishu_secret_encrypted=?,updated_at=CURRENT_TIMESTAMP WHERE id=1').run(req.body.enabled===false?0:1,encryptedWebhook||null,encrypted);
    audit(req.user,'update','feishu_settings',1,`飞书告警${req.body.enabled===false?'停用':'启用'}`);res.json({ok:true});
  }catch(error){res.status(400).json({error:error.message});}
});
app.post('/api/settings/feishu/test', auth, allow('admin'), async (req,res)=>{
  try{const sent=await sendFeishu('[SQLark Monitor] 飞书配置测试',`测试消息发送成功，操作人：${req.user.displayName}`);if(!sent)return res.status(400).json({error:'飞书告警未启用或未配置 Webhook'});audit(req.user,'test','feishu_settings',1,'发送测试消息');res.json({ok:true});}
  catch(error){res.status(400).json({error:error.message});}
});
app.post('/api/users', auth, allow('admin'), (req, res) => {
  const { username, display_name, role, password } = req.body;
  if (!/^\w{3,32}$/.test(username || '') || !display_name || !['admin','editor','viewer'].includes(role))
    return res.status(400).json({ error: '用户名需为3-32位字母数字下划线，用户资料不能为空' });
  if (!validPassword(password)) return res.status(400).json({ error: passwordRuleMessage });
  try { const r=db.prepare('INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)').run(username,bcrypt.hashSync(password,12),display_name,role); audit(req.user,'create','user',r.lastInsertRowid,username); res.status(201).json({id:r.lastInsertRowid}); }
  catch { res.status(409).json({ error: '用户名已存在' }); }
});
app.put('/api/users/:id', auth, allow('admin'), (req, res) => {
  const { display_name, role, active, password } = req.body;
  if (!display_name || !['admin','editor','viewer'].includes(role)) return res.status(400).json({error:'用户资料无效'});
  if (Number(req.params.id)===req.user.id && active===false) return res.status(400).json({error:'不能停用当前账号'});
  if (password && !validPassword(password)) return res.status(400).json({error:passwordRuleMessage});
  db.prepare(`UPDATE users SET display_name=?,role=?,active=?,password_hash=CASE WHEN ?='' THEN password_hash ELSE ? END WHERE id=?`)
    .run(display_name,role,active===false?0:1,password||'',password?bcrypt.hashSync(password,12):'',req.params.id);
  audit(req.user,'update','user',Number(req.params.id)); res.json({ok:true});
});
app.post('/api/users/:id/unlock', auth, allow('admin'), (req,res)=>{
  const target=db.prepare('SELECT username FROM users WHERE id=?').get(req.params.id);if(!target)return res.status(404).json({error:'用户不存在'});
  db.prepare('UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=?').run(req.params.id);audit(req.user,'unlock','user',Number(req.params.id),target.username);res.json({ok:true});
});
app.get('/api/backups', auth, allow('admin'), (req,res)=>res.json({
  backups:backups.listBackups(),
  settings:{enabled:process.env.AUTO_BACKUP_ENABLED!=='false',schedule:process.env.AUTO_BACKUP_CRON||'0 2 * * *',retention:Number(process.env.BACKUP_RETENTION||14),directory:backups.backupDir}
}));
app.post('/api/backups', auth, allow('admin'), async (req,res)=>{
  try{const backup=await backups.createBackup('manual');audit(req.user,'backup_create','database',null,backup.id);res.status(201).json(backup);}
  catch(error){res.status(500).json({error:`备份失败：${error.message}`});}
});
app.post('/api/backups/upload', auth, allow('admin'), backupUpload.single('file'), (req,res)=>{
  try{if(!req.file||!req.file.originalname.toLowerCase().endsWith('.db'))return res.status(400).json({error:'请选择 .db 备份文件'});const backup=backups.importBackup(req.file.buffer);audit(req.user,'backup_upload','database',null,backup.id);res.status(201).json(backup);}
  catch(error){res.status(400).json({error:`备份文件无效：${error.message}`});}
});
app.get('/api/backups/:id/download', auth, allow('admin'), (req,res)=>{
  try{const filePath=backups.resolveBackup(req.params.id);if(!fs.existsSync(filePath))return res.status(404).json({error:'备份不存在'});res.download(filePath,req.params.id);}
  catch(error){res.status(400).json({error:error.message});}
});
app.post('/api/backups/:id/restore', auth, allow('admin'), async (req,res)=>{
  try{const safety=await backups.createBackup('pre-restore');const counts=backups.restoreBackup(req.params.id);audit(req.user,'backup_restore','database',null,`恢复 ${req.params.id}，恢复前快照 ${safety.id}`);res.json({ok:true,safetyBackup:safety.id,counts});}
  catch(error){res.status(400).json({error:`恢复失败，当前数据未更改：${error.message}`});}
});
app.delete('/api/backups/:id', auth, allow('admin'), (req,res)=>{
  try{backups.deleteBackup(req.params.id);audit(req.user,'backup_delete','database',null,req.params.id);res.json({ok:true});}
  catch(error){res.status(400).json({error:error.message});}
});
app.get('/api/assets.csv', auth, (req, res) => {
  const rows = db.prepare('SELECT name,category,environment,owner,department,url,host,port,status,tags,maintenance_expires_at FROM assets ORDER BY id').all();
  const headers = Object.keys(rows[0] || {name:'',category:'',environment:'',owner:'',department:'',url:'',host:'',port:'',status:'',tags:'',maintenance_expires_at:''});
  const quote = v => `"${String(v ?? '').replaceAll('"','""')}"`;
  const csv = '\uFEFF' + [headers.join(','), ...rows.map(r => headers.map(h => quote(r[h])).join(','))].join('\r\n');
  res.type('text/csv').attachment('sqlark-assets.csv').send(csv);
});

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) return res.status(400).json({ error: error.code === 'LIMIT_FILE_SIZE' ? '文件不能超过5MB' : `文件上传失败：${error.message}` });
  if (error) return res.status(500).json({ error: '服务器处理请求失败' });
  next();
});

function startServer(port = Number(process.env.PORT || 3000), options = {}) {
  const { scheduleChecks = true, initialCheck = true } = options;
  if (scheduleChecks) {
    const minutes = Math.max(1, Number(process.env.CHECK_INTERVAL_MINUTES || 5));
    cron.schedule(`*/${minutes} * * * *`, () => runChecks().catch(console.error));
    if(process.env.AUTO_BACKUP_ENABLED!=='false'){
      const schedule=process.env.AUTO_BACKUP_CRON||'0 2 * * *';
      if(cron.validate(schedule))cron.schedule(schedule,async()=>{try{const backup=await backups.createBackup('auto');backups.pruneAutoBackups(Number(process.env.BACKUP_RETENTION||14));db.prepare("INSERT INTO audit_logs(username,action,target_type,detail) VALUES('system','backup_auto','database',?)").run(backup.id);console.log('Automatic database backup completed');}catch(error){console.error('Automatic database backup failed:',error);}});
      else console.error(`Invalid AUTO_BACKUP_CRON: ${schedule}`);
    }
  }
  const server = app.listen(port, () => {
    const actualPort = server.address()?.port || port;
    console.log(`SQLark Monitor: http://localhost:${actualPort}`);
    if (initialCheck) runChecks().catch(console.error);
  });
  return server;
}

if (require.main === module) startServer();

module.exports = { app, startServer };
