const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const testDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sqlark-monitor-test-'));
process.env.NODE_ENV = 'test';
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'automated-test-secret';
process.env.ADMIN_PASSWORD = 'AutomatedTest123!';
process.env.CHECK_TIMEOUT_MS = '1000';
process.env.FAILURE_THRESHOLD = '1';
process.env.DB_CHECK_PROFILES_JSON = JSON.stringify({ mysql_test: { username:'monitor', password:'test-only-password' } });

const { startServer } = require('../src/server');
const { sendFeishu, setDatabaseAdaptersForTest, setNotificationFetchForTest } = require('../src/monitor');
const db = require('../src/db');
setDatabaseAdaptersForTest({ mysql: async () => 'MySQL 8.0-test' });

let server;
let baseUrl;
let adminToken;
let assetId;
let importedAssetId;
let databaseAssetId;

async function request(url, options = {}) {
  const response = await fetch(`${baseUrl}${url}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}), ...options.headers }
  });
  const body = await response.json();
  return { response, body };
}

async function login(username, password) {
  const captcha = await request('/api/captcha');
  return request('/api/login', { method: 'POST', body: JSON.stringify({ username, password, captcha_id: captcha.body.id, captcha_answer: 'TEST12' }) });
}

before(async () => {
  server = startServer(0, { scheduleChecks: false, initialCheck: false });
  await new Promise(resolve => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise(resolve => server.close(resolve));
  db.close();
  fs.rmSync(testDataDir, { recursive: true, force: true });
});

test('公开门户可在未登录时读取', async () => {
  const { response, body } = await request('/api/portal/public');
  assert.equal(response.status, 200);
  assert.equal(body.login_title, 'SQLark Monitor');
  assert.ok(Array.isArray(body.links));
});

test('飞书机器人告警支持签名并发送文本消息', async () => {
  process.env.FEISHU_WEBHOOK_URL='https://open.feishu.cn/open-apis/bot/v2/hook/test';
  process.env.FEISHU_WEBHOOK_SECRET='test-secret';
  let request;
  setNotificationFetchForTest(async (url, options) => { request={url:String(url),options}; return {ok:true,json:async()=>({code:0,msg:'success'})}; });
  await sendFeishu('[SQLark资产预警] MySQL 测试库','连续 3 次健康检查失败');
  const body=JSON.parse(request.options.body);
  assert.equal(request.url,process.env.FEISHU_WEBHOOK_URL);
  assert.equal(body.msg_type,'text');
  assert.match(body.content.text,/MySQL 测试库/);
  assert.ok(body.timestamp);
  assert.ok(body.sign);
  delete process.env.FEISHU_WEBHOOK_URL;
  delete process.env.FEISHU_WEBHOOK_SECRET;
  setNotificationFetchForTest(fetch);
});

test('管理员飞书配置优先于环境变量、加密保存并立即生效', async () => {
  const loggedIn=await login('admin','AutomatedTest123!'),settingsToken=loggedIn.body.token;
  let message;
  setNotificationFetchForTest(async (url,options)=>{message=JSON.parse(options.body);return{ok:true,json:async()=>({code:0,msg:'success'})};});
  const saved=await request('/api/settings/feishu',{method:'PUT',token:settingsToken,body:JSON.stringify({enabled:true,webhook_url:'https://open.feishu.cn/open-apis/bot/v2/hook/admin-test',secret:'admin-secret'})});
  assert.equal(saved.response.status,200);
  const settings=await request('/api/settings/feishu',{token:settingsToken});
  assert.deepEqual(settings.body,{source:'database',enabled:true,webhook_configured:true,secret_configured:true});
  const stored=db.prepare('SELECT feishu_webhook_url,feishu_secret_encrypted FROM portal_settings WHERE id=1').get();
  assert.notEqual(stored.feishu_secret_encrypted,'admin-secret');
  assert.doesNotMatch(stored.feishu_webhook_url,/admin-test/);
  assert.doesNotMatch(JSON.stringify(settings.body),/admin-secret|admin-test/);
  const tested=await request('/api/settings/feishu/test',{method:'POST',token:settingsToken,body:'{}'});
  assert.equal(tested.response.status,200);
  assert.match(message.content.text,/配置测试/);
  const restored=await request('/api/settings/feishu',{method:'PUT',token:settingsToken,body:JSON.stringify({use_env:true})});
  assert.equal(restored.response.status,200);
  setNotificationFetchForTest(fetch);
});

test('错误密码被拒绝，管理员可登录', async () => {
  const challenge = await request('/api/captcha');
  const invalidCaptcha = await request('/api/login', { method: 'POST', body: JSON.stringify({ username: 'admin', password: 'AutomatedTest123!', captcha_id: challenge.body.id, captcha_answer: 'WRONG1' }) });
  assert.equal(invalidCaptcha.response.status, 400);
  const reusedCaptcha = await request('/api/login', { method: 'POST', body: JSON.stringify({ username: 'admin', password: 'AutomatedTest123!', captcha_id: challenge.body.id, captcha_answer: 'TEST12' }) });
  assert.equal(reusedCaptcha.response.status, 400);
  const failed = await login('admin', 'wrong-password');
  assert.equal(failed.response.status, 401);
  const success = await login('admin', 'AutomatedTest123!');
  assert.equal(success.response.status, 200);
  assert.equal(success.body.user.role, 'admin');
  adminToken = success.body.token;
});

test('未登录不能访问资产接口', async () => {
  const { response } = await request('/api/assets');
  assert.equal(response.status, 401);
});

test('资产校验、创建、查询和更新', async () => {
  const invalid = await request('/api/assets', { method: 'POST', token: adminToken, body: JSON.stringify({ name: '', category: '服务器', owner: '' }) });
  assert.equal(invalid.response.status, 400);
  const created = await request('/api/assets', {
    method: 'POST', token: adminToken,
    body: JSON.stringify({ name: '自动化测试服务', category: '服务器', environment: '测试', owner: 'QA', protocol: 'tcp', host: '127.0.0.1', port: server.address().port, enabled: true })
  });
  assert.equal(created.response.status, 201);
  assetId = created.body.id;
  const listed = await request('/api/assets?q=自动化', { token: adminToken });
  assert.equal(listed.body.length, 1);
  assert.equal(listed.body[0].owner, 'QA');
  const updated = await request(`/api/assets/${assetId}`, {
    method: 'PUT', token: adminToken,
    body: JSON.stringify({ name: '自动化测试服务', category: '服务器', environment: '测试', owner: '质量团队', protocol: 'tcp', host: '127.0.0.1', port: server.address().port, enabled: true })
  });
  assert.equal(updated.response.status, 200);
});

test('手工巡检可将 TCP 资产标记为在线', async () => {
  const checked = await request('/api/checks/run', { method: 'POST', token: adminToken, body: '{}' });
  assert.equal(checked.response.status, 200);
  const assets = await request('/api/assets?q=自动化', { token: adminToken });
  assert.equal(assets.body[0].status, 'online');
  assert.ok(assets.body[0].last_latency_ms >= 0);
});

test('MySQL 专项检查使用配置引用、默认端口并记录版本', async () => {
  const invalid = await request('/api/assets', { method:'POST', token:adminToken, body:JSON.stringify({ name:'无凭据数据库', category:'数据库', owner:'DBA', protocol:'mysql', host:'127.0.0.1', database_name:'sqlark', secret_ref:'明文密码' }) });
  assert.equal(invalid.response.status,400);
  const created = await request('/api/assets', { method:'POST', token:adminToken, body:JSON.stringify({ name:'MySQL 测试库', category:'数据库', environment:'测试', owner:'DBA', protocol:'mysql', host:'127.0.0.1', database_name:'sqlark', secret_ref:'profile://mysql_test', enabled:true }) });
  assert.equal(created.response.status,201);
  databaseAssetId=created.body.id;
  await request('/api/checks/run',{method:'POST',token:adminToken,body:'{}'});
  const listed=await request('/api/assets?q=MySQL',{token:adminToken});
  assert.equal(listed.body[0].port,3306);
  assert.equal(listed.body[0].status,'online');
  assert.equal(listed.body[0].last_check_detail,'MySQL 8.0-test');
  assert.equal(listed.body[0].secret_ref,'profile://mysql_test');
  assert.equal(JSON.stringify(listed.body).includes('test-only-password'),false);
});

test('只读用户不能修改资产或登录页面', async () => {
  const createdUser = await request('/api/users', {
    method: 'POST', token: adminToken,
    body: JSON.stringify({ username: 'test_viewer', display_name: '测试只读用户', role: 'viewer', password: 'ViewerTest123!' })
  });
  assert.equal(createdUser.response.status, 201);
  const viewerLogin = await login('test_viewer', 'ViewerTest123!');
  const deniedAsset = await request('/api/assets', { method: 'POST', token: viewerLogin.body.token, body: JSON.stringify({ name: '越权资产', category: '其他', owner: 'viewer' }) });
  assert.equal(deniedAsset.response.status, 403);
  const deniedPortal = await request('/api/portal/login', { method: 'PUT', token: viewerLogin.body.token, body: JSON.stringify({ login_title: 'x', login_subtitle: 'x', login_html: '<p>x</p>' }) });
  assert.equal(deniedPortal.response.status, 403);
  const deniedFeishu = await request('/api/settings/feishu', { token:viewerLogin.body.token });
  assert.equal(deniedFeishu.response.status,403);
});

test('连续五次密码错误会锁定账号，管理员可解锁', async () => {
  const created = await request('/api/users', { method: 'POST', token: adminToken, body: JSON.stringify({ username: 'lock_test', display_name: '锁定测试', role: 'viewer', password: 'LockTestPass123!' }) });
  assert.equal(created.response.status, 201);
  for (let index=0; index<4; index++) {
    const failed = await login('lock_test', 'wrong-password');
    assert.equal(failed.response.status, 401);
  }
  const locked = await login('lock_test', 'wrong-password');
  assert.equal(locked.response.status, 423);
  assert.equal(locked.body.code, 'ACCOUNT_LOCKED');
  const correctButLocked = await login('lock_test', 'LockTestPass123!');
  assert.equal(correctButLocked.response.status, 423);
  const users = await request('/api/users', { token: adminToken });
  const target = users.body.find(item => item.username === 'lock_test');
  assert.ok(target.locked_until);
  const unlocked = await request(`/api/users/${target.id}/unlock`, { method: 'POST', token: adminToken, body: '{}' });
  assert.equal(unlocked.response.status, 200);
  const successful = await login('lock_test', 'LockTestPass123!');
  assert.equal(successful.response.status, 200);
});

test('CSV 文件可预览并以事务方式批量导入', async () => {
  const templateResponse = await fetch(`${baseUrl}/api/assets/import/template`, { headers: { Authorization: `Bearer ${adminToken}` } });
  assert.equal(templateResponse.status, 200);
  assert.match(templateResponse.headers.get('content-type'), /spreadsheetml/);
  const templateForm = new FormData();
  templateForm.append('file', new Blob([await templateResponse.arrayBuffer()]), 'template.xlsx');
  const xlsxPreviewResponse = await fetch(`${baseUrl}/api/assets/import/preview`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` }, body: templateForm });
  const xlsxPreview = await xlsxPreviewResponse.json();
  assert.equal(xlsxPreviewResponse.status, 200);
  assert.equal(xlsxPreview.valid, 1);
  const csv = '\uFEFF资产名称,资产分类,所属环境,负责人,部门,检查方式,主机地址,端口,标签,启用巡检\nCSV导入服务,服务器,测试,批量导入员,测试部,tcp,127.0.0.1,65530,"批量,CSV",是';
  const form = new FormData();
  form.append('file', new Blob([csv], { type: 'text/csv' }), 'assets.csv');
  const previewResponse = await fetch(`${baseUrl}/api/assets/import/preview`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` }, body: form });
  const preview = await previewResponse.json();
  assert.equal(previewResponse.status, 200);
  assert.equal(preview.total, 1);
  assert.equal(preview.valid, 1);
  const imported = await request('/api/assets/import', { method: 'POST', token: adminToken, body: JSON.stringify({ rows: preview.rows.map(item => item.data) }) });
  assert.equal(imported.response.status, 201);
  assert.equal(imported.body.imported, 1);
  const assets = await request('/api/assets?q=CSV导入服务', { token: adminToken });
  assert.equal(assets.body.length, 1);
  importedAssetId = assets.body[0].id;
  const duplicate = await request('/api/assets/import', { method: 'POST', token: adminToken, body: JSON.stringify({ rows: preview.rows.map(item => item.data) }) });
  assert.equal(duplicate.response.status, 400);
});

test('管理员可编辑登录页面并读取审计记录', async () => {
  const saved = await request('/api/portal/login', {
    method: 'PUT', token: adminToken,
    body: JSON.stringify({ login_title: 'SQLark QA', login_subtitle: '自动化测试门户', login_html: '<h1 style="color:red">欢迎</h1><script>alert(1)</script><img src=x onerror=alert(1)><iframe src="https://evil.example"></iframe><a href="javascript:alert(1)" onclick="alert(2)">危险链接</a><a href="https://example.com">安全链接</a><p>安全内容</p>' })
  });
  assert.equal(saved.response.status, 200);
  const portal = await request('/api/portal/public');
  assert.equal(portal.body.login_title, 'SQLark QA');
  assert.doesNotMatch(portal.body.login_html, /<script/i);
  assert.doesNotMatch(portal.body.login_html, /<iframe|<img|onerror|onclick|style=|javascript:/i);
  assert.match(portal.body.login_html, /href="https:\/\/example\.com"/);
  assert.match(portal.body.login_html, /rel="noopener noreferrer"/);
  const audit = await request('/api/audit', { token: adminToken });
  assert.equal(audit.response.status, 200);
  assert.ok(audit.body.rows.length >= 1);
});

test('审计日志支持组合筛选、分页和安全 CSV 导出', async () => {
  const insert=db.prepare("INSERT INTO audit_logs(username,action,target_type,target_id,detail,created_at) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP)");
  for(let index=0;index<12;index++)insert.run('filter_user','test_filter','asset',index+1,index===0?'=HYPERLINK("https://evil.example")':`筛选日志 ${index+1}`);
  const today=new Date().toISOString().slice(0,10);
  const filtered=await request(`/api/audit?username=filter_user&action=test_filter&target_type=asset&date_from=${today}&date_to=${today}&page=1&page_size=10`,{token:adminToken});
  assert.equal(filtered.response.status,200);
  assert.equal(filtered.body.total,12);
  assert.equal(filtered.body.rows.length,10);
  assert.equal(filtered.body.totalPages,2);
  const secondPage=await request('/api/audit?username=filter_user&action=test_filter&page=2&page_size=10',{token:adminToken});
  assert.equal(secondPage.body.rows.length,2);
  const csvResponse=await fetch(`${baseUrl}/api/audit.csv?username=filter_user&action=test_filter`,{headers:{Authorization:`Bearer ${adminToken}`}});
  assert.equal(csvResponse.status,200);
  const csv=await csvResponse.text();
  assert.match(csv,/filter_user/);
  assert.match(csv,/"'=HYPERLINK/);
});

test('管理员可备份、下载、上传并事务恢复数据库', async () => {
  const created = await request('/api/backups', { method:'POST', token:adminToken, body:'{}' });
  assert.equal(created.response.status,201);
  const backupId=created.body.id;
  const listed=await request('/api/backups',{token:adminToken});
  assert.equal(listed.response.status,200);
  assert.equal(listed.body.settings.enabled,true);
  assert.ok(listed.body.backups.some(item=>item.id===backupId));
  const download=await fetch(`${baseUrl}/api/backups/${encodeURIComponent(backupId)}/download`,{headers:{Authorization:`Bearer ${adminToken}`}});
  assert.equal(download.status,200);
  const backupBuffer=await download.arrayBuffer();
  assert.ok(backupBuffer.byteLength>1000);
  const marker=await request('/api/assets',{method:'POST',token:adminToken,body:JSON.stringify({name:'恢复测试临时资产',category:'其他',owner:'测试',protocol:'none',enabled:false})});
  assert.equal(marker.response.status,201);
  const restored=await request(`/api/backups/${encodeURIComponent(backupId)}/restore`,{method:'POST',token:adminToken,body:'{}'});
  assert.equal(restored.response.status,200);
  assert.ok(restored.body.safetyBackup.includes('pre-restore'));
  const markerAfterRestore=await request('/api/assets?q=恢复测试临时资产',{token:adminToken});
  assert.equal(markerAfterRestore.body.length,0);
  const uploadForm=new FormData();uploadForm.append('file',new Blob([backupBuffer]),'uploaded.db');
  const uploadedResponse=await fetch(`${baseUrl}/api/backups/upload`,{method:'POST',headers:{Authorization:`Bearer ${adminToken}`},body:uploadForm});
  assert.equal(uploadedResponse.status,201);
  const removed=await request(`/api/backups/${encodeURIComponent(backupId)}`,{method:'DELETE',token:adminToken});
  assert.equal(removed.response.status,200);
});

test('仪表盘统计正确，管理员可删除资产', async () => {
  const dashboard = await request('/api/dashboard', { token: adminToken });
  assert.equal(dashboard.body.totals.total, 3);
  assert.equal(dashboard.body.totals.online, 2);
  const removed = await request(`/api/assets/${assetId}`, { method: 'DELETE', token: adminToken });
  assert.equal(removed.response.status, 200);
  await request(`/api/assets/${importedAssetId}`, { method: 'DELETE', token: adminToken });
  await request(`/api/assets/${databaseAssetId}`, { method: 'DELETE', token: adminToken });
  const assets = await request('/api/assets', { token: adminToken });
  assert.equal(assets.body.length, 0);
});

test('同一 IP 超过登录频率上限会被限流', async () => {
  let last;
  for (let index=0; index<9; index++) last=await login('missing_user','wrong-password');
  assert.equal(last.response.status,429);
  assert.match(last.body.error,/频繁/);
});
