const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const testDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sqlark-monitor-test-'));
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'automated-test-secret';
process.env.ADMIN_PASSWORD = 'AutomatedTest123!';
process.env.CHECK_TIMEOUT_MS = '1000';
process.env.FAILURE_THRESHOLD = '1';

const { startServer } = require('../src/server');
const db = require('../src/db');

let server;
let baseUrl;
let adminToken;
let assetId;
let importedAssetId;

async function request(url, options = {}) {
  const response = await fetch(`${baseUrl}${url}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}), ...options.headers }
  });
  const body = await response.json();
  return { response, body };
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

test('错误密码被拒绝，管理员可登录', async () => {
  const failed = await request('/api/login', { method: 'POST', body: JSON.stringify({ username: 'admin', password: 'wrong-password' }) });
  assert.equal(failed.response.status, 401);
  const success = await request('/api/login', { method: 'POST', body: JSON.stringify({ username: 'admin', password: 'AutomatedTest123!' }) });
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

test('只读用户不能修改资产或登录页面', async () => {
  const createdUser = await request('/api/users', {
    method: 'POST', token: adminToken,
    body: JSON.stringify({ username: 'test_viewer', display_name: '测试只读用户', role: 'viewer', password: 'ViewerTest123!' })
  });
  assert.equal(createdUser.response.status, 201);
  const login = await request('/api/login', { method: 'POST', body: JSON.stringify({ username: 'test_viewer', password: 'ViewerTest123!' }) });
  const deniedAsset = await request('/api/assets', { method: 'POST', token: login.body.token, body: JSON.stringify({ name: '越权资产', category: '其他', owner: 'viewer' }) });
  assert.equal(deniedAsset.response.status, 403);
  const deniedPortal = await request('/api/portal/login', { method: 'PUT', token: login.body.token, body: JSON.stringify({ login_title: 'x', login_subtitle: 'x', login_html: '<p>x</p>' }) });
  assert.equal(deniedPortal.response.status, 403);
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
    body: JSON.stringify({ login_title: 'SQLark QA', login_subtitle: '自动化测试门户', login_html: '<h1>欢迎</h1><script>alert(1)</script><p>安全内容</p>' })
  });
  assert.equal(saved.response.status, 200);
  const portal = await request('/api/portal/public');
  assert.equal(portal.body.login_title, 'SQLark QA');
  assert.doesNotMatch(portal.body.login_html, /<script/i);
  const audit = await request('/api/audit', { token: adminToken });
  assert.equal(audit.response.status, 200);
  assert.ok(audit.body.length >= 1);
});

test('仪表盘统计正确，管理员可删除资产', async () => {
  const dashboard = await request('/api/dashboard', { token: adminToken });
  assert.equal(dashboard.body.totals.total, 2);
  assert.equal(dashboard.body.totals.online, 1);
  const removed = await request(`/api/assets/${assetId}`, { method: 'DELETE', token: adminToken });
  assert.equal(removed.response.status, 200);
  await request(`/api/assets/${importedAssetId}`, { method: 'DELETE', token: adminToken });
  const assets = await request('/api/assets', { token: adminToken });
  assert.equal(assets.body.length, 0);
});
