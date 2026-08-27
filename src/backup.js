const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
const db = require('./db');

const backupDir = path.join(path.dirname(db.name), 'backups');
fs.mkdirSync(backupDir, { recursive: true });
const requiredTables = ['users','assets','alerts','audit_logs','portal_settings'];
const optionalTables = ['credential_profiles'];

function backupId(type = 'manual') {
  return `${new Date().toISOString().replace(/[:.]/g,'-')}-${Math.random().toString(16).slice(2,8)}-${type}.db`;
}
function resolveBackup(id) {
  if (!/^[a-zA-Z0-9._-]+\.db$/.test(String(id || ''))) throw new Error('备份文件名无效');
  return path.join(backupDir, id);
}
function inspectBackup(filePath) {
  const source = new Database(filePath, { readonly:true, fileMustExist:true });
  try {
    if (source.pragma('integrity_check', { simple:true }) !== 'ok') throw new Error('SQLite 完整性检查失败');
    const tables = new Set(source.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(row=>row.name));
    const missing = requiredTables.filter(table=>!tables.has(table));
    if (missing.length) throw new Error(`缺少必要数据表：${missing.join(', ')}`);
    if(source.pragma('foreign_key_check').length)throw new Error('外键完整性检查失败');
    const counts=Object.fromEntries([...requiredTables,...optionalTables.filter(table=>tables.has(table))].map(table=>[table,source.prepare(`SELECT COUNT(*) count FROM "${table}"`).get().count]));
    if(counts.portal_settings<1)throw new Error('缺少门户配置数据');
    if(!source.prepare("SELECT 1 FROM users WHERE role='admin' AND active=1 LIMIT 1").get())throw new Error('备份中没有可用管理员账号');
    return counts;
  } finally { source.close(); }
}
async function createBackup(type = 'manual') {
  const id = backupId(type), finalPath=resolveBackup(id), tempPath=`${finalPath}.tmp`;
  try {
    await db.backup(tempPath);
    const counts=inspectBackup(tempPath);
    fs.renameSync(tempPath,finalPath);
    return {...describeBackup(id),counts};
  } catch(error) { if(fs.existsSync(tempPath))fs.rmSync(tempPath,{force:true}); throw error; }
}
function describeBackup(id) {
  const stat=fs.statSync(resolveBackup(id));
  return {id,type:id.includes('-auto.db')?'auto':id.includes('-pre-restore.db')?'pre-restore':'manual',size:stat.size,createdAt:stat.birthtime.toISOString(),modifiedAt:stat.mtime.toISOString()};
}
function listBackups() {
  return fs.readdirSync(backupDir).filter(name=>name.endsWith('.db')).map(describeBackup).sort((a,b)=>b.modifiedAt.localeCompare(a.modifiedAt));
}
function deleteBackup(id) { const filePath=resolveBackup(id);if(!fs.existsSync(filePath))throw new Error('备份不存在');fs.rmSync(filePath); }
function pruneAutoBackups(retention) {
  const automatic=listBackups().filter(item=>item.type==='auto');
  for(const backup of automatic.slice(Math.max(1,retention)))deleteBackup(backup.id);
}
function restoreBackup(id) {
  const filePath=resolveBackup(id); const counts=inspectBackup(filePath); const source=new Database(filePath,{readonly:true,fileMustExist:true});
  try {
    const snapshot={};
    const sourceTables=new Set(source.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(row=>row.name));
    const restoreTables=[...requiredTables,...optionalTables.filter(table=>sourceTables.has(table))];
    for(const table of restoreTables){
      const currentColumns=new Set(db.pragma(`table_info("${table}")`).map(column=>column.name));
      const sourceColumns=source.pragma(`table_info("${table}")`).map(column=>column.name).filter(column=>currentColumns.has(column));
      snapshot[table]={columns:sourceColumns,rows:source.prepare(`SELECT ${sourceColumns.map(column=>`"${column}"`).join(',')} FROM "${table}"`).all()};
    }
    db.transaction(()=>{
      for(const table of restoreTables.slice().reverse())db.prepare(`DELETE FROM "${table}"`).run();
      for(const table of restoreTables){
        const {columns,rows}=snapshot[table];if(!rows.length)continue;
        const placeholders=columns.map(()=>'?').join(',');const statement=db.prepare(`INSERT INTO "${table}" (${columns.map(column=>`"${column}"`).join(',')}) VALUES (${placeholders})`);
        for(const row of rows)statement.run(...columns.map(column=>row[column]));
      }
    })();
    return counts;
  } finally { source.close(); }
}
function importBackup(buffer) {
  const id=backupId('manual'),finalPath=resolveBackup(id),tempPath=`${finalPath}.upload`;
  fs.writeFileSync(tempPath,buffer,{flag:'wx'});
  try{const counts=inspectBackup(tempPath);fs.renameSync(tempPath,finalPath);return{...describeBackup(id),counts};}
  catch(error){if(fs.existsSync(tempPath))fs.rmSync(tempPath,{force:true});throw error;}
}

module.exports={backupDir,createBackup,listBackups,deleteBackup,pruneAutoBackups,restoreBackup,importBackup,inspectBackup,resolveBackup};
