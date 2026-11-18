import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { resolve, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { WebSocket } from 'ws';
import { createApp, type Config } from '../server/app.ts';
import { Store, digest, verifyAudit } from '../server/store.ts';
import { createBackup, verifyBackup, restoreBackup, type BackupAccess } from '../server/backup.ts';
import { changeBackupKeys, readBackupKeys } from '../server/backup-keys.ts';
import { certificates } from '../scripts/certificates.ts';
import { Peer, type Result } from './suite.ts';

export async function runBackupEncryptionSuite(onResult?: (result: Result) => void) {
  mkdirSync('tmp', { recursive: true }); const root = mkdtempSync(resolve('tmp/backup-security-')); certificates(join(root, 'tls'));
  const password = randomBytes(24).toString('base64url'), ca = readFileSync(join(root, 'tls/ca.crt')), results: Result[] = [];
  async function fixture() {
    const config: Config = { root: mkdtempSync(join(root, 'data-')), origin: 'https://localhost', tls: { cert: readFileSync(join(root, 'tls/server.crt')), key: readFileSync(join(root, 'tls/server.key')) }, loginLimit: 1000, normalRate: 64 * 1024 ** 2, storage: { minFree: 0, backupCount: 20 } };
    const app = createApp(config), keyFile = config.root + '.backup-keys', backups = config.root + '.backups';
    await app.store.addUser('backup-admin', password, 'admin'); await app.store.addUser('backup-owner', password); app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening');
    async function login(name: string) { const ws = new WebSocket(`wss://127.0.0.1:${(app.server.address() as { port: number }).port}/ws`, { ca, rejectUnauthorized: true, headers: { Origin: config.origin } }); await once(ws, 'open'); const peer = new Peer(ws); await peer.rpc('auth.password', { name, password }); return peer; }
    const admin = await login('backup-admin'), owner = await login('backup-owner');
    const upload = async (bytes: Buffer) => { const id = String((await owner.rpc('upload.init', { name: '加密备份样本.bin', size: bytes.length, sha256: digest(bytes) })).meta.id); if (bytes.length) await owner.rpc('upload.chunk', { transferId: id, offset: 0 }, bytes); await owner.rpc('upload.finish', { transferId: id }); return id; };
    const access: BackupAccess = { keyFile }, backup = async (meta = {}) => { const result = await admin.rpc('maintenance.backup', meta); return { source: join(backups, String(result.meta.id)), id: result.meta.id, encrypted: result.meta.encrypted, keyId: result.meta.keyId }; };
    return { root, config, app, keyFile, backups, access, admin, owner, upload, backup, init: () => changeBackupKeys(keyFile), close: async () => { assert.equal(verifyAudit(app.store.all('SELECT * FROM audit')).ok, true); assert.equal(JSON.stringify(app.store.all('SELECT * FROM audit')).includes(password), false); await app.close(); } };
  }
  type Fixture = Awaited<ReturnType<typeof fixture>>;
  async function run(name: string, work: (f: Fixture) => Promise<void>) {
    const at = performance.now(); let f: Fixture | undefined, failure: unknown;
    try { f = await fixture(); await work(f); } catch (error) { failure = error; }
    finally { if (f) try { await f.close(); } catch (error) { failure ??= error; } }
    const result: Result = { name, ok: !failure, ms: Math.round(performance.now() - at), detail: failure instanceof Error ? failure.message : failure ? String(failure) : '真实 TLS/WSS、加密副本、密钥和隔离目录断言通过；未改动正式数据。' }; results.push(result); onResult?.(result);
  }
  await run('备份加密：缺钥拒绝创建且不回退明文，原文件服务保持可用', async f => {
    const before = await f.admin.rpc('maintenance.status'); assert.equal((before.meta.backupEncryption as any).configured, false);
    await assert.rejects(f.admin.rpc('maintenance.backup'), /BACKUP_KEY_MISSING/); assert.equal(existsSync(f.backups), false);
    assert.equal((await f.owner.rpc('files.list')).meta.ok, true); await assert.rejects(f.owner.rpc('maintenance.status'), /FORBIDDEN/);
  });
  await run('备份密钥：初始化后无需重启可用，接口和审计不返回密钥材料', async f => {
    const initialized = await f.init(), ring = await readBackupKeys(f.keyFile), status = await f.admin.rpc('maintenance.status');
    assert.equal((status.meta.backupEncryption as any).configured, true); assert.equal((status.meta.backupEncryption as any).activeKeyId, initialized.activeKeyId);
    for (const key of ring.keys) { assert.equal(JSON.stringify(status.meta).includes(key.material), false); assert.equal(JSON.stringify(f.app.store.all('SELECT * FROM audit')).includes(key.material), false); }
    await assert.rejects(changeBackupKeys(f.keyFile), /BACKUP_KEY_EXISTS/);
  });
  await run('备份密文：数据库、空文件和内容均加密，外部清单不含原始路径', async f => {
    await f.init(); const content = randomBytes(12345), id = await f.upload(content); await f.upload(Buffer.alloc(0)); const result = await f.backup({ legacy: true });
    assert.equal(result.encrypted, true); const header = JSON.parse(readFileSync(join(result.source, 'manifest.json'), 'utf8')); assert.equal(header.version, 2); assert.equal('entries' in header, false); assert.equal('checkpoint' in header, false);
    assert.equal(existsSync(join(result.source, 'safedrop.sqlite')), false); assert.equal(existsSync(join(result.source, 'objects', id)), false);
    const manifest = await verifyBackup(result.source, undefined, f.access), target = join(f.root, 'restored-' + crypto.randomUUID()); await restoreBackup(result.source, target, manifest.checkpoint, f.access); assert.deepEqual(readFileSync(join(target, 'objects', id)), content);
  });
  await run('备份轮换：新副本切换密钥，原副本仍由保留旧钥校验恢复', async f => {
    await f.init(); await f.upload(randomBytes(50)); const first = await f.backup(); await changeBackupKeys(f.keyFile, true); const second = await f.backup(); assert.notEqual(first.keyId, second.keyId);
    for (const result of [first, second]) await restoreBackup(result.source, join(f.root, 'rotation-' + crypto.randomUUID()), undefined, f.access);
    const state = (await f.admin.rpc('maintenance.status')).meta; assert.equal((state.backups as any[]).length, 2); assert.equal((state.backupEncryption as any).retainedKeys, 2);
  });
  await run('备份错钥：缺失、错误材料或缺少旧钥均拒绝，不创建恢复目录', async f => {
    await f.init(); const first = await f.backup(), target = join(f.root, 'wrong-' + crypto.randomUUID()); await assert.rejects(restoreBackup(first.source, target), /BACKUP_KEY_MISSING/);
    const original = await readBackupKeys(f.keyFile), wrongFile = join(f.root, 'wrong-' + crypto.randomUUID() + '.backup-keys'), wrong = JSON.parse(JSON.stringify(original)); wrong.keys[0].material = randomBytes(32).toString('base64'); writeFileSync(wrongFile, JSON.stringify(wrong), { mode: 0o600 });
    await assert.rejects(restoreBackup(first.source, target, undefined, { keyFile: wrongFile }), /BACKUP_AUTH_FAILED/); await changeBackupKeys(f.keyFile, true);
    const changed = await readBackupKeys(f.keyFile); changed.keys = changed.keys.filter(key => key.id === changed.active); writeFileSync(f.keyFile, JSON.stringify(changed)); await assert.rejects(restoreBackup(first.source, target, undefined, f.access), /BACKUP_KEY_NOT_FOUND/); assert.equal(existsSync(target), false);
  });
  await run('备份篡改：清单、密文及跨副本替换无法通过认证', async f => {
    await f.init(); await f.upload(randomBytes(64)); const first = await f.backup(), second = await f.backup(), path = join(first.source, 'sealed', '000002.bin'), original = readFileSync(path);
    writeFileSync(path, readFileSync(join(second.source, 'sealed', '000002.bin'))); await assert.rejects(verifyBackup(first.source, undefined, f.access), /BACKUP_AUTH_FAILED/); writeFileSync(path, original);
    const headerPath = join(first.source, 'manifest.json'), bytes = readFileSync(headerPath), header = JSON.parse(bytes.toString()); header.created = new Date(Date.now() + 1000).toISOString(); writeFileSync(headerPath, JSON.stringify(header)); await assert.rejects(verifyBackup(first.source, undefined, f.access), /BACKUP_AUTH_FAILED/); writeFileSync(headerPath, bytes);
    const altered = Buffer.from(original); altered[altered.length - 1] ^= 1; writeFileSync(path, altered); const target = join(f.root, 'tamper-' + crypto.randomUUID()); await assert.rejects(restoreBackup(first.source, target, undefined, f.access), /BACKUP_AUTH_FAILED/); assert.equal(existsSync(target), false);
  });
  await run('备份兼容：旧明文副本需显式确认，新格式不能通过降级绕过认证', async f => {
    await f.init(); const old = await createBackup(f.app.store, f.backups, { quota: 64 * 1024 ** 2, count: 20, minFree: 0, pending: 0, legacy: true }), source = join(f.backups, old.id);
    await assert.rejects(verifyBackup(source), /BACKUP_PLAINTEXT_CONFIRMATION_REQUIRED/); assert.equal((await verifyBackup(source, undefined, { allowPlaintext: true })).encrypted, false);
    const result = await f.backup(), path = join(result.source, 'manifest.json'), header = JSON.parse(readFileSync(path, 'utf8')); header.version = 1; writeFileSync(path, JSON.stringify(header)); await assert.rejects(verifyBackup(result.source, undefined, f.access), /BACKUP_PLAINTEXT_CONFIRMATION_REQUIRED/);
    const list = (await f.admin.rpc('maintenance.status')).meta.backups as any[]; assert.equal(list.find(row => row.id === old.id).encrypted, false);
  });
  await run('备份写入故障：失败密文占份额、无明文副本，原文件和服务保留', async f => {
    await f.init(); const bytes = randomBytes(53), id = await f.upload(bytes); f.config.storage!.backupCount = 1;
    const original = fsPromises.open; fsPromises.open = async (...args) => { const handle = await original(...args); if (String(args[0]).includes('.partial') && String(args[0]).endsWith('000002.bin')) handle.write = (async () => { throw Object.assign(new Error('injected encrypted write failure'), { code: 'ENOSPC' }); }) as typeof handle.write; return handle; }; syncBuiltinESMExports();
    try { await assert.rejects(f.admin.rpc('maintenance.backup'), /INTERNAL_ERROR/); } finally { fsPromises.open = original; syncBuiltinESMExports(); }
    assert.equal(((await f.admin.rpc('maintenance.status')).meta.backups as any[]).length, 0); await assert.rejects(f.admin.rpc('maintenance.backup'), /BACKUP_CAPACITY/);
    const partial = join(f.backups, readdirSync(f.backups)[0]); assert.equal(existsSync(join(partial, 'safedrop.sqlite')), false); assert.deepEqual(readFileSync(join(f.config.root, 'objects', id)), bytes); assert.equal((await f.owner.rpc('ping')).meta.ok, true);
  });
  return results;
}
