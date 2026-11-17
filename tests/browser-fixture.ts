// Isolated loopback-only UI fixture. No real accounts, keys or files are loaded.
// Production entrypoint always uses TLS, or the private container gateway.
import { mkdirSync, mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createApp } from '../server/app.ts';
import { digest, id } from '../server/store.ts';
mkdirSync('tmp', { recursive: true });
const port = Number(process.env.BROWSER_QA_PORT ?? 8081);
const app = createApp({ root: mkdtempSync(resolve('tmp/browser-')), origin: `http://localhost:${port}`, ...(process.env.FILE_QA === '1' ? { quota: 1024 ** 2 } : {}), ...(process.env.DELIVERY_QA === '1' ? { normalRate: 256 * 1024 } : {}), ...(process.env.MAINTENANCE_QA === '1' ? { storage: { globalQuota: 1024 ** 2, minFree: 0 } } : {}) });
const fixturePassword = 'Browser-QA-Only-2026';
const userId = await app.store.addUser('browser-admin', fixturePassword, 'admin', 'vip');
if (process.env.MAINTENANCE_QA === '1') {
  await app.store.addUser('browser-reader', fixturePassword);
  const fileId = id(), bytes = Buffer.from('SafeDrop 维护界面验收专用样本。');
  app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', fileId, userId, '08-保留样本.txt', bytes.length, digest(bytes), Date.now()); writeFileSync(join(app.store.root, 'objects', fileId), bytes);
  for (const [name, size, expired] of [['08-过期上传.bin', 96, true], ['08-活动上传.bin', 64, false]] as const) {
    const transferId = id(); app.store.run('INSERT INTO transfers VALUES(?,?,?,?,?,?,?)', transferId, userId, name, size, digest(Buffer.alloc(size)), 8, Date.now()); app.storage.touch(transferId); if (expired) app.store.run('UPDATE transfer_activity SET touched=0 WHERE id=?', transferId); writeFileSync(join(app.store.root, 'staging', transferId), Buffer.alloc(8));
  }
  const free = app.storage.free; app.storage.free = () => existsSync(join(app.store.root, 'simulate-pressure')) ? 0 : free();
  console.log('Maintenance UI fixture data: ' + app.store.root);
}
if (process.env.DELIVERY_QA === '1') {
  await app.store.addUser('browser-reader', fixturePassword);
  await app.store.addUser('browser-other', fixturePassword);
  const fileId = id(), bytes = Buffer.alloc(2 * 1024 ** 2), pattern = Buffer.from('SafeDrop 账号间受控交付验收。');
  for (let i = 0; i < bytes.length; i++) bytes[i] = pattern[i % pattern.length];
  app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', fileId, userId, '09-账号交付样本.bin', bytes.length, digest(bytes), Date.now());
  writeFileSync(join(app.store.root, 'objects', fileId), bytes);
}
if (process.env.FILE_QA === '1') {
  const bytes = Buffer.from('SafeDrop 文件管理验收专用样本。');
  for (const name of ['03-可删除样本.txt', '03-重命名样本.txt', '03-删除失败样本.txt']) {
    const fileId = id(); app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', fileId, userId, name, bytes.length, digest(bytes), Date.now());
    if (name.includes('失败')) { mkdirSync(join(app.store.root, 'objects', fileId)); writeFileSync(join(app.store.root, 'objects', fileId + '.saved'), bytes); }
    else writeFileSync(join(app.store.root, 'objects', fileId), bytes);
  }
  const transferId = id(); app.store.run('INSERT INTO transfers VALUES(?,?,?,?,?,?,?)', transferId, userId, '03-未完成上传.bin', 32768, digest(Buffer.alloc(32768)), 4096, Date.now());
  writeFileSync(join(app.store.root, 'staging', transferId), Buffer.alloc(4096));
}
app.server.listen(port, '127.0.0.1', () => console.log(`Isolated UI fixture: http://localhost:${port}`));
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => { void app.close().then(() => process.exit(0)); });
