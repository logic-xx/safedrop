// Isolated loopback-only UI fixture. No real accounts, keys or files are loaded.
// Production entrypoint always uses TLS, or the private container gateway.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createApp } from '../server/app.ts';
import { digest, id } from '../server/store.ts';
mkdirSync('tmp', { recursive: true });
const app = createApp({ root: mkdtempSync(resolve('tmp/browser-')), origin: 'http://localhost:8081', ...(process.env.FILE_QA === '1' ? { quota: 1024 ** 2 } : {}), ...(process.env.DELIVERY_QA === '1' ? { normalRate: 256 * 1024 } : {}) });
const fixturePassword = 'Browser-QA-Only-2026';
const userId = await app.store.addUser('browser-admin', fixturePassword, 'admin', 'vip');
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
app.server.listen(8081, '127.0.0.1', () => console.log('Isolated UI fixture: http://localhost:8081'));
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => { void app.close().then(() => process.exit(0)); });
