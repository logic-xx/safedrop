import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createApp } from '../server/app.ts';
import { createBackup } from '../server/backup.ts';
import { digest } from '../server/store.ts';

// New isolated fixture only; never rerun or replace the existing 08/MFA fixtures.
mkdirSync('tmp', { recursive: true }); const fixture = mkdtempSync(resolve('tmp/browser-backup-')), root = join(fixture, 'data');
const app = createApp({ root, origin: 'http://localhost:1602', webRoot: resolve('dist'), reportPath: resolve('reports/latest.json'), storage: { minFree: 0, backupCount: 3, backupQuota: 16 * 1024 ** 2 } });
const password = randomBytes(24).toString('base64url'), admin = await app.store.addUser('backup-browser-admin', password, 'admin'); await app.store.addUser('backup-browser-reader', password);
const bytes = Buffer.from('temporary encrypted backup acceptance sample\n'), id = crypto.randomUUID();
writeFileSync(join(root, 'objects', id), bytes); app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', id, admin, '加密备份保留样本.txt', bytes.length, digest(bytes), Date.now()); app.store.audit(admin, 'fixture', 'allowed');
await createBackup(app.store, root + '.backups', { quota: 16 * 1024 ** 2, count: 3, minFree: 0, pending: 0, legacy: true });
writeFileSync(join(fixture, 'credentials.json'), JSON.stringify({ admin: 'backup-browser-admin', reader: 'backup-browser-reader', password }), { mode: 0o600 });
writeFileSync(join(fixture, 'fixture.json'), JSON.stringify({ root, backups: root + '.backups', keyFile: root + '.backup-keys', sample: { id, size: bytes.length, sha256: digest(bytes) }, origin: 'http://localhost:1602' }), { mode: 0o600 });
app.server.listen(1602, '127.0.0.1', () => console.log(JSON.stringify({ ready: true, origin: 'http://localhost:1602', fixture })));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { void app.close().then(() => process.exit(0)); });
