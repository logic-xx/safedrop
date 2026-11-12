// Isolated loopback-only UI fixture. No real accounts, keys or files are loaded.
// Production entrypoint always uses TLS, or the private container gateway.
import { mkdirSync, mkdtempSync } from 'node:fs';
import { resolve } from 'node:path';
import { createApp } from '../server/app.ts';
mkdirSync('tmp', { recursive: true });
const app = createApp({ root: mkdtempSync(resolve('tmp/browser-')), origin: 'http://localhost:8081' });
await app.store.addUser('browser-admin', 'Browser-QA-Only-2026', 'admin', 'vip');
app.server.listen(8081, '127.0.0.1', () => console.log('Isolated UI fixture: http://localhost:8081'));
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => { void app.close().then(() => process.exit(0)); });
