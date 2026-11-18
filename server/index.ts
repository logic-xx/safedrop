import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createApp } from './app.ts';
import { integer } from './store.ts';
const proxy = process.env.TRUST_PROXY === '1';
const port = Number(process.env.PORT ?? (proxy ? 8080 : 8443));
const configured = (key: string, fallback: number) => process.env[key] === undefined ? fallback : integer(Number(process.env[key]));
const app = createApp({
  root: resolve(process.env.DATA_DIR ?? '.local/data'),
  origin: process.env.APP_ORIGIN ?? 'https://localhost:8443',
  mfaKeyFile: process.env.MFA_KEY_FILE,
  tls: proxy ? undefined : { cert: readFileSync(process.env.TLS_CERT ?? '.local/tls/server.crt'), key: readFileSync(process.env.TLS_KEY ?? '.local/tls/server.key') },
  storage: { globalCount: configured('GLOBAL_OBJECT_LIMIT', 10000), globalQuota: configured('GLOBAL_STORAGE_BYTES', 10 * 1024 ** 3), minFree: configured('MIN_FREE_BYTES', 256 * 1024 ** 2), auditLimit: configured('AUDIT_LIMIT_BYTES', 64 * 1024 ** 2), staleMs: configured('UPLOAD_TTL_HOURS', 168) * 3600000, cleanupIntervalMs: configured('CLEANUP_INTERVAL_SECONDS', 0) * 1000, backupRoot: process.env.BACKUP_DIR, backupQuota: configured('BACKUP_LIMIT_BYTES', 20 * 1024 ** 3), backupCount: configured('BACKUP_MAX_COUNT', 3) },
});
app.server.listen(port, proxy ? '0.0.0.0' : '127.0.0.1', () => console.log(`SafeDrop ready: ${process.env.APP_ORIGIN ?? 'https://localhost:8443'} · SFT/1`));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { void app.close().then(() => process.exit(0)); });
