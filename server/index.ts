import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createApp } from './app.ts';
const proxy = process.env.TRUST_PROXY === '1';
const port = Number(process.env.PORT ?? (proxy ? 8080 : 8443));
const app = createApp({
  root: resolve(process.env.DATA_DIR ?? '.local/data'),
  origin: process.env.APP_ORIGIN ?? 'https://localhost:8443',
  tls: proxy ? undefined : { cert: readFileSync(process.env.TLS_CERT ?? '.local/tls/server.crt'), key: readFileSync(process.env.TLS_KEY ?? '.local/tls/server.key') },
});
app.server.listen(port, proxy ? '0.0.0.0' : '127.0.0.1', () => console.log(`SafeDrop ready: ${process.env.APP_ORIGIN ?? 'https://localhost:8443'} · SFT/1`));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { void app.close().then(() => process.exit(0)); });
