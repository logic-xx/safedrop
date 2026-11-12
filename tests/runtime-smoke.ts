import { spawn } from 'node:child_process';
import { request } from 'node:https';
import { readFileSync, mkdirSync, mkdtempSync } from 'node:fs';
import { resolve } from 'node:path';
import { once } from 'node:events';
import { setTimeout as pause } from 'node:timers/promises';
import assert from 'node:assert/strict';
mkdirSync('tmp', { recursive: true });
const data = mkdtempSync(resolve('tmp/runtime-'));
const child = spawn(process.execPath, ['build/server/index.js'], { env: { ...process.env, PORT: '18443', APP_ORIGIN: 'https://localhost:18443', DATA_DIR: data }, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
child.stderr.on('data', () => {}); child.stdout.on('data', () => {});
const ca = readFileSync('.local/tls/ca.crt');
const get = (path: string, servername = 'localhost') => new Promise<{ status?: number; headers: Record<string, any>; body: string }>((yes, no) => { const r = request({ hostname: '127.0.0.1', port: 18443, path, ca, servername, timeout: 1500 }, res => { let body = ''; res.on('data', x => body += x); res.on('end', () => yes({ status: res.statusCode, headers: res.headers, body })); }); r.on('timeout', () => r.destroy(new Error('TIMEOUT'))); r.on('error', no); r.end(); });
try {
  let ready = false; for (let i = 0; i < 50; i++) { try { await get('/health'); ready = true; break; } catch { await pause(100); } }
  assert.equal(ready, true); const health = await get('/health'); assert.equal(health.status, 200); assert.equal(JSON.parse(health.body).protocol, 'SFT/1');
  const page = await get('/'); assert.equal(page.status, 200); assert.match(page.body, /SafeDrop/); assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);
  await assert.rejects(get('/health', 'wrong-host.invalid'));
  console.log('PASS compiled runtime: HTTPS health, built Vue page, CSP headers, hostname mismatch rejection');
} finally { child.kill(); await once(child, 'exit'); }
