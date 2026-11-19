import { spawn } from 'node:child_process';
import { request } from 'node:https';
import { readFileSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createServer } from 'node:net';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { setTimeout as pause } from 'node:timers/promises';
import assert from 'node:assert/strict';
import { certificates } from '../scripts/certificates.ts';
mkdirSync('tmp', { recursive: true });
const data = mkdtempSync(resolve('tmp/runtime-'));
certificates(join(data,'tls'));
// Never bind the retained verification container's 18443 port or reuse its accounts/keys.
const reservation=createServer();reservation.listen(0,'127.0.0.1');await once(reservation,'listening');
const port=(reservation.address() as {port:number}).port;await new Promise<void>(yes=>reservation.close(()=>yes()));
const child = spawn(process.execPath, ['build/server/index.js'], { env: { ...process.env, PORT: String(port), APP_ORIGIN: `https://localhost:${port}`, DATA_DIR: data, TLS_CERT:join(data,'tls/server.crt'), TLS_KEY:join(data,'tls/server.key') }, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
child.stderr.on('data', () => {}); child.stdout.on('data', () => {});
const ca = readFileSync(join(data,'tls/ca.crt'));
const get = (path: string, servername = 'localhost') => new Promise<{ status?: number; headers: Record<string, any>; body: Buffer }>((yes, no) => { const r = request({ hostname: '127.0.0.1', port, path, ca, servername, timeout: 1500 }, res => { const chunks:Buffer[]=[]; res.on('data', x => chunks.push(Buffer.from(x))); res.on('end', () => yes({ status: res.statusCode, headers: res.headers, body:Buffer.concat(chunks) })); }); r.on('timeout', () => r.destroy(new Error('TIMEOUT'))); r.on('error', no); r.end(); });
try {
  let ready = false; for (let i = 0; i < 50; i++) { try { await get('/health'); ready = true; break; } catch { await pause(100); } }
  assert.equal(ready, true);assert.equal(child.exitCode,null); const health = await get('/health'); assert.equal(health.status, 200); assert.equal(JSON.parse(health.body.toString()).protocol, 'SFT/1');
  const page = await get('/'); assert.equal(page.status, 200); assert.match(page.body.toString(), /SafeDrop/); assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);
  const asset=/src="([^"]+\.js)"/.exec(page.body.toString())![1],resource=await get(asset);assert.equal(resource.status,200);assert.deepEqual(resource.body,readFileSync('dist'+asset));
  await assert.rejects(get('/health', 'wrong-host.invalid'));
  if(process.env.RUNTIME_REPORT)writeFileSync(process.env.RUNTIME_REPORT,JSON.stringify({created:new Date().toISOString(),ok:true,node:process.version,scope:'isolated compiled entrypoint; temporary CA/data and ephemeral loopback port; not containers',health:health.status,asset,sha256:createHash('sha256').update(resource.body).digest('hex'),strictTls:true,hostnameMismatchRejected:true,csp:true,originalDataChanged:false},null,2));
  console.log('PASS compiled runtime: isolated HTTPS health, exact built Vue asset, CSP and hostname mismatch rejection');
} finally { if(child.exitCode===null&&child.signalCode===null){child.kill();await once(child, 'exit');} }
