import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rename, unlink } from 'node:fs/promises';
import { resolve, join, sep } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { createServer as createListener } from 'node:net';
import { request } from 'node:https';
import { checkServerIdentity } from 'node:tls';
import { once } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import { setTimeout as pause } from 'node:timers/promises';
import { WebSocket, WebSocketServer } from 'ws';
import { gatewayPolicy } from '../scripts/gateway-policy.mjs';

const baseline = process.env.GATEWAY_BASELINE_BINARY, candidate = process.env.GATEWAY_BINARY;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
test('Gateway upgrade retains the original CA, issues a new leaf and proxies HTTPS/WSS', {
  skip: !baseline || !candidate, timeout: 90000,
}, async () => {
  await unlink('reports/ci/gateway-upgrade.json').catch(error => { if (error.code !== 'ENOENT') throw error; });
  await mkdir('tmp', { recursive: true });
  const root = await mkdtemp(resolve('tmp/gateway-upgrade-'));
  const env = { ...process.env, XDG_DATA_HOME: join(root, 'data'), XDG_CONFIG_HOME: join(root, 'config') };
  const configuration = join(root, 'Caddyfile'), children = [];
  const backend = createServer((_req, res) => { res.writeHead(200); res.end('gateway-fixture'); });
  const sockets = new WebSocketServer({ server: backend });
  sockets.on('connection', ws => ws.on('message', (data, binary) => ws.send(data, { binary })));
  const run = (binary, args, extraEnv = env) => {
    const result = spawnSync(resolve(binary), args, { env: extraEnv, encoding: 'utf8', windowsHide: true, timeout: 15000 });
    assert.equal(result.status, 0, 'Gateway command failed; inspect the private fixture');
    return result.stdout;
  };
  let log = '', active;
  async function stop() {
    if (!active || active.exitCode !== null || active.signalCode !== null) return;
    const child = active, exited = once(child, 'exit'); child.kill();
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000); timer.unref();
    try { await exited; } finally { clearTimeout(timer); active = undefined; }
  }
  function start(binary) {
    const child = spawn(resolve(binary), ['run', '--config', configuration, '--adapter', 'caddyfile'], { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(child); active = child;
    child.stdout.on('data', chunk => { log += chunk; }); child.stderr.on('data', chunk => { log += chunk; });
    child.on('error', error => { log += error.message; });
  }
  const rootCertificate = join(env.XDG_DATA_HOME, 'caddy/pki/authorities/local/root.crt');
  let port;
  function https(ca, expectedHostname = 'localhost') {
    return new Promise((yes, no) => {
      const req = request({ hostname: '127.0.0.1', port, agent: false, servername: 'localhost', checkServerIdentity: (_name, cert) => checkServerIdentity(expectedHostname, cert), ca, path: '/', headers: { Host: 'localhost' }, timeout: 2000 }, res => {
        const leaf = res.socket.getPeerCertificate().fingerprint256;
        let body = ''; res.on('error', no); res.on('data', chunk => { body += chunk; }); res.on('end', () => yes({ status: res.statusCode, headers: res.headers, body, leaf }));
      });
      req.on('timeout', () => req.destroy(Error('HTTPS_TIMEOUT'))); req.on('error', no); req.end();
    });
  }
  async function ready(ca) {
    for (let attempt = 0; attempt < 100; attempt++) {
      assert.ok(active.exitCode === null && active.signalCode === null, 'Gateway exited; inspect the private fixture');
      try { return await https(ca ?? await readFile(rootCertificate)); } catch { await pause(100); }
    }
    throw Error('Gateway startup timed out; inspect the private fixture');
  }
  async function checkProxy(ca) {
    const response = await ready(ca);
    assert.equal(response.status, 200); assert.equal(response.body, 'gateway-fixture');
    assert.equal(response.headers['strict-transport-security'], 'max-age=31536000');
    await assert.rejects(https(ca, 'wrong-host.invalid'), error => error.code === 'ERR_TLS_CERT_ALTNAME_INVALID');
    await assert.rejects(https(undefined));
    const ws = new WebSocket(`wss://127.0.0.1:${port}/`, { ca, servername: 'localhost', headers: { Host: 'localhost' }, handshakeTimeout: 3000 });
    try {
      await once(ws, 'open'); const bytes = randomBytes(8192), received = once(ws, 'message', { signal: AbortSignal.timeout(5000) });
      ws.send(bytes); const [payload, binary] = await received;
      assert.equal(binary, true); assert.equal(sha(payload), sha(bytes));
    } finally { ws.terminate(); }
    return response;
  }
  try {
    const originalInfo = run(baseline, ['build-info']);
    assert.match(originalInfo, /github\.com\/caddyserver\/caddy\/v2\s+v2\.11\.9\s/);
    assert.match(originalInfo, /github\.com\/go-jose\/go-jose\/v3\s+v3\.0\.5\s/);
    const policy = gatewayPolicy(run(candidate, ['build-info']));
    // Adapt production configurations without binding ports, installing trust or contacting ACME.
    run(candidate, ['adapt', '--config', resolve('deploy/Caddyfile.local'), '--adapter', 'caddyfile']);
    run(candidate, ['adapt', '--config', resolve('deploy/Caddyfile.public'), '--adapter', 'caddyfile'], { ...env, DOMAIN: 'gateway-test.example.invalid', ACME_EMAIL: 'fixture@example.invalid' });
    backend.listen(0, '127.0.0.1'); await once(backend, 'listening');
    const listener = createListener(); listener.listen(0, '127.0.0.1'); await once(listener, 'listening');
    port = listener.address().port; await new Promise((yes, no) => listener.close(error => error ? no(error) : yes()));
    await writeFile(configuration, `{
  admin off
  skip_install_trust
  auto_https disable_redirects
}
https://localhost:${port} {
  bind 127.0.0.1
  tls internal
  header >Strict-Transport-Security "max-age=31536000"
  reverse_proxy 127.0.0.1:${backend.address().port}
}
`);
    start(baseline); await ready(); const ca = await readFile(rootCertificate);
    const before = await checkProxy(ca);
    const identityPaths = ['root.crt', 'root.key', 'intermediate.crt', 'intermediate.key'].map(name => join(env.XDG_DATA_HOME, 'caddy/pki/authorities/local', name));
    const identityBefore = await Promise.all(identityPaths.map(async path => sha(await readFile(path))));
    await stop();
    // Force a fresh leaf using only this test's private certificate cache.
    const leaf = resolve(env.XDG_DATA_HOME, 'caddy/certificates/local/localhost'), savedLeaf = leaf + '-before-upgrade';
    for (const path of [leaf, savedLeaf]) assert.ok(path.startsWith(root + sep));
    await rename(leaf, savedLeaf);
    start(candidate); const after = await checkProxy(ca);
    assert.notEqual(after.leaf, before.leaf, 'Candidate must issue a fresh leaf using the original CA');
    assert.deepEqual(await Promise.all(identityPaths.map(async path => sha(await readFile(path)))), identityBefore);
    await stop(); start(candidate); await checkProxy(ca);
    assert.deepEqual(await Promise.all(identityPaths.map(async path => sha(await readFile(path)))), identityBefore);
    await mkdir('reports/ci', { recursive: true });
    await writeFile('reports/ci/gateway-upgrade.json', JSON.stringify({ ok: true, created: new Date().toISOString(), scope: 'isolated host binaries; not a final image scan or user-volume upgrade', gateway: policy, caIdentityRetained: true, freshLeafWithOriginalCA: true, restart: true, strictHttpsAndHostname: true, untrustedCertificateRejected: true, binaryWss: true, productionConfigurationsAdapted: true, systemTrustModified: false }, null, 2) + '\n');
  } finally {
    await stop(); for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill();
    for (const client of sockets.clients) client.terminate();
    await new Promise(yes => sockets.close(yes));
    if (backend.listening) await new Promise(yes => backend.close(yes));
    await writeFile(join(root, 'gateway.log'), log);
  }
});
