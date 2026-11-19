import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createServer } from 'node:https';
import { createTestApp as createApp } from './test-scanner.ts';
import { certificates } from '../scripts/certificates.ts';
import { checkContainer } from './container-smoke.ts';
import { changeBackupKeys } from '../server/backup-keys.ts';

test('deployment verifier checks real HTTPS/WSS and persistence across service restart', { timeout: 60000 }, async () => {
  mkdirSync('tmp', { recursive: true }); const root = mkdtempSync(resolve('tmp/container-verifier-'));
  certificates(join(root, 'tls')); const ca = readFileSync(join(root, 'tls/ca.crt'));
  const tls = { cert: readFileSync(join(root, 'tls/server.crt')), key: readFileSync(join(root, 'tls/server.key')) };
  // An invalid gateway policy must fail verification before attempting login.
  const duplicateHeaderServer = createServer(tls, (req, res) => {
    res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
    res.setHeader('Strict-Transport-Security', ['max-age=31536000', 'max-age=31536000']);
    res.end(req.url === '/health' ? '{"status":"ok","protocol":"SFT/1"}' : 'SafeDrop');
  });
  duplicateHeaderServer.listen(0, '127.0.0.1'); await once(duplicateHeaderServer, 'listening');
  try {
    const duplicatePort = (duplicateHeaderServer.address() as { port: number }).port;
    await assert.rejects(checkContainer({ origin: `https://localhost:${duplicatePort}`, ca, accounts: [], statePath: join(root, 'unused.json'), phase: 'seed' }), /Expected exactly one HSTS response header/);
  } finally { await new Promise<void>((resolve, reject) => duplicateHeaderServer.close(error => error ? reject(error) : resolve())); }
  // Select an available local port before fixing the origin used by the service.
  await changeBackupKeys(join(root, 'data') + '.backup-keys');
  let app = createApp({ root: join(root, 'data'), origin: 'https://localhost', tls });
  app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening');
  const port = (app.server.address() as { port: number }).port; await app.close();
  const origin = `https://localhost:${port}`, accounts = ['admin', 'alice', 'bob'].map(name => ({ name, password: randomBytes(18).toString('base64url') }));
  app = createApp({ root: join(root, 'data'), origin, tls });
  try {
    for (const account of accounts) await app.store.addUser(account.name, account.password, account.name === 'admin' ? 'admin' : 'user');
    app.server.listen(port, '127.0.0.1'); await once(app.server, 'listening');
    const options = { origin, ca, accounts, statePath: join(root, 'state.json') };
    assert.equal((await checkContainer({ ...options, phase: 'seed' })).ok, true);
    await app.close(); app = createApp({ root: join(root, 'data'), origin, tls });
    app.server.listen(port, '127.0.0.1'); await once(app.server, 'listening');
    const changedState = JSON.parse(readFileSync(options.statePath, 'utf8')); changedState.sha256 = '0'.repeat(64);
    const changedStatePath = join(root, 'wrong-digest.json'); writeFileSync(changedStatePath, JSON.stringify(changedState));
    await assert.rejects(checkContainer({ ...options, statePath: changedStatePath, phase: 'resume' }), { code: 'ERR_ASSERTION' });
    assert.equal((await checkContainer({ ...options, phase: 'resume' })).ok, true);
  } finally { await app.close(); }
});
