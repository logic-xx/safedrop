// Execute on stdin inside the final image. Only a fresh /tmp directory is used.
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { WebSocket } from 'ws';
const runtime = process.env.MFA_SMOKE_BUILD ?? resolve('build');
// Keep Docker's Windows stdin transport ASCII-only; Node decodes the escapes.
const enableConfirmation = '\u542f\u7528\u53cc\u56e0\u7d20\u8ba4\u8bc1';
const { createApp } = await import(pathToFileURL(join(runtime, 'server/app.js')));
const { totp, unbase32 } = await import(pathToFileURL(join(runtime, 'server/mfa.js')));
const { encode, decode } = await import(pathToFileURL(join(runtime, 'shared/protocol.js')));
const root = mkdtempSync(join(tmpdir(), 'safedrop-mfa-')); let now = Date.now();
const config = { root: join(root, 'data'), origin: 'http://localhost', mfaClock: () => now }; let app = createApp(config);
const start = async () => { app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening'); }; await start();
const password = randomBytes(24).toString('base64url'); await app.store.addUser('mfa-only-admin', password, 'admin');
const connect = async () => {
  const ws = new WebSocket(`ws://127.0.0.1:${app.server.address().port}/ws`, { headers: { Origin: config.origin } }); await once(ws, 'open'); let seq = 0;
  ws.on('error', () => {});
  return { rpc: (op, meta = {}) => new Promise((yes, no) => { const id = ++seq, timer = setTimeout(() => { ws.off('message', received); no(new Error('RPC_TIMEOUT')); }, 5000); const received = data => { const f = decode(data); if (f.requestId !== id) return; clearTimeout(timer); ws.off('message', received); f.meta.ok ? yes(f.meta) : no(new Error(op + ':' + f.meta.code)); }; ws.on('message', received); ws.send(encode(1, id, { op, ...meta })); }) };
};
const enter = async () => { const p = await connect(); return { p, first: await p.rpc('auth.password', { name: 'mfa-only-admin', password }) }; };
try {
  const admin = (await enter()).p, setup = await admin.rpc('mfa.setup', { password }), secret = unbase32(setup.secret);
  const enabled = await admin.rpc('mfa.enable', { code: totp(secret, now), confirm: enableConfirmation }); assert.equal(enabled.recoveryCodes.length, 10);
  assert.ok(existsSync(config.root + '.mfa-key')); assert.equal(app.store.get('PRAGMA user_version').user_version, 5);
  const pending = await enter(); assert.equal(pending.first.mfaRequired, true); await assert.rejects(pending.p.rpc('maintenance.status'), /AUTH_REQUIRED/);
  await assert.rejects(pending.p.rpc('auth.mfa', { challenge: pending.first.challenge, code: totp(secret, now) }), /MFA_INVALID/);
  now += 30000; await pending.p.rpc('auth.mfa', { challenge: pending.first.challenge, code: totp(secret, now) }); assert.equal((await pending.p.rpc('maintenance.status')).ok, true);
  const recovery = await enter(); const restricted = await recovery.p.rpc('auth.mfa', { challenge: recovery.first.challenge, recoveryCode: enabled.recoveryCodes[0] }); assert.equal(restricted.user.recoveryOnly, true);
  await assert.rejects(recovery.p.rpc('maintenance.status'), /MFA_RECOVERY_ONLY/);
  const replacement = await recovery.p.rpc('mfa.setup', { password }); await recovery.p.rpc('mfa.enable', { code: totp(unbase32(replacement.secret), now), confirm: enableConfirmation });
  assert.equal((await recovery.p.rpc('maintenance.status')).ok, true);
  await app.close(); app = createApp(config); await start(); const restarted = await enter(); assert.equal(restarted.first.mfaRequired, true);
  now += 30000; await restarted.p.rpc('auth.mfa', { challenge: restarted.first.challenge, code: totp(unbase32(replacement.secret), now) }); assert.equal((await restarted.p.rpc('maintenance.status')).ok, true);
  console.log(JSON.stringify({ ok: true, version: 1, scope: 'isolated temporary data in final runtime', databaseVersion: 5, checks: ['enable and encrypted key persistence', 'password alone cannot access business', 'TOTP replay denied and full login accepted', 'recovery session restricted until new authenticator verified', 'MFA still required and usable after process restart'], originalAccountsChanged: false, originalDataChanged: false }));
} finally { await app.close(); }
