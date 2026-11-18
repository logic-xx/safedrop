import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createApp } from '../server/app.ts';
import { certificates } from '../scripts/certificates.ts';
import { MfaGuard, totp } from '../server/mfa.ts';

test('host maintenance CLI enforces TLS and stores independent checkpoints without exposing credentials', { timeout: 45000 }, async () => {
  mkdirSync('tmp', { recursive: true }); const root = mkdtempSync(resolve('tmp/maintenance-cli-')); certificates(join(root, 'tls'));
  const config = { root: join(root, 'data'), origin: 'https://localhost', tls: { cert: readFileSync(join(root, 'tls/server.crt')), key: readFileSync(join(root, 'tls/server.key')) } }, app = createApp(config), password = randomBytes(24).toString('base64url');
  await app.store.addUser('admin', password, 'admin'); app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening'); config.origin = `https://localhost:${(app.server.address() as { port: number }).port}`;
  const accounts = join(root, 'accounts.json'), destination = join(root, 'independent'); writeFileSync(accounts, JSON.stringify([{ name: 'admin', password }]), { mode: 0o600 });
  const run = (command: string, extra: string[] = [], origin = config.origin) => promisify(execFile)(process.execPath, ['node_modules/tsx/dist/cli.mjs', 'scripts/maintenance.ts', command, '--origin', origin, '--ca', join(root, 'tls/ca.crt'), '--accounts', accounts, ...extra], { windowsHide: true, timeout: 30000 });
  try {
    const result = await run('anchor', ['--destination', destination]), saved = JSON.parse(result.stdout); assert.equal(saved.saved, true); assert.equal(result.stdout.includes(password), false); assert.equal(result.stderr.includes(password), false);
    const paths = readdirSync(destination); assert.equal(paths.length, 1); const anchor = JSON.parse(readFileSync(join(destination, paths[0]), 'utf8')); assert.deepEqual(anchor, { count: saved.count, head: saved.head });
    assert.equal(existsSync(join(config.root, paths[0])), false);
    const backup = JSON.parse((await run('backup')).stdout); const source = config.root + '.backups/' + backup.id, target = join(root, 'restored');
    assert.equal(JSON.parse((await run('verify', ['--source', source, '--anchor', join(destination, paths[0])])).stdout).verified, true);
    assert.equal(JSON.parse((await run('restore', ['--source', source, '--target', target, '--anchor', join(destination, paths[0])])).stdout).id, backup.id);
    await assert.rejects(run('status', [], config.origin.replace('https:', 'http:')), /HTTPS_REQUIRED/);
    await assert.rejects(run('anchor', ['--destination', join(root, 'invalid'), '--interval-seconds', '0']), /INVALID_INTERVAL/); assert.equal(existsSync(join(root, 'invalid')), false);
    const secret = randomBytes(20), adminId = app.store.get('SELECT id FROM users WHERE name=?', 'admin')!.id, guard = new MfaGuard(app.store, config.root + '.mfa-key');
    guard.now = () => Date.now() - 30000; const enable = guard.enroll(adminId, secret, totp(secret, Date.now() - 30000)); app.store.transaction(enable);
    await assert.rejects(run('status'), /MFA_OTP_FILE_REQUIRED/);
    const otpFile = join(root, 'current-otp.txt'), currentCode = totp(secret); writeFileSync(otpFile, currentCode, { mode: 0o600 });
    const protectedResult = await run('status', ['--otp-file', otpFile]); assert.ok(JSON.parse(protectedResult.stdout).storage);
    assert.equal(protectedResult.stdout.includes(currentCode), false); assert.equal(protectedResult.stderr.includes(currentCode), false);
  } finally { await app.close(); }
});
