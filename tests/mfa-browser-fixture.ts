// Dedicated MFA UI data. Never reuse the earlier 08 fixture or container accounts.
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, join, sep } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createApp, type Config } from '../server/app.ts';
import { MfaGuard, base32, totp } from '../server/mfa.ts';
mkdirSync('tmp', { recursive: true });
const root = process.env.MFA_QA_ROOT ? resolve(process.env.MFA_QA_ROOT) : mkdtempSync(resolve('tmp/browser-mfa-'));
if (!root.startsWith(resolve('tmp') + sep) || process.env.MFA_QA_ROOT && !existsSync(join(root, 'qa-state.json'))) throw new Error('Existing MFA fixture required');
const config: Config = { root, origin: 'http://localhost' }, app = createApp(config), statePath = join(root, 'qa-state.json');
if (!existsSync(statePath)) {
  const password = randomBytes(24).toString('base64url');
  const enabledId = await app.store.addUser('mfa-enabled-admin', password, 'admin'); await app.store.addUser('mfa-setup-admin', password, 'admin'); await app.store.addUser('mfa-reader', password);
  const secret = randomBytes(20), before = Date.now() - 60000, guard = new MfaGuard(app.store, root + '.mfa-key', () => before), enroll = guard.enroll(enabledId, secret, totp(secret, before));
  const recoveryCodes = app.store.transaction(enroll);
  writeFileSync(statePath, JSON.stringify({ password, enabledSecret: base32(secret), recoveryCodes, accounts: { enabled: 'mfa-enabled-admin', setup: 'mfa-setup-admin', reader: 'mfa-reader' } }), { mode: 0o600 });
}
app.server.listen(Number(process.env.MFA_QA_PORT ?? 0), '127.0.0.1', () => {
  config.origin = `http://localhost:${(app.server.address() as { port: number }).port}`;
  writeFileSync(join(root, 'qa-runtime.json'), JSON.stringify({ origin: config.origin, root }), { mode: 0o600 });
  console.log(JSON.stringify({ origin: config.origin, root, resumed: Boolean(process.env.MFA_QA_ROOT) }));
});
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { void app.close().then(() => process.exit(0)); });
