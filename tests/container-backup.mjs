// ASCII-only: safe through Windows PowerShell 5.1's native stdin pipe.
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { Store, digest } from './build/server/store.js';
import { createBackup, verifyBackup, restoreBackup } from './build/server/backup.js';
import { changeBackupKeys, readBackupKeys } from './build/server/backup-keys.js';

const root = mkdtempSync(join(process.env.BACKUP_PROBE_TMP ?? '/tmp', 'safedrop-backup-check-')), data = join(root, 'data'), keyFile = data + '.backup-keys', backups = data + '.backups';
const store = new Store(data), checks = [], content = randomBytes(1024 * 2 + 7), id = randomUUID();
try {
  const user = await store.addUser('temporary-backup-owner', randomBytes(24).toString('base64url'));
  writeFileSync(join(data, 'objects', id), content); store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', id, user, 'temporary-content.bin', content.length, digest(content), Date.now()); store.audit(user, 'fixture', 'allowed');
  const options = { quota: 16 * 1024 ** 2, count: 10, minFree: 0, pending: 0 }, anchor = store.checkpoint();
  await assert.rejects(createBackup(store, backups, options), /BACKUP_KEY_MISSING/); assert.equal(existsSync(backups), false); checks.push('missing key rejects backup without plaintext fallback');
  await changeBackupKeys(keyFile); const originalKeys = await readBackupKeys(keyFile), first = await createBackup(store, backups, { ...options, keyFile }), source = join(backups, first.id);
  assert.equal(first.encrypted, true); assert.deepEqual(readdirSync(source).sort(), ['manifest.json', 'sealed']);
  const manifest = await verifyBackup(source, anchor, { keyFile }), target = join(root, 'restored'); await restoreBackup(source, target, anchor, { keyFile }); assert.deepEqual(readFileSync(join(target, 'objects', id)), content); assert.equal(manifest.encrypted, true);
  for (const name of readdirSync(join(source, 'sealed'))) assert.equal(readFileSync(join(source, 'sealed', name)).includes(content), false);
  checks.push('encrypted manifest and objects verify and restore with original content');
  await changeBackupKeys(keyFile, true); const second = await createBackup(store, backups, { ...options, keyFile }); assert.notEqual(second.keyId, first.keyId); await verifyBackup(source, anchor, { keyFile });
  const reload = spawnSync(process.execPath, ['--input-type=module', '-e', 'import {verifyBackup} from "./build/server/backup.js";await verifyBackup(process.argv[1],undefined,{keyFile:process.argv[2]});process.stdout.write("OK");', join(backups, second.id), keyFile], { encoding: 'utf8', windowsHide: true, timeout: 15000 });
  assert.equal(reload.status, 0, 'RUNTIME_KEY_RELOAD_FAILED'); assert.equal(reload.stdout, 'OK'); checks.push('rotation retains old keys and works in a fresh Node process');
  const wrong = join(root, 'wrong.backup-keys'); originalKeys.keys[0].material = randomBytes(32).toString('base64'); writeFileSync(wrong, JSON.stringify(originalKeys), { mode: 0o600 });
  await assert.rejects(restoreBackup(source, join(root, 'wrong-target'), anchor, { keyFile: wrong }), /BACKUP_AUTH_FAILED/); assert.equal(existsSync(join(root, 'wrong-target')), false); await assert.rejects(verifyBackup(source, anchor), /BACKUP_KEY_MISSING/); checks.push('wrong and missing keys cannot create a restore target');
  const blob = join(source, 'sealed', '000002.bin'), original = readFileSync(blob), changed = Buffer.from(original); changed[changed.length - 1] ^= 1; writeFileSync(blob, changed);
  await assert.rejects(verifyBackup(source, anchor, { keyFile }), /BACKUP_AUTH_FAILED/); writeFileSync(blob, original); checks.push('ciphertext authentication rejects tampering');
  const legacy = await createBackup(store, backups, { ...options, legacy: true }), legacySource = join(backups, legacy.id); await assert.rejects(verifyBackup(legacySource), /BACKUP_PLAINTEXT_CONFIRMATION_REQUIRED/); await verifyBackup(legacySource, anchor, { allowPlaintext: true }); checks.push('legacy plaintext is readable only with explicit compatibility selection');
  const publicHeader = readFileSync(join(source, 'manifest.json'), 'utf8'), keys = await readBackupKeys(keyFile); for (const key of keys.keys) assert.equal(publicHeader.includes(key.material), false);
  checks.push('key material stays outside backups');
  console.log(JSON.stringify({ ok: true, version: 1, node: process.version, scope: 'isolated temporary data in final runtime', checks, encrypted: true, rotation: true, keyReload: true, legacyCompatibility: true, authenticationFailuresRejected: true, originalAccountsChanged: false, originalDataChanged: false }));
} finally { store.close(); }
