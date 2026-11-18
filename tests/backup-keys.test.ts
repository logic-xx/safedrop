import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, chmod, symlink } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { changeBackupKeys, readBackupKeys, backupKey, backupKeyInfo, backupKeyLocation } from '../server/backup-keys.ts';

test('Independent backup key initialization is exclusive; rotation preserves old keys', async () => {
  await mkdir('tmp', { recursive: true }); const root = await mkdtemp(resolve('tmp/backup-key-test-')), file = join(root, 'data.backup-keys');
  await assert.rejects(readBackupKeys(file), /BACKUP_KEY_MISSING/);
  const first = await changeBackupKeys(file), original = await readFile(file);
  await assert.rejects(changeBackupKeys(file), /BACKUP_KEY_EXISTS/); assert.deepEqual(await readFile(file), original);
  const old = backupKey(await readBackupKeys(file));
  const rotated = await changeBackupKeys(file, true), ring = await readBackupKeys(file);
  assert.notEqual(rotated.activeKeyId, first.activeKeyId); assert.equal(rotated.retainedKeys, 2);
  assert.deepEqual(backupKey(ring, first.activeKeyId), old); assert.notDeepEqual(backupKey(ring), old);
  assert.equal(JSON.stringify(backupKeyInfo(ring)).includes(old.toString('base64')), false);
  await writeFile(file + '.lock', ''); const before = await readFile(file);
  await assert.rejects(changeBackupKeys(file, true), /BACKUP_KEY_BUSY/); assert.deepEqual(await readFile(file), before);
});

test('Backup key parsing and location reject malformed, missing, permissive or embedded secrets', async () => {
  await mkdir('tmp', { recursive: true }); const root = await mkdtemp(resolve('tmp/backup-key-invalid-')), data = join(root, 'data'), backups = join(root, 'backups'), file = join(root, 'data.backup-keys');
  await mkdir(data); await mkdir(backups); await changeBackupKeys(file); const ring = await readBackupKeys(file);
  await backupKeyLocation(file, data, backups, data + '.mfa-key');
  for (const path of [join(data, 'key'), join(backups, 'key'), data + '.mfa-key']) await assert.rejects(backupKeyLocation(path, data, backups, data + '.mfa-key'), /BACKUP_KEY_PATH_UNSAFE/);
  await assert.rejects(readBackupKeys(root), /BACKUP_KEY_INVALID/);
  for (const bad of [{}, { ...ring, active: 'wrong' }, { ...ring, keys: [ring.keys[0], ring.keys[0]] }, { ...ring, keys: [{ ...ring.keys[0], material: 'invalid' }] }]) {
    await writeFile(file, JSON.stringify(bad), { mode: 0o600 }); await assert.rejects(readBackupKeys(file), /BACKUP_KEY_INVALID/);
  }
  await writeFile(file, JSON.stringify(ring));
  if (process.platform !== 'win32') {
    await chmod(file, 0o644); await assert.rejects(readBackupKeys(file), /BACKUP_KEY_PERMISSIONS/); await chmod(file, 0o600);
    const link = join(root, 'linked.backup-keys'); await symlink(file, link); await assert.rejects(readBackupKeys(link), /BACKUP_KEY_INVALID/);
    const directoryLink = join(root, 'backup-alias'); await symlink(backups, directoryLink, 'dir');
    await assert.rejects(backupKeyLocation(join(directoryLink, 'hidden.backup-keys'), data, backups, data + '.mfa-key'), /BACKUP_KEY_PATH_UNSAFE/);
  }
});
