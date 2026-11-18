import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, writeFile, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { changeBackupKeys, readBackupKeys } from '../server/backup-keys.ts';
import { BackupCipher, newBackupHeader } from '../server/backup-crypto.ts';

test('Backup AEAD binds the backup, header, entry path and index and rejects nonce reuse', async () => {
  await mkdir('tmp', { recursive: true }); const root = await mkdtemp(resolve('tmp/backup-aead-')), file = join(root, 'data.backup-keys');
  await changeBackupKeys(file); const keys = await readBackupKeys(file), header = newBackupHeader('backup-' + crypto.randomUUID(), new Date().toISOString(), keys), cipher = new BackupCipher(header, keys);
  try {
    const bytes = randomBytes(1000), sealed = cipher.seal(1, 'objects/sample', bytes);
    assert.deepEqual(cipher.unseal(1, 'objects/sample', sealed), bytes);
    assert.throws(() => cipher.seal(1, 'objects/another', bytes), /BACKUP_NONCE_REUSE/);
    assert.throws(() => cipher.unseal(2, 'objects/sample', sealed), /BACKUP_AUTH_FAILED/);
    assert.throws(() => cipher.unseal(1, 'objects/another', sealed), /BACKUP_AUTH_FAILED/);
    const corrupted = Buffer.from(sealed); corrupted[0] ^= 1; assert.throws(() => cipher.unseal(1, 'objects/sample', corrupted), /BACKUP_AUTH_FAILED/);
    for (const changed of [{ ...header, id: 'backup-' + crypto.randomUUID() }, { ...header, created: new Date(Date.now() + 1000).toISOString() }, { ...header, salt: randomBytes(32).toString('base64') }]) {
      const wrong = new BackupCipher(changed, keys); try { assert.throws(() => wrong.unseal(1, 'objects/sample', sealed), /BACKUP_AUTH_FAILED/); } finally { wrong.dispose(); }
    }
    const otherFile = join(root, 'other.backup-keys'); await changeBackupKeys(otherFile); const otherKeys = await readBackupKeys(otherFile);
    assert.throws(() => new BackupCipher(header, otherKeys), /BACKUP_KEY_NOT_FOUND/);
    const empty = cipher.seal(2, 'staging/empty', Buffer.alloc(0)); assert.equal(empty.length, 16); assert.equal(cipher.unseal(2, 'staging/empty', empty).length, 0);
  } finally { cipher.dispose(); }
  assert.throws(() => cipher.seal(3, 'closed', Buffer.alloc(0)), /BACKUP_INVALID/);
});

test('Backup file encryption streams empty and multi-chunk objects and authenticates the final tag', async () => {
  await mkdir('tmp', { recursive: true }); const root = await mkdtemp(resolve('tmp/backup-stream-')), file = join(root, 'data.backup-keys');
  await changeBackupKeys(file); const keys = await readBackupKeys(file), cipher = new BackupCipher(newBackupHeader('backup-' + crypto.randomUUID(), new Date().toISOString(), keys), keys);
  try {
    for (const [index, bytes] of [Buffer.alloc(0), randomBytes(1024 * 1024 + 37)].entries()) {
      const source = join(root, 'source-' + index), encrypted = join(root, 'sealed-' + index), path = 'objects/' + index;
      await writeFile(source, bytes); const result = await cipher.sealFile(source, encrypted, bytes.length, index + 1, path);
      assert.equal(result.size, bytes.length); const chunks: Buffer[] = [];
      for await (const chunk of cipher.unsealFile(encrypted, bytes.length, index + 1, path)) chunks.push(chunk);
      assert.deepEqual(Buffer.concat(chunks), bytes);
      const altered = await readFile(encrypted); altered[altered.length - 1] ^= 1; await writeFile(encrypted, altered);
      await assert.rejects(async () => { for await (const _ of cipher.unsealFile(encrypted, bytes.length, index + 1, path)) { /* consume until tag authentication */ } }, /BACKUP_AUTH_FAILED/);
    }
    const source = join(root, 'fault-source'); await writeFile(source, randomBytes(37));
    await assert.rejects(cipher.sealFile(source, join(root, 'too-large'), 2 ** 36 - 31, 3, 'oversize'), /BACKUP_FILE_TOO_LARGE/);
    for (const [index, mode] of ['short', 'zero', 'sync'].entries()) {
      const destination = join(root, 'fault-' + mode), original = fsPromises.open;
      fsPromises.open = async (...args) => {
        const handle = await original(...args);
        if (String(args[0]) === destination) {
          const write = handle.write.bind(handle);
          if (mode === 'short') handle.write = (async (buffer: any, offset: any, length: any) => write(buffer, offset, Math.min(length, 3))) as typeof handle.write;
          if (mode === 'zero') handle.write = (async () => ({ bytesWritten: 0, buffer: Buffer.alloc(0) })) as unknown as typeof handle.write;
          if (mode === 'sync') handle.sync = async () => { throw Error('injected sync failure'); };
        }
        return handle;
      }; syncBuiltinESMExports();
      try {
        if (mode === 'short') { await cipher.sealFile(source, destination, 37, index + 3, mode); const chunks = []; for await (const chunk of cipher.unsealFile(destination, 37, index + 3, mode)) chunks.push(chunk); assert.deepEqual(Buffer.concat(chunks), await readFile(source)); }
        else await assert.rejects(cipher.sealFile(source, destination, 37, index + 3, mode), mode === 'zero' ? /BACKUP_WRITE_FAILED/ : /sync failure/);
      } finally { fsPromises.open = original; syncBuiltinESMExports(); }
    }
  } finally { cipher.dispose(); }
});
