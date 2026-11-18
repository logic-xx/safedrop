import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, writeFile, readFile, readdir, lstat, symlink } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { Store, digest } from '../server/store.ts';
import { createBackup, verifyBackup, restoreBackup } from '../server/backup.ts';
import { changeBackupKeys, readBackupKeys } from '../server/backup-keys.ts';

async function fixture() {
  await mkdir('tmp', { recursive: true }); const root = await mkdtemp(resolve('tmp/encrypted-backup-')), data = join(root, 'data'), keyFile = data + '.backup-keys', backups = data + '.backups';
  const store = new Store(data); await changeBackupKeys(keyFile); const user = await store.addUser('fixture-owner', randomBytes(24).toString('base64url'));
  const content = Buffer.from('private-file-content-' + randomUUID()), fileId = randomUUID(), emptyId = randomUUID(), transferId = randomUUID();
  for (const [id, bytes] of [[fileId, content], [emptyId, Buffer.alloc(0)]] as const) { await writeFile(join(data, 'objects', id), bytes); store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', id, user, 'private-name-' + id, bytes.length, digest(bytes), Date.now()); }
  await writeFile(join(data, 'staging', transferId), content.subarray(0, 8)); store.run('INSERT INTO transfers VALUES(?,?,?,?,?,?,?)', transferId, user, 'partial', content.length, digest(content), 8, Date.now());
  store.audit(user, 'backup-fixture', 'allowed'); const anchor = store.checkpoint(), options = { quota: 64 * 1024 ** 2, count: 20, minFree: 0, pending: 0, keyFile };
  return { root, data, keyFile, backups, store, content, fileId, emptyId, transferId, anchor, options, backup: async () => { const result = await createBackup(store, backups, options); return { ...result, source: join(backups, result.id) }; } };
}

test('Encrypted backup protects the whole snapshot and restores files, offsets and audit into a new directory', async () => {
  const f = await fixture();
  try {
    const result = await f.backup(); assert.equal(result.encrypted, true);
    assert.deepEqual((await readdir(result.source)).sort(), ['manifest.json', 'sealed']);
    const header = JSON.parse(await readFile(join(result.source, 'manifest.json'), 'utf8')); assert.equal(header.version, 2); assert.equal('entries' in header, false); assert.equal('checkpoint' in header, false);
    for (const name of await readdir(join(result.source, 'sealed'))) { const bytes = await readFile(join(result.source, 'sealed', name)); assert.equal(bytes.includes(f.content), false); assert.equal(bytes.includes(Buffer.from('SQLite format 3')), false); }
    const verified = await verifyBackup(result.source, f.anchor, { keyFile: f.keyFile }); assert.equal(verified.encrypted, true); assert.deepEqual(verified.checkpoint, f.anchor);
    await assert.rejects(verifyBackup(result.source, f.anchor, { keyFile: f.keyFile, temporaryRoot: result.source }), /BACKUP_PATH_UNSAFE/);
    if (process.platform !== 'win32') {
      const alias = join(f.root, 'source-alias'); await symlink(result.source, alias, 'dir');
      await assert.rejects(restoreBackup(result.source, join(alias, 'plaintext-restore'), f.anchor, { keyFile: f.keyFile }), /BACKUP_PATH_UNSAFE/);
      assert.equal(existsSync(join(result.source, 'plaintext-restore')), false);
    }
    const target = join(f.root, 'restored'); await restoreBackup(result.source, target, f.anchor, { keyFile: f.keyFile });
    assert.deepEqual(await readFile(join(target, 'objects', f.fileId)), f.content); assert.equal((await lstat(join(target, 'objects', f.emptyId))).size, 0);
    const restored = new Store(target); try { assert.equal(restored.get('SELECT offset FROM transfers WHERE id=?', f.transferId)!.offset, 8); } finally { restored.close(); }
    await assert.rejects(restoreBackup(result.source, target, f.anchor, { keyFile: f.keyFile }), /EEXIST/);
    assert.deepEqual(await readFile(join(f.data, 'objects', f.fileId)), f.content); assert.equal((await readdir(f.data)).some(name => name.startsWith('.backup-snapshot-')), false);
  } finally { f.store.close(); }
});

test('Missing, wrong, lost and rotated backup keys fail closed without changing the source', async () => {
  const f = await fixture();
  try {
    await assert.rejects(createBackup(f.store, join(f.root, 'without-key'), { ...f.options, keyFile: undefined }), /BACKUP_KEY_MISSING/); assert.equal(existsSync(join(f.root, 'without-key')), false);
    const first = await f.backup(), before = await readFile(f.keyFile); await changeBackupKeys(f.keyFile, true); const second = await f.backup(); assert.notEqual(first.keyId, second.keyId);
    for (const result of [first, second]) await verifyBackup(result.source, f.anchor, { keyFile: f.keyFile });
    await assert.rejects(verifyBackup(first.source, f.anchor), /BACKUP_KEY_MISSING/);
    const wrong = join(f.root, 'wrong.backup-keys'), original = JSON.parse(before.toString()); original.keys[0].material = randomBytes(32).toString('base64'); await writeFile(wrong, JSON.stringify(original), { mode: 0o600 });
    await assert.rejects(restoreBackup(first.source, join(f.root, 'bad-key'), f.anchor, { keyFile: wrong }), /BACKUP_AUTH_FAILED/); assert.equal(existsSync(join(f.root, 'bad-key')), false);
    const ring = await readBackupKeys(f.keyFile); ring.keys = ring.keys.filter(key => key.id === ring.active); await writeFile(f.keyFile, JSON.stringify(ring));
    await assert.rejects(verifyBackup(first.source, f.anchor, { keyFile: f.keyFile }), /BACKUP_KEY_NOT_FOUND/); await verifyBackup(second.source, f.anchor, { keyFile: f.keyFile });
    assert.deepEqual(await readFile(join(f.data, 'objects', f.fileId)), f.content);
  } finally { f.store.close(); }
});

test('Ciphertext, manifest and downgrade tampering is rejected before a restore target is created', async () => {
  const f = await fixture();
  try {
    const result = await f.backup(), access = { keyFile: f.keyFile }, target = join(f.root, 'tampered');
    const path = join(result.source, 'sealed', '000001.bin'), original = await readFile(path), corrupted = Buffer.from(original); corrupted[corrupted.length - 1] ^= 1; await writeFile(path, corrupted);
    await assert.rejects(restoreBackup(result.source, target, f.anchor, access), /BACKUP_AUTH_FAILED/); assert.equal(existsSync(target), false); await writeFile(path, original);
    const manifestPath = join(result.source, 'manifest.json'), manifest = await readFile(manifestPath), header = JSON.parse(manifest.toString()); header.salt = randomBytes(32).toString('base64'); await writeFile(manifestPath, JSON.stringify(header));
    await assert.rejects(verifyBackup(result.source, f.anchor, access), /BACKUP_AUTH_FAILED/); await writeFile(manifestPath, manifest);
    header.version = 1; await writeFile(manifestPath, JSON.stringify(header)); await assert.rejects(restoreBackup(result.source, target, f.anchor, access), /BACKUP_PLAINTEXT_CONFIRMATION_REQUIRED/); assert.equal(existsSync(target), false);
  } finally { f.store.close(); }
});

test('Legacy plaintext backups remain explicitly readable and consume the same retained-copy budget', async () => {
  const f = await fixture();
  try {
    const legacy = await createBackup(f.store, f.backups, { ...f.options, keyFile: undefined, legacy: true }), source = join(f.backups, legacy.id);
    await assert.rejects(verifyBackup(source, f.anchor), /BACKUP_PLAINTEXT_CONFIRMATION_REQUIRED/);
    const access = { allowPlaintext: true }; assert.equal((await verifyBackup(source, f.anchor, access)).encrypted, false);
    await restoreBackup(source, join(f.root, 'legacy-restored'), f.anchor, access); assert.deepEqual(await readFile(join(f.root, 'legacy-restored/objects', f.fileId)), f.content);
    await assert.rejects(createBackup(f.store, f.backups, { ...f.options, count: 1 }), /BACKUP_CAPACITY/); assert.equal(existsSync(source), true);
  } finally { f.store.close(); }
});
