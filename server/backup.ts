import { constants, existsSync, statfsSync } from 'node:fs';
import { mkdir, readdir, lstat, open, copyFile, rename, unlink, realpath } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { need, verifyAudit, type Checkpoint, type Row, type Store } from './store.ts';
import { BackupCipher, newBackupHeader, validBackupHeader, type EncryptedManifest } from './backup-crypto.ts';
import { backupKeyLocation, readBackupKeys } from './backup-keys.ts';
import { backupId, safePath, sealedPath, hash, durable, privateJson, separate, manifestFile, verifyBackup, type Entry, type BackupManifest } from './backup-reader.ts';
export { verifyBackup, restoreBackup, separate, type BackupAccess, type BackupManifest } from './backup-reader.ts';

async function directoryBytes(root: string, depth = 0): Promise<number> {
  need(depth < 4, 'BACKUP_PATH_UNSAFE'); let bytes = 0;
  for (const entry of await readdir(root, { withFileTypes: true })) {
    need(!entry.isSymbolicLink(), 'BACKUP_PATH_UNSAFE');
    if (entry.isDirectory()) bytes += await directoryBytes(join(root, entry.name), depth + 1);
    else { need(entry.isFile(), 'BACKUP_PATH_UNSAFE'); bytes += (await lstat(join(root, entry.name))).size; }
  }
  return bytes;
}
function space(root: string, bytes: number, minFree: number) { const stat = statfsSync(root, { bigint: true }); need(Number(stat.bavail * stat.bsize) >= bytes + minFree, 'DISK_SPACE_LOW'); }
export async function backupList(root: string) {
  if (!existsSync(root)) return [];
  need(!(await lstat(root)).isSymbolicLink(), 'BACKUP_PATH_UNSAFE');
  const list: { id: string; created: string; bytes: number; encrypted: boolean; keyId?: string }[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (!backupId.test(entry.name) || !entry.isDirectory() || entry.isSymbolicLink()) continue;
    try {
      const manifest = await manifestFile(join(root, entry.name));
      if (manifest.id !== entry.name || !Number.isSafeInteger(manifest.bytes) || manifest.bytes < 0 || typeof manifest.created !== 'string') continue;
      if (manifest.version === 2) { validBackupHeader(manifest); need(typeof manifest.sealed === 'string', 'BACKUP_INVALID'); }
      else if (manifest.version !== 1) continue;
      list.push({ id: manifest.id, created: manifest.created, bytes: manifest.bytes, encrypted: manifest.version === 2, ...(manifest.version === 2 ? { keyId: manifest.keyId } : {}) });
    } catch { /* Incomplete or invalid copies never appear as usable backups. */ }
  }
  return list.sort((a, b) => b.created.localeCompare(a.created));
}
// Caller holds the existing application-wide quiescence barrier until completion.
// Plain format creation is kept only for explicit legacy compatibility fixtures/tools.
export async function createBackup(store: Store, root: string, options: { quota: number; count: number; minFree: number; pending: number; keyFile?: string; legacy?: boolean }) {
  separate(store.root, root);
  need(Boolean(options.keyFile) !== Boolean(options.legacy), 'BACKUP_KEY_MISSING');
  if (options.keyFile) await backupKeyLocation(resolve(options.keyFile), store.root, root, store.root + '.mfa-key');
  const keys = options.keyFile ? await readBackupKeys(options.keyFile) : undefined;
  await mkdir(root, { recursive: true, mode: 0o700 }); need(!(await lstat(root)).isSymbolicLink(), 'BACKUP_PATH_UNSAFE');
  separate(await realpath(store.root), await realpath(root));
  const existingBytes = await directoryBytes(root), children = await readdir(root);
  need(children.length < options.count && existingBytes < options.quota, 'BACKUP_CAPACITY');
  const id = 'backup-' + randomUUID(), created = new Date().toISOString(), partial = join(root, '.' + id + '.partial');
  const header = keys ? newBackupHeader(id, created, keys) : undefined, cipher = header && keys ? new BackupCipher(header, keys) : undefined;
  const entries: Entry[] = []; let plainBytes = 0, storedBytes = 0, temporaryDatabase: string | undefined;
  try {
    await mkdir(partial, { mode: 0o700 });
    for (const folder of cipher ? ['sealed'] : ['objects', 'staging', 'audit']) await mkdir(join(partial, folder), { mode: 0o700 });
    const save = async (path: string, source: string | Buffer) => {
      need(entries.length < 100000, 'BACKUP_CAPACITY');
      let size: number;
      if (typeof source === 'string') { const stat = await lstat(source); need(stat.isFile() && !stat.isSymbolicLink(), 'BACKUP_SOURCE_UNSAFE'); size = stat.size; }
      else size = source.length;
      const cost = size + (cipher ? 16 : 0), index = entries.length + 1;
      need(storedBytes + cost + existingBytes <= options.quota, 'BACKUP_CAPACITY'); space(root, cost, options.minFree + options.pending);
      const destination = join(partial, cipher ? sealedPath(index) : path); let entry: Entry;
      if (cipher && typeof source === 'string') entry = { path, ...await cipher.sealFile(source, destination, size, index, path) };
      else if (typeof source === 'string') {
        await copyFile(source, destination, constants.COPYFILE_EXCL); await durable(destination);
        need((await lstat(destination)).size === size, 'BACKUP_SOURCE_CHANGED'); entry = { path, size, sha256: await hash(destination) };
      } else {
        const output = await open(destination, 'wx', 0o600);
        try { await output.writeFile(cipher ? cipher.seal(index, path, source) : source); await output.sync(); } finally { await output.close(); }
        entry = { path, size, sha256: createHash('sha256').update(source).digest('hex') };
      }
      entries.push(entry); plainBytes += size; storedBytes += cost;
    };
    const databaseBytes = Number(store.get('PRAGMA page_count')!.page_count) * Number(store.get('PRAGMA page_size')!.page_size);
    need(existingBytes + databaseBytes + (cipher ? 16 : 0) <= options.quota, 'BACKUP_CAPACITY');
    space(root, 2 * databaseBytes, options.minFree + options.pending);
    // SQLite's plain snapshot stays in the trusted data directory, outside the encrypted backup.
    const database = cipher ? join(store.root, '.backup-snapshot-' + randomUUID() + '.sqlite') : join(partial, 'safedrop.sqlite');
    if (cipher) { space(store.root, databaseBytes, options.minFree + options.pending); temporaryDatabase = database; }
    const empty = await open(database, 'wx', 0o600); await empty.close();
    store.db.prepare('VACUUM INTO ?').run(database); await durable(database);
    if (cipher) await save('safedrop.sqlite', database);
    else { entries.push({ path: 'safedrop.sqlite', size: (await lstat(database)).size, sha256: await hash(database) }); plainBytes = storedBytes = entries[0].size; }
    for (const folder of ['objects', 'staging']) for (const file of await readdir(join(store.root, folder), { withFileTypes: true })) {
      need(file.isFile() && !file.isSymbolicLink() && safePath.test(folder + '/' + file.name), 'BACKUP_SOURCE_UNSAFE');
      await save(folder + '/' + file.name, join(store.root, folder, file.name));
    }
    const snapshot = new DatabaseSync(database, { readOnly: true }); let checkpoint: Checkpoint;
    try {
      const rows = snapshot.prepare('SELECT * FROM audit ORDER BY seq').all() as Row[], verified = verifyAudit(rows);
      need(verified.ok, 'AUDIT_INTEGRITY_FAILURE'); checkpoint = { count: verified.count!, head: verified.head! };
      for (let index = 0; index < rows.length; index += 1000) await save(`audit/segment-${String(index / 1000).padStart(6, '0')}.json`, Buffer.from(JSON.stringify({ version: 1, rows: rows.slice(index, index + 1000), checkpoint })));
    } finally { snapshot.close(); }
    if (temporaryDatabase) { await unlink(temporaryDatabase); temporaryDatabase = undefined; }
    const manifest: BackupManifest = { version: 1, id, created, checkpoint, entries, bytes: plainBytes };
    const persisted: BackupManifest | EncryptedManifest = cipher && header ? { ...header, bytes: storedBytes, sealed: cipher.seal(0, 'manifest', Buffer.from(JSON.stringify(manifest))).toString('base64') } : manifest;
    const manifestBytes = Buffer.byteLength(JSON.stringify(persisted)); need(storedBytes + manifestBytes + existingBytes <= options.quota, 'BACKUP_CAPACITY'); space(root, manifestBytes, options.minFree + options.pending);
    await privateJson(join(partial, 'manifest.json'), persisted);
    if (cipher) space(store.root, entries.find(entry => entry.path === 'safedrop.sqlite')!.size, options.minFree + options.pending);
    await verifyBackup(partial, undefined, { keyFile: options.keyFile, allowPlaintext: Boolean(options.legacy), temporaryRoot: store.root }); await rename(partial, join(root, id));
    return { id, created, bytes: storedBytes, checkpoint, encrypted: Boolean(cipher), ...(header ? { keyId: header.keyId } : {}) };
  } finally {
    cipher?.dispose(); if (temporaryDatabase) await unlink(temporaryDatabase).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
}
