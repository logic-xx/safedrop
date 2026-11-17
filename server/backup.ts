import { createReadStream, constants, existsSync, statfsSync } from 'node:fs';
import { mkdir, readdir, lstat, open, readFile, copyFile, rename, unlink, realpath } from 'node:fs/promises';
import { resolve, join, sep } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { need, verifyAudit, type Checkpoint, type Row, type Store } from './store.ts';

type Entry = { path: string; size: number; sha256: string };
export type BackupManifest = { version: 1; id: string; created: string; checkpoint: Checkpoint; entries: Entry[]; bytes: number };
const backupId = /^backup-[0-9a-f-]{36}$/;
const safePath = /^(safedrop\.sqlite|(?:objects|staging)\/[a-zA-Z0-9_-]{1,100}|audit\/segment-[0-9]{6}\.json)$/;
async function hash(path: string) { const h = createHash('sha256'); for await (const chunk of createReadStream(path)) h.update(chunk); return h.digest('hex'); }
async function durable(path: string) { const h = await open(path, 'r+'); try { await h.chmod(0o600); await h.sync(); } finally { await h.close(); } }
async function json(path: string, value: unknown) { const h = await open(path, 'wx', 0o600); try { await h.writeFile(JSON.stringify(value)); await h.sync(); } finally { await h.close(); } }
async function directoryBytes(root: string, depth = 0): Promise<number> {
  need(depth < 4, 'BACKUP_PATH_UNSAFE'); let bytes = 0;
  for (const e of await readdir(root, { withFileTypes: true })) {
    need(!e.isSymbolicLink(), 'BACKUP_PATH_UNSAFE');
    if (e.isDirectory()) bytes += await directoryBytes(join(root, e.name), depth + 1);
    else { need(e.isFile(), 'BACKUP_PATH_UNSAFE'); bytes += (await lstat(join(root, e.name))).size; }
  }
  return bytes;
}
function space(root: string, bytes: number, minFree: number) { const s = statfsSync(root, { bigint: true }); need(Number(s.bavail * s.bsize) >= bytes + minFree, 'DISK_SPACE_LOW'); }
export function separate(source: string, destination: string) {
  const normalized = (p: string) => process.platform === 'win32' ? resolve(p).toLowerCase() : resolve(p);
  const a = normalized(source), b = normalized(destination); need(a !== b && !b.startsWith(a + sep) && !a.startsWith(b + sep), 'BACKUP_PATH_UNSAFE');
}
export async function backupList(root: string) {
  if (!existsSync(root)) return [];
  need(!(await lstat(root)).isSymbolicLink(), 'BACKUP_PATH_UNSAFE');
  const list: { id: string; created: string; bytes: number }[] = [];
  for (const d of await readdir(root, { withFileTypes: true })) {
    if (!backupId.test(d.name) || !d.isDirectory() || d.isSymbolicLink()) continue;
    try { const m = JSON.parse(await readFile(join(root, d.name, 'manifest.json'), 'utf8')) as BackupManifest; if (m.id === d.name && m.version === 1 && Number.isSafeInteger(m.bytes) && m.bytes >= 0) list.push({ id: m.id, created: m.created, bytes: m.bytes }); } catch { /* Incomplete backups never appear as usable copies. */ }
  }
  return list.sort((a, b) => b.created.localeCompare(a.created));
}
// Caller holds the application-wide quiescence barrier until this function returns.
export async function createBackup(store: Store, root: string, options: { quota: number; count: number; minFree: number; pending: number }) {
  separate(store.root, root); await mkdir(root, { recursive: true, mode: 0o700 });
  need(!(await lstat(root)).isSymbolicLink(), 'BACKUP_PATH_UNSAFE');
  separate(await realpath(store.root), await realpath(root));
  const existingBytes = await directoryBytes(root), children = await readdir(root);
  // Failed partial copies consume the same budget and slots; retries cannot hide them.
  need(children.length < options.count && existingBytes < options.quota, 'BACKUP_CAPACITY');
  const id = 'backup-' + randomUUID(), partial = join(root, '.' + id + '.partial'); await mkdir(partial, { mode: 0o700 });
  for (const folder of ['objects', 'staging', 'audit']) await mkdir(join(partial, folder), { mode: 0o700 });
  const entries: Entry[] = []; let bytes = 0;
  const add = async (path: string) => {
    const full = join(partial, path), s = await lstat(full); need(s.isFile() && !s.isSymbolicLink(), 'BACKUP_SOURCE_UNSAFE');
    bytes += s.size; need(bytes + existingBytes <= options.quota, 'BACKUP_CAPACITY');
    entries.push({ path, size: s.size, sha256: await hash(full) });
  };
  const databaseBytes = Number(store.get('PRAGMA page_count')!.page_count) * Number(store.get('PRAGMA page_size')!.page_size);
  need(existingBytes + databaseBytes <= options.quota, 'BACKUP_CAPACITY');
  space(root, 2 * databaseBytes, options.minFree + options.pending);
  store.db.prepare('VACUUM INTO ?').run(join(partial, 'safedrop.sqlite')); await durable(join(partial, 'safedrop.sqlite')); await add('safedrop.sqlite');
  for (const folder of ['objects', 'staging']) for (const f of await readdir(join(store.root, folder), { withFileTypes: true })) {
    need(f.isFile() && !f.isSymbolicLink() && safePath.test(folder + '/' + f.name), 'BACKUP_SOURCE_UNSAFE'); need(entries.length < 100000, 'BACKUP_CAPACITY');
    const source = join(store.root, folder, f.name), size = (await lstat(source)).size;
    need(size + bytes + existingBytes <= options.quota, 'BACKUP_CAPACITY'); space(root, size, options.minFree + options.pending);
    const path = folder + '/' + f.name; await copyFile(source, join(partial, path), constants.COPYFILE_EXCL); await durable(join(partial, path)); await add(path);
  }
  const db = new DatabaseSync(join(partial, 'safedrop.sqlite'), { readOnly: true });
  let checkpoint: Checkpoint;
  try {
    const rows = db.prepare('SELECT * FROM audit ORDER BY seq').all() as Row[]; const verified = verifyAudit(rows); need(verified.ok, 'AUDIT_INTEGRITY_FAILURE'); checkpoint = { count: verified.count!, head: verified.head! };
    for (let i = 0; i < rows.length; i += 1000) {
      const path = `audit/segment-${String(i / 1000).padStart(6, '0')}.json`;
      const segment = { version: 1, rows: rows.slice(i, i + 1000), checkpoint }, size = Buffer.byteLength(JSON.stringify(segment));
      need(bytes + size + existingBytes <= options.quota, 'BACKUP_CAPACITY'); space(root, size, options.minFree + options.pending);
      await json(join(partial, path), segment); await add(path);
    }
  } finally { db.close(); }
  const manifest: BackupManifest = { version: 1, id, created: new Date().toISOString(), checkpoint, entries, bytes };
  const manifestBytes = Buffer.byteLength(JSON.stringify(manifest)); need(bytes + manifestBytes + existingBytes <= options.quota, 'BACKUP_CAPACITY'); space(root, manifestBytes, options.minFree + options.pending);
  await json(join(partial, 'manifest.json'), manifest); await verifyBackup(partial); await rename(partial, join(root, id));
  return { id, created: manifest.created, bytes, checkpoint };
}
export async function verifyBackup(root: string, anchor?: Checkpoint) {
  need(!(await lstat(root)).isSymbolicLink(), 'BACKUP_PATH_UNSAFE');
  const manifestStat = await lstat(join(root, 'manifest.json')); need(manifestStat.isFile() && !manifestStat.isSymbolicLink() && manifestStat.size <= 32 * 1024 ** 2, 'BACKUP_INVALID');
  const m = JSON.parse(await readFile(join(root, 'manifest.json'), 'utf8')) as BackupManifest;
  need(m.version === 1 && backupId.test(m.id) && Array.isArray(m.entries) && m.entries.length <= 100000, 'BACKUP_INVALID');
  const seen = new Set<string>(); let bytes = 0;
  for (const e of m.entries) {
    need(safePath.test(e.path) && !seen.has(e.path) && Number.isSafeInteger(e.size) && e.size >= 0 && /^[0-9a-f]{64}$/.test(e.sha256), 'BACKUP_INVALID'); seen.add(e.path);
    const folder = e.path.split('/')[0]; if (folder !== 'safedrop.sqlite') need(!(await lstat(join(root, folder))).isSymbolicLink(), 'BACKUP_PATH_UNSAFE');
    const s = await lstat(join(root, e.path)); need(s.isFile() && !s.isSymbolicLink() && s.size === e.size && await hash(join(root, e.path)) === e.sha256, 'BACKUP_HASH_MISMATCH'); bytes += e.size;
  }
  need(seen.has('safedrop.sqlite') && bytes === m.bytes, 'BACKUP_INVALID');
  const db = new DatabaseSync(join(root, 'safedrop.sqlite'), { readOnly: true });
  try {
    need(Object.values(db.prepare('PRAGMA integrity_check').get()!)[0] === 'ok', 'BACKUP_INVALID');
    const rows = db.prepare('SELECT * FROM audit ORDER BY seq').all() as Row[]; need(verifyAudit(rows, m.checkpoint).ok && verifyAudit(rows, anchor).ok, 'AUDIT_INTEGRITY_FAILURE');
    need(rows.length === m.checkpoint.count, 'BACKUP_INVALID');
    const segments: Row[] = [];
    for (const e of m.entries.filter(e => e.path.startsWith('audit/')).sort((a, b) => a.path.localeCompare(b.path))) { need(e.size <= 4 * 1024 ** 2, 'BACKUP_INVALID'); segments.push(...JSON.parse(await readFile(join(root, e.path), 'utf8')).rows); }
    need(JSON.stringify(segments) === JSON.stringify(rows), 'BACKUP_INVALID');
    for (const f of db.prepare('SELECT * FROM files').all() as Row[]) {
      const e = m.entries.find(e => e.path === 'objects/' + f.id); const deleting = db.prepare("SELECT id FROM deletions WHERE id=? AND kind='files'").get(f.id);
      need(deleting || e && e.size === f.size && e.sha256 === f.sha256, 'BACKUP_INVALID');
    }
    for (const t of db.prepare('SELECT * FROM transfers').all() as Row[]) {
      const e = m.entries.find(e => e.path === 'staging/' + t.id) ?? m.entries.find(e => e.path === 'objects/' + t.id);
      const deleting = db.prepare("SELECT id FROM deletions WHERE id=? AND kind='transfers'").get(t.id);
      need(deleting || e && e.size >= t.offset && e.size <= t.size, 'BACKUP_INVALID');
    }
  } finally { db.close(); }
  return m;
}
export async function restoreBackup(source: string, target: string, anchor?: Checkpoint) {
  separate(source, target); const m = await verifyBackup(source, anchor);
  // mkdir is exclusive: existing targets, including empty directories, are never overwritten.
  await mkdir(target, { mode: 0o700 }); await json(join(target, '.restore-incomplete'), { backup: m.id });
  for (const folder of ['objects', 'staging']) await mkdir(join(target, folder), { mode: 0o700 });
  for (const e of m.entries.filter(e => !e.path.startsWith('audit/'))) {
    await copyFile(join(source, e.path), join(target, e.path), constants.COPYFILE_EXCL); await durable(join(target, e.path));
    need(await hash(join(target, e.path)) === e.sha256, 'BACKUP_HASH_MISMATCH');
  }
  await unlink(join(target, '.restore-incomplete')); return { id: m.id, checkpoint: m.checkpoint, files: m.entries.filter(e => e.path.startsWith('objects/')).length };
}
