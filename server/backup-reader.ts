import { constants, createReadStream } from 'node:fs';
import { mkdir, mkdtemp, chmod, rmdir, lstat, open, readFile, copyFile, unlink, readdir, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { Fault, need, verifyAudit, type Checkpoint, type Row } from './store.ts';
import { BackupCipher, validBackupHeader, type EncryptedManifest } from './backup-crypto.ts';
import { readBackupKeys } from './backup-keys.ts';

export type Entry = { path: string; size: number; sha256: string };
export type BackupManifest = { version: 1; id: string; created: string; checkpoint: Checkpoint; entries: Entry[]; bytes: number };
export type BackupAccess = { keyFile?: string; allowPlaintext?: boolean; temporaryRoot?: string };
export type VerifiedBackup = BackupManifest & { encrypted: boolean; keyId?: string; storedBytes: number };
export const backupId = /^backup-[0-9a-f-]{36}$/;
export const safePath = /^(safedrop\.sqlite|(?:objects|staging)\/[a-zA-Z0-9_-]{1,100}|audit\/segment-[0-9]{6}\.json)$/;
export const sealedPath = (index: number) => `sealed/${String(index).padStart(6, '0')}.bin`;
export async function hash(path: string) { const h = createHash('sha256'); for await (const chunk of createReadStream(path)) h.update(chunk); return h.digest('hex'); }
export async function durable(path: string) { const h = await open(path, 'r+'); try { await h.chmod(0o600); await h.sync(); } finally { await h.close(); } }
export async function privateJson(path: string, value: unknown) { const h = await open(path, 'wx', 0o600); try { await h.writeFile(JSON.stringify(value)); await h.sync(); } finally { await h.close(); } }
export function separate(source: string, destination: string) {
  const normalized = (p: string) => process.platform === 'win32' ? resolve(p).toLowerCase() : resolve(p);
  const a = normalized(source), b = normalized(destination); need(a !== b && !b.startsWith(a + sep) && !a.startsWith(b + sep), 'BACKUP_PATH_UNSAFE');
}
function parse(bytes: Buffer | string) { try { return JSON.parse(bytes.toString()); } catch { throw new Fault('BACKUP_INVALID'); } }
export async function manifestFile(root: string) {
  need(!(await lstat(root)).isSymbolicLink(), 'BACKUP_PATH_UNSAFE');
  const stat = await lstat(join(root, 'manifest.json')); need(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 32 * 1024 ** 2, 'BACKUP_INVALID');
  return parse(await readFile(join(root, 'manifest.json')));
}
type Reader = { root: string; manifest: BackupManifest; encrypted: boolean; keyId?: string; storedBytes: number; source(e: Entry): string; chunks(e: Entry): AsyncIterable<Buffer> };
async function withReader<T>(root: string, access: BackupAccess, work: (reader: Reader) => Promise<T>) {
  const outer = await manifestFile(root); let cipher: BackupCipher | undefined;
  try {
    let manifest: BackupManifest;
    if (outer.version === 2) {
      validBackupHeader(outer); need(access.keyFile, 'BACKUP_KEY_MISSING');
      need(typeof outer.sealed === 'string' && outer.sealed.length <= 32 * 1024 ** 2, 'BACKUP_INVALID');
      const bytes = Buffer.from(outer.sealed, 'base64'); need(bytes.toString('base64') === outer.sealed, 'BACKUP_INVALID');
      cipher = new BackupCipher(outer, await readBackupKeys(access.keyFile)); manifest = parse(cipher.unseal(0, 'manifest', bytes));
      need(manifest && manifest.id === outer.id && manifest.created === outer.created, 'BACKUP_INVALID');
    } else {
      need(outer.version === 1, 'BACKUP_INVALID'); need(access.allowPlaintext === true, 'BACKUP_PLAINTEXT_CONFIRMATION_REQUIRED'); manifest = outer;
    }
    need(manifest?.version === 1 && backupId.test(manifest.id) && typeof manifest.created === 'string' && Number.isFinite(Date.parse(manifest.created)) && Array.isArray(manifest.entries) && manifest.entries.length <= 100000, 'BACKUP_INVALID');
    need(manifest.checkpoint && Number.isSafeInteger(manifest.checkpoint.count) && manifest.checkpoint.count >= 0 && /^[a-f0-9]{64}$/.test(manifest.checkpoint.head), 'BACKUP_INVALID');
    const seen = new Set<string>(), indexes = new Map<Entry, number>(); let bytes = 0;
    for (const [index, entry] of manifest.entries.entries()) {
      need(entry && safePath.test(entry.path) && !seen.has(entry.path) && Number.isSafeInteger(entry.size) && entry.size >= 0 && /^[0-9a-f]{64}$/.test(entry.sha256), 'BACKUP_INVALID');
      seen.add(entry.path); indexes.set(entry, index + 1); bytes += entry.size; need(Number.isSafeInteger(bytes), 'BACKUP_INVALID');
    }
    need(seen.has('safedrop.sqlite') && bytes === manifest.bytes, 'BACKUP_INVALID');
    if (cipher) {
      need(Number.isSafeInteger(outer.bytes) && outer.bytes === bytes + manifest.entries.length * 16, 'BACKUP_INVALID');
      const top = await readdir(root); need(top.length === 2 && top.includes('sealed') && top.includes('manifest.json'), 'BACKUP_INVALID');
      const folder = await lstat(join(root, 'sealed')); need(folder.isDirectory() && !folder.isSymbolicLink(), 'BACKUP_PATH_UNSAFE');
      const files = await readdir(join(root, 'sealed')); need(files.length === manifest.entries.length && files.every(name => /^\d{6}\.bin$/.test(name)), 'BACKUP_INVALID');
    }
    const source = (entry: Entry) => join(root, cipher ? sealedPath(indexes.get(entry)!) : entry.path);
    const reader: Reader = { root, manifest, encrypted: Boolean(cipher), ...(cipher ? { keyId: outer.keyId } : {}), storedBytes: outer.bytes, source,
      async *chunks(entry) {
        if (!cipher && entry.path !== 'safedrop.sqlite') { const folder = await lstat(join(root, entry.path.split('/')[0])); need(folder.isDirectory() && !folder.isSymbolicLink(), 'BACKUP_PATH_UNSAFE'); }
        const file = source(entry), stat = await lstat(file); need(stat.isFile() && !stat.isSymbolicLink() && stat.size === entry.size + (cipher ? 16 : 0), 'BACKUP_HASH_MISMATCH');
        if (cipher) yield* cipher.unsealFile(file, entry.size, indexes.get(entry)!, entry.path);
        else for await (const chunk of createReadStream(file)) yield Buffer.from(chunk);
      }
    };
    return await work(reader);
  } finally { cipher?.dispose(); }
}
async function writeEntry(reader: Reader, entry: Entry, destination?: string) {
  const output = destination ? await open(destination, 'wx', 0o600) : undefined, digest = createHash('sha256'); let bytes = 0;
  try {
    for await (const chunk of reader.chunks(entry)) { bytes += chunk.length; need(bytes <= entry.size, 'BACKUP_HASH_MISMATCH'); digest.update(chunk); if (output) await output.writeFile(chunk); }
    need(bytes === entry.size && digest.digest('hex') === entry.sha256, 'BACKUP_HASH_MISMATCH');
    if (output) await output.sync();
  } finally { await output?.close(); }
}
async function verifyReader(reader: Reader, anchor?: Checkpoint, temporaryRoot?: string): Promise<VerifiedBackup> {
  const m = reader.manifest; let temporary: string | undefined, db: DatabaseSync | undefined;
  try {
    let database = reader.source(m.entries.find(entry => entry.path === 'safedrop.sqlite')!);
    if (reader.encrypted) {
      const parent = await realpath(temporaryRoot ?? tmpdir()), source = await realpath(reader.root), normalize = (path: string) => process.platform === 'win32' ? path.toLowerCase() : path;
      need(normalize(parent) !== normalize(source) && !normalize(parent).startsWith(normalize(source) + sep), 'BACKUP_PATH_UNSAFE');
      temporary = await mkdtemp(join(parent, 'safedrop-backup-verify-')); await chmod(temporary, 0o700); database = join(temporary, 'safedrop.sqlite');
    }
    for (const entry of m.entries) await writeEntry(reader, entry, reader.encrypted && entry.path === 'safedrop.sqlite' ? database : undefined);
    db = new DatabaseSync(database, { readOnly: true }); need(Object.values(db.prepare('PRAGMA integrity_check').get()!)[0] === 'ok', 'BACKUP_INVALID');
    const rows = db.prepare('SELECT * FROM audit ORDER BY seq').all() as Row[];
    need(verifyAudit(rows, m.checkpoint).ok && verifyAudit(rows, anchor).ok, 'AUDIT_INTEGRITY_FAILURE'); need(rows.length === m.checkpoint.count, 'BACKUP_INVALID');
    const segments: Row[] = [];
    for (const entry of m.entries.filter(entry => entry.path.startsWith('audit/')).sort((a, b) => a.path.localeCompare(b.path))) {
      need(entry.size <= 4 * 1024 ** 2, 'BACKUP_INVALID'); const chunks: Buffer[] = []; for await (const chunk of reader.chunks(entry)) chunks.push(chunk);
      const segment = parse(Buffer.concat(chunks)); need(Array.isArray(segment.rows) && segment.rows.length <= 1000, 'BACKUP_INVALID'); segments.push(...segment.rows);
    }
    need(JSON.stringify(segments) === JSON.stringify(rows), 'BACKUP_INVALID'); const entries = new Map(m.entries.map(entry => [entry.path, entry]));
    for (const file of db.prepare('SELECT * FROM files').all() as Row[]) {
      const entry = entries.get('objects/' + file.id), deleting = db.prepare("SELECT id FROM deletions WHERE id=? AND kind='files'").get(file.id);
      need(deleting || entry && entry.size === file.size && entry.sha256 === file.sha256, 'BACKUP_INVALID');
    }
    for (const transfer of db.prepare('SELECT * FROM transfers').all() as Row[]) {
      const entry = entries.get('staging/' + transfer.id) ?? entries.get('objects/' + transfer.id), deleting = db.prepare("SELECT id FROM deletions WHERE id=? AND kind='transfers'").get(transfer.id);
      need(deleting || entry && entry.size >= transfer.offset && entry.size <= transfer.size, 'BACKUP_INVALID');
    }
    return { ...m, encrypted: reader.encrypted, ...(reader.keyId ? { keyId: reader.keyId } : {}), storedBytes: reader.storedBytes };
  } finally {
    db?.close();
    if (temporary) {
      try { for (const suffix of ['', '-wal', '-shm', '-journal']) await unlink(join(temporary, 'safedrop.sqlite' + suffix)).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
      finally { await rmdir(temporary); }
    }
  }
}
export async function verifyBackup(root: string, anchor?: Checkpoint, access: BackupAccess = {}) { return withReader(root, access, reader => verifyReader(reader, anchor, access.temporaryRoot)); }
export async function restoreBackup(source: string, target: string, anchor?: Checkpoint, access: BackupAccess = {}) {
  separate(source, target);
  // A linked target parent must not route plaintext back into the source backup.
  separate(await realpath(source), join(await realpath(dirname(target)), basename(target)));
  return withReader(source, access, async reader => {
    const m = await verifyReader(reader, anchor, access.temporaryRoot);
    await mkdir(target, { mode: 0o700 }); await privateJson(join(target, '.restore-incomplete'), { backup: m.id });
    for (const folder of ['objects', 'staging']) await mkdir(join(target, folder), { mode: 0o700 });
    for (const entry of m.entries.filter(entry => !entry.path.startsWith('audit/'))) {
      if (reader.encrypted) await writeEntry(reader, entry, join(target, entry.path));
      else { await copyFile(reader.source(entry), join(target, entry.path), constants.COPYFILE_EXCL); await durable(join(target, entry.path)); need(await hash(join(target, entry.path)) === entry.sha256, 'BACKUP_HASH_MISMATCH'); }
    }
    await unlink(join(target, '.restore-incomplete')); return { id: m.id, checkpoint: m.checkpoint, files: m.entries.filter(entry => entry.path.startsWith('objects/')).length, encrypted: m.encrypted, ...(m.keyId ? { keyId: m.keyId } : {}) };
  });
}
