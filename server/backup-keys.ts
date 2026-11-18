import { constants } from 'node:fs';
import { open, lstat, mkdir, rename, unlink, realpath } from 'node:fs/promises';
import { basename, dirname, resolve, sep } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { Fault, need } from './store.ts';

export type BackupKeys = { version: 1; active: string; keys: { id: string; material: string }[] };
const keyId = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const normalize = (path: string) => process.platform === 'win32' ? resolve(path).toLowerCase() : resolve(path);
const within = (file: string, root: string) => normalize(file) === normalize(root) || normalize(file).startsWith(normalize(root) + sep);

export async function backupKeyLocation(file: string, data: string, backups: string, mfaFile: string) {
  need(!within(file, data) && !within(file, backups) && normalize(file) !== normalize(mfaFile), 'BACKUP_KEY_PATH_UNSAFE');
  // Resolve the existing parent too, so a directory link cannot put a key in a backup.
  const physical = resolve(await realpath(dirname(file)), basename(file));
  for (const root of [data, backups]) {
    const actual = await realpath(root).catch(error => { if (error.code === 'ENOENT') return resolve(root); throw error; });
    need(!within(physical, actual), 'BACKUP_KEY_PATH_UNSAFE');
  }
}

export async function readBackupKeys(file: string): Promise<BackupKeys> {
  try {
    const stat = await lstat(file); need(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 65536, 'BACKUP_KEY_INVALID');
    const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    let bytes: Buffer;
    try {
      const current = await handle.stat();
      need(current.isFile() && current.size <= 65536 && (process.platform === 'win32' || (current.mode & 0o077) === 0), 'BACKUP_KEY_PERMISSIONS');
      bytes = await handle.readFile(); need(bytes.length <= 65536, 'BACKUP_KEY_INVALID');
    } finally { await handle.close(); }
    let ring: BackupKeys; try { ring = JSON.parse(bytes.toString('utf8')); } catch { throw new Fault('BACKUP_KEY_INVALID'); }
    need(ring?.version === 1 && keyId.test(ring.active) && Array.isArray(ring.keys) && ring.keys.length > 0 && ring.keys.length <= 32, 'BACKUP_KEY_INVALID');
    const seen = new Set<string>();
    for (const key of ring.keys) {
      need(key && keyId.test(key.id) && !seen.has(key.id) && typeof key.material === 'string', 'BACKUP_KEY_INVALID');
      const material = Buffer.from(key.material, 'base64');
      need(material.length === 32 && material.toString('base64') === key.material, 'BACKUP_KEY_INVALID'); seen.add(key.id);
    }
    need(seen.has(ring.active), 'BACKUP_KEY_INVALID'); return ring;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new Fault('BACKUP_KEY_MISSING');
    throw error;
  }
}

export function backupKeyInfo(ring: BackupKeys) { return { activeKeyId: ring.active, keyIds: ring.keys.map(key => key.id), retainedKeys: ring.keys.length }; }
export function backupKey(ring: BackupKeys, id = ring.active) { const key = ring.keys.find(key => key.id === id); need(key, 'BACKUP_KEY_NOT_FOUND'); return Buffer.from(key.material, 'base64'); }
async function syncParent(file: string) {
  if (process.platform === 'win32') return;
  const directory = await open(dirname(file), 'r'); try { await directory.sync(); } finally { await directory.close(); }
}
async function writeKey(file: string, ring: BackupKeys) {
  const handle = await open(file, 'wx', 0o600); try { await handle.writeFile(JSON.stringify(ring)); await handle.sync(); } finally { await handle.close(); }
}
export async function changeBackupKeys(path: string, rotate = false) {
  const file = resolve(path); await mkdir(dirname(file), { recursive: true, mode: 0o700 });
  let lock;
  try { lock = await open(file + '.lock', 'wx', 0o600); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Fault('BACKUP_KEY_BUSY'); throw error; }
  const temporary = file + '.' + randomUUID() + '.partial';
  try {
    let ring: BackupKeys = rotate ? await readBackupKeys(file) : { version: 1, active: '', keys: [] };
    need(ring.keys.length < 32, 'BACKUP_KEY_CAPACITY');
    const id = randomUUID(); ring = { ...ring, active: id, keys: [...ring.keys, { id, material: randomBytes(32).toString('base64') }] };
    if (rotate) { await writeKey(temporary, ring); await rename(temporary, file); }
    else { try { await writeKey(file, ring); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Fault('BACKUP_KEY_EXISTS'); throw error; } }
    await syncParent(file); return backupKeyInfo(ring);
  } finally {
    try { await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
    finally { await lock.close(); await unlink(file + '.lock'); }
  }
}
