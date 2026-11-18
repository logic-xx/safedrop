import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, createHash } from 'node:crypto';
import { createReadStream, constants } from 'node:fs';
import { open, type FileHandle } from 'node:fs/promises';
import { backupKey, type BackupKeys } from './backup-keys.ts';
import { Fault, need } from './store.ts';

export type BackupHeader = { version: 2; scheme: 'AES-256-GCM/HKDF-SHA256'; id: string; created: string; keyId: string; salt: string };
export type EncryptedManifest = BackupHeader & { bytes: number; sealed: string };
const maxPlaintext = 2 ** 36 - 32; // SP 800-38D per-invocation plaintext bound, in bytes.
export function newBackupHeader(id: string, created: string, keys: BackupKeys): BackupHeader {
  return { version: 2, scheme: 'AES-256-GCM/HKDF-SHA256', id, created, keyId: keys.active, salt: randomBytes(32).toString('base64') };
}
export function validBackupHeader(value: BackupHeader) {
  need(value?.version === 2 && value.scheme === 'AES-256-GCM/HKDF-SHA256' && /^backup-[0-9a-f-]{36}$/.test(value.id) && typeof value.created === 'string' && Number.isFinite(Date.parse(value.created)) && typeof value.keyId === 'string' && typeof value.salt === 'string', 'BACKUP_INVALID');
  const salt = Buffer.from(value.salt, 'base64'); need(salt.length === 32 && salt.toString('base64') === value.salt, 'BACKUP_INVALID');
}
async function writeAll(handle: FileHandle, bytes: Buffer) {
  let offset = 0;
  while (offset < bytes.length) { const result = await handle.write(bytes, offset, bytes.length - offset); need(result.bytesWritten > 0, 'BACKUP_WRITE_FAILED'); offset += result.bytesWritten; }
}
export class BackupCipher {
  #key: Buffer;
  #used = new Set<number>();
  #disposed = false;
  readonly header: BackupHeader;
  constructor(header: BackupHeader, keys: BackupKeys) {
    validBackupHeader(header);
    this.header = Object.freeze({ ...header }); const master = backupKey(keys, header.keyId);
    try { this.#key = Buffer.from(hkdfSync('sha256', master, Buffer.from(header.salt, 'base64'), Buffer.from('SafeDrop backup v2/' + header.id), 32)); }
    finally { master.fill(0); }
  }
  private context(index: number, path: string) {
    need(!this.#disposed && Number.isSafeInteger(index) && index >= 0 && index <= 100000 && typeof path === 'string' && path.length <= 256, 'BACKUP_INVALID');
    const nonce = Buffer.alloc(12); nonce.writeUInt32BE(index, 8);
    const h = this.header, aad = Buffer.from(JSON.stringify([h.version, h.scheme, h.id, h.created, h.keyId, h.salt, index, path]));
    return { nonce, aad };
  }
  private encryptor(index: number, path: string) {
    need(!this.#used.has(index), 'BACKUP_NONCE_REUSE'); this.#used.add(index);
    const { nonce, aad } = this.context(index, path), cipher = createCipheriv('aes-256-gcm', this.#key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad); return cipher;
  }
  private decryptor(index: number, path: string, tag: Buffer) {
    const { nonce, aad } = this.context(index, path), cipher = createDecipheriv('aes-256-gcm', this.#key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad); cipher.setAuthTag(tag); return cipher;
  }
  seal(index: number, path: string, bytes: Buffer) {
    need(bytes.length <= maxPlaintext, 'BACKUP_FILE_TOO_LARGE');
    const cipher = this.encryptor(index, path), payload = Buffer.concat([cipher.update(bytes), cipher.final()]);
    return Buffer.concat([payload, cipher.getAuthTag()]);
  }
  unseal(index: number, path: string, bytes: Buffer) {
    need(bytes.length >= 16 && bytes.length - 16 <= maxPlaintext, 'BACKUP_INVALID');
    const cipher = this.decryptor(index, path, bytes.subarray(-16));
    try { return Buffer.concat([cipher.update(bytes.subarray(0, -16)), cipher.final()]); }
    catch { throw new Fault('BACKUP_AUTH_FAILED'); }
  }
  async sealFile(source: string, destination: string, size: number, index: number, path: string) {
    need(Number.isSafeInteger(size) && size >= 0 && size <= maxPlaintext, 'BACKUP_FILE_TOO_LARGE');
    const cipher = this.encryptor(index, path), output = await open(destination, 'wx', 0o600), hash = createHash('sha256'); let bytes = 0;
    try {
      for await (const raw of createReadStream(source)) {
        const chunk = Buffer.from(raw); bytes += chunk.length; need(bytes <= size, 'BACKUP_SOURCE_CHANGED'); hash.update(chunk); await writeAll(output, cipher.update(chunk));
      }
      need(bytes === size, 'BACKUP_SOURCE_CHANGED'); await writeAll(output, cipher.final()); await writeAll(output, cipher.getAuthTag()); await output.sync();
      return { size: bytes, sha256: hash.digest('hex') };
    } finally { await output.close(); }
  }
  async *unsealFile(source: string, size: number, index: number, path: string): AsyncGenerator<Buffer> {
    need(Number.isSafeInteger(size) && size >= 0 && size <= maxPlaintext, 'BACKUP_INVALID');
    const input = await open(source, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const stat = await input.stat(); need(stat.isFile() && stat.size === size + 16, 'BACKUP_HASH_MISMATCH');
      const tag = Buffer.alloc(16); let offset = 0;
      while (offset < 16) { const read = await input.read(tag, offset, 16 - offset, size + offset); need(read.bytesRead > 0, 'BACKUP_INVALID'); offset += read.bytesRead; }
      const cipher = this.decryptor(index, path, tag);
      if (size > 0) for await (const chunk of input.createReadStream({ start: 0, end: size - 1, autoClose: false })) yield cipher.update(chunk);
      try { const final = cipher.final(); if (final.length) yield final; } catch { throw new Fault('BACKUP_AUTH_FAILED'); }
    } finally { await input.close(); }
  }
  dispose() { this.#key.fill(0); this.#disposed = true; }
}
