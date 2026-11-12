import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes, randomUUID, scrypt as rawScrypt, timingSafeEqual } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

export const digest = (s: string | Uint8Array) => createHash('sha256').update(s).digest('hex');
export class Fault extends Error { constructor(public code: string, message = code) { super(message); } }
export function need(ok: unknown, code: string): asserts ok { if (!ok) throw new Fault(code); }
export function text(v: unknown, max = 180): string { need(typeof v === 'string' && v.length > 0 && v.length <= max, 'INVALID_INPUT'); return v; }
export function integer(v: unknown, max = Number.MAX_SAFE_INTEGER): number { need(Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) <= max, 'INVALID_INTEGER'); return Number(v); }
export const id = () => randomUUID();
const derive = (pass: string, salt: string) => new Promise<Buffer>((resolve, reject) => rawScrypt(pass, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 ** 2 }, (e, key) => e ? reject(e) : resolve(key)));
export async function passwordHash(pass: string) { const salt = randomBytes(16).toString('hex'); return `${salt}:${(await derive(pass, salt)).toString('hex')}`; }
export async function passwordCheck(pass: string, hash: string) { const [salt, hex] = hash.split(':'); const actual = await derive(pass, salt); return timingSafeEqual(actual, Buffer.from(hex, 'hex')); }
export type Row = Record<string, any>;
export interface Checkpoint { count: number; head: string }
export function verifyAudit(rows: Row[], anchor?: Checkpoint) {
  let prev = '0'.repeat(64), count = 0, anchored = !anchor || anchor.count === 0 && anchor.head === prev;
  for (const r of rows) {
    count++;
    if (r.seq !== count || r.prev !== prev || digest(prev + r.event) !== r.hash) return { ok: false, at: count, reason: 'CHAIN_MISMATCH' };
    prev = r.hash;
    if (anchor?.count === count) anchored = anchor.head === prev;
  }
  return { ok: anchored, count, head: prev, reason: anchored ? 'VERIFIED' : 'CHECKPOINT_MISMATCH' };
}
export class Store {
  db: DatabaseSync;
  constructor(public root: string) {
    mkdirSync(join(root, 'objects'), { recursive: true }); mkdirSync(join(root, 'staging'), { recursive: true });
    this.db = new DatabaseSync(join(root, 'safedrop.sqlite'));
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT UNIQUE NOT NULL,hash TEXT NOT NULL,role TEXT NOT NULL,tier TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,userId TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,agent TEXT NOT NULL,ip TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS keys(id TEXT PRIMARY KEY,userId TEXT NOT NULL,jwk TEXT NOT NULL,label TEXT NOT NULL,created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,userId TEXT NOT NULL,name TEXT NOT NULL,size INTEGER NOT NULL,sha256 TEXT NOT NULL,created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS transfers(id TEXT PRIMARY KEY,userId TEXT NOT NULL,name TEXT NOT NULL,size INTEGER NOT NULL,sha256 TEXT NOT NULL,offset INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY,event TEXT NOT NULL,prev TEXT NOT NULL,hash TEXT NOT NULL);`);
  }
  get(sql: string, ...args: any[]): Row | undefined { return this.db.prepare(sql).get(...args) as Row | undefined; }
  all(sql: string, ...args: any[]): Row[] { return this.db.prepare(sql).all(...args) as Row[]; }
  run(sql: string, ...args: any[]) { return this.db.prepare(sql).run(...args); }
  async addUser(name: string, password: string, role = 'user', tier = 'normal') {
    need(/^[a-zA-Z0-9_-]{3,32}$/.test(name) && password.length >= 12 && password.length <= 256, 'INVALID_USER');
    const userId = id(); this.run('INSERT INTO users VALUES(?,?,?,?,?)', userId, name, await passwordHash(password), role, tier); return userId;
  }
  audit(user: string, action: string, result: string, detail: Record<string, unknown> = {}) {
    const event = JSON.stringify({ time: new Date().toISOString(), user, action, result, detail });
    const last = this.get('SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1');
    const prev = last?.hash ?? '0'.repeat(64); this.run('INSERT INTO audit VALUES(?,?,?,?)', (last?.seq ?? 0) + 1, event, prev, digest(prev + event));
  }
  checkpoint(): Checkpoint { const r = this.get('SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1'); return { count: r?.seq ?? 0, head: r?.hash ?? '0'.repeat(64) }; }
  close() { this.db.close(); }
}
