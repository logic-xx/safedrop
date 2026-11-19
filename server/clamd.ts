import { createConnection } from 'node:net';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Fault, need } from './store.ts';

export type ScanInput = { path: string; size: number; sha256: string };
export type ScanVerdict = { state: 'clean' | 'quarantined' | 'error'; engine: string; sha256: string; bytes: number; signature?: string; code?: string };
export interface ScanEngine { scan(input: ScanInput, signal: AbortSignal): Promise<ScanVerdict> }
export type ClamdOptions = { host: string; port?: number; timeoutMs?: number; maxBytes?: number; maxDatabaseAgeMs?: number };
const printable = /^[\x20-\x7e]{1,200}$/;
export function clamdVersion(reply: string, maxAge: number, now = Date.now()) {
  const match = /^ClamAV (\d+)\.(\d+)\.(\d+)\/(\d+)\/(.+)$/.exec(reply);
  need(match && printable.test(reply), 'SCAN_ENGINE_INVALID');
  const [, major, minor, patch, , date] = match;
  need(Number(major) === 1 && (Number(minor) > 5 || Number(minor) === 5 && Number(patch) >= 5), 'SCAN_ENGINE_OUTDATED');
  // Scanner containers run TZ=Etc/UTC; VERSION uses ctime without an offset.
  const built = Date.parse(date + ' UTC');
  need(Number.isFinite(built) && built <= now + 3600000 && now - built <= maxAge, 'SCAN_DATABASE_STALE');
  return reply;
}
export class ClamdEngine implements ScanEngine {
  constructor(readonly options: ClamdOptions) {
    need(typeof options.host === 'string' && options.host.length > 0 && !/[\x00-\x20]/.test(options.host), 'SCAN_CONFIGURATION_INVALID');
    need(Number.isSafeInteger(options.port ?? 3310) && (options.port ?? 3310) > 0 && (options.port ?? 3310) <= 65535, 'SCAN_CONFIGURATION_INVALID');
    need(Number.isSafeInteger(options.timeoutMs ?? 90000) && (options.timeoutMs ?? 90000) >= 100 && (options.timeoutMs ?? 90000) <= 300000, 'SCAN_CONFIGURATION_INVALID');
    need(Number.isSafeInteger(options.maxBytes ?? 512 * 1024 ** 2) && (options.maxBytes ?? 512 * 1024 ** 2) > 0 && (options.maxBytes ?? 512 * 1024 ** 2) <= 512 * 1024 ** 2, 'SCAN_CONFIGURATION_INVALID');
    need(Number.isSafeInteger(options.maxDatabaseAgeMs ?? 72 * 3600000) && (options.maxDatabaseAgeMs ?? 72 * 3600000) > 0 && (options.maxDatabaseAgeMs ?? 72 * 3600000) <= 168 * 3600000, 'SCAN_CONFIGURATION_INVALID');
  }
  private async exchange(command: 'VERSION' | 'INSTREAM', signal: AbortSignal, send?: (write: (bytes: Buffer) => Promise<void>) => Promise<void>) {
    signal.throwIfAborted();
    const socket = createConnection({ host: this.options.host, port: this.options.port ?? 3310 });
    let timer: ReturnType<typeof setTimeout> | undefined, settle!: (line: string) => void, fail!: (error: Error) => void;
    let received = Buffer.alloc(0), finished = false, sent = !send;
    const response = new Promise<string>((yes, no) => { settle = yes; fail = no; });
    // Attach the rejection observer before asynchronous upload starts.
    void response.catch(() => {});
    const reject = (code: string) => { if (!finished) { finished = true; fail(new Fault(code)); } socket.destroy(); };
    const aborted = () => reject('SCAN_INTERRUPTED');
    signal.addEventListener('abort', aborted, { once: true });
    timer = setTimeout(() => reject('SCAN_TIMEOUT'), this.options.timeoutMs ?? 90000); timer.unref();
    socket.on('error', () => reject('SCANNER_UNAVAILABLE'));
    socket.on('end', () => { if (!finished) reject('SCAN_ENGINE_INVALID'); });
    socket.on('data', chunk => {
      if (finished) return;
      received = Buffer.concat([received, chunk]);
      if (received.length > 1024) return reject('SCAN_ENGINE_INVALID');
      const end = received.indexOf(0);
      if (end !== -1) {
        if (end !== received.length - 1 || !sent) return reject('SCAN_ENGINE_INVALID');
        const line = received.subarray(0, end).toString('utf8');
        if (!printable.test(line)) return reject('SCAN_ENGINE_INVALID');
        finished = true; settle(line); socket.destroy();
      }
    });
    const write = (bytes: Buffer) => new Promise<void>((yes, no) => {
      if (finished || signal.aborted || socket.destroyed) return no(new Fault('SCANNER_UNAVAILABLE'));
      socket.write(bytes, error => error ? no(new Fault('SCANNER_UNAVAILABLE')) : yes());
    });
    try {
      await new Promise<void>((yes, no) => { socket.once('connect', yes); socket.once('error', () => no(new Fault('SCANNER_UNAVAILABLE'))); socket.once('close', () => no(new Fault('SCANNER_UNAVAILABLE'))); });
      await write(Buffer.from('z' + command + '\0'));
      if (send) await send(write);
      sent = true;
      return await response;
    } catch (error) {
      if (finished) return await response;
      throw error;
    } finally {
      clearTimeout(timer); signal.removeEventListener('abort', aborted); socket.destroy();
    }
  }
  async scan(input: ScanInput, signal: AbortSignal): Promise<ScanVerdict> {
    need(Number.isSafeInteger(input.size) && input.size >= 0 && input.size <= (this.options.maxBytes ?? 512 * 1024 ** 2), 'SCAN_LIMIT');
    const age = this.options.maxDatabaseAgeMs ?? 72 * 3600000;
    const engine = clamdVersion(await this.exchange('VERSION', signal), age);
    const stat = await lstat(input.path); need(stat.isFile() && !stat.isSymbolicLink() && stat.size === input.size, 'SCAN_SOURCE_CHANGED');
    const file = await open(input.path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const hash = createHash('sha256'); let bytes = 0;
    try {
      const initial = await file.stat({ bigint: true }); need(initial.isFile() && initial.size === BigInt(input.size), 'SCAN_SOURCE_CHANGED');
      const result = await this.exchange('INSTREAM', signal, async write => {
        if (input.size) for await (const raw of file.createReadStream({ autoClose: false, signal })) {
          const chunk = Buffer.from(raw); bytes += chunk.length; need(bytes <= input.size, 'SCAN_SOURCE_CHANGED'); hash.update(chunk);
          const length = Buffer.alloc(4); length.writeUInt32BE(chunk.length); await write(length); await write(chunk);
        }
        need(bytes === input.size, 'SCAN_SOURCE_CHANGED'); await write(Buffer.alloc(4));
      });
      const digest = hash.digest('hex'), final = await file.stat({ bigint: true });
      need(digest === input.sha256 && final.size === initial.size && final.mtimeNs === initial.mtimeNs && final.ctimeNs === initial.ctimeNs, 'SCAN_SOURCE_CHANGED');
      need(await this.exchange('VERSION', signal) === engine, 'SCAN_ENGINE_CHANGED');
      const base = { engine, sha256: digest, bytes };
      if (result === 'stream: OK') return { ...base, state: 'clean' };
      const threat = /^stream: ([\x20-\x7e]{1,160}) FOUND$/.exec(result);
      if (threat) {
        if (threat[1].startsWith('Heuristics.Limits.Exceeded')) return { ...base, state: 'error', code: 'SCAN_LIMIT' };
        if (threat[1].startsWith('Heuristics.Encrypted')) return { ...base, state: 'error', code: 'SCAN_ENCRYPTED' };
        return { ...base, state: 'quarantined', signature: threat[1] };
      }
      throw new Fault(result.includes('size limit exceeded') ? 'SCAN_LIMIT' : 'SCAN_ENGINE_INVALID');
    } finally { await file.close(); }
  }
}
