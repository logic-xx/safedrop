import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Store, Fault, need, type Row } from './store.ts';
import type { ScanEngine, ScanVerdict } from './clamd.ts';

export class ScanGuard {
  private timer?: ReturnType<typeof setTimeout>;
  private active?: { id: string; abort: AbortController; done: Promise<void> };
  private closing = false;
  constructor(private store: Store, private engine: ScanEngine | undefined, private locks: Set<string>, private allowed: () => boolean, private reserve: () => (() => void) | undefined, private maxAgeMs = 168 * 3600000, private now = () => Date.now()) {
    need(Number.isSafeInteger(maxAgeMs) && maxAgeMs > 0 && maxAgeMs <= 30 * 86400000, 'SCAN_CONFIGURATION_INVALID');
    // No legacy files become clean during migration or restart.
    store.run("UPDATE file_scans SET state='pending',code='SCAN_INTERRUPTED' WHERE state='scanning'");
    this.wake();
  }
  status(file: Row) {
    const row = this.store.get('SELECT * FROM file_scans WHERE fileId=?', file.id);
    if (!row || row.sha256 !== file.sha256 || row.size !== file.size) return { state: 'unscanned', checked: 0, engine: '', signature: '', code: 'FILE_SCAN_REQUIRED' };
    if (row.state === 'clean' && (row.checked > this.now() + 3600000 || this.now() - row.checked >= this.maxAgeMs)) return { state: 'unscanned', checked: row.checked, engine: row.engine, signature: '', code: 'SCAN_RESULT_EXPIRED' };
    return { state: row.state, checked: row.checked, engine: row.engine, signature: row.signature, code: row.code };
  }
  requireClean(file: Row) {
    const status = this.status(file);
    need(status.state === 'clean', status.state === 'quarantined' ? 'FILE_QUARANTINED' : 'FILE_SCAN_REQUIRED');
  }
  enqueue(file: Row) {
    const current = this.status(file); if (current.state === 'pending' || current.state === 'scanning') return false;
    this.store.run("INSERT INTO file_scans(fileId,sha256,size,state,generation,requested) VALUES(?,?,?,'pending',?,?) ON CONFLICT(fileId) DO UPDATE SET sha256=excluded.sha256,size=excluded.size,state='pending',generation=excluded.generation,requested=excluded.requested,checked=0,engine='',signature='',code=''", file.id, file.sha256, file.size, randomUUID(), this.now());
    return true;
  }
  wake(delay = 0) {
    if (this.closing || this.active) return;
    if (this.timer) { if (delay) return; clearTimeout(this.timer); this.timer = undefined; }
    this.timer = setTimeout(() => { this.timer = undefined; void this.pump().catch(() => {}); }, delay); this.timer.unref();
  }
  private async pump() {
    if (this.closing || this.active || !this.allowed()) return;
    const pending = this.store.all("SELECT s.*,f.userId FROM file_scans s JOIN files f ON f.id=s.fileId LEFT JOIN deletions d ON d.id=f.id AND d.kind='files' WHERE s.state='pending' AND d.id IS NULL ORDER BY s.requested,s.fileId LIMIT 32");
    const task = pending.find(row => !this.locks.has(row.fileId));
    if (!task) { if (pending.length) this.wake(100); return; }
    const release = this.reserve(); if (!release) { this.wake(30000); return; }
    const abort = new AbortController(); let done!: () => void, retryDelay = 0;
    this.active = { id: task.fileId, abort, done: new Promise<void>(yes => { done = yes; }) }; this.locks.add(task.fileId);
    try {
      this.store.transaction(() => {
        this.store.run("UPDATE file_scans SET state='scanning',code='' WHERE fileId=? AND generation=?", task.fileId, task.generation);
        this.store.audit('system', 'files.scan.begin', 'allowed', { fileId: task.fileId, ownerId: task.userId });
      });
      let verdict: ScanVerdict;
      try {
        need(this.engine, 'SCANNER_UNAVAILABLE');
        verdict = await this.engine.scan({ path: join(this.store.root, 'objects', task.fileId), size: task.size, sha256: task.sha256 }, abort.signal);
        need(!abort.signal.aborted, 'SCAN_INTERRUPTED');
        need(verdict.sha256 === task.sha256 && verdict.bytes === task.size && typeof verdict.engine === 'string' && verdict.engine.length > 0 && verdict.engine.length <= 200 && ['clean', 'quarantined', 'error'].includes(verdict.state), 'SCAN_SOURCE_CHANGED');
      } catch (error) { verdict = { state: 'error', engine: '', sha256: task.sha256, bytes: task.size, code: error instanceof Fault ? error.code : 'SCANNER_UNAVAILABLE' }; }
      const file = this.store.get('SELECT * FROM files WHERE id=?', task.fileId), current = this.store.get('SELECT * FROM file_scans WHERE fileId=?', task.fileId);
      if (!file || file.sha256 !== task.sha256 || file.size !== task.size || !current || current.generation !== task.generation || current.state !== 'scanning') return;
      const state = this.closing ? 'pending' : verdict.state;
      this.store.transaction(() => {
        this.store.run('UPDATE file_scans SET state=?,checked=?,engine=?,signature=?,code=? WHERE fileId=? AND generation=?', state, state === 'pending' ? 0 : this.now(), verdict.engine, verdict.signature?.slice(0, 160) ?? '', verdict.code ?? '', task.fileId, task.generation);
        this.store.audit('system', 'files.scan', state === 'clean' ? 'allowed' : 'denied', { fileId: task.fileId, ownerId: task.userId, state, engine: verdict.engine, ...(verdict.signature ? { signature: verdict.signature.slice(0, 160) } : {}), ...(verdict.code ? { code: verdict.code } : {}) });
      });
    } catch { retryDelay = 30000; /* Failed state/audit writes never publish clean. Avoid a failing-disk retry loop. */ }
    finally { this.locks.delete(task.fileId); release(); this.active = undefined; done(); this.wake(retryDelay); }
  }
  async idle() { await this.active?.done; }
  async cancel(fileId: string) { if (this.active?.id === fileId) { this.active.abort.abort(); await this.active.done; } }
  summary() { return { required: true, configured: Boolean(this.engine), active: Boolean(this.active), resultMaxHours: this.maxAgeMs / 3600000, counts: this.store.all("SELECT CASE WHEN s.fileId IS NULL OR s.sha256<>f.sha256 OR s.size<>f.size OR (s.state='clean' AND (s.checked<=? OR s.checked>?)) THEN 'unscanned' ELSE s.state END AS state,COUNT(*) AS count FROM files f LEFT JOIN file_scans s ON s.fileId=f.id GROUP BY 1", this.now() - this.maxAgeMs, this.now() + 3600000) }; }
  async close() { this.closing = true; clearTimeout(this.timer); this.active?.abort.abort(); await this.idle(); }
}
