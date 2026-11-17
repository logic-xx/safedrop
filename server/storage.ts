import { statfsSync } from 'node:fs';
import { need, type Store } from './store.ts';

export interface StoragePolicy { globalQuota?: number; globalCount?: number; minFree?: number; auditLimit?: number; staleMs?: number; cleanupIntervalMs?: number; backupRoot?: string; backupQuota?: number; backupCount?: number }
export class StorageGuard {
  constructor(public store: Store, public policy: StoragePolicy, public free = () => {
    const s = statfsSync(store.root, { bigint: true }); return Number(s.bavail * s.bsize);
  }) {}
  usage() {
    const used = this.store.get('SELECT COALESCE(SUM(size),0) AS n FROM files')!.n as number;
    const reserved = this.store.get('SELECT COALESCE(SUM(size),0) AS n FROM transfers')!.n as number;
    const pending = this.store.get('SELECT COALESCE(SUM(MAX(0,size-offset)),0) AS n FROM transfers')!.n as number;
    const objects = this.store.get('SELECT (SELECT COUNT(*) FROM files)+(SELECT COUNT(*) FROM transfers) AS n')!.n as number, objectLimit = this.policy.globalCount ?? 10000;
    let diskFree: number | null = null; try { diskFree = this.free(); if (!Number.isSafeInteger(diskFree) || diskFree < 0) diskFree = null; } catch { /* Allocation fails closed if the filesystem cannot be measured. */ }
    const limit = this.policy.globalQuota ?? 10 * 1024 ** 3, minFree = this.policy.minFree ?? 256 * 1024 ** 2;
    return { used, reserved, pending, objects, objectLimit, limit, minFree, diskFree, available: Math.max(0, limit - used - reserved), pressure: diskFree === null || diskFree < minFree + pending || used + reserved > limit || objects > objectLimit };
  }
  allocate(size: number) {
    const s = this.usage(); need(s.used + s.reserved + size <= s.limit, 'GLOBAL_STORAGE_QUOTA');
    need(s.objects < s.objectLimit, 'GLOBAL_OBJECT_LIMIT');
    need(s.diskFree !== null, 'STORAGE_UNAVAILABLE'); need(s.diskFree >= s.minFree + s.pending + size, 'DISK_SPACE_LOW');
  }
  write() { const s = this.usage(); need(s.diskFree !== null, 'STORAGE_UNAVAILABLE'); need(s.diskFree >= s.minFree + s.pending, 'DISK_SPACE_LOW'); }
  touch(id: string) { this.store.run('INSERT INTO transfer_activity VALUES(?,?) ON CONFLICT(id) DO UPDATE SET touched=excluded.touched', id, Date.now()); }
  expired() {
    return this.store.all('SELECT t.* FROM transfers t LEFT JOIN transfer_activity a ON a.id=t.id WHERE COALESCE(a.touched,t.created)<? ORDER BY COALESCE(a.touched,t.created),t.id LIMIT 16', Date.now() - (this.policy.staleMs ?? 7 * 86400000));
  }
}
