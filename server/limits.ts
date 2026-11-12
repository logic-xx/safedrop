import { setTimeout as delay } from 'node:timers/promises';
import { need } from './store.ts';
export class RateGate {
  buckets = new Map<string, { count: number; reset: number }>();
  allow(key: string, limit: number, ms = 60_000) {
    const now = Date.now(); let b = this.buckets.get(key);
    if (!b || now >= b.reset) { b = { count: 0, reset: now + ms }; this.buckets.set(key, b); }
    if (this.buckets.size > 10000) for (const [k, v] of this.buckets) if (v.reset < now) this.buckets.delete(k);
    return ++b.count <= limit;
  }
}
// Reserve time synchronously so all sessions/tasks of one account share a budget.
export class Bandwidth {
  next = new Map<string, number>();
  constructor(public normal = 1024 * 1024, public vip = 4 * 1024 * 1024) {}
  rate(tier: string) { return tier === 'vip' ? this.vip : this.normal; }
  async take(user: string, tier: string, size: number, signal: AbortSignal) {
    const now = performance.now(), start = Math.max(now, this.next.get(user) ?? now);
    need(start - now < 30000, 'BANDWIDTH_QUEUE_FULL');
    this.next.set(user, start + size / this.rate(tier) * 1000);
    if (start > now) await delay(start - now, undefined, { signal });
    signal.throwIfAborted();
  }
}
