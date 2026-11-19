import { readFile } from 'node:fs/promises';
import { createApp as createRealApp, type Config } from '../server/app.ts';
import { digest } from '../server/store.ts';
import { setTimeout as pause } from 'node:timers/promises';
import type { ScanEngine } from '../server/clamd.ts';

// Regression fixtures only. Malware/transport suites use their own engine explicitly.
// This is never imported by production or treated as evidence of a real ClamAV scan.
export const fixtureCleanScanner: ScanEngine = { async scan(input, signal) {
  signal.throwIfAborted(); const bytes = await readFile(input.path); signal.throwIfAborted();
  return { state: 'clean', engine: 'TEST-ONLY controlled clean scanner', bytes: bytes.length, sha256: digest(bytes) };
} };
export function createTestApp(config: Config) { config.scanner ??= fixtureCleanScanner; return createRealApp(config); }
export async function scanFixtureFile(app: ReturnType<typeof createRealApp>, id: string) {
  const file = app.store.get('SELECT * FROM files WHERE id=?', id)!; app.scans.enqueue(file); app.scans.wake();
  for (let i = 0; i < 200; i++) { const state = app.scans.status(file).state; if (state === 'clean') return; if (state === 'error' || state === 'quarantined') throw Error('CONTROLLED_FIXTURE_SCAN_FAILED'); await pause(10); }
  throw Error('CONTROLLED_FIXTURE_SCAN_TIMEOUT');
}
export type { Config } from '../server/app.ts';
