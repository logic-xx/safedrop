import { readFile, mkdir, open } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { WebSocket } from 'ws';
import { once } from 'node:events';
import { setTimeout as pause } from 'node:timers/promises';
import { encode, decode } from '../shared/protocol.ts';
import { need } from '../server/store.ts';
import { verifyBackup, restoreBackup } from '../server/backup.ts';

const [command, ...values] = process.argv.slice(2), args: Record<string, string> = {};
for (let i = 0; i < values.length; i += 2) { need(values[i].startsWith('--') && values[i + 1], 'INVALID_ARGUMENTS'); args[values[i].slice(2)] = values[i + 1]; }
async function remote() {
  need(args.origin && args.ca && args.accounts, 'ORIGIN_CA_ACCOUNTS_REQUIRED'); const url = new URL(args.origin); need(url.protocol === 'https:', 'HTTPS_REQUIRED');
  const accounts = JSON.parse(await readFile(args.accounts, 'utf8')), admin = accounts.find((a: Record<string, string>) => a.name === (args.admin ?? 'admin')); need(admin, 'ADMIN_NOT_FOUND');
  const ws = new WebSocket(args.origin.replace(/^https:/, 'wss:') + '/ws', { ca: await readFile(args.ca), rejectUnauthorized: true, headers: { Origin: args.origin } }); await once(ws, 'open');
  let seq = 0;
  const rpc = (op: string, meta: Record<string, unknown> = {}) => new Promise<Record<string, any>>((yes, no) => {
    const id = ++seq, timer = setTimeout(() => { ws.off('message', received); no(new Error('REQUEST_TIMEOUT')); }, op === 'maintenance.backup' ? 600000 : 30000);
    const received = (data: WebSocket.RawData) => { const frame = decode(Buffer.from(data as Buffer)); if (frame.requestId !== id) return; clearTimeout(timer); ws.off('message', received); frame.meta.ok ? yes(frame.meta) : no(new Error(String(frame.meta.code))); };
    ws.on('message', received); ws.send(encode(1, id, { op, ...meta }));
  });
  try {
    await rpc('auth.password', { name: admin.name, password: admin.password });
    if (command === 'backup') return await rpc('maintenance.backup');
    if (command === 'anchor') {
      need(args.destination, 'DESTINATION_REQUIRED'); const verified = await rpc('audit.verify'); need(verified.ok && verified.count !== undefined && verified.head, 'AUDIT_INTEGRITY_FAILURE');
      const root = resolve(args.destination); await mkdir(root, { recursive: true, mode: 0o700 });
      const path = join(root, `checkpoint-${verified.count}-${verified.head}.json`), handle = await open(path, 'wx', 0o600).catch(e => { if (e.code !== 'EEXIST') throw e; });
      if (handle) try { await handle.writeFile(JSON.stringify({ count: verified.count, head: verified.head })); await handle.sync(); } finally { await handle.close(); }
      else { const existing = JSON.parse(await readFile(path, 'utf8')); need(existing.count === verified.count && existing.head === verified.head, 'CHECKPOINT_FILE_MISMATCH'); }
      return { saved: true, count: verified.count, head: verified.head };
    }
    return await rpc('maintenance.status');
  } finally { ws.close(); }
}
try {
  let result: unknown;
  const interval = args['interval-seconds'] === undefined ? undefined : Number(args['interval-seconds']);
  if (interval !== undefined) need(command === 'anchor' && Number.isSafeInteger(interval) && interval >= 10 && interval <= 86400, 'INVALID_INTERVAL');
  const anchor = args.anchor ? JSON.parse(await readFile(args.anchor, 'utf8')) : undefined;
  if (command === 'verify') { need(args.source, 'SOURCE_REQUIRED'); const m = await verifyBackup(resolve(args.source), anchor); result = { verified: true, id: m.id, bytes: m.bytes, checkpoint: m.checkpoint }; }
  else if (command === 'restore') { need(args.source && args.target, 'SOURCE_TARGET_REQUIRED'); result = await restoreBackup(resolve(args.source), resolve(args.target), anchor); }
  else if (['status', 'backup', 'anchor'].includes(command)) result = await remote();
  else throw new Error('Usage: maintenance <status|backup|anchor|verify|restore> --option value');
  console.log(JSON.stringify(result, null, 2));
  if (interval !== undefined) {
    while (true) { await pause(interval * 1000); console.log(JSON.stringify(await remote())); }
  }
} catch (e) { console.error(e instanceof Error ? e.message : 'MAINTENANCE_FAILED'); process.exitCode = 1; }
