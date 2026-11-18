// Read-only migration evidence. Emit row fingerprints, never credentials or file contents.
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { resolve, join } from 'node:path';
const db = new DatabaseSync(join(resolve(process.env.DATA_DIR ?? '.local/data'), 'safedrop.sqlite'), { readOnly: true });
try {
  db.exec('BEGIN');
  const tables = {};
  for (const table of ['users', 'sessions', 'keys', 'files', 'transfers', 'audit', 'settings', 'invitations', 'deletions', 'deliveries', 'transfer_activity', 'mfa_settings', 'mfa_recovery', 'mfa_sessions', 'mfa_attempts']) {
    if (!db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(table)) continue;
    const rows = db.prepare(`SELECT * FROM ${table}`).all(), records = {};
    for (const row of rows) {
      // All process-bound sessions intentionally expire when the application starts.
      if (table === 'sessions') delete row.revoked;
      // Additive defaults must match legacy users while existing status fields stay covered.
      if (table === 'users') { row.disabled ??= 0; row.authVersion ??= 0; }
      const normalized = Object.fromEntries(Object.keys(row).sort().map(key => [key, row[key]]));
      const recordId = table === 'mfa_recovery' ? `${row.userId}:${row.hash}` : row.id ?? row.seq ?? row.key ?? row.sessionId ?? row.userId;
      if (recordId === undefined) throw new Error('SNAPSHOT_RECORD_ID_REQUIRED');
      records[String(recordId)] = createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
    }
    tables[table] = records;
  }
  db.exec('COMMIT');
  console.log(JSON.stringify({ version: 1, tables }));
} finally { db.close(); }
