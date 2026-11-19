// Read-only migration evidence. Emit row fingerprints, never credentials or file contents.
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { resolve, join } from 'node:path';
const db = new DatabaseSync(join(resolve(process.env.DATA_DIR ?? '.local/data'), 'safedrop.sqlite'), { readOnly: true });
try {
  db.exec('BEGIN');
  const tables = {};
  for (const table of ['users', 'sessions', 'keys', 'files', 'transfers', 'audit', 'settings', 'invitations', 'deletions', 'deliveries', 'transfer_activity', 'mfa_settings', 'mfa_recovery', 'mfa_sessions', 'mfa_attempts', 'file_scans']) {
    if (!db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(table)) continue;
    const rows = db.prepare(`SELECT * FROM ${table}`).all(), records = {};
    for (const row of rows) {
      // All process-bound sessions intentionally expire when the application starts.
      if (table === 'sessions') delete row.revoked;
      // Background verdicts can finish/requeue across restart; retain binding and request identity.
      if (table === 'file_scans') for (const field of ['state','checked','engine','signature','code']) delete row[field];
      // Additive defaults must match legacy users while existing status fields stay covered.
      if (table === 'users') { row.disabled ??= 0; row.authVersion ??= 0; }
      if (table === 'deliveries') {
        row.expires ??= 0;
        // Timed grants may be durably marked expired; immutable identity and deadline remain covered.
        if (row.expires > 0 && (!row.revoked || row.reason === 'expired')) for (const field of ['revoked','revokedAt','reason']) delete row[field];
      }
      const normalized = Object.fromEntries(Object.keys(row).sort().map(key => [key, row[key]]));
      const recordId = table === 'mfa_recovery' ? `${row.userId}:${row.hash}` : row.id ?? row.seq ?? row.key ?? row.sessionId ?? row.userId ?? row.fileId;
      if (recordId === undefined) throw new Error('SNAPSHOT_RECORD_ID_REQUIRED');
      records[String(recordId)] = createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
    }
    tables[table] = records;
  }
  db.exec('COMMIT');
  console.log(JSON.stringify({ version: 1, tables }));
} finally { db.close(); }
