import { createServer as httpsServer } from 'node:https';
import { createServer as httpServer, type IncomingMessage } from 'node:http';
import { readFileSync, existsSync, createReadStream } from 'node:fs';
import { open, rename, unlink, stat } from 'node:fs/promises';
import { resolve, join, sep, extname } from 'node:path';
import { createPublicKey, randomBytes, verify } from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';
import { CHUNK, MAX_FRAME, encode, decode, type Frame } from '../shared/protocol.ts';
import { Store, Fault, need, text, integer, id, digest, passwordCheck, passwordHash, validAccount, verifyAudit, type Row, type Checkpoint } from './store.ts';
import { Bandwidth, RateGate } from './limits.ts';
import { createHash } from 'node:crypto';

export interface Config { root: string; origin: string; tls?: { cert: Buffer; key: Buffer }; webRoot?: string; reportPath?: string; maxFile?: number; quota?: number; normalRate?: number; vipRate?: number; sessionMs?: number; loginLimit?: number }
interface Context { ws: WebSocket; connection: string; ip: string; agent: string; session?: string; user?: Row; abort: AbortController; pending: number; alive: boolean; challenge?: { key: Row; message: string; expires: number } }
async function hashFile(path: string, bytes?: number) {
  const h = createHash('sha256');
  if (bytes === 0) return h.digest('hex');
  for await (const chunk of createReadStream(path, bytes === undefined ? {} : { start: 0, end: bytes - 1 })) h.update(chunk);
  return h.digest('hex');
}
export function createApp(config: Config) {
  const store = new Store(config.root);
  need(verifyAudit(store.all('SELECT * FROM audit ORDER BY seq')).ok, 'AUDIT_INTEGRITY_FAILURE');
  store.run('UPDATE sessions SET revoked=1 WHERE revoked=0');
  const rate = new RateGate(), bw = new Bandwidth(config.normalRate, config.vipRate);
  const contexts = new Set<Context>(), locks = new Set<string>();
  const operations = new Set<Promise<void>>();
  let hashing = 0, authenticating = 0, queuedBytes = 0;
  const root = resolve(config.webRoot ?? 'dist');
  const request = (req: IncomingMessage, res: import('node:http').ServerResponse) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405).end(); return; }
    if (req.url === '/health') { res.setHeader('Content-Type', 'application/json'); res.end('{"status":"ok","protocol":"SFT/1"}'); return; }
    let path: string;
    try { path = resolve(root, '.' + decodeURIComponent(new URL(req.url ?? '/', 'https://local').pathname)); }
    catch { res.writeHead(400).end(); return; }
    if (path !== root && !path.startsWith(root + sep)) { res.writeHead(403).end(); return; }
    if (path === root || !existsSync(path) && !extname(path)) path = join(root, 'index.html');
    const mime: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
    if (!existsSync(path) || !mime[extname(path)]) { res.writeHead(404).end(); return; }
    res.setHeader('Content-Type', mime[extname(path)]); res.setHeader('Cache-Control', extname(path) === '.html' ? 'no-store' : 'public,max-age=3600');
    const stream = createReadStream(path); stream.on('error', () => { if (!res.headersSent) res.writeHead(500); res.end(); }); stream.pipe(res);
  };
  const server = config.tls ? httpsServer({ ...config.tls, minVersion: 'TLSv1.2', handshakeTimeout: 8000 }, request) : httpServer(request);
  server.maxConnections = 64; server.headersTimeout = 8000; server.requestTimeout = 15000; server.maxHeadersCount = 40;
  server.on('connection', socket => { socket.setKeepAlive(true, 30000); socket.setNoDelay(true); socket.setTimeout(60000, () => socket.destroy()); });
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME, perMessageDeflate: false });
  server.on('upgrade', (req, socket, head) => {
    const ip = req.socket.remoteAddress ?? 'unknown';
    if (req.url !== '/ws' || req.headers.origin !== config.origin || contexts.size >= 48 || !rate.allow('upgrade:' + ip, 120)) { socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return; }
    wss.handleUpgrade(req, socket, head, ws => { req.socket.setTimeout(0); wss.emit('connection', ws, req); });
  });
  const audit = (c: Context, action: string, result: string, detail: Record<string, unknown> = {}) => store.audit(c.user?.name ?? 'anonymous', action, result, detail);
  function authorized(c: Context) {
    need(!c.abort.signal.aborted && c.user && c.session, 'AUTH_REQUIRED');
    const s = store.get('SELECT * FROM sessions WHERE id=?', c.session);
    const u = store.get('SELECT * FROM users WHERE id=?', c.user.id);
    need(s && !s.revoked && s.expires > Date.now() && u && !u.disabled, 'SESSION_EXPIRED');
    c.user = u; return u;
  }
  const admin = (c: Context) => need(authorized(c).role === 'admin', 'FORBIDDEN');
  function stopUser(userId: string, reason: string, replyContext?: Context) {
    for (const ctx of contexts) {
      if (ctx.challenge?.key.userId === userId) ctx.challenge = undefined;
      if (ctx.user?.id !== userId) continue;
      const stop = () => { ctx.abort.abort(); ctx.ws.close(4001, reason); };
      // The database is already revoked; allow only this operation's acknowledgement.
      if (ctx === replyContext) setTimeout(stop, 10); else stop();
    }
  }
  function establish(c: Context, u: Row, method: string) {
    need(!c.user, 'ALREADY_AUTHENTICATED');
    const current = store.get('SELECT * FROM users WHERE id=?', u.id);
    need(current && !current.disabled && current.authVersion === u.authVersion, 'INVALID_CREDENTIALS');
    need(store.get('SELECT COUNT(*) AS n FROM sessions WHERE userId=? AND revoked=0 AND expires>?', u.id, Date.now())!.n < 8, 'SESSION_LIMIT');
    c.user = u; c.session = id();
    store.run('INSERT INTO sessions VALUES(?,?,?,?,0,?,?)', c.session, u.id, Date.now(), Date.now() + (config.sessionMs ?? 3600000), c.agent, c.ip);
    audit(c, 'auth.login', 'allowed', { method }); return { user: { name: u.name, role: u.role, tier: u.tier, rate: bw.rate(u.tier) }, session: c.session, connection: c.connection };
  }
  function owned(c: Context, table: 'transfers' | 'files', transferId: unknown) {
    const u = authorized(c); const row = store.get(`SELECT * FROM ${table} WHERE id=? AND userId=?`, text(transferId, 80), u.id); need(row, 'NOT_FOUND'); return row;
  }
  async function dispatch(c: Context, f: Frame): Promise<{ meta?: Row; payload?: Uint8Array }> {
    const m = f.meta, op = text(m.op, 64);
    need(f.type === 1 && f.requestId > 0, 'INVALID_REQUEST');
    if (op !== 'upload.chunk') need(f.payload.length === 0, 'UNEXPECTED_PAYLOAD');
    if (op === 'hello') return { meta: { protocol: 'SFT/1', connection: c.connection, chunkSize: CHUNK, maxFile: config.maxFile ?? 512 * 1024 ** 2, heartbeatSeconds: 20, registration: store.registration() } };
    if (op === 'ping') return { meta: { time: Date.now() } };
    if (op === 'auth.register') {
      need(!c.user, 'ALREADY_AUTHENTICATED');
      need(rate.allow('register:' + c.ip, 6) && rate.allow('register:global', 30) && authenticating < 4, 'RATE_LIMITED');
      need(store.registration() === 'invitation', 'REGISTRATION_CLOSED');
      const token = text(m.token, 64), name = text(m.name, 32), pass = text(m.password, 256);
      validAccount(name, pass); need(/^sd1_[A-Za-z0-9_-]{43}$/.test(token), 'INVITATION_INVALID');
      const tokenHash = digest(token);
      const usable = () => {
        need(store.registration() === 'invitation', 'REGISTRATION_CLOSED');
        const invite = store.get('SELECT * FROM invitations WHERE tokenHash=?', tokenHash);
        need(invite && !invite.revoked && !invite.usedBy && invite.expires > Date.now(), 'INVITATION_INVALID'); return invite;
      };
      usable(); authenticating++;
      try {
        const hash = await passwordHash(pass); c.abort.signal.throwIfAborted();
        const userId = id();
        store.transaction(() => {
          const invite = usable(); need(!store.get('SELECT id FROM users WHERE name=?', name), 'ACCOUNT_UNAVAILABLE');
          store.run("INSERT INTO users(id,name,hash,role,tier) VALUES(?,?,?,'user','normal')", userId, name, hash);
          store.run('UPDATE invitations SET usedBy=?,usedAt=? WHERE id=?', userId, Date.now(), invite.id);
          store.audit(name, op, 'allowed', { invitationId: invite.id });
        });
        return { meta: { registered: true } };
      } finally { authenticating--; }
    }
    if (op === 'auth.password') {
      need(!c.user, 'ALREADY_AUTHENTICATED');
      need(rate.allow('login:' + c.ip, config.loginLimit ?? 10) && authenticating < 4, 'RATE_LIMITED'); authenticating++;
      try {
        const name = text(m.name, 64), pass = text(m.password, 256), u = store.get('SELECT * FROM users WHERE name=?', name);
        // A dummy hash performs equivalent work for unknown accounts.
        const valid = await passwordCheck(pass, u?.hash ?? ('0'.repeat(32) + ':' + '0'.repeat(64)));
        need(u && valid, 'INVALID_CREDENTIALS'); c.abort.signal.throwIfAborted(); return { meta: establish(c, u, 'password') };
      } finally { authenticating--; }
    }
    if (op === 'auth.challenge') {
      need(!c.user && rate.allow('challenge:' + c.ip, 30), 'RATE_LIMITED');
      const key = store.get('SELECT k.*,u.name FROM keys k JOIN users u ON u.id=k.userId WHERE k.id=? AND u.name=? AND u.disabled=0', text(m.keyId, 80), text(m.name, 64));
      need(key, 'INVALID_CREDENTIALS'); const expires = Date.now() + 30000;
      const message = JSON.stringify(['SFT/1 AUTH', c.connection, key.name, key.id, randomBytes(32).toString('base64url'), expires]);
      c.challenge = { key, message, expires }; return { meta: { message, expires } };
    }
    if (op === 'auth.prove') {
      const challenge = c.challenge; c.challenge = undefined;
      need(challenge && challenge.expires > Date.now(), 'CHALLENGE_INVALID');
      need(store.get('SELECT id FROM keys WHERE id=?', challenge.key.id), 'CHALLENGE_INVALID');
      const publicKey = createPublicKey({ key: JSON.parse(challenge.key.jwk), format: 'jwk' });
      need(verify('sha256', Buffer.from(challenge.message), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(text(m.signature, 256), 'base64')), 'INVALID_SIGNATURE');
      return { meta: establish(c, store.get('SELECT * FROM users WHERE id=?', challenge.key.userId)!, 'public-key') };
    }
    const u = authorized(c);
    if (op === 'account.password') {
      need(rate.allow('reauth:' + u.id, 10) && authenticating < 4, 'RATE_LIMITED');
      const oldPass = text(m.password, 256), newPass = text(m.newPassword, 256); validAccount(u.name, newPass);
      need(oldPass !== newPass, 'PASSWORD_UNCHANGED'); authenticating++;
      try {
        need(await passwordCheck(oldPass, u.hash), 'INVALID_CREDENTIALS');
        const hash = await passwordHash(newPass); authorized(c);
        store.transaction(() => {
          need(store.get('SELECT authVersion FROM users WHERE id=?', u.id)!.authVersion === u.authVersion, 'SESSION_EXPIRED');
          store.run('UPDATE users SET hash=?,authVersion=authVersion+1 WHERE id=?', hash, u.id);
          store.run('UPDATE sessions SET revoked=1 WHERE userId=?', u.id);
          store.run('DELETE FROM keys WHERE userId=?', u.id);
          audit(c, op, 'allowed', { sessions: 'revoked', keys: 'revoked' });
        });
        stopUser(u.id, 'PASSWORD_CHANGED', c); return {};
      } finally { authenticating--; }
    }
    if (op === 'registration.set') {
      admin(c); need(m.mode === 'invitation' || m.mode === 'closed', 'INVALID_INPUT');
      store.transaction(() => { store.run("UPDATE settings SET value=? WHERE key='registration'", m.mode); audit(c, op, 'allowed', { mode: m.mode }); }); return {};
    }
    if (op === 'invitations.create') {
      admin(c); need(store.registration() === 'invitation', 'REGISTRATION_CLOSED');
      need(rate.allow('invite-create:' + u.id, 10), 'RATE_LIMITED');
      const hours = integer(m.hours, 168); need(hours >= 1, 'INVALID_INPUT');
      need(store.get('SELECT COUNT(*) AS n FROM invitations WHERE usedBy IS NULL AND revoked=0 AND expires>?', Date.now())!.n < 100, 'INVITATION_LIMIT');
      const inviteId = id(), token = 'sd1_' + randomBytes(32).toString('base64url'), created = Date.now(), expires = created + hours * 3600000;
      store.transaction(() => { store.run('INSERT INTO invitations(id,tokenHash,createdBy,created,expires) VALUES(?,?,?,?,?)', inviteId, digest(token), u.id, created, expires); audit(c, op, 'allowed', { invitationId: inviteId, expires }); });
      return { meta: { id: inviteId, token, expires } };
    }
    if (op === 'invitations.list') {
      admin(c); return { meta: { registration: store.registration(), invitations: store.all('SELECT id,created,expires,usedAt,revoked FROM invitations ORDER BY created DESC,id DESC LIMIT 12 OFFSET ?', integer(m.offset ?? 0, 10000)) } };
    }
    if (op === 'invitations.revoke') {
      admin(c); const inviteId = text(m.invitationId, 80); need(store.get('SELECT id FROM invitations WHERE id=?', inviteId), 'NOT_FOUND');
      store.transaction(() => { store.run('UPDATE invitations SET revoked=1 WHERE id=?', inviteId); audit(c, op, 'allowed', { invitationId: inviteId }); }); return {};
    }
    if (op === 'users.list') {
      admin(c); return { meta: { users: store.all('SELECT id,name,role,tier,disabled FROM users ORDER BY name LIMIT 12 OFFSET ?', integer(m.offset ?? 0, 10000)) } };
    }
    if (op === 'users.disable') {
      admin(c); const userId = text(m.userId, 80);
      store.transaction(() => {
        const target = store.get('SELECT * FROM users WHERE id=?', userId); need(target, 'NOT_FOUND');
        if (!target.disabled && target.role === 'admin') need(store.get("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND disabled=0")!.n > 1, 'LAST_ADMIN');
        store.run('UPDATE users SET disabled=1,authVersion=authVersion+1 WHERE id=?', userId);
        store.run('UPDATE sessions SET revoked=1 WHERE userId=?', userId);
        store.run('DELETE FROM keys WHERE userId=?', userId);
        audit(c, op, 'allowed', { userId, sessions: 'revoked', keys: 'revoked' });
      });
      stopUser(userId, 'ACCOUNT_DISABLED', c); return {};
    }
    if (op === 'files.list') return { meta: { files: store.all('SELECT id,name,size,sha256,created FROM files WHERE userId=? ORDER BY created DESC,id DESC LIMIT 12 OFFSET ?', u.id, integer(m.offset ?? 0, 10000)) } };
    if (op === 'transfers.list') return { meta: { transfers: store.all('SELECT id,name,size,sha256,offset,created FROM transfers WHERE userId=? ORDER BY created DESC LIMIT 16', u.id) } };
    if (op === 'upload.init') {
      const name = text(m.name); need(!/[\\/\x00-\x1f:]/.test(name) && !['.', '..'].includes(name), 'INVALID_FILENAME');
      const size = integer(m.size, config.maxFile ?? 512 * 1024 ** 2), sha = text(m.sha256, 64); need(/^[a-f0-9]{64}$/.test(sha), 'INVALID_HASH');
      if (m.transferId) { const t = store.get('SELECT * FROM transfers WHERE id=? AND userId=?', text(m.transferId, 80), u.id) ?? store.get('SELECT *,size AS offset,1 AS completed FROM files WHERE id=? AND userId=?', m.transferId, u.id); need(t, 'NOT_FOUND'); need(t.name === name && t.size === size && t.sha256 === sha, 'FILE_CHANGED'); return { meta: t }; }
      need(store.get('SELECT COUNT(*) AS n FROM files WHERE userId=?', u.id)!.n < 1000, 'FILE_COUNT_LIMIT');
      need(store.get('SELECT COUNT(*) AS n FROM transfers WHERE userId=?', u.id)!.n < 16, 'TRANSFER_LIMIT');
      const used = store.get('SELECT (SELECT COALESCE(SUM(size),0) FROM files WHERE userId=?) + (SELECT COALESCE(SUM(size),0) FROM transfers WHERE userId=?) AS n', u.id, u.id)!.n;
      need(used + size <= (config.quota ?? 1024 ** 3), 'STORAGE_QUOTA');
      const transferId = id(); store.run('INSERT INTO transfers VALUES(?,?,?,?,?,0,?)', transferId, u.id, name, size, sha, Date.now());
      try { const h = await open(join(config.root, 'staging', transferId), 'wx', 0o600); await h.close(); } catch (e) { store.run('DELETE FROM transfers WHERE id=?', transferId); throw e; }
      audit(c, op, 'allowed', { transferId, size }); return { meta: { id: transferId, offset: 0 } };
    }
    if (['upload.chunk', 'upload.finish', 'upload.cancel'].includes(op)) {
      if (op === 'upload.finish') { const done = store.get('SELECT id,sha256 FROM files WHERE id=? AND userId=?', text(m.transferId, 80), u.id); if (done) return { meta: { fileId: done.id, sha256: done.sha256 } }; }
      const t = owned(c, 'transfers', m.transferId); need(!locks.has(t.id), 'TRANSFER_BUSY'); locks.add(t.id);
      const path = join(config.root, 'staging', t.id);
      try {
        if (op === 'upload.chunk') {
          const offset = integer(m.offset, t.size); need(f.payload.length > 0 && offset + f.payload.length <= t.size && offset <= t.offset, 'INVALID_OFFSET');
          await bw.take(u.id, u.tier, f.payload.length, c.abort.signal); authorized(c);
          const h = await open(path, 'r+');
          try {
            authorized(c);
            if (offset < t.offset) {
              need(offset + f.payload.length <= t.offset, 'INVALID_OFFSET'); const buf = Buffer.alloc(f.payload.length); const { bytesRead } = await h.read(buf, 0, buf.length, offset);
              need(bytesRead === buf.length && buf.equals(Buffer.from(f.payload)), 'CHUNK_CONFLICT');
            } else {
              let written = 0; while (written < f.payload.length) { authorized(c); const r = await h.write(f.payload, written, f.payload.length - written, offset + written); need(r.bytesWritten > 0, 'WRITE_FAILED'); written += r.bytesWritten; }
              await h.sync(); authorized(c); store.run('UPDATE transfers SET offset=? WHERE id=?', offset + written, t.id); t.offset = offset + written;
            }
          } finally { await h.close(); }
          return { meta: { offset: t.offset } };
        }
        if (op === 'upload.cancel') { await unlink(path).catch(() => {}); authorized(c); store.run('DELETE FROM transfers WHERE id=?', t.id); audit(c, op, 'allowed', { transferId: t.id }); return {}; }
        need(t.offset === t.size, 'INCOMPLETE_FILE'); need(hashing < 4, 'SERVER_BUSY'); hashing++;
        try {
          const final = join(config.root, 'objects', t.id), source = existsSync(path) ? path : final;
          need((await stat(source)).size === t.size && await hashFile(source) === t.sha256, 'HASH_MISMATCH'); authorized(c);
          if (source !== final) await rename(path, final);
          authorized(c);
          store.db.exec('BEGIN IMMEDIATE');
          try { store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', t.id, u.id, t.name, t.size, t.sha256, Date.now()); store.run('DELETE FROM transfers WHERE id=?', t.id); store.db.exec('COMMIT'); } catch (e) { store.db.exec('ROLLBACK'); throw e; }
          audit(c, op, 'allowed', { fileId: t.id, size: t.size, sha256: t.sha256 }); return { meta: { fileId: t.id, sha256: t.sha256 } };
        } finally { hashing--; }
      } finally { locks.delete(t.id); }
    }
    if (op === 'download.init') {
      const file = owned(c, 'files', m.fileId), offset = integer(m.offset ?? 0, file.size);
      if (offset) { need(hashing < 4, 'SERVER_BUSY'); hashing++; try { need(await hashFile(join(config.root, 'objects', file.id), offset) === m.prefixHash, 'PREFIX_MISMATCH'); } finally { hashing--; } }
      authorized(c); audit(c, op, 'allowed', { fileId: file.id, offset }); return { meta: file };
    }
    if (op === 'download.chunk') {
      const file = owned(c, 'files', m.fileId), offset = integer(m.offset, file.size), length = Math.min(CHUNK, file.size - offset);
      await bw.take(u.id, u.tier, length, c.abort.signal); authorized(c);
      const h = await open(join(config.root, 'objects', file.id), 'r'); const out = Buffer.alloc(length);
      try { const { bytesRead } = await h.read(out, 0, length, offset); need(bytesRead === length, 'READ_FAILED'); } finally { await h.close(); }
      authorized(c); return { meta: { offset, next: offset + length, eof: offset + length === file.size }, payload: out };
    }
    if (op === 'sessions.list') return { meta: { sessions: store.all('SELECT id,created,expires,agent,ip FROM sessions WHERE userId=? AND revoked=0 AND expires>? ORDER BY created DESC', u.id, Date.now()), current: c.session } };
    if (op === 'sessions.revoke' || op === 'auth.logout') {
      const sid = op === 'auth.logout' ? c.session! : text(m.sessionId, 80);
      need(store.get('SELECT id FROM sessions WHERE id=? AND userId=?', sid, u.id), 'NOT_FOUND');
      store.run('UPDATE sessions SET revoked=1 WHERE id=?', sid); audit(c, 'sessions.revoke', 'allowed', {});
      setTimeout(() => { for (const ctx of contexts) if (ctx.session === sid) { ctx.abort.abort(); ctx.ws.close(4001, 'SESSION_REVOKED'); } }, 10);
      return {};
    }
    if (op === 'keys.list') return { meta: { keys: store.all('SELECT id,label,created FROM keys WHERE userId=?', u.id) } };
    if (op === 'keys.enroll' || op === 'keys.revoke') {
      need(rate.allow('reauth:' + u.id, 10) && authenticating < 4, 'RATE_LIMITED'); authenticating++;
      try { need(await passwordCheck(text(m.password, 256), u.hash), 'INVALID_CREDENTIALS'); } finally { authenticating--; }
      need(authorized(c).authVersion === u.authVersion, 'SESSION_EXPIRED');
      if (op === 'keys.revoke') { need(store.get('SELECT id FROM keys WHERE id=? AND userId=?', text(m.keyId, 80), u.id), 'NOT_FOUND'); store.run('DELETE FROM keys WHERE id=?', m.keyId); audit(c, op, 'allowed'); return {}; }
      need(store.get('SELECT COUNT(*) AS n FROM keys WHERE userId=?', u.id)!.n < 5, 'KEY_LIMIT');
      need(m.jwk && typeof m.jwk === 'object', 'INVALID_KEY'); const j = m.jwk as Row;
      need(j.kty === 'EC' && j.crv === 'P-256' && !j.d && typeof j.x === 'string' && typeof j.y === 'string', 'INVALID_KEY');
      const jwk = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: j.x, y: j.y }, format: 'jwk' }).export({ format: 'jwk' });
      const keyId = id(); store.run('INSERT INTO keys VALUES(?,?,?,?,?)', keyId, u.id, JSON.stringify(jwk), text(m.label, 60), Date.now()); audit(c, op, 'allowed', { keyId }); return { meta: { keyId } };
    }
    if (op === 'events.list') {
      const events = store.all('SELECT seq,event FROM audit ORDER BY seq DESC LIMIT 300').map(r => ({ seq: r.seq, ...JSON.parse(r.event) })).filter(r => u.role === 'admin' || r.user === u.name).slice(0, 24);
      return { meta: { events } };
    }
    if (op === 'audit.page') { admin(c); return { meta: { rows: store.all('SELECT * FROM audit WHERE seq>? ORDER BY seq LIMIT 8', integer(m.after ?? 0)), checkpoint: store.checkpoint() } }; }
    if (op === 'audit.verify') { admin(c); const anchor = m.checkpoint as Checkpoint | undefined; if (anchor) { integer(anchor.count); need(/^[a-f0-9]{64}$/.test(anchor.head), 'INVALID_CHECKPOINT'); } return { meta: verifyAudit(store.all('SELECT * FROM audit ORDER BY seq'), anchor) }; }
    if (op === 'report.latest') { admin(c); const p = config.reportPath ?? resolve('reports/latest.json'); return { meta: { report: existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : null } }; }
    throw new Fault('UNKNOWN_OPERATION');
  }
  wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
    const c: Context = { ws, connection: id(), ip: req.socket.remoteAddress ?? 'unknown', agent: (req.headers['user-agent'] ?? 'unknown').slice(0, 160), abort: new AbortController(), pending: 0, alive: true };
    contexts.add(c); let queue = Promise.resolve();
    const authDeadline = setTimeout(() => { if (!c.user) ws.close(4003, 'AUTH_TIMEOUT'); }, 30000);
    ws.on('pong', () => { c.alive = true; });
    ws.on('message', (data, binary) => {
      const bytes = Buffer.isBuffer(data) ? data : Buffer.concat(Array.isArray(data) ? data : [Buffer.from(data)]);
      if (!binary || c.pending >= 8 || queuedBytes + bytes.length > 16 * 1024 ** 2 || !rate.allow('messages:' + c.connection, 1200)) { c.abort.abort(); ws.close(4008, 'RATE_LIMITED'); return; }
      c.pending++; queuedBytes += bytes.length;
      queue = queue.then(async () => {
        let frame: Frame | undefined;
        try {
          c.abort.signal.throwIfAborted(); frame = decode(bytes); const result = await dispatch(c, frame);
          if (ws.readyState === WebSocket.OPEN && !c.abort.signal.aborted) ws.send(encode(2, frame.requestId, { ok: true, ...result.meta }, result.payload, frame.streamId));
        } catch (e) {
          const code = e instanceof Fault ? e.code : frame ? 'INTERNAL_ERROR' : 'INVALID_FRAME';
          if (!c.abort.signal.aborted && rate.allow('audit-denied:' + c.ip, 30)) audit(c, typeof frame?.meta.op === 'string' ? frame.meta.op.slice(0, 64) : 'protocol.invalid', 'denied', { code });
          if (frame && ws.readyState === WebSocket.OPEN) ws.send(encode(2, frame.requestId, { ok: false, code }));
          else ws.close(4002, 'INVALID_FRAME');
        } finally { c.pending--; queuedBytes -= bytes.length; }
      }).catch(() => { ws.terminate(); });
      const work = queue; operations.add(work); void work.then(() => operations.delete(work));
    });
    ws.on('error', () => { /* Peer protocol violations must not crash the server. */ });
    ws.on('close', () => { clearTimeout(authDeadline); c.abort.abort(); contexts.delete(c); if (c.session) try { store.run('UPDATE sessions SET revoked=1 WHERE id=?', c.session); } catch { /* The connection is already invalid; a storage failure must not escape this event handler. */ } });
  });
  const heartbeat = setInterval(() => {
    for (const c of contexts) {
      if (!c.alive) { c.ws.terminate(); continue; }
      if (c.session) try { authorized(c); } catch { c.abort.abort(); c.ws.close(4001, 'SESSION_EXPIRED'); continue; }
      c.alive = false; c.ws.ping();
    }
  }, 20000); heartbeat.unref();
  store.audit('system', 'server.start', 'allowed', { protocol: 'SFT/1' });
  return { server, store, bw, async close() { clearInterval(heartbeat); for (const c of contexts) { c.abort.abort(); c.ws.terminate(); } await new Promise<void>(r => wss.close(() => r())); await Promise.allSettled([...operations]); await new Promise<void>(r => server.close(() => r())); store.close(); } };
}
