import { sha256 } from '@noble/hashes/sha2.js';
import { encode, decode, CHUNK, type Metadata, type Frame } from '../shared/protocol.ts';
export const hex = (a: Uint8Array) => [...a].map(n => n.toString(16).padStart(2, '0')).join('');
export const b64 = (a: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(a)));
const messages: Record<string, string> = { GLOBAL_OBJECT_LIMIT: '全局文件和上传任务数量已达上限，请联系管理员', GLOBAL_STORAGE_QUOTA: '全局存储预算不足，请联系管理员或清理不再需要的文件', DISK_SPACE_LOW: '磁盘余量不足，写入已暂停；现有任务和预留保留，请联系管理员', STORAGE_UNAVAILABLE: '无法读取磁盘余量，新的写入已拒绝，请联系管理员', AUDIT_CAPACITY: '审计容量不足，操作已受保护限制，请联系部署维护者归档并调整容量', MAINTENANCE_BUSY: '服务正在创建一致备份或执行维护，请稍后重试；原任务和数据保留', BACKUP_CAPACITY: '备份份数或容量已达上限，请由部署维护者处理旧备份及未完成副本后重试', BACKUP_SOURCE_UNSAFE: '存在异常存储对象，备份未完成，请联系部署维护者检查', BACKUP_INVALID: '备份校验未通过，请检查存储和原始记录', BACKUP_PATH_UNSAFE: '备份目录不符合隔离要求，请检查部署配置', INVALID_DELIVERY_EXPIRY: '有效期须为 1～720 的整数小时', DELIVERY_EXPIRED: '接收授权已到期，后续下载和续传已停止，请联系发送者重新授权', DELIVERY_UNAVAILABLE: '接收授权已失效，后续下载和续传已停止，请联系发送者', RECIPIENT_UNAVAILABLE: '接收账号不可用，请核对已注册且未停用的账号；不能发送给自己', DELIVERY_LIMIT: '有效接收授权已达上限，请先撤销不再需要的授权', UPLOAD_PREPARE_FAILED: '创建上传暂存失败，预留空间已保留，请在未完成上传中取消清理后重试', DELETE_FAILED: '磁盘清理失败，文件记录和空间占用已保留，请重试清理', FILE_DELETING: '文件已进入删除流程，下载和重命名已停止，请在文件列表重试清理', TRANSFER_CANCELING: '上传已进入取消流程，空间仍预留，请重试取消清理', FILE_BUSY: '文件正在处理，请稍后重试', FILE_COUNT_LIMIT: '文件与未完成上传数量已达上限，请先清理', TRANSFER_LIMIT: '未完成上传数量已达上限，请先完成或取消任务', ACCOUNT_DISABLED: '账号已被管理员停用，全部会话和公钥已失效', PASSWORD_CHANGED: '口令已修改，请用新口令重新登录并按需重新绑定公钥', SESSION_REVOKED: '此会话已撤销，请重新登录', INVALID_USER: '账号须为 3～32 位字母、数字、下划线或短横线，口令须为 12～256 个字符', ACCOUNT_UNAVAILABLE: '该账号不可使用，请换一个账号', INVITATION_INVALID: '邀请无效、已到期、已使用或已撤销', REGISTRATION_CLOSED: '当前已关闭自助注册，请联系管理员', LAST_ADMIN: '不能停用最后一个可用管理员', PASSWORD_UNCHANGED: '新口令不能与当前口令相同', FORBIDDEN: '此操作需要管理员权限', INVITATION_LIMIT: '待领取邀请已达上限，请先撤销不再使用的邀请', INVALID_INPUT: '输入无效，请检查后重试', INVALID_INTEGER: '数值超出允许范围', TASK_SESSION_CHANGED: '登录状态已变化，请在原账号下重新选择文件后继续', AUTH_REQUIRED: '请先登录', INVALID_CREDENTIALS: '账号或口令不正确', RATE_LIMITED: '请求过于频繁，请稍后重试', INVALID_FILENAME: '文件名包含不允许的字符', STORAGE_QUOTA: '存储配额不足', PREFIX_MISMATCH: '本地文件与服务器版本不一致，请重新下载', HASH_MISMATCH: '文件完整性校验失败', NOT_FOUND: '文件或任务不存在，或无权访问', CHALLENGE_INVALID: '认证挑战已失效', SESSION_EXPIRED: '会话已失效，请重新登录', CONNECTION_CLOSED: '连接中断，请重新登录后继续', REQUEST_TIMEOUT: '请求超时，任务可稍后恢复', TRANSFER_BUSY: '该文件正在其他任务中传输' };
messages.REPORT_TOO_LARGE = '验证报告超过单次读取上限，请由部署维护者在本地查看完整报告';
Object.assign(messages, {
  INVALID_FOLDER_NAME: '文件夹名称过长，请缩短后重试',
  FOLDER_NAME_EXISTS: '根目录已有同名文件夹',
  FOLDER_LIMIT: '个人文件夹数量已达上限',
  INVALID_EVENT_RANGE: '结束时间须晚于开始时间，事件查询范围最多为 31 天',
  INVALID_EVENT_CURSOR: '事件翻页位置无效，请刷新事件后重试',
  EVENT_RESPONSE_TOO_LARGE: '事件详情超过显示上限，请联系部署维护者检查原始审计记录',
  FILE_SCAN_REQUIRED: '文件尚未通过安全扫描，下载和交付已阻止；请等待完成或由所有者请求扫描',
  FILE_QUARANTINED: '文件检测到威胁并已隔离，下载和交付已阻止；原文件仍保留并计入占用',
  SCANNER_UNAVAILABLE: '本地扫描引擎不可用，本次未通过；请稍后重试或联系部署维护者',
  SCAN_TIMEOUT: '本次扫描超时，文件没有被判为通过；可稍后重试',
  SCAN_LIMIT: '文件或展开内容超过扫描上限，本次不能完成安全检查',
  SCAN_ENCRYPTED: '文件包含加密内容，扫描器不能检查完整内容，下载和交付仍受阻止',
  SCAN_DATABASE_STALE: '扫描签名库过期或时间异常，请由部署维护者更新后重试',
  SCAN_ENGINE_OUTDATED: '扫描引擎未达到本版要求，请由部署维护者升级后重试',
  SCAN_ENGINE_CHANGED: '扫描期间引擎或签名库发生变化，请重试以取得一致结果',
  SCAN_ENGINE_INVALID: '扫描引擎返回无效结果，本次未通过，请联系部署维护者',
  SCAN_SOURCE_CHANGED: '扫描期间文件内容或元数据发生变化，本次未通过，请检查存储',
  SCAN_INTERRUPTED: '本次扫描被中断，文件尚未通过，可重新请求扫描',
  SCAN_RESULT_EXPIRED: '先前扫描结果已过期或时间异常，需要重新扫描后才能下载和交付',
  BACKUP_KEY_MISSING: '备份密钥缺失，新备份已拒绝；请由部署维护者核对或恢复独立保存的密钥',
  BACKUP_KEY_NOT_FOUND: '密钥文件不含此副本所需的旧密钥，请恢复保留该密钥的副本',
  BACKUP_KEY_INVALID: '备份密钥文件无效，请由部署维护者恢复正确文件',
  BACKUP_KEY_PERMISSIONS: '备份密钥权限不安全，请由部署维护者限制访问',
  BACKUP_KEY_UNAVAILABLE: '备份密钥无法读取，请由部署维护者检查权限和配置',
  BACKUP_KEY_PATH_UNSAFE: '备份密钥须独立于业务目录、备份目录和双因素密钥保存',
  BACKUP_AUTH_FAILED: '备份认证未通过：密钥不匹配或副本已损坏，恢复已拒绝',
  BACKUP_PLAINTEXT_CONFIRMATION_REQUIRED: '此副本为旧明文格式，需由部署维护者明确选择兼容校验',
  BACKUP_SOURCE_CHANGED: '备份期间检测到源内容变化，副本未完成，请检查存储',
  BACKUP_WRITE_FAILED: '备份写入失败，未完成副本仍占用容量，请联系部署维护者检查',
  BACKUP_FILE_TOO_LARGE: '单个对象超过本版备份加密支持的大小，请联系部署维护者',
  MFA_REQUIRED: '请完成双因素认证后再操作',
  MFA_PASSWORD_REQUIRED: '此管理员已开启双因素认证，请使用口令加验证器验证码登录；公钥不能替代',
  MFA_INVALID: '验证码或恢复码无效。用过的验证码不能重用，请等待下一组；恢复码每份只能使用一次',
  MFA_RATE_LIMITED: '双因素验证尝试过多，账号暂时受保护限制，请五分钟后重试',
  MFA_CHALLENGE_INVALID: '本次双因素登录已失效，请返回口令登录重新开始',
  MFA_RECOVERY_ONLY: '当前为恢复会话，请先重新绑定并验证新验证器，完成后才能使用管理与文件功能',
  MFA_SETUP_EXPIRED: '本次验证器绑定已失效，请重新验证口令并开始绑定',
  MFA_ALREADY_ENABLED: '双因素认证已经启用；遗失验证器时请通过恢复码登录后重新绑定',
  MFA_NOT_ENABLED: '此账号尚未启用双因素认证',
  MFA_KEY_UNAVAILABLE: '无法读取双因素保护密钥，请联系部署维护者恢复正确的密钥文件',
  MFA_KEY_PATH_UNSAFE: '双因素保护密钥必须放在业务数据和备份目录之外，请检查部署配置',
  MFA_CHANGED: '双因素配置已更新，此会话与原公钥已失效，请重新登录'
});
export const human = (e: unknown) => { const s = e instanceof Error ? e.message : String(e); return messages[s] ?? s; };
export class Client {
  ws?: WebSocket; seq = 0; onState = (_: string) => {}; onLost = (_reason = '') => {};
  pending = new Map<number, { resolve: (v: Frame) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  retry = 0; closed = false; timer?: ReturnType<typeof setTimeout>; opening?: Promise<void>;
  connect(): Promise<void> {
    if (this.ws?.readyState === WebSocket.OPEN) return Promise.resolve();
    if (this.opening) return this.opening;
    clearTimeout(this.timer); this.onState('connecting');
    this.opening = new Promise((resolve, reject) => {
      const ws = this.ws = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`); ws.binaryType = 'arraybuffer';
      ws.onopen = () => { if (this.ws !== ws) { ws.close(1000); reject(new Error('CONNECTION_CLOSED')); return; } this.retry = 0; this.onState('online'); resolve(); };
      ws.onmessage = event => {
        if (this.ws !== ws) return;
        try { const f = decode(new Uint8Array(event.data)); const p = this.pending.get(f.requestId); if (!p) return; clearTimeout(p.timer); this.pending.delete(f.requestId); f.meta.ok ? p.resolve(f) : p.reject(new Error(String(f.meta.code))); }
        catch { ws.close(4002); }
      };
      ws.onerror = () => reject(new Error('连接失败，请确认服务及证书信任设置'));
      ws.onclose = event => {
        if (this.ws !== ws) { reject(new Error('CONNECTION_CLOSED')); return; }
        this.opening = undefined; this.onState(event.code === 4001 ? 'revoked' : 'offline'); this.onLost(event.reason ?? '');
        for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new Error('CONNECTION_CLOSED')); } this.pending.clear();
        reject(new Error('CONNECTION_CLOSED'));
        if (!this.closed && event.code === 1006) this.timer = setTimeout(() => { void this.connect().catch(() => {}); }, Math.min(15000, 1000 * 2 ** this.retry++));
      };
    });
    return this.opening;
  }
  async rpc(op: string, meta: Metadata = {}, payload?: Uint8Array): Promise<Frame> {
    await this.connect(); if (this.pending.size >= 6) throw new Error('请求队列已满，请稍后重试');
    const requestId = ++this.seq;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(requestId); reject(new Error('REQUEST_TIMEOUT')); }, op === 'maintenance.backup' ? 600000 : 45000);
      this.pending.set(requestId, { resolve, reject, timer }); this.ws!.send(encode(1, requestId, { op, ...meta }, payload));
    });
  }
  disconnect() {
    clearTimeout(this.timer); this.timer = undefined;
    const ws = this.ws; this.ws = undefined; this.opening = undefined;
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new Error('CONNECTION_CLOSED')); } this.pending.clear();
    this.onState('offline'); this.onLost(); ws?.close(1000);
  }
  stop() { this.closed = true; this.disconnect(); }
}
let dbPromise: Promise<IDBDatabase>;
function database() { return dbPromise ??= new Promise((resolve, reject) => { const r = indexedDB.open('safedrop-device', 1); r.onupgradeneeded = () => r.result.createObjectStore('state'); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); }); }
export async function localGet<T>(key: string): Promise<T | undefined> { const db = await database(); return new Promise((resolve, reject) => { const r = db.transaction('state').objectStore('state').get(key); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); }); }
export async function localPut(key: string, value: unknown) { const db = await database(); return new Promise<void>((resolve, reject) => { const tx = db.transaction('state', 'readwrite'); value === undefined ? tx.objectStore('state').delete(key) : tx.objectStore('state').put(value, key); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); }); }
export async function hashBlob(blob: Blob, onProgress?: (n: number) => void) {
  const h = sha256.create(); for (let i = 0; i < blob.size; i += CHUNK) { h.update(new Uint8Array(await blob.slice(i, i + CHUNK).arrayBuffer())); onProgress?.(Math.min(blob.size, i + CHUNK)); } return hex(h.digest());
}
export async function bindKey(client: Client, name: string, password: string) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const { meta } = await client.rpc('keys.enroll', { jwk, password, label: '本机浏览器 · P-256' });
  await localPut('key:' + name, { privateKey: pair.privateKey, keyId: meta.keyId });
}
export async function loginWithKey(client: Client, name: string) {
  const key = await localGet<{ privateKey: CryptoKey; keyId: string }>('key:' + name); if (!key) throw new Error('此浏览器尚未为该账号绑定公钥，请先用口令登录');
  try {
    const { meta } = await client.rpc('auth.challenge', { name, keyId: key.keyId });
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, new TextEncoder().encode(String(meta.message)));
    return await client.rpc('auth.prove', { signature: b64(signature) });
  } catch (error) {
    if (error instanceof Error && error.message === 'INVALID_CREDENTIALS') throw new Error('公钥认证未通过，请使用口令登录并检查本机公钥绑定');
    throw error;
  }
}
export function saveJSON(name: string, data: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a'); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 10000);
}
