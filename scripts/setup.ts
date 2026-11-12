import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { certificates } from './certificates.ts';
import { Store } from '../server/store.ts';
const dir = resolve(process.env.LOCAL_DIR ?? '.local'); mkdirSync(dir, { recursive: true });
if (process.env.TRUST_PROXY !== '1') certificates(join(dir, 'tls'));
const store = new Store(resolve(process.env.DATA_DIR ?? join(dir, 'data')));
if (!existsSync(join(dir, 'accounts.json'))) {
  const accounts = [];
  for (const [name, role, tier] of [['admin', 'admin', 'vip'], ['alice', 'user', 'normal'], ['bob', 'user', 'vip']]) {
    if (store.get('SELECT id FROM users WHERE name=?', name)) continue;
    const password = randomBytes(18).toString('base64url'); await store.addUser(name, password, role, tier); accounts.push({ name, password, role, tier });
  }
  writeFileSync(join(dir, 'accounts.json'), JSON.stringify(accounts, null, 2), { mode: 0o600 });
}
store.close();
console.log('初始化完成。随机账号资料已保存在运行数据目录的 accounts.json，请勿提交或公开。');
