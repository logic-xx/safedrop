import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
export function certificates(dir: string) {
  mkdirSync(dir, { recursive: true });
  if (existsSync(join(dir, 'server.crt'))) return;
  const openssl = process.env.OPENSSL_PATH || 'openssl';
  writeFileSync(join(dir, 'openssl.cnf'), '[req]\ndistinguished_name=dn\n[dn]\n');
  const run = (...args: string[]) => execFileSync(openssl, args, { cwd: dir, env: { ...process.env, OPENSSL_CONF: join(dir, 'openssl.cnf') }, stdio: 'pipe', windowsHide: true });
  run('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-sha256', '-days', '365', '-subj', '/CN=SafeDrop Local Development CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  run('req', '-newkey', 'rsa:3072', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost');
  writeFileSync(join(dir, 'server.ext'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
  run('x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.crt', '-days', '90', '-sha256', '-extfile', 'server.ext');
}
