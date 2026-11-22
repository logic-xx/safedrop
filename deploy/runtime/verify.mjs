import assert from 'node:assert/strict';
import { readFile, readdir, lstat, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const systemSSL = /^lib(?:ssl|crypto)\.so(?:\.|$)/i;

// Also used with isolated synthetic roots in negative tests; this alone is not
// Linux runtime evidence. No deletion or inventory rewriting takes place here.
export async function verifyFiles(root, manifest) {
  const at = name => {
    assert.ok(/^\/?[a-zA-Z0-9_+./-]+$/.test(name) && !name.split('/').includes('..'), 'INVALID_RUNTIME_PATH');
    return join(root, name.replace(/^\//, ''));
  };
  for (const file of [...manifest.files, ...manifest.metadata]) {
    const path = at(file.path), stat = await lstat(path);
    assert.ok(stat.isFile() && !stat.isSymbolicLink(), 'RUNTIME_REGULAR_FILE_REQUIRED:' + file.path);
    const bytes = await readFile(path);
    assert.equal(sha256(bytes), file.sha256, 'RUNTIME_HASH_MISMATCH:' + file.path);
    if (file.package) {
      const text = bytes.toString();
      assert.ok(text.includes('Package: ' + file.package + '\n') && text.includes('Version: ' + file.version + '\n'), 'RUNTIME_PACKAGE_MISMATCH');
    }
  }
  const visit = async path => {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      assert.ok(!systemSSL.test(entry.name), 'UNEXPECTED_SYSTEM_OPENSSL:' + entry.name);
      if (entry.isDirectory()) await visit(join(path, entry.name));
    }
  };
  for (const dir of ['usr/lib', 'usr/local/lib']) {
    try { await visit(at(dir)); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
  // Scan all real package metadata, not only the allowlisted copied entries.
  for (const file of await readdir(at('var/lib/dpkg/status.d'))) {
    assert.ok(!/(?:openssl|libssl)/i.test(file), 'SYSTEM_OPENSSL_PACKAGE_PRESENT');
    if (file.endsWith('.md5sums')) continue;
    const text = await readFile(at('var/lib/dpkg/status.d/' + file), 'utf8');
    assert.ok(!/^Package: (?:openssl(?:-|$)|libssl)/m.test(text), 'SYSTEM_OPENSSL_PACKAGE_PRESENT');
  }
}

export async function verifyRuntime() {
  const bytes = await readFile(new URL('./manifest.json', import.meta.url)), manifest = JSON.parse(bytes);
  assert.equal(process.platform, 'linux', 'FINAL_LINUX_RUNTIME_REQUIRED');
  assert.equal(process.arch, manifest.architecture);
  assert.equal(process.version, manifest.nodeVersion);
  assert.equal(await realpath(process.execPath), '/nodejs/bin/node');
  assert.equal(process.config.variables.node_shared_openssl, false, 'STATIC_NODE_TLS_REQUIRED');
  assert.equal(process.config.variables.node_use_quic, false, 'NODE_QUIC_MUST_REMAIN_DISABLED');
  await verifyFiles('/', manifest);
  // COPY may dereference a top-level symlink. Verify the ABI lookup name's
  // actual bytes too, whether it is a link or an identical regular file.
  assert.equal(sha256(await readFile('/usr/lib/x86_64-linux-gnu/libstdc++.so.6')),
    manifest.files.find(f => f.path === '/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.33').sha256, 'CXX_RUNTIME_ALIAS_MISMATCH');
  assert.ok(!(await readFile('/proc/self/maps', 'utf8')).split('\n').some(line => /\/lib(?:ssl|crypto)\.so(?:\.|\s|$)/.test(line)), 'SYSTEM_OPENSSL_LOADED');
  return { version: 1, ok: true, platform: process.platform, architecture: process.arch, node: process.version,
    openssl: process.versions.openssl, sharedOpenSSL: false, quic: false, noSystemOpenSSL: true,
    manifestSha256: sha256(bytes), nodeImage: manifest.nodeImage, baseImage: manifest.baseImage,
    verifiedFiles: manifest.files.length, verifiedMetadata: manifest.metadata.length };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(await verifyRuntime()));
}
