import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, copyFileSync, lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { setTimeout as pause } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { gatewayPolicy } from './gateway-policy.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const files = ['images.tar', 'compose.yaml', 'Caddyfile', 'image-manifest.json', 'README.md'];
const ci = {
  revision: '28a3f4fa5deea226a81f33d813f500627065b96d',
  run: 'https://github.com/logic-xx/safedrop/actions/runs/45008996789',
  images: {
    app: 'sha256:b0ce5d7dec356880fd0c1dd9f5c74f68685607bfaef0fd25c9fdfaf3d57a0f72',
    gateway: 'sha256:bd2cf5c3d121dadd552de4da5eb18f90231cccbd76ee58977038e76b8de5e275',
    scanner: 'sha256:efc3d7b7712f969f0fcbb583f4bf86d184eaaf125602ea45ed2aced1a03f418a',
  },
};
const retained = {
  runtime: '2026-11-22T09:51:13.6913144Z', version: 12,
  app: 'sha256:cce5bc40b2c082651c6ce06854b2ac15439ade76da2c9aaad45320c4b53998c5',
  scanner: 'sha256:0e81c2e06347b988e6bacb30e3571ed7796dfa997be9b87d182266fbdd9c14e1',
};
const validImageId = /^sha256:[a-f0-9]{64}$/;
const vendor = JSON.parse(readFileSync(join(root, 'deploy/scanner/vendor-manifest.json'), 'utf8'));

function command(file, args, { cwd = root, env = process.env, show = false, input, timeout } = {}) {
  const result = spawnSync(file, args, {
    cwd, env, input, timeout, encoding: 'utf8', windowsHide: true,
    stdio: show ? 'inherit' : [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const detail = (result.stderr || result.error?.message || '').trim();
    throw new Error(`${file} ${args.slice(0, 2).join(' ')} failed${detail ? `: ${detail}` : ''}`);
  }
  return result.stdout ?? '';
}

const docker = (args, options) => command('docker', args, options);
const tar = (args, options) => command('tar', args, options);
const writeJson = (path, data) => writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`, { flag: 'wx' });

async function hashFile(path) {
  const hash = createHash('sha256');
  for await (const part of createReadStream(path)) hash.update(part);
  return hash.digest('hex');
}

function inspectImage(ref) {
  const [image] = JSON.parse(docker(['image', 'inspect', ref]));
  assert.match(image.Id, validImageId);
  assert.equal(`${image.Os}/${image.Architecture}`, 'linux/amd64');
  return image;
}

function approvedImage(role) {
  for (const ref of [retained[role], ci.images[role]].filter(Boolean)) {
    try { return inspectImage(ref); }
    catch (error) { if (!/no such image/i.test(error.message)) throw error; }
  }
  if (role === 'gateway') {
    const containers = docker(['ps', '-aq', '--filter', 'label=com.docker.compose.project=safedrop-check',
      '--filter', 'label=com.docker.compose.service=gateway']).trim().split(/\s+/).filter(Boolean);
    assert.equal(containers.length, 1, 'Need the gateway from the recorded safedrop-check deployment or the exact CI image');
    const id = docker(['inspect', '--format', '{{.Image}}', containers[0]]).trim();
    assert.match(id, validImageId);
    return inspectImage(id);
  }
  throw new Error(`Approved ${role} image is missing from this Docker engine`);
}

function validateCompose(model, port) {
  assert.deepEqual(Object.keys(model.services).sort(), ['app', 'gateway', 'scanner']);
  for (const [name, service] of Object.entries(model.services)) {
    assert.equal(service.pull_policy, 'never', `${name} must only use loaded images`);
    assert.equal(service.platform, 'linux/amd64');
    assert.equal(service.build, undefined);
    assert.equal(service.read_only, true);
  }
  assert.equal(model.networks.backend.internal, true);
  assert.deepEqual(Object.keys(model.services.scanner.networks), ['backend']);
  assert.deepEqual(Object.keys(model.services.app.networks), ['backend']);
  assert.equal(model.services.scanner.ports, undefined);
  assert.equal(model.services.app.ports, undefined);
  assert.equal(model.services.scanner.volumes, undefined);
  assert.equal(model.services.app.environment.CLAMD_HOST, 'scanner');
  assert.equal(model.services.app.environment.APP_ORIGIN, `https://localhost:${port}`);
  assert.equal(model.services.gateway.ports.length, 1);
  const [binding] = model.services.gateway.ports;
  assert.equal(binding.host_ip, '127.0.0.1');
  assert.equal(Number(binding.published), port);
  assert.equal(Number(binding.target), 8443);
}

function verifySavedImages(path, images) {
  const paths = new Set(tar(['-tf', path]).trimEnd().split(/\r?\n/));
  const manifest = JSON.parse(tar(['-xOf', path, 'manifest.json']));
  assert.equal(manifest.length, images.length);
  for (const { tag, id } of images) {
    const entry = manifest.find(row => row.RepoTags?.some(ref => ref.replace(/^docker\.io\/library\//, '') === tag));
    assert.equal(entry?.RepoTags.length, 1);
    assert.ok(paths.has(entry.Config) && entry.Layers.length > 0 && entry.Layers.every(layer => paths.has(layer)), `Incomplete image archive for ${tag}`);
    const config = tar(['-xOf', path, entry.Config]);
    assert.equal(`sha256:${createHash('sha256').update(config).digest('hex')}`, id);
  }
}

function reserveTestPort() {
  return new Promise((resolve, reject) => {
    const listener = createServer();
    listener.on('error', reject);
    listener.listen(0, '127.0.0.1', () => {
      const { port } = listener.address();
      listener.close(error => { if (error) reject(error); else resolve(port); });
    });
  });
}

async function copyGatewayCa(compose, caPath) {
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      compose(['cp', 'gateway:/data/caddy/pki/authorities/local/root.crt', caPath]);
      return;
    } catch (error) {
      if (attempt === 29 || !/not found|no such file|could not find/i.test(error.message)) throw error;
      await pause(500);
    }
  }
}

function signatureExpiry(engine) {
  const match = /^ClamAV 1\.5\.5\/(\d+)\/(.+)$/.exec(engine);
  assert.ok(match, 'Offline scanner must provide a valid ClamAV build and signature version');
  const builtAt = Date.parse(`${match[2]} UTC`);
  const expiresAt = builtAt + 72 * 60 * 60 * 1000;
  assert.ok(Number.isFinite(builtAt) && builtAt <= Date.now() + 3600000 && expiresAt > Date.now(), 'Offline signature database is stale or has an invalid build time');
  return { version: Number(match[1]), builtAt: new Date(builtAt).toISOString(), expiresAt: new Date(expiresAt).toISOString() };
}

async function makeBundle() {
  assert.equal(docker(['version', '--format', '{{.Server.Os}}/{{.Server.Arch}}']).trim(), 'linux/amd64', 'A local Linux amd64 Docker engine is required');
  const contextHost = (!process.env.DOCKER_CONTEXT && process.env.DOCKER_HOST) || docker(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}']).trim();
  assert.match(contextHost, /^(npipe|unix):\/\//, 'Use a local Docker Desktop or Unix Docker engine for the loopback test');
  const { probeOfflineImages } = await import('./offline-image-probe.mjs');
  const source = Object.fromEntries(['app', 'gateway', 'scanner'].map(role => [role, approvedImage(role)]));
  for (const [role, image] of Object.entries(source)) {
    assert.ok(image.RepoTags?.some(tag => tag !== '<none>:<none>'), `The original ${role} image must retain a tag during verification`);
  }
  const gatewayLayer = docker(['image', 'history', '--no-trunc', '--format', '{{.CreatedBy}}', source.gateway.Id]).split(/\r?\n/, 1)[0].trim();
  assert.match(gatewayLayer, /^COPY \/out\/caddy \/usr\/bin\/caddy(?: # buildkit)?$/, 'Need a gateway image produced by the project Dockerfile');
  const gateway = gatewayPolicy(docker(['run', '--rm', '--network', 'none', '--entrypoint', '/usr/bin/caddy', source.gateway.Id, 'build-info']));
  const runId = randomBytes(8).toString('hex');
  const tag = `0.1.0-${runId}`;
  const defaultProject = `safedrop-offline-${runId}`;
  const project = `safedrop-offline-check-${runId}`;
  const output = join(root, 'output', 'offline-images', `SafeDrop-${tag}-linux-amd64`);
  const bundle = join(output, 'bundle');
  const build = join(output, 'scanner-build');
  mkdirSync(output, { recursive: true });
  mkdirSync(bundle);
  mkdirSync(build);
  const stages = { signatures: false, archive: false, loaded: false, transfer: false };
  const images = Object.entries(source).map(([role, original]) => ({ role, tag: `safedrop-offline-${role}:${tag}`, sourceId: original.Id }));
  const baseTag = `safedrop-offline-scanner-base:${tag}`;
  let fetcher;
  let baseTagged = false;
  let started = false;
  let compose;
  try {
    console.log('Refreshing official signatures in a new scanner container.');
    fetcher = docker(['create', '--name', `${project}-signature-fetch`, '--network', 'bridge',
      '--entrypoint', '/nodejs/bin/node', source.scanner.Id, '/tmp/prepare-signatures.mjs']).trim();
    assert.match(fetcher, /^[a-f0-9]{64}$/);
    docker(['cp', join(root, 'scripts', 'offline-signatures.mjs'), `${fetcher}:/tmp/prepare-signatures.mjs`]);
    docker(['start', '-a', fetcher], { show: true });
    assert.equal(docker(['inspect', '--format', '{{.State.ExitCode}}', fetcher]).trim(), '0');
    const db = join(build, 'db');
    docker(['cp', `${fetcher}:/tmp/verified-databases`, db]);
    const names = readdirSync(db).sort();
    assert.deepEqual(names.map(name => name.replace(/\.(cvd|cld)$/, '')), ['bytecode', 'daily', 'main']);
    const databases = [];
    for (const name of names) {
      assert.match(name, /^(bytecode|daily|main)\.(cvd|cld)$/);
      const path = join(db, name);
      const stat = lstatSync(path);
      assert.ok(stat.isFile() && stat.size > 512);
      databases.push({ name, bytes: stat.size, sha256: await hashFile(path) });
    }
    stages.signatures = true;
    docker(['rm', fetcher]);
    fetcher = undefined;

    docker(['tag', source.scanner.Id, baseTag]);
    baseTagged = true;
    const clamd = readFileSync(join(root, 'deploy/scanner/clamd.conf'), 'utf8').replaceAll('\r\n', '\n');
    assert.match(clamd, /^DatabaseDirectory \/data\/db$/m);
    writeFileSync(join(build, 'clamd.conf'), clamd.replace(/^DatabaseDirectory \/data\/db$/m, 'DatabaseDirectory /offline-db'));
    writeFileSync(join(build, 'Dockerfile'), [
      `FROM ${baseTag}`,
      'COPY --chown=65532:65532 db/ /offline-db/',
      'COPY clamd.conf /scanner/clamd.conf',
      'ENTRYPOINT ["/usr/local/sbin/clamd"]',
      'CMD ["--foreground", "--config-file=/scanner/clamd.conf"]',
      '',
    ].join('\n'));
    const offlineScanner = images.find(image => image.role === 'scanner');
    docker(['build', '--pull=false', '--network=none', '--platform=linux/amd64', '--tag', offlineScanner.tag, build], { show: true });
    const proofCode = readFileSync(join(root, 'scripts', 'scanner-provenance.mjs'), 'utf8');
    const proofArgs = ['run', '--rm', '-i', '--network', 'none', '--entrypoint', '/nodejs/bin/node'];
    const scanProof = JSON.parse(docker([...proofArgs, offlineScanner.tag, '--input-type=module', '-'], { input: proofCode }));
    assert.equal(scanProof.ok, true);
    assert.equal(scanProof.archiveSha256, vendor.archive.sha256);
    assert.equal(scanProof.manifestSha256, createHash('sha256').update(JSON.stringify(vendor)).digest('hex'));
    const signatures = { ...signatureExpiry(scanProof.engine), files: databases };
    for (const image of images) {
      if (image.role !== 'scanner') docker(['tag', image.sourceId, image.tag]);
      image.id = inspectImage(image.tag).Id;
      assert.equal(image.id === image.sourceId, image.role !== 'scanner');
    }

    const imageTar = join(bundle, 'images.tar');
    docker(['image', 'save', '--output', imageTar, ...images.map(image => image.tag)], { show: true });
    verifySavedImages(imageTar, images);
    stages.archive = true;
    console.log('Loading the three saved images and checking imported IDs.');
    for (const image of images) docker(['image', 'rm', image.tag]);
    docker(['image', 'load', '--input', imageTar], { show: true });
    for (const image of images) assert.equal(inspectImage(image.tag).Id, image.id);
    stages.loaded = true;

    const app = images.find(image => image.role === 'app');
    const nodeRuntime = ['/nodejs/bin/node', '/runtime/verify.mjs'];
    const runtime = {};
    for (const image of [app, offlineScanner]) {
      const current = JSON.parse(docker(['run', '--rm', '--network', 'none', '--entrypoint', nodeRuntime[0], image.tag, nodeRuntime[1]]));
      assert.ok(current.ok && current.noSystemOpenSSL && current.sharedOpenSSL === false && current.quic === false);
      runtime[image.role] = { node: current.node, openssl: current.openssl, manifestSha256: current.manifestSha256 };
    }
    const appVersion = docker(['run', '--rm', '--network', 'none', '--entrypoint', '/nodejs/bin/node', app.tag,
      '-p', 'require("/app/package.json").version']).trim();
    assert.equal(appVersion, '0.1.0');

    const template = readFileSync(join(root, 'deploy', 'offline', 'compose.yaml'), 'utf8');
    writeFileSync(join(bundle, 'compose.yaml'), template.replaceAll('0.1.0-prepared', tag).replace('safedrop-offline-prepared', defaultProject));
    copyFileSync(join(root, 'deploy', 'Caddyfile.local'), join(bundle, 'Caddyfile'));
    const guide = readFileSync(join(root, 'deploy', 'offline', 'README.md'), 'utf8');
    writeFileSync(join(bundle, 'README.md'), guide.replaceAll('safedrop-offline-prepared', defaultProject));
    const port = await reserveTestPort();
    const env = { ...process.env, SAFEDROP_OFFLINE_PORT: String(port) };
    compose = (args, options) => docker(['compose', '-f', 'compose.yaml', '-p', project, ...args], { cwd: bundle, env, ...options });
    const resolved = JSON.parse(compose(['config', '--format', 'json']));
    validateCompose(resolved, port);
    for (const image of images) assert.equal(resolved.services[image.role].image, image.tag);
    started = true;
    console.log('Starting a new Compose project from the loaded images with pull and build disabled.');
    compose(['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '360'], { show: true });
    for (const image of images) {
      const container = compose(['ps', '-q', image.role]).trim();
      assert.match(container, /^[a-f0-9]{12,64}$/);
      assert.equal(docker(['inspect', '--format', '{{.Image}}', container]).trim(), image.id);
    }
    const caPath = join(output, 'verify-ca.crt');
    await copyGatewayCa(compose, caPath);
    const accountsText = compose(['exec', '-T', 'app', '/nodejs/bin/node', '-e',
      "process.stdout.write(require('node:fs').readFileSync('/data/accounts.json','utf8'))"]);
    let accounts;
    try { accounts = JSON.parse(accountsText); }
    catch { throw new Error('The verification project did not generate valid account material'); }
    const password = accounts.find(account => account.name === 'alice')?.password;
    assert.ok(typeof password === 'string' && password.length >= 12);
    const transfer = await probeOfflineImages({ origin: `https://localhost:${port}`, ca: readFileSync(caPath), password });
    signatureExpiry(scanProof.engine);
    stages.transfer = true;
    console.log('PASS loaded images, strict HTTPS/WSS, upload, real ClamAV scan, and byte-identical download.');
    compose(['down'], { show: true });
    started = false;

    writeJson(join(bundle, 'image-manifest.json'), {
      created: new Date().toISOString(), platform: 'linux/amd64', defaultProject, appVersion, caddy: '2.11.9',
      engine: scanProof.engine, signatures, runtime, images,
      source: 'https://github.com/logic-xx/safedrop', historicalEvidence: { ci, retained },
      gatewayBuild: gateway,
      verification: { project, loaded: true, usedNewNamedVolumes: true, pullDisabled: true, buildDisabled: true, ...transfer },
    });
    const sums = [];
    for (const name of files) sums.push(`${await hashFile(join(bundle, name))}  ${name}`);
    writeFileSync(join(bundle, 'SHA256SUMS.txt'), `${sums.join('\n')}\n`, { flag: 'wx' });
    const expectedEntries = [...files, 'SHA256SUMS.txt'];
    assert.deepEqual(readdirSync(bundle).sort(), [...expectedEntries].sort());
    const archive = join(output, `SafeDrop-${tag}-linux-amd64.tar.gz`);
    tar(['-czf', `${archive}.partial`, '-C', bundle, ...expectedEntries], { show: true });
    assert.deepEqual(tar(['-tzf', `${archive}.partial`]).trimEnd().split(/\r?\n/).sort(), [...expectedEntries].sort());
    const sha256 = await hashFile(`${archive}.partial`);
    renameSync(`${archive}.partial`, archive);
    writeFileSync(`${archive}.sha256`, `${sha256}  SafeDrop-${tag}-linux-amd64.tar.gz\n`, { flag: 'wx' });
    writeJson(join(output, 'verification.json'), { ok: true, imageIds: images, stages, transfer, signatures, archiveSha256: sha256, project });
    console.log(`Verified distribution: ${archive}`);
  } catch (error) {
    writeJson(join(output, 'verification-failed.json'), { ok: false, project, stages, error: error.message });
    throw error;
  } finally {
    const cleanup = args => { try { docker(args); } catch (error) { console.error(error.message); } };
    if (started) {
      try { compose(['down']); } catch (error) { console.error(error.message); }
    }
    if (fetcher && /^[a-f0-9]{64}$/.test(fetcher)) cleanup(['rm', '-f', fetcher]);
    if (baseTagged) cleanup(['image', 'rm', baseTag]);
  }
}

try {
  if (process.argv[2] === '--check-only' && process.argv.length === 3) {
    const cwd = join(root, 'deploy', 'offline');
    const model = docker(['compose', '-f', 'compose.yaml', 'config', '--format', 'json'], { cwd, env: { ...process.env, SAFEDROP_OFFLINE_PORT: '18446' } });
    validateCompose(JSON.parse(model), 18446);
    console.log('Offline Compose configuration checked without contacting the engine.');
  } else {
    assert.equal(process.argv.length, 2, 'Usage: node scripts/package-offline-images.mjs [--check-only]');
    await makeBundle();
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
