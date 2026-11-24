import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, copyFileSync, lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { setTimeout as pause } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { gatewayPolicy } from './gateway-policy.mjs';
import { verifySavedImages } from './verify-image-archive.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const noSignatureNetwork = 'compose.no-signature-network.yaml';
const files = ['images.tar', 'compose.yaml', noSignatureNetwork, 'Caddyfile', 'image-manifest.json', 'README.md'];
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
let dockerContext;

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

const docker = (args, options) => command('docker', dockerContext ? ['--context', dockerContext, ...args] : args, options);
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

function validateCompose(model, port, disconnected) {
  assert.deepEqual(Object.keys(model.services).sort(), ['app', 'gateway', 'scanner']);
  for (const [name, service] of Object.entries(model.services)) {
    assert.equal(service.pull_policy, 'never', `${name} must only use loaded images`);
    assert.equal(service.platform, 'linux/amd64');
    assert.equal(service.build, undefined);
    assert.equal(service.read_only, true);
  }
  assert.equal(model.networks.backend.internal, true);
  assert.deepEqual(Object.keys(model.services.scanner.networks).sort(), ['backend', 'signatures']);
  assert.equal(Boolean(model.networks.signatures.internal), disconnected);
  assert.deepEqual(Object.keys(model.services.app.networks), ['backend']);
  assert.equal(model.services.scanner.ports, undefined);
  assert.equal(model.services.app.ports, undefined);
  assert.deepEqual(model.services.scanner.volumes.map(({ type, source, target }) => ({ type, source, target })),
    [{ type: 'volume', source: 'scanner_data', target: '/data' }]);
  assert.equal(model.services.app.environment.CLAMD_HOST, 'scanner');
  assert.equal(model.services.app.environment.APP_ORIGIN, `https://localhost:${port}`);
  assert.equal(model.services.gateway.ports.length, 1);
  const [binding] = model.services.gateway.ports;
  assert.equal(binding.host_ip, '127.0.0.1');
  assert.equal(Number(binding.published), port);
  assert.equal(Number(binding.target), 8443);
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

function signatureExpiry(engine, fresh) {
  const match = /^ClamAV 1\.5\.5\/(\d+)\/(.+)$/.exec(engine);
  assert.ok(match, 'Offline scanner must provide a valid ClamAV build and signature version');
  const builtAt = Date.parse(`${match[2]} UTC`);
  const expiresAt = builtAt + 72 * 60 * 60 * 1000;
  assert.ok(Number.isFinite(builtAt) && builtAt <= Date.now() + 3600000, 'Invalid signature publication time');
  assert.equal(expiresAt > Date.now(), fresh, `Expected a ${fresh ? 'valid' : 'stale'} signature database, got ${engine}`);
  return { version: Number(match[1]), builtAt: new Date(builtAt).toISOString(), expiresAt: new Date(expiresAt).toISOString() };
}

function deploymentEnv(port) {
  const env = { ...process.env, SAFEDROP_OFFLINE_PORT: String(port) };
  for (const role of ['APP', 'SCANNER', 'GATEWAY']) delete env[`SAFEDROP_${role}_IMAGE`];
  return env;
}

async function verifyDeployment({ output, bundle, images, runId, stale, probeOfflineImages, keepRunning = false }) {
  const scenario = stale ? 'disconnected' : 'connected';
  const project = 'safedrop-offline-check-' + runId + '-' + scenario;
  const port = await reserveTestPort();
  const args = ['compose', '-f', 'compose.yaml', ...(stale ? ['-f', noSignatureNetwork] : []), '-p', project];
  const options = { cwd: bundle, env: deploymentEnv(port) };
  const compose = (command, extra) => docker([...args, ...command], { ...options, ...extra });
  const resolved = JSON.parse(compose(['config', '--format', 'json']));
  validateCompose(resolved, port, stale);
  for (const image of images) assert.equal(resolved.services[image.role].image, image.tag);
  const node = '/nodejs/bin/node';
  const origin = 'https://localhost:' + port;
  let passed = false;
  try {
    console.log('Checking imported images (' + scenario + ') with new named volumes and no pull or build.');
    compose(['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '600'], { show: true });
    const status = compose(['ps']);
    console.log(status);
    writeFileSync(join(output, scenario + '-compose-ps.txt'), status, { flag: 'wx' });
    for (const image of images) {
      const container = compose(['ps', '-q', image.role]).trim();
      assert.match(container, /^[a-f0-9]{12,64}$/);
      assert.equal(docker(['inspect', '--format', '{{.Image}}', container]).trim(), image.id);
    }
    const caPath = join(output, scenario + '-ca.crt');
    await copyGatewayCa(compose, caPath);
    const password = compose(['exec', '-T', 'app', node, '-e',
      "process.stdout.write(JSON.parse(require('node:fs').readFileSync('/data/accounts.json','utf8')).find(account=>account.name==='alice').password)"]).trim();
    assert.ok(password.length >= 12, 'The isolated project must generate account material');

    const proofCode = readFileSync(join(root, 'scripts', 'scanner-provenance.mjs'), 'utf8');
    const proof = JSON.parse(compose(['exec', '-T', 'scanner', node, '--input-type=module', '-'], { input: proofCode }));
    assert.equal(proof.ok, true);
    assert.equal(proof.archiveSha256, vendor.archive.sha256);
    assert.equal(proof.manifestSha256, createHash('sha256').update(JSON.stringify(vendor)).digest('hex'));
    const signatures = signatureExpiry(proof.engine, !stale);
    const transfer = await probeOfflineImages({ origin, ca: readFileSync(caPath), password, stale });
    if (!stale) assert.equal(signatureExpiry(transfer.engine, true).version, signatures.version);
    passed = true;
    return { project, origin, port, signatures, transfer, usedNewNamedVolumes: true, pullDisabled: true, buildDisabled: true };
  } finally {
    try {
      writeFileSync(join(output, scenario + '-compose.log'), compose(['logs', '--no-color', 'scanner', 'gateway']), { flag: 'wx' });
    } catch (error) { console.error(error.message); }
    if (!passed || !keepRunning) compose(['down'], { show: true });
  }
}

async function makeBundle(keepRunning) {
  assert.equal(docker(['version', '--format', '{{.Server.Os}}/{{.Server.Arch}}']).trim(), 'linux/amd64', 'A local Linux amd64 Docker engine is required');
  const contextHost = (!dockerContext && !process.env.DOCKER_CONTEXT && process.env.DOCKER_HOST) ||
    docker(['context', 'inspect', ...(dockerContext ? [dockerContext] : []), '--format', '{{.Endpoints.docker.Host}}']).trim();
  assert.match(contextHost, /^(npipe|unix):\/\//, 'Use a local Docker Desktop or Unix Docker engine for the loopback test');
  const { probeOfflineImages } = await import('./offline-image-probe.mjs');
  const scannerSource = approvedImage('scanner'), gatewaySource = approvedImage('gateway');
  for (const image of [scannerSource, gatewaySource]) {
    assert.ok(image.RepoTags?.some(tag => tag !== '<none>:<none>'), 'The original image must retain a tag during verification');
  }
  const gatewayLayer = docker(['image', 'history', '--no-trunc', '--format', '{{.CreatedBy}}', gatewaySource.Id]).split(/\r?\n/, 1)[0].trim();
  assert.match(gatewayLayer, /^COPY \/out\/caddy \/usr\/bin\/caddy(?: # buildkit)?$/, 'Need a gateway image produced by the project Dockerfile');
  const gateway = gatewayPolicy(docker(['run', '--rm', '--network', 'none', '--entrypoint', '/usr/bin/caddy', gatewaySource.Id, 'build-info']));
  const runId = randomBytes(8).toString('hex');
  const tag = '0.1.0-' + runId;
  const defaultProject = 'safedrop-offline-' + runId;
  const output = join(root, 'output', 'offline-images', 'SafeDrop-' + tag + '-linux-amd64');
  const bundle = join(output, 'bundle');
  mkdirSync(bundle, { recursive: true });
  const stages = { archive: false, loaded: false, disconnected: false, updated: false, transfer: false };
  const images = [
    { role: 'app', tag: 'safedrop-offline-app:' + tag },
    { role: 'gateway', tag: 'safedrop-offline-gateway:' + tag, sourceId: gatewaySource.Id },
    { role: 'scanner', tag: 'safedrop-offline-scanner:' + tag, sourceId: scannerSource.Id },
  ];
  const [app, , scanner] = images;
  const revision = command('git', ['rev-parse', 'HEAD']).trim();
  const modified = command('git', ['status', '--porcelain']).trim() !== '';
  let connected;
  try {
    console.log('Building the current application once on the packaging machine.');
    docker(['build', '--platform=linux/amd64', '--label', 'org.opencontainers.image.revision=' + revision, '--tag', app.tag, '.'], { show: true });
    for (const image of images) {
      if (image.sourceId) docker(['tag', image.sourceId, image.tag]);
      image.id = inspectImage(image.tag).Id;
      if (image.sourceId) assert.equal(image.id, image.sourceId);
    }

    const imageTar = join(bundle, 'images.tar');
    docker(['image', 'save', '--output', imageTar, ...images.map(image => image.tag)], { show: true });
    const identities = await verifySavedImages(imageTar, images);
    images.forEach((image, index) => Object.assign(image, identities[index]));
    const imageTarSha256 = await hashFile(imageTar);
    stages.archive = true;
    console.log('Loading the three saved images and checking imported IDs.');
    for (const image of images) docker(['image', 'rm', image.tag]);
    docker(['image', 'load', '--input', imageTar], { show: true });
    for (const image of images) assert.equal(inspectImage(image.tag).Id, image.id);
    stages.loaded = true;

    const nodeRuntime = ['/nodejs/bin/node', '/runtime/verify.mjs'];
    const runtime = {};
    for (const image of [app, scanner]) {
      const current = JSON.parse(docker(['run', '--rm', '--network', 'none', '--entrypoint', nodeRuntime[0], image.tag, nodeRuntime[1]]));
      assert.ok(current.ok && current.noSystemOpenSSL && current.sharedOpenSSL === false && current.quic === false);
      runtime[image.role] = { node: current.node, openssl: current.openssl, manifestSha256: current.manifestSha256 };
    }
    const appVersion = docker(['run', '--rm', '--network', 'none', '--entrypoint', '/nodejs/bin/node', app.tag,
      '-p', 'require("/app/package.json").version']).trim();
    assert.equal(appVersion, '0.1.0');

    const template = readFileSync(join(root, 'deploy', 'offline', 'compose.yaml'), 'utf8');
    assert.ok(template.includes('source: ../Caddyfile.local'), 'Gateway bind must point to the repository Caddyfile');
    writeFileSync(join(bundle, 'compose.yaml'), template.replaceAll('0.1.0-prepared', tag)
      .replace('safedrop-offline-prepared', defaultProject).replace('source: ../Caddyfile.local', 'source: ./Caddyfile'));
    copyFileSync(join(root, 'deploy', 'offline', noSignatureNetwork), join(bundle, noSignatureNetwork));
    copyFileSync(join(root, 'deploy', 'Caddyfile.local'), join(bundle, 'Caddyfile'));
    const guide = readFileSync(join(root, 'deploy', 'offline', 'README.md'), 'utf8');
    writeFileSync(join(bundle, 'README.md'), guide.replaceAll('safedrop-offline-prepared', defaultProject));

    const disconnected = await verifyDeployment({ output, bundle, images, runId, stale: true, probeOfflineImages });
    stages.disconnected = true;
    connected = await verifyDeployment({ output, bundle, images, runId, stale: false, probeOfflineImages, keepRunning });
    assert.ok(connected.signatures.version > disconnected.signatures.version, 'FreshClam must replace the expired seed');
    assert.ok(Date.parse(connected.signatures.builtAt) > Date.parse(disconnected.signatures.builtAt));
    stages.updated = true;
    stages.transfer = true;
    assert.equal(await hashFile(imageTar), imageTarSha256, 'Saved image archive changed during verification');
    const signatures = { seed: disconnected.signatures, updated: connected.signatures };

    writeJson(join(bundle, 'image-manifest.json'), {
      created: new Date().toISOString(), platform: 'linux/amd64', defaultProject, appVersion, caddy: '2.11.9',
      signatures, runtime, images, imageTarSha256, sourceRevision: revision, sourceModified: modified,
      source: 'https://github.com/logic-xx/safedrop', historicalEvidence: { ci, retained },
      gatewayBuild: gateway, verification: { disconnected, connected },
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
    writeJson(join(output, 'verification.json'), { ok: true, imageIds: images, stages, disconnected, connected, signatures, archiveSha256: sha256 });
    console.log(`Verified distribution: ${archive}`);
    if (keepRunning) console.log(`Review instance: ${connected.project} · ${connected.origin} · CA: ${join(output, 'connected-ca.crt')}`);
  } catch (error) {
    writeJson(join(output, 'verification-failed.json'), { ok: false, stages, error: error.message });
    if (connected && keepRunning) {
      try {
        docker(['compose', '-p', connected.project, 'down'], { cwd: bundle, env: deploymentEnv(connected.port), show: true });
      } catch (cleanupError) { console.error(cleanupError.message); }
    }
    throw error;
  }
}

try {
  const { values } = parseArgs({ options: {
    'check-only': { type: 'boolean' },
    'keep-review-running': { type: 'boolean' },
    context: { type: 'string' },
  } });
  dockerContext = values.context;
  if (values['check-only']) {
    const cwd = join(root, 'deploy', 'offline');
    const env = deploymentEnv(18446);
    for (const disconnected of [false, true]) {
      const compose = ['compose', '-f', 'compose.yaml', ...(disconnected ? ['-f', noSignatureNetwork] : [])];
      const model = docker([...compose, 'config', '--format', 'json'], { cwd, env });
      validateCompose(JSON.parse(model), 18446, disconnected);
    }
    console.log('Offline Compose configuration checked without contacting the engine.');
  } else {
    await makeBundle(values['keep-review-running']);
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
