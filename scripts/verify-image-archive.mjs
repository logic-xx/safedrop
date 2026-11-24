import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { open } from 'node:fs/promises';

const sha256 = /^sha256:[a-f0-9]{64}$/;
const block = 512;
const maxJsonBytes = 8 * 1024 * 1024;
const familiar = tag => tag.replace(/^docker\.io\/library\//, '');

function field(bytes, start, end) {
  return bytes.subarray(start, end).toString('utf8').split('\0', 1)[0];
}

async function indexTar(file) {
  const size = (await file.stat()).size;
  const entries = new Map();
  const buffer = Buffer.alloc(block);
  for (let offset = 0; offset + block <= size;) {
    assert.equal((await file.read(buffer, 0, block, offset)).bytesRead, block);
    if (buffer.every(byte => byte === 0)) return entries;
    const length = field(buffer, 124, 136).trim();
    assert.match(length, /^[0-7]+$/, 'Expected a Docker tar entry with an octal size');
    const bytes = parseInt(length, 8);
    const start = offset + block;
    offset = start + Math.ceil(bytes / block) * block;
    assert.ok(Number.isSafeInteger(offset) && offset <= size, 'Truncated image archive');
    const type = field(buffer, 156, 157);
    if (type && type !== '0') continue;
    const name = [field(buffer, 345, 500), field(buffer, 0, 100)].filter(Boolean).join('/');
    assert.ok(name && !entries.has(name), `Duplicate or empty image archive entry: ${name}`);
    entries.set(name, { start, bytes });
  }
  throw Error('Image archive is missing its end marker');
}

export async function verifySavedImages(path, images) {
  const file = await open(path, 'r');
  try {
    const entries = await indexTar(file);
    const hashes = new Map();
    function entry(name) {
      const value = entries.get(name);
      assert.ok(value, `Missing image archive entry: ${name}`);
      return value;
    }
    async function digest(name) {
      if (hashes.has(name)) return hashes.get(name);
      const { start, bytes } = entry(name);
      const hash = createHash('sha256');
      if (bytes) for await (const part of createReadStream(path, { start, end: start + bytes - 1 })) hash.update(part);
      const value = 'sha256:' + hash.digest('hex');
      hashes.set(name, value);
      return value;
    }
    async function json(name) {
      const { start, bytes } = entry(name);
      assert.ok(bytes > 0 && bytes <= maxJsonBytes, `Invalid metadata size: ${name}`);
      const content = Buffer.alloc(bytes);
      assert.equal((await file.read(content, 0, bytes, start)).bytesRead, bytes);
      return JSON.parse(content.toString('utf8'));
    }
    async function blob(descriptor) {
      assert.match(descriptor.digest, sha256);
      const name = 'blobs/sha256/' + descriptor.digest.slice(7);
      assert.equal(entry(name).bytes, descriptor.size, `OCI blob size mismatch: ${name}`);
      assert.equal(await digest(name), descriptor.digest, `OCI blob digest mismatch: ${name}`);
      return name;
    }
    async function manifests(descriptor, depth = 0) {
      assert.ok(depth <= 5, 'Unexpected OCI index nesting');
      const manifest = await json(await blob(descriptor));
      assert.equal(manifest.schemaVersion, 2);
      if (Array.isArray(manifest.manifests)) {
        const leaves = [];
        for (const item of manifest.manifests) leaves.push(...await manifests(item, depth + 1));
        return leaves;
      }
      const config = await blob(manifest.config);
      const layers = [];
      for (const layer of manifest.layers) layers.push(await blob(layer));
      return [{ descriptor, config, layers }];
    }

    const manifest = await json('manifest.json');
    assert.equal(manifest.length, images.length);
    const roots = [];
    if (entries.has('index.json')) {
      const index = await json('index.json');
      assert.equal(index.schemaVersion, 2);
      assert.equal(index.manifests.length, images.length);
      for (const descriptor of index.manifests) {
        roots.push({ descriptor, leaves: await manifests(descriptor) });
      }
    }
    const results = [];
    for (const image of images) {
      const rows = manifest.filter(row => row.RepoTags?.some(tag => familiar(tag) === image.tag));
      assert.equal(rows.length, 1, `Expected one saved image for ${image.tag}`);
      const [row] = rows;
      assert.equal(row.RepoTags.length, 1);
      const configDigest = await digest(row.Config);
      const config = await json(row.Config);
      assert.equal(`${config.os}/${config.architecture}`, 'linux/amd64');
      assert.ok(row.Layers.length > 0 && row.Layers.length === config.rootfs.diff_ids.length);
      if (!roots.length) {
        assert.equal(configDigest, image.id, `Classic image ID mismatch: ${image.tag}`);
        for (const [i, layer] of row.Layers.entries()) {
          assert.equal(await digest(layer), config.rootfs.diff_ids[i], `Layer digest mismatch: ${layer}`);
        }
        results.push({ configDigest });
        continue;
      }
      const expected = roots.filter(root => {
        const tag = root.descriptor.annotations?.['io.containerd.image.name'];
        return (!tag || familiar(tag) === image.tag) && root.leaves.some(leaf => leaf.config === row.Config);
      });
      assert.equal(expected.length, 1, `Expected a unique OCI image for ${image.tag}`);
      const [{ descriptor, leaves }] = expected;
      const [leaf, ...extra] = leaves.filter(item => item.config === row.Config);
      assert.equal(extra.length, 0);
      assert.deepEqual(leaf.layers, row.Layers, `OCI and Docker layer order differs for ${image.tag}`);
      assert.ok(image.id === descriptor.digest || image.id === configDigest, `Saved image ID mismatch: ${image.tag}`);
      results.push({ targetDigest: descriptor.digest, manifestDigest: leaf.descriptor.digest, configDigest });
    }
    return results;
  } finally {
    await file.close();
  }
}
