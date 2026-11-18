import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';

export function gatewayPolicy(text) {
  assert.equal(typeof text, 'string', 'INVALID_GATEWAY_BUILD_INFO');
  const modules = new Map();
  let go;
  for (const line of text.trim().split(/\r?\n/)) {
    const fields = line.trim().split(/\s+/);
    if (fields[0] === 'go') { assert.equal(go, undefined, 'DUPLICATE_GO_VERSION'); go = fields[1]; }
    if (fields[0] === 'dep') {
      assert.ok(!modules.has(fields[1]), 'DUPLICATE_GATEWAY_MODULE');
      modules.set(fields[1], fields[2]);
    }
    assert.notEqual(fields[0], '=>', 'GATEWAY_MODULE_REPLACEMENT_DENIED');
  }
  const expected = {
    'github.com/caddyserver/caddy/v2': 'v2.11.9',
    'github.com/smallstep/certificates': 'v0.30.3-0.20261105213751-6d5a251fbe01',
    'go.step.sm/crypto': 'v0.92.0',
    'github.com/go-jose/go-jose/v4': 'v4.1.9',
    'golang.org/x/net': 'v0.62.0',
  };
  assert.equal(go, 'go1.27.4', 'UNEXPECTED_GATEWAY_GO_VERSION');
  for (const [name, version] of Object.entries(expected)) assert.equal(modules.get(name), version, 'UNEXPECTED_GATEWAY_MODULE:' + name);
  assert.ok(!modules.has('github.com/go-jose/go-jose/v3') && !modules.has('gopkg.in/square/go-jose.v2'), 'OLD_GO_JOSE_DENIED');
  return { ok: true, go, modules: expected, oldGoJosePresent: false };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let text = '';
  for await (const chunk of process.stdin) text += chunk;
  console.log(JSON.stringify(gatewayPolicy(text)));
}
