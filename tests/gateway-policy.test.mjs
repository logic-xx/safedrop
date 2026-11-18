import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gatewayPolicy } from '../scripts/gateway-policy.mjs';

const good = `go\tgo1.27.4
dep\tgithub.com/caddyserver/caddy/v2\tv2.11.9
dep\tgithub.com/smallstep/certificates\tv0.30.3-0.20261105213751-6d5a251fbe01
dep\tgo.step.sm/crypto\tv0.92.0
dep\tgithub.com/go-jose/go-jose/v4\tv4.1.9
dep\tgolang.org/x/net\tv0.62.0
`;

test('Gateway runtime proof rejects missing, outdated or replaced dependencies', () => {
  assert.equal(gatewayPolicy(good).ok, true);
  for (const text of ['', good.replace('go1.27.4', 'go1.27.3'), good.replace('v0.62.0', 'v0.60.0'), good.replace('v4.1.9', 'v4.1.5'), good.replace(/dep\tgo.step.sm\/crypto[^\n]+\n/, ''), good + '=>\t./modified-source\t(devel)\n']) assert.throws(() => gatewayPolicy(text));
});

test('Gateway runtime proof rejects old go-jose even alongside patched v4', () => {
  for (const name of ['github.com/go-jose/go-jose/v3', 'gopkg.in/square/go-jose.v2']) assert.throws(() => gatewayPolicy(good + `dep\t${name}\tv3.0.5\n`));
  assert.throws(() => gatewayPolicy(good + 'dep\tgolang.org/x/net\tv0.60.0\n'));
});
