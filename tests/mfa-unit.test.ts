import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32, unbase32, hotp, totp } from '../server/mfa.ts';

test('HOTP and TOTP match RFC 4226 and RFC 6238 public SHA-1 test vectors', () => {
  const secret = Buffer.from('12345678901234567890');
  assert.equal(base32(secret), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'); assert.deepEqual(unbase32(base32(secret)), secret);
  [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489].forEach((value, counter) => assert.equal(hotp(secret, counter), String(value).padStart(6, '0')));
  for (const [time, code] of [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'], [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']] as const) assert.equal(totp(secret, time * 1000, 8), code);
});
