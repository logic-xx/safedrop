// Runs only in the disposable scanner container used to prepare a distribution.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFile, mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';

const db = '/data/db';
const officialConfig = '/scanner/freshclam.conf';
const updateConfig = '/tmp/safedrop-offline-freshclam.conf';
const selected = /^(main|daily|bytecode)\.(cvd|cld)$/;
await mkdir(db, { recursive: true, mode: 0o700 });
for (const name of (await readdir('/seed')).filter(name => selected.test(name))) {
  await copyFile(`/seed/${name}`, `${db}/${name}`);
}

const config = await readFile(officialConfig, 'utf8');
assert.match(config, /^TestDatabases yes$/m);
await writeFile(updateConfig, config.replace(/^NotifyClamd .*\n/m, ''), { mode: 0o600 });
execFileSync('/usr/local/bin/freshclam', ['--foreground', '--stdout', `--config-file=${updateConfig}`], {
  stdio: 'inherit', timeout: 300000,
});

const output = '/tmp/verified-databases';
await mkdir(output);
const names = await readdir(db);
for (const kind of ['main', 'daily', 'bytecode']) {
  const matches = [`${kind}.cvd`, `${kind}.cld`].filter(name => names.includes(name));
  assert.equal(matches.length, 1, `Missing or ambiguous official ${kind} database`);
  const [name] = matches;
  const info = await stat(`${db}/${name}`);
  assert.ok(info.isFile() && info.size > 512, `Invalid ${kind} database file`);
  await copyFile(`${db}/${name}`, `${output}/${name}`);
}
