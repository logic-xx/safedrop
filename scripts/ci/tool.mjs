import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve, join } from 'node:path';
const pins = JSON.parse(await readFile(new URL('./tools.json', import.meta.url), 'utf8'));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export async function tool(name) {
  const pin = pins[name], asset = pin?.[`${process.platform}-${process.arch}`];
  if (!asset) throw Error('UNSUPPORTED_CI_TOOL_OR_PLATFORM');
  const root = resolve('.local/ci-tools', `${name}-${pin.version}-${process.platform}-${process.arch}`);
  const executable = join(root, name + (process.platform === 'win32' ? '.exe' : ''));
  try {
    const installed = JSON.parse(await readFile(join(root, 'installed.json'), 'utf8'));
    if (installed.archive === asset.sha256 && installed.binary === hash(await readFile(executable))) return executable;
  } catch { /* Download a missing or changed local tool again. */ }
  await mkdir(root, { recursive: true });
  const url = `https://github.com/${pin.repository}/releases/download/v${pin.version}/${asset.asset}`;
  const response = await fetch(url, { signal: AbortSignal.timeout(120000) });
  if (!response.ok) throw Error(`CI_TOOL_DOWNLOAD_FAILED:${name}:${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (hash(bytes) !== asset.sha256) throw Error(`CI_TOOL_CHECKSUM_MISMATCH:${name}`);
  const archive = join(root, asset.asset); await writeFile(archive, bytes);
  const extracted = spawnSync('tar', ['-xf', archive, '-C', root, name + (process.platform === 'win32' ? '.exe' : '')], { encoding: 'utf8', windowsHide: true });
  if (extracted.error || extracted.status !== 0) throw Error(`CI_TOOL_EXTRACT_FAILED:${name}`);
  await chmod(executable, 0o700);
  await writeFile(join(root, 'installed.json'), JSON.stringify({ archive: asset.sha256, binary: hash(await readFile(executable)) }));
  return executable;
}
