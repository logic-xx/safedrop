import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

test('Windows PowerShell forwards Node eval source as one native argument', { skip: process.platform !== 'win32' }, () => {
  // Use the actual Docker wrapper with Node as an isolated argument receiver.
  // This never contacts the engine or changes the user's command aliases.
  const script = String.raw`
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) 'scripts/verify-container.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'PowerShell parse failure' }
$definition = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-DockerChecked' }, $true)
. ([scriptblock]::Create($definition.Extent.Text))
Set-Alias -Name docker -Value (Get-Command node).Source
$source = @'
const marker = 'spaces, quotes and a dollar $x';
console.log(JSON.stringify([marker, ...process.argv.slice(1)]));
'@
$nativeArgs = @('--input-type=module', '--eval', $source, '--', 'two words', 'sd1_disposable')
Invoke-DockerChecked -DockerArgs $nativeArgs
`;
  const result = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  assert.deepEqual(JSON.parse(result.trim()), ['spaces, quotes and a dollar $x', 'two words', 'sd1_disposable']);
});
