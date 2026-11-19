import { readFile, writeFile, mkdir, mkdtemp, copyFile, rm, unlink, lstat, readdir } from 'node:fs/promises';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve, join, dirname, sep } from 'node:path';
import { tool } from './tool.mjs';
import { auditPolicy, safeSourcePath, imagePolicy, secureNode24, scanRuntimePolicy } from './policy.mjs';
import { gatewayPolicy } from '../gateway-policy.mjs';
import { scannerAssessment } from './scanner-assessment.mjs';
import { VENDOR } from '../../deploy/scanner/vendor-artifact.mjs';
const [mode, reference, imageSource = 'docker'] = process.argv.slice(2);
const git = args => execFileSync('git', args, { encoding: 'utf8', windowsHide: true });
const json = async path => JSON.parse(await readFile(path, 'utf8'));
const reportRoot = resolve('reports/ci'), privateRoot = resolve('.local/ci-raw');
await mkdir(reportRoot, { recursive: true }); await mkdir(privateRoot, { recursive: true });
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const names = [...new Set(git(['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean))].sort();
const metadata = { created: new Date().toISOString(), commit: git(['rev-parse','HEAD']).trim(), dirty: Boolean(git(['status','--porcelain'])), node: process.version, platform: `${process.platform}/${process.arch}`, runId: process.env.GITHUB_RUN_ID ?? null, runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? null };
const save = async (name, result) => writeFile(join(reportRoot, name + '.json'), JSON.stringify({ ...metadata, ...result }, null, 2) + '\n');
const run = (executable, args, timeout = 600000, env = process.env) => spawnSync(executable, args, { encoding: 'utf8', windowsHide: true, timeout, env, maxBuffer: 16 * 1024 ** 2 });
const resultName = mode === 'image' && reference ? 'image-' + digest(reference).slice(0,12) : mode;
const modes = ['audit','secrets','scanner-test','workflow','image','artifacts','runtime-report'];
const failureName = 'failure-' + (modes.includes(mode) ? resultName : 'usage');
try {
  if (modes.includes(mode)) {
    for (const name of [resultName,failureName,...(mode === 'audit' ? ['npm-all','npm-production'] : [])]) await unlink(join(reportRoot,name+'.json')).catch(e => { if(e.code!=='ENOENT') throw e; });
  }
  if (mode === 'audit') {
    if (!process.env.npm_execpath) throw Error('RUN_WITH_NPM_RUN_CI_AUDIT');
    const reports = [];
    for (const production of [false,true]) {
      const result = run(process.execPath, [process.env.npm_execpath,'audit','--json','--audit-level=high','--cache',resolve('.npm-cache'),...(production ? ['--omit=dev'] : [])]);
      if (result.error || ![0,1].includes(result.status)) throw Error('NPM_AUDIT_EXECUTION_FAILED');
      const report = JSON.parse(result.stdout); reports.push(report);
      await writeFile(join(reportRoot, production ? 'npm-production.json' : 'npm-all.json'), JSON.stringify(report, null, 2));
    }
    const result = auditPolicy(...reports, await json('package-lock.json'), await json(new URL('./exceptions.json', import.meta.url)));
    await save('audit', result); console.log(`Dependency audit: ${result.status}; accepted ${result.accepted.length}; blocked ${result.blocked.length}; production high/critical ${result.production.high + result.production.critical}`);
    if (!result.ok) process.exitCode = 1;
  } else if (mode === 'secrets') {
    if (git(['rev-parse','--is-shallow-repository']).trim() !== 'false') throw Error('FULL_GIT_HISTORY_REQUIRED');
    const unsafe = names.filter(path => !safeSourcePath(path));
    if (unsafe.length) throw Error('PRIVATE_OR_GENERATED_SOURCE_PATH:' + unsafe.join(','));
    const executable = await tool('gitleaks'), snapshot = await mkdtemp(resolve('.local/ci-source-'));
    const results = []; let tree = '';
    try {
      for (const path of names) {
        const destination = join(snapshot, path); await mkdir(dirname(destination), { recursive: true });
        try {
          const stat = await lstat(path); if (!stat.isFile() || stat.isSymbolicLink()) throw Error('NON_REGULAR_SOURCE_FILE:' + path);
          await copyFile(path, destination); tree += path + ':' + digest(await readFile(path)) + '\n';
        }
        catch (e) { if (e.code !== 'ENOENT') throw e; }
      }
      for (const history of [false,true]) {
        const reportPath = join(privateRoot, history ? 'gitleaks-history.json' : 'gitleaks-current.json');
        await unlink(reportPath).catch(e => { if (e.code !== 'ENOENT') throw e; });
        const result = run(executable, [history ? 'git' : 'dir','--redact=100','--no-banner','--ignore-gitleaks-allow','--report-format','json','--report-path',reportPath,'--exit-code','1',...(history ? ['--log-opts=--all'] : []),history ? '.' : snapshot]);
        if (result.error || ![0,1].includes(result.status)) throw Error('GITLEAKS_EXECUTION_FAILED');
        const raw = await json(reportPath); if (!Array.isArray(raw)) throw Error('INVALID_GITLEAKS_REPORT');
        const findings = raw.map(r => ({ rule: r.RuleID, file: r.File.replace(snapshot + sep,''), startLine: r.StartLine, commit: r.Commit || null, fingerprint: r.Fingerprint }));
        results.push({ scope: history ? 'all reachable git history' : 'current non-ignored source files', ok: result.status === 0 && findings.length === 0, findings });
      }
      const ok = results.every(r => r.ok); await save('secrets', { ok, version: (await json(new URL('./tools.json',import.meta.url))).gitleaks.version, sourceSha256: digest(tree), results });
      console.log(`Secret scan: ${ok ? 'passed' : 'failed'}; current and full reachable history checked; findings ${results.reduce((n,r) => n+r.findings.length,0)}`); if (!ok) process.exitCode = 1;
    } finally {
      if (!snapshot.startsWith(resolve('.local') + sep) || !snapshot.startsWith(resolve('.local/ci-source-'))) throw Error('UNSAFE_TEMP_CLEANUP');
      await rm(snapshot, { recursive: true, force: true });
    }
  } else if (mode === 'runtime-report') {
    const report = await json('reports/container-latest.json');
    const scanning = scanRuntimePolicy(report);
    if(report.scannerBuildInput?.verified!==true||report.scannerBuildInput?.localContextRequired!==true||report.scannerBuildInput?.sha256!==VENDOR.sha256||report.scannerBuildInput?.bytes!==VENDOR.bytes)throw Error('VERIFIED_LOCAL_VENDOR_BUILD_INPUT_REQUIRED');
    if(report.ok !== true || report.version !== 10 || report.gateway?.ok !== true || report.mfa?.ok !== true || report.stableAccounts !== true || report.stableCA !== true || report.backup?.verified !== true || report.backup?.isolatedRestore !== true || report.backup?.independentCheckpoint !== true || report.backup?.encrypted !== true || report.backupEncryption?.ok !== true || report.backupEncryption?.stableKeyRing !== true || report.backupEncryption?.rotation !== true || report.backupEncryption?.keyReload !== true || report.backupEncryption?.legacyCompatibility !== true || report.backupEncryption?.authenticationFailuresRejected !== true || report.before?.ok !== true || report.after?.ok !== true || report.profile?.ok !== true || report.scannerProvenance?.ok !== true || !secureNode24(report.mfa?.node)) throw Error('RUNTIME_CONTAINER_VERIFICATION_REQUIRED');
    gatewayPolicy('go\t'+report.gateway.go+'\n'+Object.entries(report.gateway.modules??{}).map(([name,version])=>'dep\t'+name+'\t'+version).join('\n'));
    if(report.gateway.oldGoJosePresent!==false) throw Error('GATEWAY_LEGACY_DEPENDENCY_PRESENT');
    await save('runtime-report',{ok:true,scope:process.env.GITHUB_ACTIONS === 'true' ? 'isolated CI containers; no user data volumes' : 'local containers; see original report for retained data scope',containerReportCreated:report.created,node:report.mfa.node,stableAccounts:true,stableCA:true,backup:report.backup,mfa:report.mfa,gateway:report.gateway,backupEncryption:report.backupEncryption,scanning,scannerProvenance:report.scannerProvenance,scannerBuildInput:report.scannerBuildInput,upgradeIdentity:report.upgradeIdentity,profileChecks:report.profile.checks.length});
    console.log('Isolated runtime, strict HTTPS/WSS, persistent data and backup checks: passed');
  } else if (mode === 'artifacts') {
    const executable = await tool('gitleaks'), snapshot = await mkdtemp(resolve('.local/ci-artifact-'));
    const paths = ['reports/latest.json','reports/latest.html',...(await readdir(reportRoot)).filter(n=>n.endsWith('.json')).map(n=>'reports/ci/'+n)];
    let files = 0;
    try {
      for(const path of paths) {
        try {
          const stat=await lstat(path); if(!stat.isFile() || stat.isSymbolicLink()) throw Error('NON_REGULAR_ARTIFACT');
          const destination=join(snapshot,path); await mkdir(dirname(destination),{recursive:true}); await copyFile(path,destination); files++;
        } catch(e) { if(e.code!=='ENOENT') throw e; }
      }
      const report=join(privateRoot,'gitleaks-artifacts.json'); await unlink(report).catch(e=>{if(e.code!=='ENOENT')throw e;});
      const result=run(executable,['dir','--redact=100','--no-banner','--ignore-gitleaks-allow','--report-format','json','--report-path',report,'--exit-code','1',snapshot]);
      if(result.error || ![0,1].includes(result.status)) throw Error('ARTIFACT_SCANNER_FAILED');
      const findings=await json(report); if(!Array.isArray(findings)) throw Error('INVALID_ARTIFACT_SCAN_REPORT');
      if(result.status!==0 || findings.length!==0) throw Error('ARTIFACT_CREDENTIAL_DETECTED:UPLOAD_BLOCKED');
      await save('artifacts',{ok:true,files,findings:0,scope:'only the explicit public report upload paths'}); console.log(`Artifact credential check: passed; ${files} report files`);
    } finally {
      if(!snapshot.startsWith(resolve('.local')+sep) || !snapshot.startsWith(resolve('.local/ci-artifact-'))) throw Error('UNSAFE_TEMP_CLEANUP');
      await rm(snapshot,{recursive:true,force:true});
    }
  } else if (mode === 'scanner-test') {
    const executable = await tool('gitleaks');
    const result = run(process.execPath, ['--test','tests/ci-policy.test.mjs','tests/scanner-assessment.test.mjs','tests/scanner-vendor.test.mjs'], 60000, { ...process.env, CI_GITLEAKS: executable });
    const ok = !result.error && result.status === 0; await save('scanner-test', { ok, scope: 'policy negatives and real synthetic-token detection/redaction' });
    if (!ok) throw Error('CI_SCANNER_SELF_TEST_FAILED'); console.log('Policy and real scanner self-test: passed');
  } else if (mode === 'workflow') {
    const executable = await tool('actionlint');
    const result = run(executable, ['-shellcheck=','-pyflakes=','.github/workflows/security.yml']);
    const ok = !result.error && result.status === 0; await save('workflow', { ok, diagnostics: (result.stdout + result.stderr).trim() });
    if (!ok) throw Error('WORKFLOW_LINT_FAILED'); console.log('Workflow syntax and expressions: passed');
  } else if (mode === 'image') {
    if (!reference || !['docker','remote'].includes(imageSource)) throw Error('IMAGE_REFERENCE_AND_SOURCE_REQUIRED');
    const executable = await tool('trivy'), path = join(privateRoot,'trivy-' + digest(reference).slice(0,12) + '.json');
    await unlink(path).catch(e => { if (e.code !== 'ENOENT') throw e; });
    // Only public registries are used. Do not read the operator's Docker login
    // configuration or invoke their desktop credential helper for public DBs.
    const registry = resolve('.local/ci-public-registry'), temporary = resolve('.local/ci-temp');
    await mkdir(registry,{recursive:true}); await mkdir(temporary,{recursive:true}); await writeFile(join(registry,'config.json'),'{"auths":{}}');
    // Go's file URL handling cannot round-trip the sandbox's # in its default
    // temporary path on Windows. Keep only this child process's files here.
    const result = run(executable, ['image','--image-src',imageSource,'--scanners','vuln','--list-all-pkgs','--no-progress','--format','json','--output',path,'--cache-dir',resolve('.local/trivy-cache'),'--timeout','10m',reference],660000,{...process.env,DOCKER_CONFIG:registry,TEMP:temporary,TMP:temporary,TMPDIR:temporary});
    if (result.error || result.status !== 0) {
      await writeFile(join(privateRoot,'trivy-error.txt'), result.stderr ?? String(result.error));
      throw Error('TRIVY_SCAN_FAILED:SEE_PRIVATE_LOCAL_DIAGNOSTICS');
    }
    const raw = await json(path);let policy = imagePolicy(raw);
    if(reference==='safedrop-scanner:verify'){
      if(imageSource!=='docker')throw Error('ACTUAL_SCANNER_IMAGE_REQUIRED');
      const runtime=await json('reports/container-latest.json');scanRuntimePolicy(runtime);
      policy=scannerAssessment(raw,policy,runtime.scannerProvenance,await json('deploy/scanner/vendor-manifest.json'),await json('deploy/scanner/vendor-fixed.openvex.json'));
    }
    const database = await json(resolve('.local/trivy-cache/db/metadata.json')).catch(()=>null);
    await save(resultName, { ...policy, reference, imageSource, scope: imageSource === 'docker' ? 'local built image' : 'remote registry image; not the final application image', database, version: (await json(new URL('./tools.json',import.meta.url))).trivy.version });
    console.log(`Image scan: ${policy.status}; raw high/critical ${policy.rawBlocked??policy.blocked}; vendor-fixed ${policy.fixedByVendor?.length??0}; blocking ${policy.blocked}; report reports/ci/${resultName}.json`); if (!policy.ok) process.exitCode = 1;
  } else throw Error('Usage: check.mjs <audit|secrets|scanner-test|workflow|image|artifacts|runtime-report> [image-reference] [docker|remote]');
} catch (e) {
  const error = e instanceof Error ? e.message : 'CI_CHECK_FAILED';
  await save(failureName, { ok:false, error, ...(mode === 'image' ? { reference, imageSource } : {}) });
  console.error(error); process.exitCode = 1;
}
