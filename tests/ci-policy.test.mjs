import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { join, resolve, sep } from 'node:path';
import { auditPolicy, safeSourcePath, imagePolicy, secureNode24 } from '../scripts/ci/policy.mjs';
test('CI runtime evidence requires a security-patched supported Node 24 version',()=>{
  for(const version of ['v24.14.0','v24.22.0','v24.22.2','v25.0.0','v26.0.0','v24.22.3-rc.1','']) assert.equal(secureNode24(version),false,version);
  for(const version of ['v24.22.3','24.22.4','v24.23.0']) assert.equal(secureNode24(version),true,version);
});
const empty = () => ({auditReportVersion:2,metadata:{vulnerabilities:{info:0,low:0,moderate:0,high:0,critical:0,total:0}},vulnerabilities:{}});
const advisory='https://example.invalid/advisory', now=Date.parse('2026-11-18T00:00:00Z');
function fixture() {
  const all=empty(); all.metadata.vulnerabilities.high=all.metadata.vulnerabilities.total=1;
  all.vulnerabilities.example={via:[{name:'example',url:advisory,severity:'high'}],nodes:['node_modules/example']};
  return {all,production:empty(),lock:{packages:{'node_modules/example':{dev:true,version:'1.0.0'}}},exceptions:[{ecosystem:'npm',package:'example',versions:['1.0.0'],advisory,severity:'high',devOnly:true,expires:'2026-11-19T00:00:00Z',reason:'Temporary, reviewed development-only exposure pending upstream correction.'}]};
}
test('CI audit exception is exact, temporary and limited to development dependencies',()=>{
  const f=fixture(), check=()=>auditPolicy(f.all,f.production,f.lock,f.exceptions,now);
  assert.equal(check().status,'accepted-risk');
  f.lock.packages['node_modules/example'].dev=false; assert.equal(check().ok,false);
  f.lock.packages['node_modules/example'].dev=true; f.lock.packages['node_modules/example'].version='1.0.1'; assert.equal(check().ok,false);
  f.lock.packages['node_modules/example'].version='1.0.0'; f.exceptions[0].advisory+='-other'; assert.equal(check().ok,false);
});
test('CI audit blocks expired exceptions, new advisories and production findings',()=>{
  const f=fixture(); assert.equal(auditPolicy(f.all,f.production,f.lock,f.exceptions,now+86400000).ok,false);
  f.all.vulnerabilities.example.via.push({name:'example',url:advisory+'-new',severity:'critical'});
  assert.equal(auditPolicy(f.all,f.production,f.lock,f.exceptions,now).ok,false);
  f.all.vulnerabilities.example.via.pop(); f.production.metadata.vulnerabilities.high=f.production.metadata.vulnerabilities.total=1;
  assert.equal(auditPolicy(f.all,f.production,f.lock,f.exceptions,now).ok,false);
});
test('CI audit never accepts a missing or failed scanner response',()=>{
  const f=fixture(); assert.throws(()=>auditPolicy({},f.production,f.lock,f.exceptions,now));
  f.production.error={code:'ENETDOWN'}; assert.throws(()=>auditPolicy(f.all,f.production,f.lock,f.exceptions,now));
  f.production=empty(); f.all.vulnerabilities={}; assert.throws(()=>auditPolicy(f.all,f.production,f.lock,f.exceptions,now));
});
test('CI source policy rejects private/generated files even if added to Git',()=>{
  for(const path of ['.local/accounts.json','tmp/fixture.ts','reports/check.json','dist/index.js','node_modules/module.js','.env','.env.production','keys/admin.mfa-key','keys/tls.key','ca.pem','data/store.sqlite','accounts.json','store.backups/manifest.json','backups/data.bin','notes/private/note.md','qa-pending-seed.json']) assert.equal(safeSourcePath(path),false,path);
  for(const path of ['.env.example','server/mfa.ts','tests/mfa-suite.ts','.github/workflows/security.yml']) assert.equal(safeSourcePath(path),true,path);
});
test('CI image policy blocks unfixed high severity findings and rejects invalid output',()=>{
  const report={SchemaVersion:2,ArtifactType:'container_image',ArtifactName:'safedrop:test',Metadata:{ImageID:'sha256:'+'a'.repeat(64),OS:{Family:'debian'}},Results:[{Target:'runtime',Vulnerabilities:[{VulnerabilityID:'CVE-TEST',PkgName:'example',InstalledVersion:'1',Severity:'HIGH'}]}]};
  assert.equal(imagePolicy(report).ok,false); assert.equal(imagePolicy(report).findings[0].fixed,null);
  report.Results[0].Vulnerabilities[0].Severity='LOW'; assert.equal(imagePolicy(report).ok,true);
  assert.throws(()=>imagePolicy({})); assert.throws(()=>imagePolicy({...report,Results:null})); assert.throws(()=>imagePolicy({...report,Results:[]}));
  assert.throws(()=>imagePolicy({...report,Metadata:{OS:{Family:'debian'}}}));
  report.Results[0].Vulnerabilities[0].Severity=''; assert.throws(()=>imagePolicy(report));
});
test('Real credential scanner rejects a synthetic token and redacts its report',{skip:!process.env.CI_GITLEAKS},()=>{
  // The network-free test uses the already checksum-verified CLI; regular npm test
  // can run without installing scanners. CI runs the positive probe after setup.
  const binary=process.env.CI_GITLEAKS;
  mkdirSync('tmp',{recursive:true}); const root=mkdtempSync(resolve('tmp/ci-scanner-'));
  try {
    const token='ghp_'+randomBytes(27).toString('base64url').replace(/[-_]/g,'A');
    writeFileSync(join(root,'credential.txt'),'github_token = "'+token+'"\n');
    const report=join(root,'result.json');
    const r=spawnSync(binary,['dir','--no-banner','--redact=100','--report-format','json','--report-path',report,root],{encoding:'utf8',windowsHide:true,timeout:30000});
    assert.equal(r.status,1); const text=readFileSync(report,'utf8'); assert.equal(text.includes(token),false);
    assert.ok(JSON.parse(text).some(x=>x.RuleID==='github-pat'));
  } finally {
    assert.ok(root.startsWith(resolve('tmp')+sep)); rmSync(root,{recursive:true,force:true});
  }
});
