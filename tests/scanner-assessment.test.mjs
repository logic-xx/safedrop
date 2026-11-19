import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {imagePolicy} from '../scripts/ci/policy.mjs';
import {scannerAssessment} from '../scripts/ci/scanner-assessment.mjs';
const manifest=JSON.parse(readFileSync(new URL('../deploy/scanner/vendor-manifest.json',import.meta.url))),vex=JSON.parse(readFileSync(new URL('../deploy/scanner/vendor-fixed.openvex.json',import.meta.url)));
const clone=x=>structuredClone(x);
function fixture(){
 const imageId='sha256:'+'a'.repeat(64),raw={SchemaVersion:2,ArtifactType:'container_image',ArtifactName:'safedrop-scanner:verify',Metadata:{ImageID:imageId,OS:{Family:'debian',Name:'13.7'}},Results:[{Target:'scanner (debian 13.7)',Class:'os-pkgs',Type:'debian',Packages:[{Name:'clamav',Version:'1.5.5',Release:'1'}],Vulnerabilities:vex.statements.map(s=>({VulnerabilityID:s.vulnerability.name,PkgName:'clamav',InstalledVersion:'1.5.5-1',Severity:'HIGH',DataSource:{ID:'debian'}}))}]};
 const proof={ok:true,imageId,platform:'linux/x64',engine:'ClamAV 1.5.5/28187/ctime',archiveSha256:manifest.archive.sha256,manifestSha256:vex.vendorBinding.manifestSha256,files:clone(manifest.files),symlinks:clone(manifest.symlinks)};
 return {raw,proof,check(){return scannerAssessment(raw,imagePolicy(raw),proof,manifest,vex);}};
}
test('Vendor-fixed assessment retains all seven raw findings and leaves generic image policy strict',()=>{
 const f=fixture(),before=clone(f.raw);assert.equal(imagePolicy(f.raw).blocked,7);
 const r=f.check();assert.equal(r.ok,true);assert.equal(r.rawBlocked,7);assert.equal(r.fixedByVendor.length,7);assert.equal(r.findings.length,7);assert.equal(r.blocked,0);assert.equal(r.status,'passed-with-vendor-fixes');assert.deepEqual(f.raw,before);
});
test('Unknown high/critical findings and another package, source, version or OS remain blocking',()=>{
 for(const patch of [{VulnerabilityID:'CVE-2026-999999'},{PkgName:'another-library'},{InstalledVersion:'1.5.4-1'},{DataSource:{ID:'nvd'}},{FixedVersion:'1.5.6-1'}]){
  const f=fixture();Object.assign(f.raw.Results[0].Vulnerabilities[0],patch);assert.equal(f.check().ok,false,JSON.stringify(patch));assert.equal(f.check().blocked,1);
 }
 const f=fixture();f.raw.Results.push({Target:'unrelated result',Type:'alpine',Class:'os-pkgs',Vulnerabilities:[{...f.raw.Results[0].Vulnerabilities[0],Severity:'CRITICAL'}]});assert.equal(f.check().blocked,1);
 const duplicate=fixture();duplicate.raw.Results[0].Vulnerabilities.push({...duplicate.raw.Results[0].Vulnerabilities[0],DataSource:{ID:'nvd'}});assert.equal(duplicate.check().blocked,1);
});
test('Assessment fails closed on missing/reused provenance or changed vendor bytes, links or manifest',()=>{
 for(const change of [f=>f.proof.ok=false,f=>f.proof.imageId='sha256:'+'b'.repeat(64),f=>f.proof.files[0].sha256='0'.repeat(64),f=>f.proof.symlinks[0].target='older.so',f=>f.proof.files.pop(),f=>f.proof.platform='win32/x64',f=>f.proof.engine='ClamAV 1.5.4/123/time',f=>f.proof.manifestSha256='0'.repeat(64),f=>f.proof.archiveSha256='0'.repeat(64),f=>f.raw.Results[0].Packages=[]]){const f=fixture();change(f);assert.throws(()=>f.check());}
 const f=fixture();assert.throws(()=>scannerAssessment(f.raw,imagePolicy(f.raw),undefined,manifest,vex));
 const changed=clone(manifest);changed.files[0].sha256='0'.repeat(64);assert.throws(()=>scannerAssessment(f.raw,imagePolicy(f.raw),f.proof,changed,vex));
 const unrelated=clone(vex);unrelated.statements[0].products=[{'@id':'pkg:generic/clamav@1.5.4'}];assert.throws(()=>scannerAssessment(f.raw,imagePolicy(f.raw),f.proof,manifest,unrelated));
});
