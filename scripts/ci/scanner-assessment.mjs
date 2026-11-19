import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

// No ignored CVEs or version ranges. These fixed findings stay in the report.
// Adjudication requires the actual scanned image and every pinned vendor byte/link.
export function scannerAssessment(raw,policy,proof,manifest,vex){
 const binding=vex.vendorBinding,hash=createHash('sha256').update(JSON.stringify(manifest)).digest('hex');
 assert.equal(manifest.schema,1);assert.equal(manifest.product,'ClamAV');
 assert.equal(manifest.version,binding.version);assert.equal(manifest.packageVersion,binding.packageVersion);
 assert.equal(manifest.archive.sha256,binding.archiveSha256);assert.equal(hash,binding.manifestSha256);
 assert.ok(manifest.files.length>=8&&manifest.symlinks.length>=1,'VENDOR_MANIFEST_INCOMPLETE');
 assert.equal(proof?.ok,true,'ACTUAL_SCANNER_PROVENANCE_REQUIRED');
 assert.equal(proof.imageId,raw.Metadata.ImageID,'SCANNER_IMAGE_PROVENANCE_MISMATCH');
 assert.equal(proof.imageId,policy.imageId);assert.equal(proof.platform,'linux/x64');
 assert.equal(proof.archiveSha256,binding.archiveSha256);assert.equal(proof.manifestSha256,hash);
 assert.ok(proof.engine.startsWith('ClamAV '+manifest.version+'/'),'SCANNER_BINARY_VERSION_MISMATCH');
 assert.deepEqual(proof.files,manifest.files,'SCANNER_BINARY_HASH_MISMATCH');
 assert.deepEqual(proof.symlinks,manifest.symlinks,'SCANNER_LIBRARY_LINK_MISMATCH');
 assert.equal(raw.Metadata.OS.Family,'debian');assert.match(raw.Metadata.OS.Name,/^13(?:\.|$)/);
 const osResults=raw.Results.filter(r=>r.Class==='os-pkgs'&&r.Type==='debian');
 const packageVersion=p=>(p.Epoch?String(p.Epoch)+':':'')+p.Version+(p.Release?'-'+p.Release:'');
 assert.ok(osResults.some(r=>r.Packages?.some(p=>p.Name==='clamav'&&packageVersion(p)===binding.packageVersion)),'SCANNER_PACKAGE_INVENTORY_REQUIRED');
 assert.equal(vex['@context'],'https://openvex.dev/ns/v0.2.0');
 const statements=new Map();for(const statement of vex.statements){
  assert.equal(statement.status,'fixed');assert.equal(statement.upstreamFixedVersion,'1.5.3');
  assert.deepEqual(statement.products,[{'@id':'pkg:generic/clamav@'+manifest.version}]);
  assert.ok(statement.references.includes('https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.3'));
  assert.match(statement.vulnerability.name,/^CVE-\d{4}-\d+$/);assert.ok(!statements.has(statement.vulnerability.name));
  statements.set(statement.vulnerability.name,statement);
 }
 const fixedByVendor=[];
 for(const result of osResults)for(const finding of result.Vulnerabilities??[]){
  const statement=statements.get(finding.VulnerabilityID);
  if(statement&&finding.PkgName==='clamav'&&finding.InstalledVersion===binding.packageVersion&&finding.DataSource?.ID==='debian'&&!finding.FixedVersion){
   fixedByVendor.push({target:result.Target,class:result.Class,type:result.Type,dataSource:finding.DataSource.ID,id:finding.VulnerabilityID,package:finding.PkgName,installed:finding.InstalledVersion,status:'fixed',upstreamFixedVersion:statement.upstreamFixedVersion,source:statement.references[0]});
  }
 }
 const same=(a,b)=>['target','class','type','dataSource','id','package','installed'].every(k=>a[k]===b[k]);
 const blocking=policy.findings.filter(f=>['HIGH','CRITICAL'].includes(f.severity)&&!fixedByVendor.some(x=>same(x,f)));
 return {...policy,ok:blocking.length===0,status:blocking.length?'failed':fixedByVendor.length?'passed-with-vendor-fixes':'passed',rawBlocked:policy.blocked,blocked:blocking.length,fixedByVendor,blocking,scannerProvenance:{imageId:proof.imageId,engine:proof.engine,archiveSha256:proof.archiveSha256,manifestSha256:hash,filesVerified:proof.files.length,symlinksVerified:proof.symlinks.length}};
}
