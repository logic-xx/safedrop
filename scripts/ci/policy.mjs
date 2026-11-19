import assert from 'node:assert/strict';
export const high = severity => ['high', 'critical', 'HIGH', 'CRITICAL'].includes(severity);
export function secureNode24(version) {
  const match = /^v?24\.(\d+)\.(\d+)$/.exec(version ?? '');
  return Boolean(match && (+match[1] > 22 || +match[1] === 22 && +match[2] >= 3));
}
export function auditPolicy(all, production, lock, exceptions, now = Date.now()) {
  for (const report of [all, production]) {
    assert.equal(report.auditReportVersion, 2, 'INVALID_AUDIT_REPORT');
    assert.ok(!report.error && report.metadata?.vulnerabilities && report.vulnerabilities, 'AUDIT_UNAVAILABLE');
    for (const level of ['info','low','moderate','high','critical','total']) assert.ok(Number.isSafeInteger(report.metadata.vulnerabilities[level]), 'INVALID_AUDIT_COUNTS');
  }
  const findings = [...new Map(Object.values(all.vulnerabilities).flatMap(v => v.via.filter(x => typeof x === 'object' && high(x.severity))).map(x => [x.url, x])).values()];
  const accepted = [], blocked = [];
  for (const finding of findings) {
    const nodes = all.vulnerabilities[finding.name]?.nodes;
    const exception = exceptions.find(e => e.ecosystem === 'npm' && e.package === finding.name && e.advisory === finding.url && e.severity === finding.severity && e.devOnly === true && Number.isFinite(Date.parse(e.expires)) && now < Date.parse(e.expires) && typeof e.reason === 'string' && e.reason.length >= 30 && nodes?.length && nodes.every(path => lock.packages[path]?.dev === true && e.versions.includes(lock.packages[path]?.version)));
    (exception ? accepted : blocked).push({ package: finding.name, advisory: finding.url, severity: finding.severity, ...(exception ? { expires: exception.expires, reason: exception.reason } : {}) });
  }
  const totals = all.metadata.vulnerabilities, prod = production.metadata.vulnerabilities;
  assert.ok(!(totals.high + totals.critical > 0 && findings.length === 0), 'MISSING_AUDIT_ADVISORIES');
  const ok = prod.high + prod.critical === 0 && blocked.length === 0;
  return { ok, status: !ok ? 'failed' : accepted.length ? 'accepted-risk' : 'passed', all: totals, production: prod, accepted, blocked };
}
export function safeSourcePath(path) {
  return !/(^|\/)(\.local|tmp|reports|output|dist|build|node_modules|\.git|backups?|[^/]+\.backups|notes\/private)(\/|$)|(^|\/)(accounts|state|qa-[^/]+)\.json$|(^|\/)\.env(?:\..*)?$|\.(?:mfa-key|backup-keys(?:\.[^/]*)?|sqlite3?(?:-wal|-shm)?|db|pem|key|p12|pfx)$/i.test(path) || path === '.env.example';
}
export function imagePolicy(report) {
  assert.ok(report.SchemaVersion === 2 && report.ArtifactType === 'container_image' && typeof report.ArtifactName === 'string' && typeof report.Metadata?.OS?.Family === 'string' && /^sha256:[a-f0-9]{64}$/.test(report.Metadata?.ImageID ?? '') && Array.isArray(report.Results) && report.Results.length > 0, 'INVALID_IMAGE_REPORT_OR_MISSING_PACKAGE_INVENTORY');
  const findings = report.Results.flatMap(r => {
    assert.equal(typeof r.Target,'string','INVALID_IMAGE_TARGET');
    return (r.Vulnerabilities ?? []).map(v => {
      for(const key of ['VulnerabilityID','PkgName','InstalledVersion','Severity']) assert.equal(typeof v[key],'string','INVALID_IMAGE_FINDING');
      assert.ok(['UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'].includes(v.Severity),'INVALID_IMAGE_SEVERITY');
      return { target: r.Target, class:r.Class??null, type:r.Type??null, dataSource:v.DataSource?.ID??null, id: v.VulnerabilityID, package: v.PkgName, installed: v.InstalledVersion, fixed: v.FixedVersion ?? null, severity: v.Severity, url: v.PrimaryURL };
    });
  });
  const blocked = findings.filter(v => high(v.severity));
  return { ok: blocked.length === 0, status: blocked.length ? 'failed' : 'passed', artifact: report.ArtifactName, imageId: report.Metadata?.ImageID ?? null, repoDigests: report.Metadata?.RepoDigests ?? [], findings, blocked: blocked.length };
}
export function scanRuntimePolicy(report) {
  assert.equal(report.version,10,'SCANNING_CONTAINER_REPORT_V10_REQUIRED');
  const scan=report.scanning;
  assert.ok(scan && scan.databaseVersion===6 && secureNode24(scan.node) && /^ClamAV 1\.5\.5\//.test(scan.engine??''),'PATCHED_SCANNER_RUNTIME_REQUIRED');
  for(const field of ['ok','malwareApi','encryptedArchiveRejected','recursionLimitRejected','unavailableRejected','legacyDefaultBlocked','expiryRejected','restart','encryptedBackupRestore']) assert.equal(scan[field],true,'REAL_SCANNER_CHECK_REQUIRED:'+field);
  for(const field of ['originalAccountsChanged','originalDataChanged']) assert.equal(scan[field],false,'SCANNER_FIXTURE_ISOLATION_REQUIRED');
  return scan;
}
