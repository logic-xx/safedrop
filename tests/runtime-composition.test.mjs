import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile, readFile, rm} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {join, dirname, resolve, sep} from 'node:path';
import {verifyFiles, verifyRuntime} from '../deploy/runtime/verify.mjs';

async function fixture(run) {
  await mkdir('tmp',{recursive:true});
  const root=await mkdtemp(resolve('tmp/runtime-inventory-'));
  const file={path:'/usr/lib/runtime.so',data:'exact official bytes'},meta={path:'var/lib/dpkg/status.d/runtime',data:'Package: runtime\nVersion: 1\n',package:'runtime',version:'1'};
  const hash=x=>createHash('sha256').update(x).digest('hex');
  for(const f of [file,meta]) {const path=join(root,f.path.replace(/^\//,''));await mkdir(dirname(path),{recursive:true});await writeFile(path,f.data);}
  const manifest={files:[{path:file.path,sha256:hash(file.data)}],metadata:[{path:meta.path,sha256:hash(meta.data),package:meta.package,version:meta.version}]};
  try {await run(root,manifest);} finally {assert.ok(root.startsWith(resolve('tmp')+sep));await rm(root,{recursive:true,force:true});}
}
test('Runtime file verification rejects altered binary bytes, metadata and unsafe paths',async()=>{
  await fixture(async(root,m)=>{
    await verifyFiles(root,m);
    await writeFile(join(root,'usr/lib/runtime.so'),'tampered');
    await assert.rejects(verifyFiles(root,m),/RUNTIME_HASH_MISMATCH/);
  });
  await fixture(async(root,m)=>{
    await writeFile(join(root,m.metadata[0].path),'Package: runtime\nVersion: 2\n');
    await assert.rejects(verifyFiles(root,m),/RUNTIME_HASH_MISMATCH/);
    await assert.rejects(verifyFiles(root,{...m,files:[{path:'../outside',sha256:'0'.repeat(64)}]}),/INVALID_RUNTIME_PATH/);
  });
});
test('Runtime verification discovers unexpected SSL files and unlisted SSL package inventory',async()=>{
  for(const name of ['usr/lib/nested/libssl.so.3','usr/lib/libcrypto.so.3','usr/local/lib/libssl.so']) await fixture(async(root,m)=>{
    const path=join(root,name);await mkdir(dirname(path),{recursive:true});await writeFile(path,'unwanted');
    await assert.rejects(verifyFiles(root,m),/UNEXPECTED_SYSTEM_OPENSSL/);
  });
  for(const [name,text] of [['libssl3t64','Package: libssl3t64\n'],['innocent-name','Package: libssl3t64\nVersion: 1\n']]) await fixture(async(root,m)=>{
    await writeFile(join(root,'var/lib/dpkg/status.d',name),text);
    await assert.rejects(verifyFiles(root,m),/SYSTEM_OPENSSL_PACKAGE_PRESENT/);
  });
});
test('Both Dockerfiles retain pinned official files, package inventory, licenses and final runtime verification',async()=>{
  const m=JSON.parse(await readFile('deploy/runtime/manifest.json','utf8'));
  for(const path of ['Dockerfile','deploy/scanner/Dockerfile']) {
    const text=await readFile(path,'utf8');
    assert.ok(text.includes('FROM '+m.nodeImage+' AS node_runtime'));
    assert.ok(text.includes('FROM '+m.baseImage));
    for(const file of m.metadata) assert.ok(text.includes('/'+file.path)||(file.path.endsWith('/copyright')&&text.includes('/usr/share/doc/gcc-14-base /usr/share/doc/gcc-14-base')),file.path);
    assert.ok(text.includes('COPY --from=node_runtime /nodejs /nodejs'));
    assert.ok(text.includes('COPY deploy/runtime/ /runtime/'));
    assert.ok(text.includes('RUN ["/nodejs/bin/node", "/runtime/verify.mjs"]'));
    assert.ok(text.includes('ENTRYPOINT ["/nodejs/bin/node"]'));
    assert.ok(!/COPY .*lib(?:ssl|crypto)/.test(text));
  }
});
test('A non-Linux host cannot generate final Linux runtime composition evidence',{skip:process.platform==='linux'},async()=>{
  await assert.rejects(verifyRuntime(),/FINAL_LINUX_RUNTIME_REQUIRED/);
});
