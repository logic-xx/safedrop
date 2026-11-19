import {mkdir,lstat,readFile,readdir,copyFile,rename,writeFile} from 'node:fs/promises';
import {constants} from 'node:fs';
import {resolve,join,sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
import {VENDOR,verifyVendor,downloadVendor} from '../deploy/scanner/vendor-artifact.mjs';

export async function prepareVendor(root,{source,expected=VENDOR,downloadOptions}={}){
 await mkdir(root,{recursive:true,mode:0o700});const dir=await lstat(root);assert.ok(dir.isDirectory()&&!dir.isSymbolicLink(),'VENDOR_CONTEXT_NOT_DIRECTORY');
 const allowed=new Set(['vendor.deb','vendor.deb.partial','.dockerignore']);for(const name of await readdir(root))assert.ok(allowed.has(name),'UNEXPECTED_VENDOR_CONTEXT_FILE');
 try{const s=await lstat(join(root,'.dockerignore'));assert.ok(s.isFile()&&!s.isSymbolicLink(),'VENDOR_IGNORE_NOT_REGULAR');}catch(e){if(e.code!=='ENOENT')throw e;}
 const target=join(root,'vendor.deb');let from='cache';
 try{await lstat(target);await verifyVendor(target,expected);}
 catch(e){
  if(e.code!=='ENOENT')throw e;
  let hasSource=false;if(source){try{await lstat(source);hasSource=true;}catch(error){if(error.code!=='ENOENT')throw error;}}
  if(hasSource){await verifyVendor(source,expected);const partial=target+'.partial';let flags=constants.COPYFILE_EXCL;try{const s=await lstat(partial);assert.ok(s.isFile()&&!s.isSymbolicLink(),'VENDOR_PARTIAL_NOT_REGULAR');flags=0;}catch(error){if(error.code!=='ENOENT')throw error;}await copyFile(source,partial,flags);await verifyVendor(partial,expected);await rename(partial,target);from='existing-local-package';}
  else{await downloadVendor(target,expected,downloadOptions);from='official-https';}
 }
 assert.ok((await readdir(root)).every(name=>['vendor.deb','.dockerignore'].includes(name)),'VENDOR_CONTEXT_NOT_READY');
 await writeFile(join(root,'.dockerignore'),'*\n!vendor.deb\n');return {ok:true,from,context:resolve(root),...await verifyVendor(target,expected)};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const local=resolve('.local'),root=resolve('.local/scanner-build/clamav-'+VENDOR.version);assert.ok(root.startsWith(local+sep));
 const manifest=JSON.parse(await readFile('deploy/scanner/vendor-manifest.json','utf8'));assert.equal(manifest.archive.sha256,VENDOR.sha256);assert.equal(manifest.archive.url,VENDOR.url);
 const result=await prepareVendor(root,{source:resolve('.local/clamav-'+VENDOR.version+'/clamav-'+VENDOR.version+'.linux.x86_64.deb')});
 await mkdir('.local/container-check',{recursive:true});const override=resolve('.local/container-check/scanner-build.override.json');
 await writeFile(override,JSON.stringify({services:{scanner:{build:{args:{REQUIRE_LOCAL_VENDOR:'1'},additional_contexts:{vendor_package:result.context}}}}},null,2)+'\n');
 console.log(JSON.stringify({...result,override}));
}
