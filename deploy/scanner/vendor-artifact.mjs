import {createHash} from 'node:crypto';
import {createReadStream,constants} from 'node:fs';
import {lstat,open,rename} from 'node:fs/promises';
import assert from 'node:assert/strict';

export const VENDOR={version:'1.5.5',url:'https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.5/clamav-1.5.5.linux.x86_64.deb',bytes:107577342,sha256:'fff17fb1f8917d1ea1308c9736dabe376077458aba000a5dadcce7193a8c538c'};
export async function verifyVendor(path,expected=VENDOR){
 const stat=await lstat(path);assert.ok(stat.isFile()&&!stat.isSymbolicLink(),'CLAMAV_VENDOR_NOT_REGULAR');assert.equal(stat.size,expected.bytes,'CLAMAV_VENDOR_SIZE_MISMATCH');
 const hash=createHash('sha256');for await(const chunk of createReadStream(path))hash.update(chunk);
 assert.equal(hash.digest('hex'),expected.sha256,'CLAMAV_VENDOR_HASH_MISMATCH');return {bytes:stat.size,sha256:expected.sha256};
}
const size=async path=>{try{const s=await lstat(path);assert.ok(s.isFile()&&!s.isSymbolicLink(),'CLAMAV_VENDOR_NOT_REGULAR');return s.size;}catch(e){if(e.code==='ENOENT')return 0;throw e;}};
export async function downloadVendor(target,expected=VENDOR,{fetcher=fetch,timeoutMs=300000,attempts=3}={}){
 const partial=target+'.partial';
 for(let attempt=0;attempt<attempts;attempt++){
  let offset=await size(partial);assert.ok(offset<=expected.bytes,'CLAMAV_VENDOR_PARTIAL_OVERSIZE');
  if(offset===expected.bytes){await verifyVendor(partial,expected);await rename(partial,target);return verifyVendor(target,expected);}
  let response;
  try{
   response=await fetcher(expected.url,{signal:AbortSignal.timeout(timeoutMs),headers:{'Accept-Encoding':'identity',...(offset?{Range:`bytes=${offset}-`}:{})}});
   assert.ok(response.status===200||response.status===206,'CLAMAV_VENDOR_DOWNLOAD_FAILED');
   if(response.status===206){const match=/^bytes (\d+)-(\d+)\/(\d+)$/.exec(response.headers.get('content-range')??'');assert.ok(match&&Number(match[1])===offset&&Number(match[2])===expected.bytes-1&&Number(match[3])===expected.bytes,'CLAMAV_VENDOR_RANGE_MISMATCH');}
   else offset=0; // A server may ignore Range; restart this partial, never append a full response.
   try{const state=await lstat(partial);assert.ok(state.isFile()&&!state.isSymbolicLink(),'CLAMAV_VENDOR_NOT_REGULAR');if(offset)assert.equal(state.size,offset,'CLAMAV_VENDOR_PARTIAL_CHANGED');}catch(e){if(e.code!=='ENOENT')throw e;assert.equal(offset,0,'CLAMAV_VENDOR_PARTIAL_CHANGED');}
   const flags=constants.O_WRONLY|constants.O_CREAT|(offset?constants.O_APPEND:constants.O_TRUNC)|(constants.O_NOFOLLOW??0);
   const file=await open(partial,flags,0o600);
   try{for await(const raw of response.body){const chunk=Buffer.from(raw);assert.ok(offset+chunk.length<=expected.bytes,'CLAMAV_VENDOR_DOWNLOAD_OVERSIZE');let written=0;while(written<chunk.length){const result=await file.write(chunk,written,chunk.length-written);assert.ok(result.bytesWritten>0,'CLAMAV_VENDOR_WRITE_FAILED');written+=result.bytesWritten;}offset+=chunk.length;}await file.sync();}finally{await file.close();}
   assert.equal(offset,expected.bytes,'CLAMAV_VENDOR_DOWNLOAD_TRUNCATED');
  }catch(e){await response?.body?.cancel().catch(()=>{});if(attempt===attempts-1)throw e;continue;}
  // Integrity failures are not treated as transient network failures.
  await verifyVendor(partial,expected);await rename(partial,target);return verifyVendor(target,expected);
 }
 throw Error('CLAMAV_VENDOR_DOWNLOAD_FAILED');
}
