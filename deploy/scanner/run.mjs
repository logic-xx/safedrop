import {mkdir,readdir,access,copyFile,rename} from 'node:fs/promises';
import {constants} from 'node:fs';
import {spawn,spawnSync,execFileSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import assert from 'node:assert/strict';
await mkdir('/data/db',{recursive:true,mode:0o700});
for(const name of await readdir('/seed'))if(/^[a-z]+\.(?:cvd|cld)$/.test(name)){
 const target='/data/db/'+name,base=target.replace(/\.(?:cvd|cld)$/,'');
 if(await access(base+'.cvd').then(()=>true,()=>false)||await access(base+'.cld').then(()=>true,()=>false))continue;
 const partial='/data/db/.seed-'+randomUUID()+'.partial';await copyFile('/seed/'+name,partial,constants.COPYFILE_EXCL);await rename(partial,target);
}
// Finish the first update before accepting scans; avoid a definition reload during the first request.
const initial=spawnSync('/usr/local/bin/freshclam',['--foreground','--stdout','--config-file=/scanner/freshclam.conf'],{stdio:'inherit',timeout:240000});
if(initial.status!==0)console.error('Initial signature update unavailable; cached databases remain subject to per-scan freshness checks.');
const version=execFileSync('/usr/local/sbin/clamd',['--config-file=/scanner/clamd.conf','--version'],{encoding:'utf8'}).trim();assert.match(version,/^ClamAV 1\.5\.5(?:\/|$)/);console.log('SafeDrop scanner: '+version);
const children=[spawn('/usr/local/sbin/clamd',['--foreground','--config-file=/scanner/clamd.conf'],{stdio:'inherit'}),spawn('/usr/local/bin/freshclam',['--daemon','--foreground','--stdout','--config-file=/scanner/freshclam.conf'],{stdio:'inherit'})];
let stopping=false,exitCode=1;
const stop=code=>{if(stopping)return;stopping=true;exitCode=code;for(const child of children)child.kill('SIGTERM');setTimeout(()=>{for(const child of children)child.kill('SIGKILL');process.exit(exitCode);},10000).unref();};
for(const child of children){child.on('error',()=>stop(1));child.on('exit',code=>{if(!stopping)stop(code===0?1:code??1);if(children.every(p=>p.exitCode!==null||p.signalCode!==null))process.exit(exitCode);});}
process.on('SIGTERM',()=>stop(0));process.on('SIGINT',()=>stop(0));
