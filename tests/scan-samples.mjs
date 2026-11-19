// Harmless test vectors only. Never imported by application runtime. ASCII-only for stdin probes.
import {crc32} from 'node:zlib';
export const eicarSample=()=>Buffer.from(['X5O!P%@AP[4','\\PZX54(P^)7CC)7}$EICAR-','STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'].join(''));
export function zipSample(bytes,name='sample.txt'){
 const filename=Buffer.from(name),checksum=crc32(bytes),local=Buffer.alloc(30),central=Buffer.alloc(46),end=Buffer.alloc(22);
 local.writeUInt32LE(0x04034b50);local.writeUInt16LE(20,4);local.writeUInt32LE(checksum,14);local.writeUInt32LE(bytes.length,18);local.writeUInt32LE(bytes.length,22);local.writeUInt16LE(filename.length,26);
 central.writeUInt32LE(0x02014b50);central.writeUInt16LE(20,4);central.writeUInt16LE(20,6);central.writeUInt32LE(checksum,16);central.writeUInt32LE(bytes.length,20);central.writeUInt32LE(bytes.length,24);central.writeUInt16LE(filename.length,28);
 const offset=local.length+filename.length+bytes.length;end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(central.length+filename.length,12);end.writeUInt32LE(offset,16);
 return Buffer.concat([local,filename,bytes,central,filename,end]);
}
// AES ZIP of the harmless sentence above. Not a user file or deployment secret.
export const encryptedBenignZip=()=>Buffer.from('UEsDBDMAAQBjALlKc10AAAAATgAAADIAAAANAAsAaW5ub2N1b3VzLnR4dAGZBwACAEFFAwAAsm9TzG1fPBie6psX8lOlh4qRee5V/0M/qHNx+/eEQfZNtjPFD9tIQ5XFrf3HRyD3eHcQqFDYlejoAJspuIiaFrhcA//dOf1JaqFGPUl7UEsBAj8AMwABAGMAuUpzXQAAAABOAAAAMgAAAA0ALwAAAAAAAAAgAAAAAAAAAGlubm9jdW91cy50eHQKACAAAAAAAAEAGAAkSVtZxHfdAQAAAAAAAAAAAAAAAAAAAAABmQcAAgBBRQMAAFBLBQYAAAAAAQABAGoAAACEAAAAAAA=','base64');
