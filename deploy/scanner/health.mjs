import {createConnection} from 'node:net';
const socket=createConnection({host:'127.0.0.1',port:3310});let bytes='';const timer=setTimeout(()=>{socket.destroy();process.exit(1);},3000);
socket.on('connect',()=>socket.write('zPING\0'));socket.on('data',chunk=>{bytes+=chunk.toString();if(bytes.length>32)process.exit(1);if(bytes.includes('\0')){clearTimeout(timer);socket.destroy();process.exit(bytes==='PONG\0'?0:1);}});socket.on('error',()=>process.exit(1));socket.on('end',()=>process.exit(1));
