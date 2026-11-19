import {downloadVendor,verifyVendor} from './vendor-artifact.mjs';
if(process.argv[2]==='--verify')await verifyVendor(process.argv[3]);
else await downloadVendor('/vendor.deb');
