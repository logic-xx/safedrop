import { readFileSync } from 'node:fs';
import { verifyAudit } from '../server/store.ts';
const [log, checkpoint] = process.argv.slice(2);
if (!log) { console.error('用法：npm run audit:verify -- 审计文件.json [独立检查点.json]'); process.exit(1); }
const data = JSON.parse(readFileSync(log, 'utf8'));
const anchor = checkpoint ? JSON.parse(readFileSync(checkpoint, 'utf8')) : undefined;
const result = verifyAudit(data.rows, anchor); console.log(JSON.stringify({ ...result, independentCheckpoint: Boolean(anchor) }, null, 2));
if (!result.ok) process.exitCode = 1;
