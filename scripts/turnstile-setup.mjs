// 从 stdin 读取 `wrangler turnstile widget create --json` 输出：
// sitekey（公开）写入 wrangler.toml；secret 只通过管道交给 `wrangler secret put`，绝不打印/落盘。
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
let raw = '';
for await (const c of process.stdin) raw += c;
let w;
try { w = JSON.parse(raw.slice(raw.indexOf('{'))); } catch { 
  console.error('无法解析 widget create 输出（不打印原文以免泄露）。长度=', raw.length);
  console.error('首行:', raw.split('\n')[0].replace(/[A-Za-z0-9_-]{30,}/g, '[redacted]'));
  process.exit(1);
}
const r = w.result ?? w;
const sitekey = r.sitekey, secret = r.secret;
if (!sitekey || !secret) {
  console.error('输出缺少 sitekey/secret 字段，keys=', Object.keys(r));
  process.exit(1);
}
console.error('widget 已创建: name=', r.name, 'mode=', r.mode, 'domains=', JSON.stringify(r.domains), 'sitekey=', sitekey);
const p = 'wrangler.toml';
writeFileSync(p, readFileSync(p, 'utf8').replace(/TURNSTILE_SITEKEY = "PENDING"/, `TURNSTILE_SITEKEY = "${sitekey}"`));
const ch = spawn('npx', ['wrangler', 'secret', 'put', 'TURNSTILE_SECRET'], { stdio: ['pipe', 'inherit', 'inherit'] });
ch.stdin.end(secret);
ch.on('exit', (code) => { console.error('secret put exit', code); process.exit(code ?? 1); });
