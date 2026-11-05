#!/usr/bin/env node
// 邀请码管理脚本（管理员用）。管理 token 从文件读取，绝不打印。
//
//   node scripts/invite.mjs create [--user 用户名] [--ttl 72h]   生成一次性邀请（默认 72 小时；支持 60s / 30m / 12h / 7d，范围 60 秒–30 天）
//   node scripts/invite.mjs list                                  列出未使用、未过期的邀请（只显示 id，不显示邀请码）
//   node scripts/invite.mjs revoke <id>                           撤销邀请（id 为 16 位十六进制，见 create / list 输出）
//
// 通用选项：
//   --base <URL>         默认 https://passkey-demo.example.workers.dev
//   --token-file <路径>  默认 <项目根>/.admin-token（应为 chmod 600）
//   --local              本地 wrangler dev：base=http://localhost:8787，token 取自 .dev.vars 中的 ADMIN_TOKEN（与线上不同）
//   --json               以 JSON 输出（create 的输出包含邀请码明文，请只发给受邀人）
import { openSync, fstatSync, readFileSync, closeSync } from 'node:fs';
import { assertSafeBase } from './safe-base.mjs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const flags = {};
const pos = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--local' || a === '--json') flags[a.slice(2)] = true;
  else if (a.startsWith('--')) { flags[a.slice(2)] = args[i + 1]; i++; }
  else pos.push(a);
}
const [cmd, arg] = pos;
const die = (msg, code = 1) => { console.error(msg); process.exit(code); };
const usage = () => die(readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n').slice(1, 14).map((l) => l.replace(/^\/\/ ?/, '')).join('\n'), 2);
if (!['create', 'list', 'revoke'].includes(cmd)) usage();

const BASE = (flags.base || (flags.local ? 'http://localhost:8787' : 'https://passkey-demo.example.workers.dev')).replace(/\/$/, '');
function loadToken() {
  if (flags.local && !flags['token-file']) {
    const m = /^ADMIN_TOKEN=(.+)$/m.exec(readFileSync(join(ROOT, '.dev.vars'), 'utf8'));
    if (!m) die('.dev.vars 中没有 ADMIN_TOKEN');
    return m[1].trim();
  }
  const file = flags['token-file'] || join(ROOT, '.admin-token');
  // 先 open，再对同一 fd 做 fstat 与读取：检查与使用的是同一个文件（无 stat→read 竞态）
  let fd;
  try { fd = openSync(file, 'r'); } catch { die(`找不到管理 token 文件：${file}`); }
  let t;
  try {
    if (fstatSync(fd).mode & 0o077) console.error(`警告：${file} 的权限过宽，建议 chmod 600`);
    t = readFileSync(fd, 'utf8').trim();
  } finally { closeSync(fd); }
  if (t.length < 32) die('管理 token 文件内容无效（过短）');
  return t;
}
try { assertSafeBase(BASE); } catch (e) { die(e.message); }
const TOKEN = loadToken();

function parseTtl(s) {
  if (s === undefined) return undefined;
  const m = /^(\d+)\s*([smhd]?)$/.exec(String(s).trim());
  if (!m) die('--ttl 格式：60s / 30m / 12h / 7d');
  return Number(m[1]) * { '': 1, s: 1, m: 60, h: 3600, d: 86400 }[m[2]];
}
async function call(method, path, body) {
  const r = await fetch(BASE + path, {
    method,
    headers: { Authorization: `Bearer ${TOKEN}`, Origin: new URL(BASE).origin, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await r.json(); } catch { /* ignore */ }
  if (!r.ok) die(`失败：HTTP ${r.status} ${data.error || ''}`);
  return data;
}
const fmt = (t) => new Date(t).toLocaleString('zh-CN', { hour12: false, timeZone: process.env.TZ || 'Asia/Taipei' });

if (cmd === 'create') {
  const body = {};
  const ttl = parseTtl(flags.ttl);
  if (ttl !== undefined) body.ttlSeconds = ttl;
  if (flags.user) body.username = flags.user;
  const d = await call('POST', '/api/admin/invites', body);
  if (flags.json) { console.log(JSON.stringify(d, null, 2)); process.exit(0); }
  console.log(`已创建一次性邀请  id=${d.id}  绑定用户名=${d.username || '（不限）'}  过期时间=${fmt(d.expiresAt)}`);
  console.log(`邀请码：${d.code}`);
  console.log(`邀请链接：${d.link}`);
  console.log('（邀请码明文只显示这一次，服务器只保存它的 SHA-256；请通过私密渠道发给受邀人）');
} else if (cmd === 'list') {
  const d = await call('GET', '/api/admin/invites');
  if (flags.json) { console.log(JSON.stringify(d, null, 2)); process.exit(0); }
  if (!d.invites.length) console.log('当前没有有效邀请。');
  for (const i of d.invites) console.log(`id=${i.id}  绑定用户名=${i.username || '（不限）'}  创建=${fmt(i.createdAt)}  过期=${fmt(i.expiresAt)}`);
  if (d.truncated) console.log('（列表被截断，只显示前 200 个）');
} else if (cmd === 'revoke') {
  if (!/^[0-9a-f]{16}$/.test(arg || '')) die('用法：node scripts/invite.mjs revoke <16 位十六进制 id>');
  const d = await call('POST', '/api/admin/invites/revoke', { id: arg });
  console.log(flags.json ? JSON.stringify(d) : `已撤销 ${d.revoked} 个邀请（id=${arg}）`);
}
