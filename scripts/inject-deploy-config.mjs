#!/usr/bin/env node
// 把 deploy environment 的 DEPLOY_* 注入 wrangler.toml 的已知占位行。
// 只替换这些占位赋值，不重排 TOML，不改限流 namespace_id 与 Durable Object 段。
// 不打印 secret 值。用法：
//   node scripts/inject-deploy-config.mjs <wrangler.toml>
//   node scripts/inject-deploy-config.mjs --check <wrangler.toml>
import { lstatSync, readFileSync, writeFileSync } from 'node:fs';

export const FIELDS = [
  { key: 'DEPLOY_WORKER_NAME', from: 'name = "pkauth-idp"', quote: (v) => `name = "${v}"`, ok: isWorkerName },
  { key: 'DEPLOY_RP_ID', from: 'RP_ID = "id.example.com"', quote: (v) => `RP_ID = "${v}"`, ok: isRpId },
  { key: 'DEPLOY_ORIGIN', from: 'ORIGIN = "https://id.example.com"', quote: (v) => `ORIGIN = "${v}"`, ok: isOrigin },
  { key: 'DEPLOY_RP_NAME', from: 'RP_NAME = "pkauth"', quote: (v) => `RP_NAME = "${v}"`, ok: isRpName },
  { key: 'DEPLOY_PRINCIPALS', from: 'PRINCIPALS = "root_example"', quote: (v) => `PRINCIPALS = "${v}"`, ok: isPrincipals },
  { key: 'DEPLOY_KV_ID', from: 'id = "00000000000000000000000000000000"', quote: (v) => `id = "${v}"`, ok: isKvId },
  { key: 'DEPLOY_TURNSTILE_SITEKEY', from: 'TURNSTILE_SITEKEY = "1x00000000000000000000AA"', quote: (v) => `TURNSTILE_SITEKEY = "${v}"`, ok: isSitekey },
];

function isWorkerName(v) {
  // 账号级 Workers Scripts:Edit 能改该账户里的任意已有 Worker。只接受现有生产脚本名。
  return v === 'passkey-demo';
}
function isLabel(v) {
  if (v.length < 1 || v.length > 63 || v.startsWith('-') || v.endsWith('-')) return false;
  for (const c of v) {
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c === '-')) return false;
  }
  return true;
}
function isHostname(v) {
  if (v.length > 253) return false;
  const labels = v.split('.');
  if (labels.length < 2) return false;
  return labels.every(isLabel);
}
function hasExampleCom(v) {
  return v.toLowerCase().includes('example.com');
}
function isRpId(v) {
  return v !== 'localhost' && isHostname(v) && !hasExampleCom(v);
}
function isOrigin(v) {
  if (!v.startsWith('https://') || hasExampleCom(v)) return false;
  const rest = v.slice('https://'.length);
  if (rest.includes('/') || rest.includes('?') || rest.includes('#') || rest.includes('@') || rest.includes('\\')) return false;
  const colon = rest.lastIndexOf(':');
  if (colon === -1) return isHostname(rest);
  const host = rest.slice(0, colon);
  const port = rest.slice(colon + 1);
  if (port.length < 1 || port.length > 5) return false;
  for (const c of port) if (c < '0' || c > '9') return false;
  const n = Number(port);
  return n >= 1 && n <= 65535 && isHostname(host);
}
function isRpName(v) {
  if (v.length < 1 || v.length > 64) return false;
  for (const c of v) {
    const code = c.codePointAt(0);
    if (code < 0x20 || code === 0x7f || c === '"' || c === '\\') return false;
  }
  return true;
}
function isUsername(v) {
  if (v.length < 3 || v.length > 32) return false;
  for (const c of v) {
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c === '_' || c === '-')) return false;
  }
  return true;
}
function isPrincipals(v) {
  if (v === 'root_example') return false;
  const parts = v.split(',');
  if (parts.length < 1 || parts.length > 20) return false;
  return parts.every(isUsername);
}
function isKvId(v) {
  if (v.length !== 32) return false;
  let zeros = true;
  for (const c of v) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    if (c !== '0') zeros = false;
  }
  return !zeros;
}
function isSitekey(v) {
  if (v === '1x00000000000000000000AA' || v === '2x00000000000000000000AB' || v === '3x00000000000000000000FF') return false;
  if (!v.startsWith('0x4')) return false;
  const rest = v.slice(3);
  if (rest.length < 18 || rest.length > 80) return false;
  for (const c of rest) {
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c === '_' || c === '-')) return false;
  }
  return true;
}

// 注入之后仍拒绝的占位。issue 代码不含配置值。
export function placeholderIssues(toml) {
  const lines = String(toml).split('\n');
  const issues = [];
  const mainAt = lines.findIndex((l) => l.startsWith('main = '));
  const names = (mainAt === -1 ? [] : lines.slice(0, mainAt)).filter((l) => l.startsWith('name = "') && l.endsWith('"') && l.length > 'name = ""'.length);
  if (names.length !== 1) issues.push('missing:name');
  else if (names[0] !== 'name = "passkey-demo"') issues.push('worker-name');
  const one = (prefix, code, bad) => {
    const hits = lines.filter((l) => l.startsWith(prefix));
    if (hits.length !== 1) issues.push(`missing:${code}`);
    else if (bad(hits[0])) issues.push(code);
  };
  one('RP_ID = ', 'rp-id', (l) => hasExampleCom(l));
  one('ORIGIN = ', 'origin', (l) => hasExampleCom(l));
  one('RP_NAME = ', 'rp-name', () => false);
  one('PRINCIPALS = ', 'principals', (l) => l === 'PRINCIPALS = "root_example"');
  one('TURNSTILE_SITEKEY = ', 'turnstile-sitekey', (l) => l === 'TURNSTILE_SITEKEY = "1x00000000000000000000AA"');
  const kv = lines.filter((l) => l.startsWith('id = "') && l.endsWith('"') && l.length === 'id = ""'.length + 32);
  if (kv.length !== 1) issues.push('missing:kv-id');
  else if (kv[0] === 'id = "00000000000000000000000000000000"') issues.push('kv-id');
  return issues;
}

function onlyKnownLinesChanged(before, after, pairs) {
  const b = before.split('\n');
  const a = after.split('\n');
  if (b.length !== a.length) return false;
  const pending = new Map(pairs);
  for (let i = 0; i < b.length; i++) {
    if (pending.get(b[i]) === a[i]) pending.delete(b[i]);
    else if (b[i] !== a[i]) return false;
  }
  return pending.size === 0;
}

// env 为 process.env 或测试替身。失败时 errors 只有字段名 / 问题代码，没有值。
export function injectDeployConfig(toml, env) {
  const errors = [];
  const values = {};
  for (const field of FIELDS) {
    const raw = env[field.key];
    if (typeof raw !== 'string' || raw.trim() === '') errors.push(`missing:${field.key}`);
    else if (raw !== raw.trim() || !field.ok(raw)) errors.push(`invalid:${field.key}`);
    else values[field.key] = raw;
  }
  if (errors.length) return { ok: false, errors };
  const lines = String(toml).split('\n');
  const indexes = [];
  for (const field of FIELDS) {
    const hits = [];
    lines.forEach((line, i) => { if (line === field.from) hits.push(i); });
    if (hits.length !== 1) errors.push(`anchor:${field.key}`);
    else indexes.push(hits[0]);
  }
  if (errors.length) return { ok: false, errors };
  const nextLines = lines.slice();
  const pairs = [];
  FIELDS.forEach((field, i) => {
    const to = field.quote(values[field.key]);
    nextLines[indexes[i]] = to;
    pairs.push([field.from, to]);
  });
  const next = nextLines.join('\n');
  if (!onlyKnownLinesChanged(String(toml), next, pairs)) return { ok: false, errors: ['frozen-section'] };
  const still = placeholderIssues(next);
  if (still.length) return { ok: false, errors: still.map((x) => `still:${x}`) };
  return { ok: true, toml: next };
}

function die(code) {
  console.error(`部署配置注入失败：${code}`);
  process.exit(1);
}
function assertRegular(path) {
  let st;
  try { st = lstatSync(path); } catch { die('unreadable'); }
  if (!st.isFile()) die('not-regular-file');
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const check = args[0] === '--check';
  const path = check ? args[1] : args[0];
  if (!path || args.length !== (check ? 2 : 1)) die('usage');
  assertRegular(path);
  let toml;
  try { toml = readFileSync(path, 'utf8'); } catch { die('unreadable'); }
  if (check) {
    const issues = placeholderIssues(toml);
    if (issues.length) die(`placeholder:${issues.join(',')}`);
    console.log('占位检查通过');
  } else {
    const result = injectDeployConfig(toml, process.env);
    if (!result.ok) die(result.errors.join(','));
    try { writeFileSync(path, result.toml); } catch { die('unwritable'); }
    console.log(`已注入部署配置字段：${FIELDS.map((f) => f.key).join(',')}`);
  }
}
