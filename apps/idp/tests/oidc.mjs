// OIDC Phase 1 端到端测试（规格：docs/specs/oidc-phase1.md，AC-5 … AC-20）
// 用法：node tests/oidc.mjs（自己启动 wrangler dev，全新本地状态；端口 8787 须空闲；.dev.vars 需含 OIDC_SIGNING_KEY，见 scripts/oidc-keygen.mjs）
//   阶段 1：OIDC_SIGNING_KEY 覆盖为无效值 → 验证 fail closed，并注册用户（模拟“上线 OIDC 前就有的 passkey”）
//   阶段 2：用 .dev.vars 里的密钥重启（同一持久化目录）→ 旧 passkey 登录并走完整 OIDC 流程
// RP 回调地址 localhost:8788/8798：测试内起最小 HTTP 服务只记录回调 URL。不打印任何 token、code、cookie。
import { chromium } from 'playwright';
import { readFileSync, mkdirSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const APP_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
import * as oauth from 'oauth4webapi';
import { createServer } from 'node:http';

const BASE = 'http://localhost:8787';
const PERSIST = `/tmp/pk-oidc-${Date.now()}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
const check = (name, ok, detail = '') => { results.push({ name, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail && !ok ? '  — ' + detail : ''}`); };
const log = (...a) => console.log('     ', ...a);

let dev = null, devOut = '';
async function startDev(extra = []) {
  mkdirSync(PERSIST, { recursive: true });
  dev = spawn('npx', ['wrangler', 'dev', '--port', '8787', '--persist-to', PERSIST, ...extra], { cwd: APP_ROOT, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; dev.stdout.on('data', (d) => { out += d; devOut += d; }); dev.stderr.on('data', (d) => { out += d; devOut += d; });
  for (let i = 0; i < 120; i++) { await sleep(500); if (/Ready on/.test(out)) { await sleep(500); return; } }
  console.log(out.slice(-800)); throw new Error('wrangler dev 启动超时');
}
async function stopDev() { if (!dev) return; try { process.kill(-dev.pid, 'SIGTERM'); } catch { /* */ } await sleep(2500); dev = null; }
process.on('exit', (code) => { if (code && process.env.OIDC_TEST_DEBUG) console.log(devOut.slice(-3000)); if (dev) try { process.kill(-dev.pid, 'SIGTERM'); } catch { /* */ } });

// 限流节奏：每个路径 60 秒内最多 8 次（服务端是 10 次）
const hits = {};
async function budget(path, n = 1) {
  hits[path] ||= [];
  for (;;) {
    const now = Date.now();
    hits[path] = hits[path].filter((t) => now - t < 62000);
    if (hits[path].length + n <= 8) break;
    const wait = 62000 - (now - hits[path][0]) + 200;
    log(`[节奏控制] ${path} 已用 ${hits[path].length} 次，等待 ${Math.ceil(wait / 1000)} 秒…`);
    await sleep(wait);
  }
  for (let i = 0; i < n; i++) hits[path].push(Date.now());
}
const TOKEN = /^ADMIN_TOKEN=(.+)$/m.exec(readFileSync(join(APP_ROOT, '.dev.vars'), 'utf8'))[1].trim();
async function invite(username) {
  await budget('/api/admin/invites');
  const r = await fetch(BASE + '/api/admin/invites', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: BASE, Authorization: `Bearer ${TOKEN}` }, body: JSON.stringify({ username, ttlSeconds: 600 }) });
  if (r.status !== 200) throw new Error('建邀请失败 ' + r.status);
  return (await r.json()).link;
}

const browser = await chromium.launch();
const context = await browser.newContext({ locale: 'zh-CN' });
const page = await context.newPage();
page.on('pageerror', (e) => log('pageerror:', e.message));
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
// RP 回调：拦截并记录完整回调 URL
let lastCallback = null;
const rps = [8788, 8798].map((port) => createServer((req, res) => { lastCallback = new URL(req.url, `http://localhost:${port}`); res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('rp callback'); }).listen(port, '127.0.0.1'));

// ===== 阶段 1：未配置有效密钥 =====
const U = 'o_user';
await startDev(['--var', 'OIDC_SIGNING_KEY:off']);
{
  const r = await fetch(BASE + '/.well-known/openid-configuration');
  const t = await fetch(BASE + '/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=refresh_token' });
  check('未配置签名密钥时 discovery 返回 503', r.status === 503 && t.status === 503, `${r.status}/${t.status}`);
}
await budget('/api/register/options'); await budget('/api/register/verify');
await page.goto((await invite(U)).replace(/^https?:\/\/[^/]+/, BASE));
await page.locator('#anon').waitFor();
await page.waitForFunction(() => window.__pk && window.__pk.getTurnstileToken(), null, { timeout: 30000 });
await page.click('#btn-register');
const registered = await page.locator('#authed').waitFor({ timeout: 20000 }).then(() => true).catch(() => false);
await budget('/api/logout');
await page.evaluate(() => fetch('/api/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }));
await stopDev();

// ===== 阶段 2：启用 OIDC =====
await startDev(['--var', 'STEPUP_TEST_WINDOW_SECONDS:4']);
const opt = { [oauth.allowInsecureRequests]: true };
await budget('/.well-known/openid-configuration');
const as = await oauth.processDiscoveryResponse(new URL(BASE), await oauth.discoveryRequest(new URL(BASE), opt));
check('discovery 解析成功且 issuer 匹配', as.issuer === BASE && as.code_challenge_methods_supported.join() === 'S256' && as.authorization_response_iss_parameter_supported === true);
const jwks = (await (await fetch(as.jwks_uri)).json()).keys;
check('JWKS 只含公钥', jwks.length >= 1 && jwks.every((k) => !('d' in k) && k.kid && k.alg === 'ES256'));

const A = { client_id: 'demo-rp-local', id_token_signed_response_alg: 'ES256' };
const RA = 'http://localhost:8788/callback';
const B = { client_id: 'demo-rp-local-b', id_token_signed_response_alg: 'ES256' };
const RB = 'http://localhost:8798/callback';

async function authUrl(client, redirectUri, extra = {}) {
  const verifier = oauth.generateRandomCodeVerifier();
  const state = oauth.generateRandomState(), nonce = oauth.generateRandomNonce();
  const u = new URL(as.authorization_endpoint);
  const p = { client_id: client.client_id, redirect_uri: redirectUri, response_type: 'code', scope: 'openid profile offline_access', state, nonce, code_challenge: await oauth.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256', ...extra };
  for (const [k, v] of Object.entries(p)) if (v !== null) u.searchParams.set(k, v);
  return { url: u.toString(), verifier, state, nonce };
}
// 浏览器顶层导航到 authorize，必要时在页面上登录 / step-up，返回 RP 收到的回调 URL
async function browse(a, { login = false, stepUp = false } = {}) {
  lastCallback = null;
  await budget('/oauth/authorize', 2);
  await page.goto(a.url);
  if (login) {
    await budget('/api/login/options'); await budget('/api/login/verify');
    await page.locator('#btn-login').click();
  }
  if (stepUp) {
    await budget('/api/stepup/options'); await budget('/api/stepup/verify');
    await page.locator('#btn-oidc-continue').click();
  }
  for (let i = 0; i < 60 && !lastCallback; i++) await sleep(250);
  return lastCallback;
}
async function exchange(client, redirectUri, a, cb) {
  await budget('/oauth/token');
  const params = oauth.validateAuthResponse(as, client, cb, a.state);
  return oauth.processAuthorizationCodeResponse(as, client, await oauth.authorizationCodeGrantRequest(as, client, oauth.None(), params, redirectUri, a.verifier, opt), { expectedNonce: a.nonce, requireIdToken: true });
}
async function tokenRaw(form) {
  await budget('/oauth/token');
  const r = await fetch(as.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form).toString() });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}
const refreshRaw = (client, rt) => tokenRaw({ grant_type: 'refresh_token', client_id: client.client_id, refresh_token: rt });
// 资源方：只用 JWKS 和 node:crypto 本地校验 access token
function verifyAccess(tok, audience) {
  const [h, p, s] = tok.split('.');
  const hdr = JSON.parse(Buffer.from(h, 'base64url'));
  const jwk = jwks.find((k) => k.kid === hdr.kid);
  const ok = hdr.alg === 'ES256' && hdr.typ === 'at+jwt' && jwk && nodeVerify('sha256', Buffer.from(`${h}.${p}`), { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url'));
  const c = JSON.parse(Buffer.from(p, 'base64url'));
  return ok && c.iss === BASE && c.aud.includes(audience) && c.exp > Date.now() / 1000 ? c : null;
}
const idClaims = (t) => JSON.parse(Buffer.from(t.id_token.split('.')[1], 'base64url'));
const safe = async (fn) => { try { return await fn(); } catch (e) { return { error: e }; } };

// AC-6 + AC-8：阶段 1 注册的旧 passkey 登录 → 回到 authorize → code → token
const a1 = await authUrl(A, RA);
const cb1 = await browse(a1, { login: true });
const t1 = cb1 && await safe(() => exchange(A, RA, a1, cb1));
check('未开 OIDC 时注册的 passkey，开启后仍能登录并完成授权', registered && !!cb1 && cb1.searchParams.get('iss') === BASE && !!t1?.access_token, t1?.error?.message);
check('授权码 + PKCE S256 换 token，id_token 签名/iss/aud/exp/nonce 由 oauth4webapi 校验通过', !!t1?.id_token && !t1.error);
const c1 = t1?.id_token ? idClaims(t1) : {};
check('id_token 带 amr/acr/auth_time', Array.isArray(c1.amr) && c1.amr.includes('hwk') && /^urn:pkauth:acr:/.test(c1.acr) && Math.abs(c1.auth_time - Date.now() / 1000) < 120);
const at1 = t1?.access_token ? verifyAccess(t1.access_token, 'http://localhost:8789/api') : null;
check('资源方用 JWKS 本地校验 access token，aud 含两个资源，ent 正确', !!at1 && at1.aud.includes('http://localhost:8788/api') && JSON.stringify(at1.ent) === '["demo:read"]' && at1.client_id === A.client_id);

// AC-11：同一授权码第二次兑换
const replay = await tokenRaw({ grant_type: 'authorization_code', client_id: A.client_id, redirect_uri: RA, code: cb1?.searchParams.get('code') || '', code_verifier: a1.verifier });
check('同一授权码第二次兑换被拒', replay.status === 400 && replay.json.error === 'invalid_grant');

// AC-12：错误 verifier；缺少 PKCE / plain
const a2 = await authUrl(A, RA);
const cb2 = await browse(a2);
const wrong = await tokenRaw({ grant_type: 'authorization_code', client_id: A.client_id, redirect_uri: RA, code: cb2?.searchParams.get('code') || '', code_verifier: oauth.generateRandomCodeVerifier() });
check('错误 code_verifier 被拒', !!cb2?.searchParams.get('code') && wrong.status === 400 && wrong.json.error === 'invalid_grant');
const noPkce = await browse(await authUrl(A, RA, { code_challenge: null, code_challenge_method: null }));
const plain = await browse(await authUrl(A, RA, { code_challenge_method: 'plain' }));
check('缺少 PKCE 或 plain 被拒', noPkce?.searchParams.get('error') === 'invalid_request' && plain?.searchParams.get('error') === 'invalid_request' && !noPkce.searchParams.get('code') && !plain.searchParams.get('code'));

// AC-13/14/15：refresh 轮换 / 重放 / 系列吊销
const r1 = t1?.refresh_token || '';
const rot = await refreshRaw(A, r1);
const r2 = rot.json.refresh_token;
check('refresh 轮换拿到新 refresh token', rot.status === 200 && !!r2 && r2 !== r1 && !!verifyAccess(rot.json.access_token, 'http://localhost:8788/api'));
const reuse = await refreshRaw(A, r1);
check('宽限内重放刚刚轮换的 refresh 返回同一份新 token', reuse.status === 200 && reuse.json.refresh_token === r2);

// AC-16：未登记 redirect_uri / 未知 client
await budget('/oauth/authorize', 2);
const bad1 = await page.request.get((await authUrl(A, 'https://evil.example.com/cb')).url, { maxRedirects: 0 });
const bad2 = await page.request.get((await authUrl({ client_id: 'nope' }, RA)).url, { maxRedirects: 0 });
check('未登记 redirect_uri / 未知 client 返回 400 且不重定向', bad1.status() === 400 && bad2.status() === 400 && !bad1.headers().location && !bad2.headers().location);

// AC-19：userinfo
await budget('/oauth/userinfo');
const ui = await (await fetch(as.userinfo_endpoint, { headers: { Authorization: `Bearer ${rot.json.access_token}` } })).json();
check('userinfo 返回与 id_token 相同的 sub，sub 不含用户名', ui.sub === c1.sub && !String(ui.sub).includes(U) && ui.preferred_username === U);

// AC-20：多应用隔离
const ab = await authUrl(B, RB, { scope: 'openid' });
const cbB = await browse(ab);
const tB = cbB && await safe(() => exchange(B, RB, ab, cbB));
const atB = tB?.access_token ? JSON.parse(Buffer.from(tB.access_token.split('.')[1], 'base64url')) : null;
check('client A 的 access token aud 不含 client B 的资源', !!atB && atB.aud.includes('http://localhost:8798/api') && !atB.aud.includes('http://localhost:8788/api') && !at1?.aud.includes('http://localhost:8798/api') && !tB.refresh_token);

// AC-17：step-up（窗口 4 秒）
await sleep(5000);
const as1 = await authUrl(A, RA, { acr_values: 'urn:pkauth:acr:stepup' });
const cbS = await browse(as1, { stepUp: true });
const tS = cbS && await safe(() => exchange(A, RA, as1, cbS));
const cS = tS?.id_token ? idClaims(tS) : {};
check('acr_values=stepup 在窗口外先 step-up，id_token acr=stepup 且 auth_time 刷新', cS.acr === 'urn:pkauth:acr:stepup' && cS.auth_time > c1.auth_time, tS?.error?.message);
await budget('/oauth/authorize', 2);
const none = await fetch((await authUrl(A, RA, { prompt: 'none' })).url, { redirect: 'manual' });
const loc = none.headers.get('location') ? new URL(none.headers.get('location')) : null;
const maxAge = await fetch((await authUrl(A, RA, { max_age: '0' })).url, { redirect: 'manual' }); // 无会话 → 去登录页
check('prompt=none 无会话返回 login_required', none.status === 302 && loc?.origin === 'http://localhost:8788' && loc.searchParams.get('error') === 'login_required' && /^\/\?continue=/.test(maxAge.headers.get('location') || ''));

// AC-18：IdP 退出后 refresh 失效
const rS = tS?.refresh_token || '';
await budget('/api/logout');
await page.goto(BASE + '/'); // 当前页面停在 RP 回调上，先回到 IdP 同源再退出
await page.evaluate(() => fetch('/api/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }));
const afterLogout = await refreshRaw(A, rS);
check('IdP 退出登录后 refresh 失效', !!rS && afterLogout.status === 400 && afterLogout.json.error === 'invalid_grant');

await browser.close();
for (const r of rps) r.close();
await stopDev();
const fail = results.filter((r) => !r.ok).length;
console.log(`\n结果：${results.length - fail}/${results.length} 通过`);
process.exit(fail ? 1 : 0);
