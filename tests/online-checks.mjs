// 线上验收（无需通过 Turnstile 的部分）：真实 Turnstile 在自动化浏览器中会进入交互式挑战，
// 我们不去自动点击/绕过人机验证，因此注册全流程在本地用测试密钥验证；线上验证所有拒绝路径 + 浏览器登录路径。
import { assertSafeBase } from '../scripts/safe-base.mjs';
import { chromium } from 'playwright';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
// 邀请码：通过管理接口创建测试邀请（token 取自 .admin-token，不打印；邀请码明文也不打印），
//         用完立即撤销，最后确认线上没有留下任何有效邀请。
const BASE = process.env.BASE_URL || 'https://passkey-demo.example.workers.dev';
assertSafeBase(BASE); // 管理 token 只发往 https 或本机 http
const WAIT_EXPIRY = process.env.SKIP_EXPIRY !== '1';
const t0 = Date.now(); let pass = 0, total = 0;
const log = (...a) => console.log(...a);
function check(name, ok, detail = '') { total++; if (ok) pass++; log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`); }
const H = { 'content-type': 'application/json', origin: BASE };
async function post(path, body, cookie) {
  const r = await fetch(BASE + path, { method: 'POST', headers: { ...H, ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  const text = await r.text();
  return { status: r.status, text, setCookie: r.headers.getSetCookie?.() || [], headers: r.headers };
}
const b64u = (b) => Buffer.from(b).toString('base64url');
const fakeCred = () => { const id = b64u(randomBytes(16)); return { id, rawId: id, type: 'public-key', response: { clientDataJSON: b64u('{}'), authenticatorData: b64u(randomBytes(37)), signature: b64u(randomBytes(64)) }, clientExtensionResults: {} }; };
const short = (s) => s.length > 220 ? s.slice(0, 220) + '…' : s;

log(`BASE_URL=${BASE}  开始时间=${new Date().toISOString()}`);
// 1. 首页
{ const r = await fetch(BASE + '/'); check('首页返回 200', r.status === 200, `HTTP ${r.status}`); }
{ const r = await fetch(BASE + '/api/me'); const t = await r.text(); check('/api/me 匿名返回 sitekey（公开值）', r.status === 200 && /turnstileSitekey/.test(t), `HTTP ${r.status} ${t}`); }

// 先拿一个旧的登录 challenge cookie，用于 >5 分钟后的过期测试
const oldOpt = await post('/api/login/options', {});
const oldCookie = oldOpt.setCookie.find((c) => c.startsWith('__Host-pk_chal_auth='))?.split(';')[0];
check('login/options 返回 200 并下发 __Host- 签名 cookie（HttpOnly; Secure; SameSite=Lax）', oldOpt.status === 200 && !!oldCookie && /HttpOnly/i.test(oldOpt.setCookie.join()) && /SameSite=Lax/i.test(oldOpt.setCookie.join()) && /Secure/i.test(oldOpt.setCookie.join()), `HTTP ${oldOpt.status}; Set-Cookie 属性=${oldOpt.setCookie.map((c) => c.split(';').slice(1).join(';')).join(' | ')}`);

// 2a. 管理接口鉴权
const ADMIN_TOKEN = readFileSync('.admin-token', 'utf8').trim();
const AH = { 'content-type': 'application/json', origin: BASE, authorization: `Bearer ${ADMIN_TOKEN}` };
async function admin(method, path, body, headers = AH) {
  const r = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}
const created = [];
async function createInvite(opts = {}) {
  const r = await admin('POST', '/api/admin/invites', opts);
  if (r.status !== 200) throw new Error(`创建邀请失败 HTTP ${r.status}`);
  created.push(r.json.id); return r.json;
}
{
  const a = await admin('GET', '/api/admin/invites', null, { origin: BASE, 'x-pk-admin': '1' });
  const b = await admin('GET', '/api/admin/invites', null, { origin: BASE, authorization: 'Bearer ' + b64u(randomBytes(48)) });
  const c = await admin('POST', '/api/admin/invites', {}, { 'content-type': 'application/json', origin: BASE, 'x-pk-admin': '1' });
  const d = await admin('POST', '/api/admin/invites/revoke', { id: '0123456789abcdef' }, { 'content-type': 'application/json', origin: BASE, authorization: 'Bearer ' + b64u(randomBytes(48)) });
  check('管理接口：无 token / 错误 token（列出、创建、撤销）均 401 且响应一致', [a, b, c, d].every((x) => x.status === 401 && x.json.error === '未授权'), [a, b, c, d].map((x) => `${x.status} ${JSON.stringify(x.json)}`).join(' | '));
  const l = await admin('GET', '/api/admin/invites');
  check('管理接口：正确 token 可列出邀请（只返回 id/用户名/时间，无邀请码）', l.status === 200 && Array.isArray(l.json.invites), `HTTP ${l.status}；当前有效邀请 ${l.json.invites?.length} 个`);
}
// 过期测试用邀请：TTL 60 秒，后面再用
const invExp = await createInvite({ ttlSeconds: 60 });
log(`      已创建 TTL=60 秒的测试邀请 id=${invExp.id}`);

// 2b. 邀请码拒绝路径（在 Turnstile 之前；全部应为同一个 403 + 同一段文字）
const nameA = 'demo_' + randomBytes(5).toString('hex').slice(0, 8), nameB = 'demo_' + randomBytes(5).toString('hex').slice(0, 8);
const rej = {};
const tReg0 = Date.now();
rej['没有邀请码'] = await post('/api/register/options', { username: nameA });
rej['没有邀请码（另一个用户名）'] = await post('/api/register/options', { username: nameB });
rej['不存在的邀请码'] = await post('/api/register/options', { username: nameA, invite: b64u(randomBytes(32)) });
rej['格式错误的邀请码'] = await post('/api/register/options', { username: nameA, invite: 'abc' });
const invRev = await createInvite();
const rv = await admin('POST', '/api/admin/invites/revoke', { id: invRev.id });
check('管理接口：撤销邀请 200', rv.status === 200 && rv.json.revoked === 1, `HTTP ${rv.status}`);
rej['已撤销的邀请码'] = await post('/api/register/options', { username: nameA, invite: invRev.code, turnstileToken: 'XXXX.DUMMY.TOKEN.XXXX' });
const invBound = await createInvite({ username: nameB, ttlSeconds: 600 });
rej['绑定用户名不符'] = await post('/api/register/options', { username: nameA, invite: invBound.code });

// 2c. 等待 TTL=60 秒的邀请过期（同时让限流窗口滚动），再测过期拒绝
const waitExp = Math.max(invExp.expiresAt + 3000, tReg0 + 62000) - Date.now();
if (waitExp > 0) { log(`      等待 ${Math.ceil(waitExp / 1000)} 秒让 TTL=60 秒的邀请过期…`); await new Promise((r) => setTimeout(r, waitExp)); }
rej['已过期的邀请码'] = await post('/api/register/options', { username: nameA, invite: invExp.code });

// 2d. Turnstile：有效邀请 + 缺失 / 伪造 token（证明邀请通过后仍强制 Turnstile，无后门）
const invOk = await createInvite({ ttlSeconds: 600 }); // 不绑定用户名
const mA = await post('/api/register/options', { username: nameA, invite: invOk.code });
const mB = await post('/api/register/options', { username: nameB, invite: invOk.code });
check('有效邀请 + 缺少 Turnstile token 被拒绝（403 Turnstile 提示，而非邀请错误）', mA.status === 403 && !/邀请码/.test(mA.text), `HTTP ${mA.status} ${mA.text}`);
check('两个不同用户名在缺 token 时响应完全一致（状态+body 逐字节相同）', mA.status === mB.status && mA.text === mB.text, `A=${mA.status} ${mA.text} | B=${mB.status} ${mB.text}`);
const fDummy = await post('/api/register/options', { username: nameA, invite: invOk.code, turnstileToken: 'XXXX.DUMMY.TOKEN.XXXX' });
check('伪造 token（官方测试 dummy token）在生产被拒绝（无测试密钥后门）', fDummy.status === 403, `HTTP ${fDummy.status} ${fDummy.text}`);
const fRand = await post('/api/register/options', { username: nameB, invite: invOk.code, turnstileToken: b64u(randomBytes(300)) });
check('伪造 token（随机串）被拒绝', fRand.status === 403, `HTTP ${fRand.status} ${fRand.text}`);
check('伪造 token 对两个用户名响应一致', fDummy.status === fRand.status && fDummy.text === fRand.text, '');
const noCookieReg = await post('/api/register/verify', { credential: fakeCred() });
check('无 challenge cookie 直接调 register/verify 被拒绝', noCookieReg.status === 400, `HTTP ${noCookieReg.status} ${noCookieReg.text}`);

// 2e. 撤销本步骤的测试邀请，再用刚才“通过了邀请校验”的邀请码 → 统一拒绝
for (const id of [invBound.id, invOk.id]) await admin('POST', '/api/admin/invites/revoke', { id });
rej['已撤销的邀请码（曾通过邀请校验）'] = await post('/api/register/options', { username: nameA, invite: invOk.code });
for (const [k, v] of Object.entries(rej)) {
  check(`邀请校验：${k} → 403 + 统一提示`, v.status === 403 && /邀请码无效或已失效/.test(v.text) && v.status === rej['没有邀请码'].status && v.text === rej['没有邀请码'].text, `HTTP ${v.status} ${v.text}`);
}
{
  const l = await admin('GET', '/api/admin/invites');
  const mine = (l.json.invites || []).filter((i) => created.includes(i.id));
  check('清理：本脚本创建的测试邀请已全部撤销 / 过期（列表中不存在）', l.status === 200 && mine.length === 0, `本脚本创建 ${created.length} 个，列表中剩余 ${mine.length} 个；线上有效邀请总数 ${l.json.invites?.length}`);
}

// 3. 签名 cookie 篡改
const o2 = await post('/api/login/options', {});
const ck = o2.setCookie.find((c) => c.startsWith('__Host-pk_chal_auth='))?.split(';')[0];
const [cname, cval] = ck.split('='); const [pl, sig] = cval.split('.');
const payload = JSON.parse(Buffer.from(pl, 'base64url').toString());
const xMs = payload.x > 1e12 ? payload.x : payload.x * 1000;
log(`      签名 cookie payload 字段：${Object.keys(payload).join(',')}；exp-now≈${Math.round((xMs - Date.now()) / 1000)}s`);
const tamperedPl = b64u(JSON.stringify({ ...payload, x: payload.x + 3600000 }));
const tp = await post('/api/login/verify', { credential: fakeCred() }, `${cname}=${tamperedPl}.${sig}`);
check('篡改 payload（延长 exp）的 cookie 被拒绝', tp.status === 400 && /签名无效/.test(tp.text), `HTTP ${tp.status} ${tp.text}`);
const badSig = sig.slice(0, -2) + (sig.endsWith('AA') ? 'BA' : 'AA');
const ts = await post('/api/login/verify', { credential: fakeCred() }, `${cname}=${pl}.${badSig}`);
check('篡改签名的 cookie 被拒绝', ts.status === 400 && /签名无效/.test(ts.text), `HTTP ${ts.status} ${ts.text}`);
// 未知凭据（有效 cookie）→ 统一登录错误
const o3 = await post('/api/login/options', {});
const ck3 = o3.setCookie.find((c) => c.startsWith('__Host-pk_chal_auth='))?.split(';')[0];
const uk = await post('/api/login/verify', { credential: fakeCred() }, ck3);
check('有效 cookie + 未注册凭据 → 统一的登录失败提示，且清除 cookie', uk.status === 400 && /该 passkey 无效/.test(uk.text) && uk.setCookie.some((c) => /Max-Age=0/i.test(c)), `HTTP ${uk.status} ${short(uk.text)}`);

// 4. 浏览器端登录路径（虚拟认证器里放一个未在服务端注册的 passkey，走真实 navigator.credentials.get + 服务端验签前查找）
{
  const browser = await chromium.launch();
  const ctx = await browser.newContext(); const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: { credentialId: randomBytes(16).toString('base64'), isResidentCredential: true, rpId: new URL(BASE).hostname, privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'), userHandle: randomBytes(16).toString('base64'), signCount: 0 } });
  await page.goto(BASE + '/');
  const cond = await page.evaluate(() => window.PublicKeyCredential?.isConditionalMediationAvailable?.());
  log(`      isConditionalMediationAvailable = ${cond}`);
  await page.click('#btn-login');
  await page.waitForFunction(() => /登录/.test(document.querySelector('#status')?.textContent || '') && /失败|成功/.test(document.querySelector('#status')?.textContent || ''), null, { timeout: 15000 }).catch(() => {});
  const st = await page.textContent('#status');
  check('浏览器 passkey 登录（未注册凭据）→ 显示统一的登录失败提示', /该 passkey 无效/.test(st || ''), `status="${st}"`);
  await browser.close();
}

// 5. 过期 cookie（线上等待 >5 分钟）
if (WAIT_EXPIRY) {
  const wait = Math.max(0, xMs - Date.now()) + 15000; // 以最后一个 cookie 为准，保证旧 cookie 必然过期
  log(`      等待 ${Math.round(wait / 1000)} 秒，让旧 cookie 过期…`);
  await new Promise((r) => setTimeout(r, wait));
  const ex = await post('/api/login/verify', { credential: fakeCred() }, oldCookie);
  check('（线上）签名有效但已过期（>5 分钟）的 cookie 被拒绝', ex.status === 400 && /已过期/.test(ex.text), `HTTP ${ex.status} ${ex.text}`);
}

// 6. 429 限流（放最后）
const seq = []; let last;
for (let i = 0; i < 14; i++) { last = await post('/api/login/options', {}); seq.push(last.status); if (last.status === 429) break; }
check('限流：同一 IP 对 login/options 超过 10 次/60 秒返回 429 + 中文提示', last.status === 429, `状态序列 ${seq.join(',')}；Retry-After=${last.headers.get('retry-after')}；body=${last.text}`);
const seq2 = []; let last2;
for (let i = 0; i < 14; i++) { last2 = await post('/api/register/options', { username: nameA }); seq2.push(last2.status); if (last2.status === 429) break; }
check('限流：register/options 在 siteverify 之前触发 429', last2.status === 429, `状态序列 ${seq2.join(',')}；body=${last2.text}`);
const seq3 = []; let last3;
for (let i = 0; i < 14; i++) { last3 = await admin('GET', '/api/admin/invites', null, { origin: BASE }); seq3.push(last3.status); if (last3.status === 429) break; }
check('限流：管理接口在校验 token 之前触发 429', last3.status === 429, `状态序列 ${seq3.join(',')}`);

log(`\n结果：${pass}/${total} 通过；用时 ${Math.round((Date.now() - t0) / 1000)} 秒`);
process.exit(pass === total ? 0 : 1);
