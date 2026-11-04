// 端到端测试（加固版 + 邀请码）：Playwright + Chromium + CDP 虚拟认证器
// 用法：
//   本地：BASE_URL=http://localhost:8787 node tests/e2e.mjs     （wrangler dev + .dev.vars 中的 Turnstile 测试密钥）
//   线上：BASE_URL=https://passkey-demo.example.workers.dev node tests/e2e.mjs
// 说明：接口有限流（每 IP 每接口 10 次/60 秒），脚本会主动控制节奏，最后才专门触发 429。
// 邀请码：脚本通过管理接口创建测试邀请（本地 token 取自 .dev.vars 的 ADMIN_TOKEN，线上取自 .admin-token），
//         token 和邀请码明文都不会打印；结束前撤销所有本脚本创建且未用掉的邀请。
import { chromium, request as pwRequest } from 'playwright';
import { mkdirSync, readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';

const BASE = (process.env.BASE_URL || 'http://localhost:8787').replace(/\/$/, '');
const ORIGIN = new URL(BASE).origin;
const LOCAL = new URL(BASE).hostname === 'localhost';
const SHOT = process.env.SHOT || (LOCAL ? 'shots/logged-in-local.png' : 'shots/logged-in.png');
const HEADED = process.env.HEADED === '1';
const rand = () => Math.random().toString(36).slice(2, 10);
const user = 'demo_' + rand();
const results = [];
const T0 = Date.now();
function check(name, ok, detail = '') {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
}
const log = (...a) => console.log('     ', ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const short = (s, n = 160) => (s.length > n ? s.slice(0, n) + '…' : s);

// ---- 限流节奏控制：每个接口 60 秒内最多发 8 次（留余量）----
const hits = {};
async function budget(path, n = 1) {
  hits[path] ||= [];
  for (;;) {
    const now = Date.now();
    hits[path] = hits[path].filter((t) => now - t < 62000);
    if (hits[path].length + n <= 8) break;
    const wait = 62000 - (now - hits[path][0]) + 200;
    log(`[节奏控制] ${path} 已用 ${hits[path].length} 次，等待 ${Math.ceil(wait / 1000)} 秒以免触发限流…`);
    await sleep(wait);
  }
  for (let i = 0; i < n; i++) hits[path].push(Date.now());
}

// ---- 管理接口（创建 / 撤销测试邀请）----
const ADMIN_TOKEN = LOCAL
  ? /^ADMIN_TOKEN=(.+)$/m.exec(readFileSync('.dev.vars', 'utf8'))[1].trim()
  : readFileSync('.admin-token', 'utf8').trim();
const AH = { 'Content-Type': 'application/json', Origin: ORIGIN, Authorization: `Bearer ${ADMIN_TOKEN}` };
const INVITE_ERR = /邀请码无效或已失效/;
const created = []; // 本脚本创建的邀请（用于结束前清理）
async function adminFetch(method, path, body, headers = AH) {
  await budget('/api/admin/invites' + (path.endsWith('/revoke') ? '/revoke' : ''));
  const r = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}
async function createInvite(opts = {}) {
  const r = await adminFetch('POST', '/api/admin/invites', opts);
  if (r.status !== 200) throw new Error(`创建邀请失败 HTTP ${r.status}`);
  created.push(r.json.id);
  return r.json; // { code, id, username, expiresAt, link }
}
const revokeInvite = (id) => adminFetch('POST', '/api/admin/invites/revoke', { id });
const listInvites = async () => (await adminFetch('GET', '/api/admin/invites')).json.invites || [];

const browser = await chromium.launch({ headless: !HEADED });
const context = await browser.newContext({ locale: 'zh-CN' });
const page = await context.newPage();
page.on('pageerror', (e) => log('pageerror:', e.message));
page.on('console', (m) => { if (m.type() === 'error') log('console.error:', short(m.text())); });
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
async function newAuthenticator() {
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  return authenticatorId;
}
let authId = await newAuthenticator();
const api = await pwRequest.newContext();
const H = { 'Content-Type': 'application/json', Origin: ORIGIN };

const status = () => page.locator('#status').innerText();
const count = async () => Number(await page.locator('#me-count').innerText());
async function waitStatus(re, timeout = 20000) {
  await page.waitForFunction((src) => new RegExp(src).test(document.getElementById('status').textContent), re.source, { timeout });
  return status();
}
async function clearStatus() { await page.evaluate(() => { document.getElementById('status').textContent = ''; }); }
async function waitToken(timeout = 45000) {
  const h = await page.waitForFunction(() => window.__pk && window.__pk.getTurnstileToken(), null, { timeout, polling: 250 });
  return h.jsonValue();
}
function cookieFrom(header, name) {
  return (header || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(name + '='))?.slice(name.length + 1) || null;
}

console.log(`BASE_URL=${BASE}  测试用户=${user}  模式=${LOCAL ? '本地（Turnstile 测试密钥）' : '线上（真实 Turnstile）'}  headed=${HEADED}`);

// 0. 线上过期测试：先拿一个登录 challenge cookie，脚本最后（>5 分钟后）再用
let oldAuthCookie = null;
if (!LOCAL) {
  await budget('/api/login/options');
  const r = await api.post(BASE + '/api/login/options', { headers: H, data: '{}' });
  oldAuthCookie = cookieFrom((r.headers()['set-cookie'] || '').split('\n').find((l) => l.startsWith('__Host-pk_chal_auth=')), '__Host-pk_chal_auth');
  log('已获取一个旧的登录 challenge cookie（用于 >5 分钟后的过期测试），HTTP', r.status());
}

// 0b. 过期测试用邀请：TTL 60 秒（KV expiration 的最小值），脚本后面（>60 秒后）再使用
const invExpiring = await createInvite({ ttlSeconds: 60 });
log(`已创建 TTL=60 秒的测试邀请 id=${invExpiring.id}（稍后验证过期拒绝）`);

// 1. 页面
const home = await page.goto(BASE + '/');
check('首页返回 200', home.status() === 200, `HTTP ${home.status()}`);
const csp = home.headers()['content-security-policy'] || '';
check('CSP 放行 Turnstile（script-src/frame-src challenges.cloudflare.com）', /script-src 'self' https:\/\/challenges\.cloudflare\.com/.test(csp) && /frame-src https:\/\/challenges\.cloudflare\.com/.test(csp));
await page.locator('#anon').waitFor();

// 2. Turnstile 小组件
let token = null;
try { token = await waitToken(); } catch { /* 下面判断 */ }
check('Turnstile 小组件渲染并返回 token', !!token, token ? `token 长度 ${token.length}${token === 'XXXX.DUMMY.TOKEN.XXXX' ? '（测试密钥 dummy token）' : ''}` : '45 秒内未拿到 token');
if (!token) {
  await page.screenshot({ path: 'shots/turnstile-fail.png', fullPage: true });
  log('Turnstile 未通过，已截图 shots/turnstile-fail.png；无法继续注册流程。');
}

// 3. 注册（抓取 register/verify 的请求，用于后续重放/用途混用测试）
let capReg = null;
await page.route('**/api/register/verify', async (route) => {
  const req = route.request();
  if (!capReg) capReg = { body: req.postData(), cookie: cookieFrom((await req.allHeaders())['cookie'], '__Host-pk_chal_reg') };
  await route.continue();
});
let registered = false;
const inv1 = await createInvite();
if (token) {
  await budget('/api/register/options'); await budget('/api/register/verify');
  await page.fill('#reg-invite', inv1.code);
  await page.fill('#reg-username', user);
  await page.click('#btn-register');
  log('status:', await waitStatus(/注册成功|注册失败/));
  registered = await page.locator('#authed').waitFor({ timeout: 10000 }).then(() => true).catch(() => false);
}
await page.unroute('**/api/register/verify');
check('有效邀请码：注册新用户后进入已登录视图', registered && (await page.locator('#me-name').innerText()) === user);
check('注册成功后邀请立即失效（管理列表中已不存在）', !(await listInvites()).some((i) => i.id === inv1.id));
if (!registered) { await finish(); }
check('已绑定 passkey 数量 = 1', (await count()) === 1);

// 4. 同一认证器再次添加 → excludeCredentials 阻止
await clearStatus(); await budget('/api/register/options');
await page.click('#btn-add');
const exStatus = await waitStatus(/注册成功|注册失败/);
check('excludeCredentials：同一认证器不能重复注册', /已经有该账号的 passkey/.test(exStatus) && (await count()) === 1, exStatus);

// 5. 换新认证器添加到 5 个（已登录添加不需要 Turnstile）
for (let i = 2; i <= 5; i++) {
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: authId });
  authId = await newAuthenticator();
  await clearStatus(); await budget('/api/register/options'); await budget('/api/register/verify');
  await page.click('#btn-add');
  await waitStatus(/注册成功|注册失败/);
  await page.waitForFunction((n) => document.getElementById('me-count').textContent === String(n), i, { timeout: 10000 }).catch(() => {});
  check(`添加第 ${i} 个 passkey 后列表显示 ${i} 个`, (await count()) === i, await status());
}
check('达到 5 个后“添加”按钮被禁用', await page.locator('#btn-add').isDisabled());

// 6. 第 6 个
await budget('/api/register/options');
const sixth = await page.evaluate(async () => {
  const r = await fetch('/api/register/options', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  return { status: r.status, body: await r.text() };
});
check('第 6 个 passkey 被拒绝', sixth.status === 400 && /最多只能绑定 5 个/.test(sixth.body), `HTTP ${sixth.status} ${sixth.body}`);

// 7. 退出
await budget('/api/logout');
await page.click('#btn-logout');
await page.locator('#anon').waitFor();
const meAfter = await page.evaluate(() => fetch('/api/me').then((r) => r.json()));
check('退出后 /api/me 为未登录', meAfter.loggedIn === false, JSON.stringify(meAfter));
check('退出后会话 cookie 已清除', !(await context.cookies()).some((c) => c.name === '__Host-pk_sess'));

// 8. Turnstile：缺少 / 伪造 token（带有效邀请码，证明邀请通过后仍强制 Turnstile）
const invProbe = await createInvite();
await budget('/api/register/options', 2);
const noTok = await api.post(BASE + '/api/register/options', { headers: H, data: JSON.stringify({ username: 'demo_' + rand(), invite: invProbe.code }) });
const noTokBody = await noTok.text();
check('有效邀请 + 缺少 Turnstile token 的注册被拒绝', noTok.status() === 403 && !INVITE_ERR.test(noTokBody), `HTTP ${noTok.status()} ${noTokBody}`);
const forged = await api.post(BASE + '/api/register/options', { headers: H, data: JSON.stringify({ username: 'demo_' + rand(), invite: invProbe.code, turnstileToken: 'forged.' + rand() + '.token' }) });
const forgedBody = await forged.text();
if (LOCAL) {
  log(`伪造 token（本地测试密钥 1x… 对任何 token 都返回 success，所以本地无法测伪造）：HTTP ${forged.status()} ${short(forgedBody, 80)}`);
} else {
  check('伪造的 Turnstile token 被拒绝', forged.status() === 403, `HTTP ${forged.status()} ${forgedBody}`);
}

// 9. 用户名存在 / 不存在：options 阶段响应一致
async function freshToken() {
  await page.evaluate(() => { if (window.turnstile) window.turnstile.reset(); });
  await page.waitForFunction(() => !window.__pk.getTurnstileToken(), null, { timeout: 5000 }).catch(() => {});
  return waitToken();
}
function shape(o) {
  const x = JSON.parse(JSON.stringify(o));
  x.options.challenge = '<random>'; x.options.user.id = '<random>'; x.options.user.name = '<name>'; x.options.user.displayName = '<name>';
  return JSON.stringify(x);
}
const other = 'demo_' + rand();
const probes = [];
for (const [label, name] of [['已存在', user], ['不存在', other], ['已存在', user], ['不存在', other]]) {
  const t = LOCAL ? 'XXXX.DUMMY.TOKEN.XXXX' : await freshToken().catch(() => null);
  if (!t) { log('拿不到新的 Turnstile token，跳过一次探测'); continue; }
  await budget('/api/register/options');
  const t1 = Date.now();
  const r = await api.post(BASE + '/api/register/options', { headers: H, data: JSON.stringify({ username: name, invite: invProbe.code, turnstileToken: t }) });
  const ms = Date.now() - t1;
  const body = await r.json().catch(() => ({}));
  probes.push({ label, status: r.status(), ms, shape: r.ok() ? shape(body) : JSON.stringify(body), exclude: body.options?.excludeCredentials?.length, setCookie: !!r.headers()['set-cookie'] });
}
for (const p of probes) log(`${p.label}用户名：HTTP ${p.status}，${p.ms} ms，excludeCredentials=${p.exclude}，Set-Cookie=${p.setCookie}`);
const ex = probes.filter((p) => p.label === '已存在'), ne = probes.filter((p) => p.label === '不存在');
check('options 阶段：已存在与不存在的用户名返回相同状态码与相同结构（随机字段除外）',
  ex.length > 0 && ne.length > 0 && probes.every((p) => p.status === 200 && p.shape === probes[0].shape),
  `状态码 ${probes.map((p) => p.status).join('/')}；结构一致=${probes.every((p) => p.shape === probes[0]?.shape)}`);
if (probes[0]) log('options 响应结构（随机字段已替换）：', short(probes[0].shape, 400));
// 没有 Turnstile token 时，两种用户名的响应体逐字节一致
await budget('/api/register/options', 2);
const n1 = await api.post(BASE + '/api/register/options', { headers: H, data: JSON.stringify({ username: user, invite: invProbe.code }) });
const n2 = await api.post(BASE + '/api/register/options', { headers: H, data: JSON.stringify({ username: other, invite: invProbe.code }) });
const [b1, b2] = [await n1.text(), await n2.text()];
check('无 token 时两种用户名的状态码与响应体完全一致', n1.status() === n2.status() && b1 === b2, `HTTP ${n1.status()}/${n2.status()} ${b1}`);

// 10. verify 阶段：未登录给“已存在用户名”注册 → 统一失败
await clearStatus();
await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: authId });
authId = await newAuthenticator();
const tk2 = LOCAL ? await freshToken() : await freshToken().catch(() => null);
if (tk2) {
  await budget('/api/register/options'); await budget('/api/register/verify');
  await page.fill('#reg-invite', invProbe.code);
  await page.fill('#reg-username', user);
  await page.click('#btn-register');
  const st = await waitStatus(/注册成功|注册失败/);
  check('未登录给已存在用户名注册 → verify 返回统一失败（防接管 + 不泄露原因）', /该用户名不可用或请求无效/.test(st) && !(await page.locator('#authed').isVisible()), st);
  check('注册失败时不消耗邀请（邀请仍在列表中）', (await listInvites()).some((i) => i.id === invProbe.id));
} else log('拿不到新的 Turnstile token，跳过 verify 阶段统一失败测试');

// 11. 注册重放：同一 body + 同一签名 cookie
if (capReg?.cookie) {
  await budget('/api/register/verify');
  const rr = await api.post(BASE + '/api/register/verify', { headers: { ...H, Cookie: `__Host-pk_chal_reg=${capReg.cookie}` }, data: capReg.body });
  const rt = await rr.text();
  // 首先被“邀请已用掉”拦下（403 统一邀请错误）；即使没有邀请这一层，也会被凭据 ID 去重 / 用户已存在拦下（400）
  check('重放注册响应被拒绝（challenge 已由 DO 原子作废 → 400；或邀请已用掉 → 统一邀请错误）', (rr.status() === 400 && /challenge 已被使用/.test(rt)) || (rr.status() === 403 && INVITE_ERR.test(rt)), `HTTP ${rr.status()} ${rt}`);
}

// 12. 可发现凭据登录 + 抓取 verify
// 用第 5 个认证器之前的凭据都已被删除，换回一个已注册的认证器不可行；这里重新用 UI 登录需要一个仍在的认证器。
// 第 10 步新建的认证器里有一个“未登记”的凭据（verify 失败），所以再换一个认证器并给它导入不了……
// 简化：重新注册一个新用户做登录相关测试。
await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: authId });
authId = await newAuthenticator();
const user2 = 'demo_' + rand();
// 绑定用户名的邀请 + 邀请链接自动填充
const inv2 = await createInvite({ username: user2 });
check('创建绑定用户名的邀请：返回 id / 链接，绑定用户名正确', /^[0-9a-f]{16}$/.test(inv2.id) && inv2.username === user2 && inv2.link.includes('#invite=') && inv2.link.includes(`u=${user2}`));
await page.goto(inv2.link.replace(/^https?:\/\/[^/]+/, BASE));
await page.locator('#anon').waitFor();
const filled = { invite: await page.inputValue('#reg-invite'), user: await page.inputValue('#reg-username'), url: page.url() };
check('打开邀请链接：自动填入邀请码和用户名，并从地址栏移除邀请码', filled.invite === inv2.code && filled.user === user2 && !filled.url.includes(inv2.code), `url=${filled.url.replace(inv2.code, '<code>')}`);
const tk3 = await waitToken().catch(() => null);
let loginOk = false, capLogin = null;
if (tk3) {
  await clearStatus(); await budget('/api/register/options'); await budget('/api/register/verify');
  await page.click('#btn-register');
  await waitStatus(/注册成功|注册失败/);
  await page.locator('#authed').waitFor();
  check('绑定用户名的邀请：用绑定的用户名注册成功', (await page.locator('#me-name').innerText()) === user2);
  await budget('/api/logout');
  await page.click('#btn-logout');
  await page.locator('#anon').waitFor();
  await page.route('**/api/login/verify', async (route) => {
    const req = route.request();
    if (!capLogin) capLogin = { body: req.postData(), cookie: cookieFrom((await req.allHeaders())['cookie'], '__Host-pk_chal_auth') };
    await route.continue();
  });
  await clearStatus(); await budget('/api/login/options'); await budget('/api/login/verify');
  await page.click('#btn-login');
  log('status:', await waitStatus(/登录成功|登录失败/));
  loginOk = await page.locator('#authed').waitFor({ timeout: 10000 }).then(() => true).catch(() => false);
  await page.unroute('**/api/login/verify');
}
check('可发现凭据登录（无用户名）成功', loginOk && (await page.locator('#me-name').innerText().catch(() => '')) === user2, `用户 ${user2}`);

// 13. 登录重放
if (capLogin?.cookie) {
  await budget('/api/login/verify');
  const rp = await api.post(BASE + '/api/login/verify', { headers: { ...H, Cookie: `__Host-pk_chal_auth=${capLogin.cookie}` }, data: capLogin.body });
  check('重放同一登录响应被拒绝（KV used 标记）', rp.status() === 400, `HTTP ${rp.status()} ${await rp.text()}`);
}

// 14. 陈旧 challenge（签 #1，cookie 已是 #2）
await budget('/api/login/options', 2); await budget('/api/login/verify');
const stale = await page.evaluate(async () => {
  const post = (p, b) => fetch(p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) });
  const o1 = (await (await post('/api/login/options', {})).json()).options;
  const o2 = (await (await post('/api/login/options', {})).json()).options;
  const cred = await window.__pk.startAuthentication({ optionsJSON: o1 });
  const r = await post('/api/login/verify', { credential: cred });
  return { c1: o1.challenge.slice(0, 8) + '…', c2: o2.challenge.slice(0, 8) + '…', status: r.status, body: await r.text() };
});
check('基于陈旧 challenge 的响应被拒绝', stale.status === 400, `challenge#1=${stale.c1} 当前=${stale.c2} → HTTP ${stale.status} ${short(stale.body, 120)}`);

// 15. 篡改 challenge cookie
await budget('/api/login/options');
const lo = await api.post(BASE + '/api/login/options', { headers: H, data: '{}' });
const good = cookieFrom((lo.headers()['set-cookie'] || '').split('\n').find((l) => l.startsWith('__Host-pk_chal_auth=')), '__Host-pk_chal_auth');
const [pl, sg] = good.split('.');
const payload = JSON.parse(Buffer.from(pl, 'base64url').toString());
const tamperedPayload = Buffer.from(JSON.stringify({ ...payload, x: payload.x + 3600_000 })).toString('base64url') + '.' + sg;
const flip = (s, i) => s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1);
const tamperedSig = pl + '.' + flip(sg, 5);
const body = capLogin?.body || JSON.stringify({ credential: { id: 'AAAA', rawId: 'AAAA', type: 'public-key', response: { clientDataJSON: 'AAAA', authenticatorData: 'AAAA', signature: 'AAAA' } } });
for (const [label, val] of [['篡改 payload（延长 exp）', tamperedPayload], ['篡改签名', tamperedSig]]) {
  await budget('/api/login/verify');
  const r = await api.post(BASE + '/api/login/verify', { headers: { ...H, Cookie: `__Host-pk_chal_auth=${val}` }, data: body });
  const t = await r.text();
  check(`被${label}的 challenge cookie 被拒绝`, r.status() === 400 && /签名无效/.test(t), `HTTP ${r.status()} ${t}`);
}
log('签名 cookie payload 字段：', Object.keys(payload).join(','), `（p=${payload.p} f=${payload.f} u="${payload.u}"，exp-now≈${Math.round((payload.x - Date.now()) / 1000)}s）`);

// 16. 用途混用：注册 cookie 当登录 cookie 用（签名有效，但 purpose 不符）
if (capReg?.cookie) {
  await budget('/api/login/verify');
  const r = await api.post(BASE + '/api/login/verify', { headers: { ...H, Cookie: `__Host-pk_chal_auth=${capReg.cookie}` }, data: body });
  const t = await r.text();
  check('注册用途的 cookie 不能用于登录（purpose 校验）', r.status() === 400 && /(用途不匹配|已过期)/.test(t), `HTTP ${r.status()} ${t}`);
}

// 17. 过期 cookie
if (LOCAL) {
  // 本地：用 .dev.vars 中的本地 HMAC 密钥签一个 exp 已过去的 payload（这个密钥只存在于本地，线上是另一个随机密钥）
  const key = Buffer.from(/^CHAL_HMAC_KEY=(.+)$/m.exec(readFileSync('.dev.vars', 'utf8'))[1].trim(), 'base64');
  const pe = Buffer.from(JSON.stringify({ ...payload, x: Date.now() - 1000 })).toString('base64url');
  const expired = pe + '.' + createHmac('sha256', key).update(pe).digest('base64url');
  await budget('/api/login/verify');
  const r = await api.post(BASE + '/api/login/verify', { headers: { ...H, Cookie: `__Host-pk_chal_auth=${expired}` }, data: body });
  const t = await r.text();
  check('（本地）签名有效但已过期的 cookie 被拒绝', r.status() === 400 && /已过期/.test(t), `HTTP ${r.status()} ${t}`);
}

// 18. 其他输入校验
const noOrigin = await api.post(BASE + '/api/me', { headers: { 'Content-Type': 'application/json' }, data: '{}' });
log('（POST /api/me 不存在的路由）HTTP', noOrigin.status());
await budget('/api/login/options');
const badOrigin = await api.post(BASE + '/api/login/options', { headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' }, data: '{}' });
check('错误 Origin 的 POST 被拒绝', badOrigin.status() === 403, `HTTP ${badOrigin.status()} ${await badOrigin.text()}`);
await budget('/api/register/options');
const badName = await api.post(BASE + '/api/register/options', { headers: H, data: JSON.stringify({ username: 'a!' }) });
check('非法用户名被拒绝', badName.status() === 400, `HTTP ${badName.status()} ${await badName.text()}`);
await budget('/api/login/verify');
const big = await api.post(BASE + '/api/login/verify', { headers: H, data: JSON.stringify({ pad: 'x'.repeat(20000) }) });
check('超大请求体被拒绝', big.status() === 413, `HTTP ${big.status()} ${await big.text()}`);

// 18b. 邀请码拒绝路径（全部应返回同一个 403 + 同一段文字）
async function regOpt(username, invite) {
  await budget('/api/register/options');
  const r = await api.post(BASE + '/api/register/options', { headers: H, data: JSON.stringify({ username, invite, turnstileToken: LOCAL ? 'XXXX.DUMMY.TOKEN.XXXX' : undefined }) });
  return { status: r.status(), body: await r.text() };
}
const invRej = {};
invRej['没有邀请码'] = await regOpt('demo_' + rand(), undefined);
invRej['格式错误的邀请码'] = await regOpt('demo_' + rand(), 'abc');
invRej['不存在的邀请码（格式正确）'] = await regOpt('demo_' + rand(), Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url'));
invRej['已用过的邀请码'] = await regOpt('demo_' + rand(), inv1.code);
const invRev = await createInvite();
const rv = await revokeInvite(invRev.id);
check('管理接口撤销邀请返回 200', rv.status === 200 && rv.json.revoked === 1, `HTTP ${rv.status} ${JSON.stringify(rv.json)}`);
invRej['已撤销的邀请码'] = await regOpt('demo_' + rand(), invRev.code);
const rv2 = await revokeInvite(invRev.id);
check('重复撤销返回 404', rv2.status === 404, `HTTP ${rv2.status}`);
const invBound = await createInvite({ username: 'demo_bound_' + rand().slice(0, 4) });
invRej['绑定用户名不符'] = await regOpt('demo_' + rand(), invBound.code);
const okBound = await regOpt(invBound.username, invBound.code);
check('绑定用户名的邀请：用绑定的用户名请求 options 通过（对照组）', okBound.status === 200, `HTTP ${okBound.status}`);
await revokeInvite(invBound.id);
const leftExp = invExpiring.expiresAt + 3000 - Date.now();
if (leftExp > 0) { log(`等待 ${Math.ceil(leftExp / 1000)} 秒让 TTL=60 秒的邀请过期…`); await sleep(leftExp); }
invRej['已过期的邀请码'] = await regOpt('demo_' + rand(), invExpiring.code);
const ref = invRej['没有邀请码'];
for (const [k, v] of Object.entries(invRej)) {
  check(`邀请校验：${k} → 拒绝注册（403 + 统一提示）`, v.status === 403 && INVITE_ERR.test(v.body) && v.status === ref.status && v.body === ref.body, `HTTP ${v.status} ${v.body}`);
}

// 18c. options 之后、verify 之前邀请被撤销 → verify 拒绝且不写入任何数据
await budget('/api/logout');
await page.click('#btn-logout');
await page.locator('#anon').waitFor();
await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: authId });
authId = await newAuthenticator();
const user3 = 'demo_' + rand();
const inv3 = await createInvite();
let revokedMid = false;
await page.route('**/api/register/verify', async (route) => {
  if (!revokedMid) { revokedMid = (await revokeInvite(inv3.id)).status === 200; }
  await route.continue();
});
const tk4 = await freshToken().catch(() => null);
await clearStatus(); await budget('/api/register/options'); await budget('/api/register/verify');
await page.fill('#reg-invite', inv3.code);
await page.fill('#reg-username', user3);
await page.click('#btn-register');
const st3 = await waitStatus(/注册成功|注册失败/);
await page.unroute('**/api/register/verify');
check('options 后邀请被撤销 → verify 拒绝（统一提示，不登录）', !!tk4 && revokedMid && INVITE_ERR.test(st3) && !(await page.locator('#authed').isVisible()), st3);
// 证明上面没有写入：同一用户名用新邀请仍可注册
const inv4 = await createInvite({ username: user3 });
await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: authId });
authId = await newAuthenticator();
await freshToken().catch(() => null);
await clearStatus(); await budget('/api/register/options'); await budget('/api/register/verify');
await page.fill('#reg-invite', inv4.code);
await page.fill('#reg-username', user3);
await page.click('#btn-register');
const st4 = await waitStatus(/注册成功|注册失败/);
await page.waitForFunction((u) => document.getElementById('me-name')?.textContent === u, user3, { timeout: 10000 }).catch(() => {});
check('被拒绝的 verify 没有写入用户：同一用户名换新邀请仍可注册', /注册成功/.test(st4) && (await page.locator('#me-name').innerText().catch(() => '')) === user3, st4);

// 18d. 管理接口鉴权
const adm = {};
adm['没有 Authorization'] = await adminFetch('GET', '/api/admin/invites', null, { Origin: ORIGIN, 'X-PK-Admin': '1' });
adm['错误的 token'] = await adminFetch('GET', '/api/admin/invites', null, { Origin: ORIGIN, Authorization: 'Bearer ' + Buffer.from(crypto.getRandomValues(new Uint8Array(48))).toString('base64url') });
adm['错误的方案（Basic）'] = await adminFetch('GET', '/api/admin/invites', null, { Origin: ORIGIN, Authorization: 'Basic dXNlcjpwYXNz' });
adm['无 token 创建邀请'] = await adminFetch('POST', '/api/admin/invites', {}, { 'Content-Type': 'application/json', Origin: ORIGIN, 'X-PK-Admin': '1' });
adm['错误 token 撤销邀请'] = await adminFetch('POST', '/api/admin/invites/revoke', { id: '0123456789abcdef' }, { 'Content-Type': 'application/json', Origin: ORIGIN, Authorization: 'Bearer ' + 'x'.repeat(64) });
for (const [k, v] of Object.entries(adm)) check(`管理接口：${k} → 401`, v.status === 401 && v.json.error === '未授权', `HTTP ${v.status} ${JSON.stringify(v.json)}`);
const lst = await adminFetch('GET', '/api/admin/invites');
const lstText = JSON.stringify(lst.json);
check('管理接口：正确 token 可列出邀请，列表不含任何邀请码明文或哈希全文', lst.status === 200 && Array.isArray(lst.json.invites) && ![inv1, invProbe, inv2, inv3, inv4, invExpiring].some((i) => lstText.includes(i.code)) && !/[0-9a-f]{64}/.test(lstText), `${lst.json.invites?.length} 个有效邀请`);
const badTtl = await adminFetch('POST', '/api/admin/invites', { ttlSeconds: 10 });
check('管理接口：TTL 小于 60 秒被拒绝（400）', badTtl.status === 400, `HTTP ${badTtl.status}`);

// 19. 截图
await page.locator('#authed').waitFor();
await page.evaluate(() => { document.getElementById('debug').open = true; });
mkdirSync('shots', { recursive: true });
await page.screenshot({ path: SHOT, fullPage: true });
const pageText = await page.locator('body').innerText();
check('页面文本中不包含任何 cookie 值', !(await context.cookies()).some((c) => c.value && c.value.length > 8 && pageText.includes(c.value)));
log('截图已保存：', SHOT);

// 20. 线上：>5 分钟的旧 cookie
if (oldAuthCookie) {
  const left = 300_000 + 15_000 - (Date.now() - T0);
  if (left > 0) { log(`等待 ${Math.ceil(left / 1000)} 秒，让第 0 步拿到的 cookie 超过 5 分钟…`); await sleep(left); }
  const r = await api.post(BASE + '/api/login/verify', { headers: { ...H, Cookie: `__Host-pk_chal_auth=${oldAuthCookie}` }, data: body });
  const t = await r.text();
  check(`（线上）${Math.round((Date.now() - T0) / 1000)} 秒前签发的真实 cookie 已过期被拒绝`, r.status() === 400 && /已过期/.test(t), `HTTP ${r.status()} ${t}`);
}

// 21. 限流：连续请求 /api/login/options（options 阶段不写 KV）
const statuses = [];
let body429 = '', retryAfter = '';
for (let i = 0; i < 25; i++) {
  const r = await api.post(BASE + '/api/login/options', { headers: H, data: '{}' });
  statuses.push(r.status());
  if (r.status() === 429) { body429 = await r.text(); retryAfter = r.headers()['retry-after']; break; }
}
check('限流：同一 IP 超过 10 次/60 秒返回 429 + 中文提示', statuses.includes(429) && /请求过于频繁/.test(body429), `状态序列 ${statuses.join(',')}；Retry-After=${retryAfter}；body=${body429}`);

// 22. 清理：撤销本脚本创建的、仍有效的邀请，然后确认一个都不剩
const still = (await listInvites()).filter((i) => created.includes(i.id));
for (const i of still) await revokeInvite(i.id);
const remain = (await listInvites()).filter((i) => created.includes(i.id));
check('清理：本脚本创建的测试邀请已全部撤销 / 用掉', remain.length === 0, `撤销 ${still.length} 个，剩余 ${remain.length} 个`);

// 23. 管理接口限流（放最后）
const aseq = []; let a429 = '';
for (let i = 0; i < 14; i++) {
  const r = await fetch(BASE + '/api/admin/invites', { headers: { Origin: ORIGIN } });
  aseq.push(r.status);
  if (r.status === 429) { a429 = await r.text(); break; }
}
check('管理接口限流：超过 10 次/60 秒返回 429（在校验 token 之前）', aseq.includes(429), `状态序列 ${aseq.join(',')}；${a429}`);

console.log(`\n测试用户：${user}、${user2}、${user3}`);
await finish();

async function finish() {
  await api.dispose();
  await browser.close();
  const failed = results.filter((r) => !r.ok).length;
  console.log(`结果：${results.length - failed}/${results.length} 通过；用时 ${Math.round((Date.now() - T0) / 1000)} 秒`);
  process.exit(failed ? 1 : 0);
}
