// 网页邀请管理（/admin）测试：Playwright + Chromium + CDP 虚拟认证器
// 用法：
//   本地：node tests/admin-ui.mjs（脚本自己启动 wrangler dev，使用全新的本地 KV 目录，端口 8787 须空闲）
//         阶段 1：PRINCIPALS 取 wrangler.toml 的默认值（本地不存在该用户），用 Bearer 邀请注册测试用户；
//         阶段 2：重启 wrangler dev，--var PRINCIPALS:e2e_principal,e2e_ghost，测试三种角色、越权、无角色、未登录、跨站。
//   线上：BASE_URL=https://passkey-demo.example.workers.dev node tests/admin-ui.mjs
//         线上注册需要真人通过 Turnstile，脚本没有带角色的 passkey 会话：只测拒绝路径、静态资源、邀请链接自动填充，以及（应急 Bearer 入口）接口逻辑。
// 不打印任何 token、邀请码、会话 cookie 明文；结束前撤销本脚本创建的所有邀请。
import { randomBytes } from 'node:crypto';
import { chromium } from 'playwright';
import { readFileSync, mkdirSync } from 'node:fs';
import { spawn } from 'node:child_process';

const BASE = (process.env.BASE_URL || 'http://localhost:8787').replace(/\/$/, '');
const ORIGIN = new URL(BASE).origin;
const LOCAL = new URL(BASE).hostname === 'localhost';
const P_USER = 'e2e_principal', L_USER = 'e2e_lead', I_USER = 'e2e_inviter', I2_USER = 'e2e_inviter2', GHOST = 'e2e_ghost';

// ---- 本地：由脚本管理 wrangler dev ----
let dev = null;
const PERSIST = `/tmp/pk-admin-${Date.now()}`;
async function startDev(extra = []) {
  mkdirSync(PERSIST, { recursive: true });
  dev = spawn('npx', ['wrangler', 'dev', '--port', '8787', '--persist-to', PERSIST, ...extra], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  dev.stdout.on('data', (d) => { out += d; });
  dev.stderr.on('data', (d) => { out += d; });
  for (let i = 0; i < 120; i++) {
    await sleep(500);
    if (/Ready on/.test(out)) { await sleep(500); return; }
  }
  console.log(out.slice(-800));
  throw new Error('wrangler dev 启动超时');
}
async function stopDev() {
  if (!dev) return;
  try { process.kill(-dev.pid, 'SIGTERM'); } catch { /* 已退出 */ }
  await sleep(2500);
  dev = null;
}
const rand = () => randomBytes(5).toString('hex').slice(0, 8);
const results = [];
const T0 = Date.now();
function check(name, ok, detail = '') {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
}
const log = (...a) => console.log('     ', ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const INVITE_RE = /^[A-Za-z0-9_-]{43}$/;
const INVITE_ERR = /邀请码无效或已失效/;

// ---- 限流节奏（RL_ADMIN 按路径 + IP：/admin、/api/admin/invites、/api/admin/invites/revoke 各 10 次/60 秒）----
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
const LIST = '/api/admin/invites', REVOKE = '/api/admin/invites/revoke', PAGE = '/admin', MEM = '/api/admin/members';

// ---- 应急 Bearer 入口（本地 token 取自 .dev.vars，线上取自 .admin-token；不打印）----
const TOKEN = LOCAL ? /^ADMIN_TOKEN=(.+)$/m.exec(readFileSync('.dev.vars', 'utf8'))[1].trim() : readFileSync('.admin-token', 'utf8').trim();
const BH = { 'Content-Type': 'application/json', Origin: ORIGIN, Authorization: `Bearer ${TOKEN}` };
const created = new Set();
async function raw(method, path, { headers = {}, body, cookie } = {}) {
  if (path.startsWith('/api/admin') || path.startsWith('/admin')) await budget(path === PAGE || path.startsWith('/admin') ? PAGE : path);
  const h = { ...headers };
  if (cookie) h.Cookie = cookie;
  const r = await fetch(BASE + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch { /* html */ }
  return { status: r.status, text, json };
}
async function bearerCreate(body = {}) {
  const r = await raw('POST', LIST, { headers: BH, body });
  if (r.status !== 200) throw new Error(`Bearer 创建邀请失败 HTTP ${r.status}`);
  created.add(r.json.id);
  return r.json;
}
const bearerList = async () => (await raw('GET', LIST, { headers: BH })).json?.invites || [];
const bearerRevoke = (id) => raw('POST', REVOKE, { headers: BH, body: { id } });
// KV list 在线上有最长约 60 秒的缓存（最终一致）：按 key 的读取立即生效，list 可能短暂滞后，因此线上轮询最多 ~180 秒（实测超过 90 秒的情况出现过）
async function listUntil(pred, label) {
  const t = Date.now();
  for (;;) {
    const l = await bearerList();
    if (await pred(l)) { if (Date.now() - t > 1000) log(`[最终一致] ${label}：${Math.round((Date.now() - t) / 1000)} 秒后 list 一致`); return l; }
    if (Date.now() - t > (LOCAL ? 20000 : 180000)) return l;
    await sleep(LOCAL ? 1000 : 15000);
  }
}
async function regOpt(username, invite) {
  await budget('/api/register/options');
  return raw('POST', '/api/register/options', { headers: { 'Content-Type': 'application/json', Origin: ORIGIN }, body: { username, invite, turnstileToken: LOCAL ? 'XXXX.DUMMY.TOKEN.XXXX' : undefined } });
}

process.on('exit', () => { if (dev) try { process.kill(-dev.pid, 'SIGTERM'); } catch { /* 已退出 */ } });
if (LOCAL) await startDev();
console.log(`BASE_URL=${BASE}  模式=${LOCAL ? '本地（完整流程）' : '线上（无管理员会话：拒绝路径 + Bearer 应急入口）'}  开始=${new Date().toISOString()}`);

// ===== A. 未登录 =====
const anonPage = await raw('GET', '/admin');
check('未登录访问 /admin → 403 无权访问页（不返回管理页面）', anonPage.status === 403 && /无权访问/.test(anonPage.text) && !/inv-form/.test(anonPage.text), `HTTP ${anonPage.status}`);
for (const p of ['/admin.html', '/admin/', '/Admin']) {
  const r = await raw('GET', p);
  check(`未登录访问别名 ${p} → 403`, r.status === 403 && !/inv-form/.test(r.text), `HTTP ${r.status}`);
}
const anonApi = {
  'GET 列表（带 X-PK-Admin）': await raw('GET', LIST, { headers: { 'X-PK-Admin': '1' } }),
  'POST 创建（同源 Origin + X-PK-Admin）': await raw('POST', LIST, { headers: { 'Content-Type': 'application/json', Origin: ORIGIN, 'X-PK-Admin': '1' }, body: {} }),
  'POST 撤销（同源 Origin + X-PK-Admin）': await raw('POST', REVOKE, { headers: { 'Content-Type': 'application/json', Origin: ORIGIN, 'X-PK-Admin': '1' }, body: { id: '0123456789abcdef' } }),
  'GET 成员角色（带 X-PK-Admin）': await raw('GET', MEM, { headers: { 'X-PK-Admin': '1' } }),
  'POST 分配角色（同源 Origin + X-PK-Admin）': await raw('POST', MEM, { headers: { 'Content-Type': 'application/json', Origin: ORIGIN, 'X-PK-Admin': '1' }, body: { username: 'root_example', role: null } }),
};
for (const [k, v] of Object.entries(anonApi)) check(`未登录调用管理接口：${k} → 401 统一提示`, v.status === 401 && v.json?.error === '未授权', `HTTP ${v.status} ${v.text}`);
const forgedSess = await raw('GET', LIST, { headers: { 'X-PK-Admin': '1' }, cookie: `__Host-pk_sess=${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url')}` });
check('伪造的会话 cookie → 401', forgedSess.status === 401 && forgedSess.json?.error === '未授权', `HTTP ${forgedSess.status}`);

// ===== B. 跨站特征（不带会话也应在读 KV 之前拒绝）=====
const xs = {
  'GET + Origin=https://evil.example': await raw('GET', LIST, { headers: { 'X-PK-Admin': '1', Origin: 'https://evil.example' } }),
  'GET + Sec-Fetch-Site: cross-site': await raw('GET', LIST, { headers: { 'X-PK-Admin': '1', 'Sec-Fetch-Site': 'cross-site' } }),
  'GET + Sec-Fetch-Site: same-site': await raw('GET', LIST, { headers: { 'X-PK-Admin': '1', 'Sec-Fetch-Site': 'same-site' } }),
  'GET 缺少 X-PK-Admin 头': await raw('GET', LIST, {}),
};
for (const [k, v] of Object.entries(xs)) check(`跨站 / CSRF 特征：${k} → 403`, v.status === 403 && /来源校验失败/.test(v.text), `HTTP ${v.status} ${v.text}`);
const xsPost = await raw('POST', LIST, { headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example', 'X-PK-Admin': '1' }, body: {} });
check('跨站 Origin 的 POST 创建 → 403', xsPost.status === 403, `HTTP ${xsPost.status} ${xsPost.text}`);
const xsMem = await raw('POST', MEM, { headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example', 'X-PK-Admin': '1' }, body: { username: 'root_example', role: 'inviter' } });
check('跨站 Origin 的 POST 分配角色 → 403', xsMem.status === 403 && /来源/.test(xsMem.text), `HTTP ${xsMem.status}`);
const xsPage = await raw('GET', '/admin', { headers: { 'Sec-Fetch-Site': 'cross-site' } });
check('从其他站点跳转到 /admin（Sec-Fetch-Site: cross-site）→ 403', xsPage.status === 403, `HTTP ${xsPage.status}`);

// ===== C. 静态资源 =====
for (const [p, ct] of [['/admin.js', /javascript/], ['/style.css', /css/], ['/', /html/]]) {
  const r = await fetch(BASE + p);
  check(`静态资源 ${p} 正常加载`, r.status === 200 && ct.test(r.headers.get('content-type') || ''), `HTTP ${r.status} ${r.headers.get('content-type')}`);
}
const meAnon = await (await fetch(BASE + '/api/me')).json();
check('/api/me 未登录不返回角色', meAnon.loggedIn === false && !meAnon.role);

// ===== D. 应急 Bearer 入口（线上用它验证生成 / 列表 / 撤销的接口逻辑）=====
const bInv = await bearerCreate({ ttlSeconds: 600, username: 'demo_b_' + rand().slice(0, 5) });
check('Bearer：生成邀请返回 id / 链接 / 过期时间', /^[0-9a-f]{16}$/.test(bInv.id) && INVITE_RE.test(bInv.code) && bInv.link.startsWith(ORIGIN + '/#invite=') && bInv.expiresAt - bInv.createdAt === 600000);
let bl = await bearerList();
const bRow = bl.find((i) => i.id === bInv.id);
check('Bearer：列表含新邀请（编号 / 绑定用户名 / 状态 / 创建者），不含邀请码', !!bRow && bRow.username === bInv.username && bRow.status === 'pending' && bRow.createdBy === '#token' && !JSON.stringify(bl).includes(bInv.code), bRow ? JSON.stringify({ ...bRow }) : '未找到');
const probe1 = await regOpt(bInv.username, bInv.code);
check('Bearer 生成的邀请可通过邀请校验（随后被 Turnstile 拦下 / 本地测试密钥放行）', LOCAL ? probe1.status === 200 : probe1.status === 403 && !INVITE_ERR.test(probe1.text) && /人机验证/.test(probe1.text), `HTTP ${probe1.status}`);
const bRv = await bearerRevoke(bInv.id);
check('Bearer：撤销 → 200', bRv.status === 200 && bRv.json?.revoked === 1, `HTTP ${bRv.status}`);
const probe2 = await regOpt(bInv.username, bInv.code);
check('撤销后的邀请被拒绝（403 统一提示）', probe2.status === 403 && INVITE_ERR.test(probe2.text), `HTTP ${probe2.status} ${probe2.text}`);
bl = await listUntil((l) => !l.some((i) => i.id === bInv.id), '撤销后从列表消失');
check('撤销后列表中不再出现', !bl.some((i) => i.id === bInv.id));
const bMem = await raw('GET', MEM, { headers: BH });
const bMemSet = await raw('POST', MEM, { headers: BH, body: { username: 'root_example', role: 'inviter' } });
check('Bearer 应急入口不能查看 / 修改角色 → 403', bMem.status === 403 && bMemSet.status === 403, `HTTP ${bMem.status}/${bMemSet.status}`);
const wrongBearer = await raw('GET', LIST, { headers: { Authorization: 'Bearer ' + 'y'.repeat(64) } });
check('错误 Bearer → 401（带 Authorization 时不回退到会话）', wrongBearer.status === 401 && wrongBearer.json?.error === '未授权', `HTTP ${wrongBearer.status}`);

// ===== E. 本地：三种角色的完整网页流程 =====
const browser = await chromium.launch();
async function newCtx() {
  const context = await browser.newContext({ locale: 'zh-CN', viewport: { width: 1180, height: 900 }, permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await context.newPage();
  page.on('pageerror', (e) => log('pageerror:', e.message));
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  return { context, page };
}

// 线上：邀请链接自动填充（不注册，因为线上 Turnstile 需要真人）
if (!LOCAL) {
  const fu = 'demo_fill_' + rand().slice(0, 5);
  const fInv = await bearerCreate({ ttlSeconds: 600, username: fu });
  const F = await newCtx();
  await F.page.goto(fInv.link);
  await F.page.locator('#anon').waitFor();
  await F.page.waitForFunction(() => document.getElementById('reg-invite').value.length === 43, null, { timeout: 10000 }).catch(() => {});
  const filledCode = (await F.page.inputValue('#reg-invite')) === fInv.code;
  const filledUser = (await F.page.inputValue('#reg-username')) === fu;
  check('线上：打开邀请链接后自动填入邀请码和绑定的用户名', filledCode && filledUser, `邀请码已填入=${filledCode} 用户名已填入=${filledUser}`);
  check('线上：打开邀请链接后地址栏不再保留邀请码', !F.page.url().includes(fInv.code));
  const rv = await bearerRevoke(fInv.id);
  check('线上：自动填充测试用的邀请已撤销', rv.status === 200);
  const after = await regOpt(fu, fInv.code);
  check('线上：撤销后用该邀请注册被拒绝（403 统一提示）', after.status === 403 && INVITE_ERR.test(after.text), `HTTP ${after.status}`);
  log('线上：没有带角色的 passkey 会话（注册需要真人通过 Turnstile），网页签发 / 列表 / 撤销 / 角色分配 —— 线上未测，见本地结果和 docs/acceptance-checklist.md。');
}

if (LOCAL) {
  async function registerVia(page, link, username) {
    await budget('/api/register/options'); await budget('/api/register/verify');
    await page.goto(link.replace(/^https?:\/\/[^/]+/, BASE));
    await page.locator('#anon').waitFor();
    if (username) await page.fill('#reg-username', username);
    await page.waitForFunction(() => window.__pk && window.__pk.getTurnstileToken(), null, { timeout: 30000 });
    await page.click('#btn-register');
    await page.waitForFunction(() => /注册成功|注册失败/.test(document.getElementById('status').textContent), null, { timeout: 20000 });
    return page.locator('#authed').waitFor({ timeout: 10000 }).then(() => true).catch(() => false);
  }
  const cookieHeader = async (context) => (await context.cookies()).filter((c) => c.name === '__Host-pk_sess').map((c) => `${c.name}=${c.value}`).join('; ');
  // 在某个浏览器上下文里发同源管理请求（带 X-PK-Admin）
  async function inPage(page, method, path, body) {
    await budget(path);
    return page.evaluate(async ([method, path, body]) => {
      const go = () => fetch(path, { method, headers: { 'X-PK-Admin': '1', 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    let r = await go();
    // 敏感操作返回 {stepUp:true} 时，用虚拟认证器做一次 step-up 再重试（与页面里的自动 step-up 行为一致）
    if (r.status === 403) { const j = await r.clone().json().catch(() => ({})); const su = (window.__pk && window.__pk.stepUp) || (window.__pkAdmin && window.__pkAdmin.stepUp); if (j.stepUp && su) { await su(); r = await go(); } }
      return { status: r.status, text: await r.text() };
    }, [method, path, body]);
  }
  async function openAdmin(page, viewMembers) {
    await budget(PAGE); await budget(LIST); if (viewMembers) await budget(MEM);
    const resp = await page.goto(BASE + '/admin');
    if (resp.status() === 200) {
      await page.waitForFunction(() => !/…/.test(document.getElementById('adm-role').textContent), null, { timeout: 10000 }).catch(() => {});
      if (viewMembers) await page.locator('#mem-list tr').first().waitFor({ timeout: 10000 }).catch(() => {});
    }
    return resp;
  }
  async function uiCreate(page, ttl, user) {
    await budget(LIST, 2);
    await page.selectOption('#inv-ttl', String(ttl));
    await page.fill('#inv-user', user || '');
    await page.click('#btn-create');
    await page.waitForFunction(() => /已生成邀请|生成失败/.test(document.getElementById('status').textContent), null, { timeout: 10000 });
    await page.locator('#inv-result').waitFor();
    const r = { code: await page.inputValue('#res-code'), link: await page.inputValue('#res-link'), id: await page.locator('#res-id').innerText() };
    if (r.id) created.add(r.id);
    await page.waitForSelector(`#inv-list tr[data-id="${r.id}"]`, { timeout: 10000 }).catch(() => {});
    return r;
  }
  async function uiRevoke(page, id) {
    await budget(REVOKE); await budget(LIST);
    page.once('dialog', (d) => d.accept());
    await page.click(`#inv-list tr[data-id="${id}"] button.revoke`);
    await page.waitForFunction((id) => !document.querySelector(`#inv-list tr[data-id="${id}"]`), id, { timeout: 10000 }).catch(() => {});
    return !(await page.locator(`#inv-list tr[data-id="${id}"]`).count());
  }
  async function uiGrant(page, username, role) {
    await budget(MEM, 2);
    await page.fill('#mem-user', username);
    await page.selectOption('#mem-role', role);
    await page.click('#btn-grant');
    await page.waitForFunction(() => /已授予|角色没有变化|修改角色失败/.test(document.getElementById('status').textContent), null, { timeout: 10000 });
    await page.waitForSelector(`#mem-list tr[data-user="${username}"]`, { timeout: 5000 }).catch(() => {});
    return page.locator('#status').innerText();
  }

  // E0. 阶段 1：用 Bearer 邀请注册测试用户（此时它们都还不是负责人）
  const ctx = {};
  for (const u of [P_USER, L_USER, I_USER, I2_USER]) {
    const inv = await bearerCreate({ username: u, ttlSeconds: 600 });
    ctx[u] = await newCtx();
    const ok = await registerVia(ctx[u].page, inv.link);
    check(`阶段 1：${u} 用绑定邀请注册并登录`, ok && (await ctx[u].page.locator('#me-name').innerText()) === u);
  }
  check('阶段 1：没有角色的用户首页不显示“邀请管理”入口', !(await ctx[P_USER].page.locator('#admin-link').isVisible()));

  // 阶段 2：重启，PRINCIPALS=e2e_principal,e2e_ghost（模拟 Worker vars），同一个本地 KV
  await stopDev();
  await startDev(['--var', `PRINCIPALS:${P_USER},${GHOST}`]);
  for (const k of Object.keys(hits)) delete hits[k];
  log('阶段 2：wrangler dev 已重启，PRINCIPALS=' + `${P_USER},${GHOST}`);
  const P = ctx[P_USER], L = ctx[L_USER], I = ctx[I_USER], I2 = ctx[I2_USER];

  // E1. 负责人
  await P.page.goto(BASE + '/');
  await P.page.locator('#authed').waitFor();
  await P.page.waitForFunction(() => !document.getElementById('admin-link').hidden, null, { timeout: 5000 }).catch(() => {});
  check('负责人首页显示角色和“邀请管理”入口', (await P.page.locator('#admin-link').isVisible()) && (await P.page.locator('#admin-role').innerText()) === '负责人');
  const pResp = await openAdmin(P.page, true);
  check('负责人访问 /admin → 200，页面显示当前用户和角色“负责人（principal）”', pResp.status() === 200 && (await P.page.locator('#adm-name').innerText()) === P_USER && (await P.page.locator('#adm-role').innerText()) === '负责人（principal）', `HTTP ${pResp.status()}`);
  check('/admin 响应带 CSP 且 Cache-Control: no-store', /default-src 'none'/.test(pResp.headers()['content-security-policy'] || '') && /no-store/.test(pResp.headers()['cache-control'] || ''));
  check('负责人看得到“成员角色”区，可授予成员主管和邀请人', (await P.page.locator('#members').isVisible()) && JSON.stringify(await P.page.locator('#mem-role option').evaluateAll((o) => o.map((x) => x.value))) === '["membership_lead","inviter"]');
  const pRows = await P.page.locator('#mem-list tr').evaluateAll((rs) => rs.map((r) => [r.dataset.user, r.children[1].textContent, r.querySelector('button.remove-role') ? 'btn' : 'none']));
  check('成员列表：vars 里的负责人显示为“负责人”，没有移除按钮', pRows.some(([u, r, b]) => u === P_USER && /负责人/.test(r) && b === 'none') && pRows.some(([u, r, b]) => u === GHOST && b === 'none'), JSON.stringify(pRows));

  // E2. 负责人在页面上分配角色
  check('负责人在页面上授予 e2e_lead“成员主管”', /已授予/.test(await uiGrant(P.page, L_USER, 'membership_lead')));
  check('负责人在页面上授予 e2e_inviter“邀请人”', /已授予/.test(await uiGrant(P.page, I_USER, 'inviter')));
  check('负责人在页面上授予 e2e_inviter2“邀请人”', /已授予/.test(await uiGrant(P.page, I2_USER, 'inviter')));
  // 角色变化会吊销被授予者的全部会话（服务端会话表），被授予者需重新用 passkey 登录
  async function relogin(c, name) {
    await c.page.goto(BASE + '/');
    await c.page.click('#btn-login');
    await c.page.waitForFunction((n) => document.getElementById('me-name') && document.getElementById('me-name').textContent === n, name, { timeout: 15000 });
  }
  { const r = await (await ctx[I_USER].page.request.get(BASE + '/api/me')).json().catch(() => ({}));
    check('授予角色后被授予者旧会话已失效', r.loggedIn === false, JSON.stringify(r)); }
  for (const n of [L_USER, I_USER, I2_USER]) await relogin(ctx[n], n);
  const same = await inPage(P.page, 'POST', MEM, { username: I_USER, role: 'inviter' });
  check('重复授予相同角色：不写 KV（changed=false）', same.status === 200 && JSON.parse(same.text).changed === false, same.text);
  const pSelf = await inPage(P.page, 'POST', MEM, { username: P_USER, role: null });
  check('越权：负责人移除自己（vars）→ 403', pSelf.status === 403 && /权限不足/.test(pSelf.text), pSelf.text);
  const pGhost = await inPage(P.page, 'POST', MEM, { username: GHOST, role: 'inviter' });
  check('越权：在页面上修改另一位 vars 负责人 → 403', pGhost.status === 403 && /PRINCIPALS/.test(pGhost.text), pGhost.text);
  const pPrinc = await inPage(P.page, 'POST', MEM, { username: L_USER, role: 'principal' });
  check('越权：通过接口授予“负责人”→ 400（只能在 Worker vars 配置）', pPrinc.status === 400, pPrinc.text);
  const pNoUser = await inPage(P.page, 'POST', MEM, { username: 'nobody_' + rand().slice(0, 5), role: 'inviter' });
  check('给未注册的用户分配角色 → 404', pNoUser.status === 404, pNoUser.text);

  // E3. 负责人签发、复制、列表、撤销
  const boundUser = 'demo_inv_' + rand().slice(0, 5);
  const t1 = Date.now();
  const u1 = await uiCreate(P.page, 3600, boundUser);
  check('负责人页面签发邀请：显示 43 位邀请码和对应链接（含绑定用户名）', INVITE_RE.test(u1.code) && u1.link === `${ORIGIN}/#invite=${u1.code}&u=${boundUser}` && /^[0-9a-f]{16}$/.test(u1.id));
  check('页面提示“只显示这一次”', (await P.page.locator('#inv-result .warn').isVisible()) && /只显示这一次/.test(await P.page.locator('#inv-result .warn').innerText()));
  await P.page.click('#copy-code');
  const clip1 = await P.page.evaluate(() => navigator.clipboard.readText());
  await P.page.click('#copy-link');
  const clip2 = await P.page.evaluate(() => navigator.clipboard.readText());
  check('一键复制：邀请码与邀请链接分别复制到剪贴板', clip1 === u1.code && clip2 === u1.link);
  const cells = await P.page.locator(`#inv-list tr[data-id="${u1.id}"] td`).allInnerTexts();
  const expTxt = new Date(t1 + 3600000).toLocaleString('zh-CN', { hour12: false, timeZone: 'Asia/Taipei' }).slice(0, 13);
  check('列表显示：编号 / 绑定用户名 / 状态 / 创建时间 / 过期时间 / 签发者', cells[0] === u1.id && cells[1] === boundUser && /待使用（剩余/.test(cells[2]) && cells[3].length > 8 && cells[4].startsWith(expTxt) && cells[5] === P_USER, JSON.stringify(cells.slice(0, 6)));
  check('列表中不包含邀请码明文', !(await P.page.locator('#inv-list').innerHTML()).includes(u1.code));
  const ok1 = await regOpt(boundUser, u1.code);
  check('页面签发的邀请通过注册校验（绑定用户名）', ok1.status === 200, `HTTP ${ok1.status}`);
  const bad1 = await regOpt('demo_other_' + rand().slice(0, 4), u1.code);
  check('绑定邀请：换用户名被拒绝', bad1.status === 403 && INVITE_ERR.test(bad1.text));
  check('负责人页面撤销邀请：行从列表消失', (await uiRevoke(P.page, u1.id)) && /已撤销邀请/.test(await P.page.locator('#status').innerText()));
  const rv1 = await regOpt(boundUser, u1.code);
  check('撤销后的邀请被拒绝（403 统一提示）', rv1.status === 403 && INVITE_ERR.test(rv1.text));

  // E4. 页面签发不绑定的邀请 → 普通用户完成注册 → 邀请立即失效
  const u2 = await uiCreate(P.page, 86400, '');
  const normalUser = 'demo_user_' + rand().slice(0, 5);
  const N = await newCtx();
  const okN = await registerVia(N.page, u2.link, normalUser);
  check('页面签发的邀请链接打开后自动填入邀请码，普通用户通过 Turnstile（测试密钥）完成 passkey 注册', okN && (await N.page.locator('#me-name').innerText()) === normalUser);
  check('没有角色的用户首页不显示“邀请管理”入口', !(await N.page.locator('#admin-link').isVisible()));
  await openAdmin(P.page, true);
  check('注册成功后该邀请从管理列表消失（一次性）', !(await P.page.locator(`#inv-list tr[data-id="${u2.id}"]`).count()));
  check('刷新后不再显示任何邀请码明文', (await P.page.locator('#inv-result').isHidden()) && (await P.page.inputValue('#res-code')) === '');
  const reuse = await regOpt('demo_' + rand(), u2.code);
  check('用过的邀请再次使用被拒绝', reuse.status === 403 && INVITE_ERR.test(reuse.text));

  // E5. 邀请人：签发、只能撤销自己的；看不到成员区；不能分配角色
  const pInv = await uiCreate(P.page, 3600, ''); // 负责人签发的，留给邀请人尝试越权撤销
  await P.page.click('#btn-done');
  const iResp = await openAdmin(I.page, false);
  check('邀请人访问 /admin → 200，角色显示“邀请人（inviter）”', iResp.status() === 200 && (await I.page.locator('#adm-role').innerText()) === '邀请人（inviter）');
  check('邀请人看不到“成员角色”区', await I.page.locator('#members').isHidden());
  const iInv = await uiCreate(I.page, 3600, '');
  check('邀请人在页面上签发邀请', INVITE_RE.test(iInv.code));
  await I.page.click('#btn-done');
  check('邀请人列表中：别人签发的邀请“撤销”按钮禁用，自己签发的可用', (await I.page.locator(`#inv-list tr[data-id="${pInv.id}"] button.revoke`).isDisabled()) && (await I.page.locator(`#inv-list tr[data-id="${iInv.id}"] button.revoke`).isEnabled()));
  const iRvOther = await inPage(I.page, 'POST', REVOKE, { id: pInv.id });
  check('越权：邀请人通过接口撤销别人签发的邀请 → 403，邀请仍有效', iRvOther.status === 403 && /权限不足/.test(iRvOther.text) && (await regOpt('demo_' + rand().slice(0, 6), pInv.code)).status === 200, iRvOther.text);
  const iMem = await inPage(I.page, 'GET', MEM);
  check('越权：邀请人查看成员角色 → 403', iMem.status === 403, iMem.text);
  const iGrant = await inPage(I.page, 'POST', MEM, { username: normalUser, role: 'inviter' });
  check('越权：邀请人给别人授予邀请人 → 403', iGrant.status === 403, iGrant.text);
  const iSelf = await inPage(I.page, 'POST', MEM, { username: I_USER, role: 'membership_lead' });
  check('越权：邀请人把自己升为成员主管 → 403', iSelf.status === 403, iSelf.text);
  check('邀请人在页面上撤销自己签发的邀请', await uiRevoke(I.page, iInv.id));

  // E6. 成员主管：撤销任何邀请；只能分配 / 移除邀请人
  const lResp = await openAdmin(L.page, true);
  check('成员主管访问 /admin → 200，角色显示“成员主管（membership_lead）”', lResp.status() === 200 && (await L.page.locator('#adm-role').innerText()) === '成员主管（membership_lead）');
  check('成员主管的角色下拉框只有“邀请人”', JSON.stringify(await L.page.locator('#mem-role option').evaluateAll((o) => o.map((x) => x.value))) === '["inviter"]');
  const lRows = await L.page.locator('#mem-list tr').evaluateAll((rs) => rs.map((r) => [r.dataset.user, r.querySelector('button.remove-role') ? 'btn' : 'none']));
  check('成员主管的成员列表：只有邀请人行有“移除角色”按钮', lRows.every(([u, b]) => (b === 'btn') === (u === I_USER || u === I2_USER)), JSON.stringify(lRows));
  check('成员主管在页面上撤销负责人签发的邀请', await uiRevoke(L.page, pInv.id));
  const lUp = await inPage(L.page, 'POST', MEM, { username: normalUser, role: 'membership_lead' });
  check('越权：成员主管授予“成员主管”→ 403', lUp.status === 403 && /权限不足/.test(lUp.text), lUp.text);
  const lSelf = await inPage(L.page, 'POST', MEM, { username: L_USER, role: null });
  check('越权：成员主管修改自己的角色 → 403', lSelf.status === 403, lSelf.text);
  const lP = await inPage(L.page, 'POST', MEM, { username: P_USER, role: null });
  check('越权：成员主管移除负责人 → 403', lP.status === 403, lP.text);
  check('成员主管在页面上授予普通用户“邀请人”', /已授予/.test(await uiGrant(L.page, normalUser, 'inviter')));
  const lDown = await inPage(L.page, 'POST', MEM, { username: normalUser, role: null });
  check('成员主管移除邀请人的角色', lDown.status === 200 && JSON.parse(lDown.text).changed === true, lDown.text);
  // 负责人在页面上移除 e2e_inviter2
  await openAdmin(P.page, true);
  await budget(MEM, 2);
  P.page.once('dialog', (d) => d.accept());
  await P.page.click(`#mem-list tr[data-user="${I2_USER}"] button.remove-role`);
  // 状态文字先于成员列表刷新出现，所以等待该行消失（而不是只等状态文字）
  await P.page.waitForFunction((u) => /已移除/.test(document.getElementById('status').textContent) && !document.querySelector(`#mem-list tr[data-user="${u}"]`), I2_USER, { timeout: 15000 }).catch(() => {});
  check('负责人在页面上移除 e2e_inviter2 的角色', !(await P.page.locator(`#mem-list tr[data-user="${I2_USER}"]`).count()));
  const lLead = await inPage(L.page, 'POST', MEM, { username: L_USER, role: 'inviter' });
  check('越权：成员主管把自己降级 / 改动 → 403', lLead.status === 403);

  // E7. 没有角色的已登录用户（普通用户、被移除角色的邀请人）
  for (const [name, c] of [['普通用户', N], ['被移除角色的 e2e_inviter2', I2]]) {
    await budget(PAGE);
    const r = await c.page.goto(BASE + '/admin');
    check(`${name}访问 /admin → 403 无权访问`, r.status() === 403 && /无权访问/.test(await c.page.content()), `HTTP ${r.status()}`);
    await c.page.goto(BASE + '/');
    const res = [await inPage(c.page, 'GET', LIST), await inPage(c.page, 'POST', LIST, {}), await inPage(c.page, 'POST', REVOKE, { id: '0123456789abcdef' }), await inPage(c.page, 'GET', MEM), await inPage(c.page, 'POST', MEM, { username: name === '普通用户' ? normalUser : I2_USER, role: 'inviter' })];
    check(`${name}（同源浏览器请求）调用列表 / 签发 / 撤销 / 成员 / 自授角色 → 全部 401`, res.every((x) => x.status === 401 && /未授权/.test(x.text)), res.map((x) => x.status).join('/'));
  }

  // E8. vars 负责人用户名不能被新注册（防抢注）
  const gInv = await bearerCreate({ ttlSeconds: 600 });
  const g1 = await regOpt(GHOST, gInv.code);
  const G = await newCtx();
  const okG = await registerVia(G.page, gInv.link, GHOST);
  check('PRINCIPALS 里尚未注册的用户名不能用邀请注册（统一失败提示，邀请不被消耗）', g1.status === 200 && !okG && /注册失败/.test(await G.page.locator('#status').innerText()) && (await bearerList()).some((i) => i.id === gInv.id));
  await bearerRevoke(gInv.id);

  // E9. 截图（隐藏一次性结果区后；确认页面上没有任何邀请码明文）
  const shotInv = await uiCreate(P.page, 604800, 'demo_guest');
  await P.page.click('#btn-done');
  const shotIv2 = await uiCreate(P.page, 86400, '');
  await P.page.click('#btn-done');
  await openAdmin(P.page, true);
  await P.page.evaluate(() => { document.getElementById('status').textContent = ''; });
  const html = await P.page.content();
  const leak = [shotInv.code, shotIv2.code, u1.code, u2.code, TOKEN].some((s) => s && html.includes(s)) || /[A-Za-z0-9_-]{43}/.test(await P.page.locator('body').innerText());
  check('截图前检查：页面中没有邀请码和 token 明文', !leak && (await P.page.locator('#inv-result').isHidden()));
  if (!leak) {
    mkdirSync('shots', { recursive: true });
    await P.page.screenshot({ path: 'shots/admin.png', fullPage: true });
    check('已保存截图 shots/admin.png（本地负责人登录的管理页）', true);
  }

  // E10. 负责人会话 + 跨站特征 → 403；对照组 → 200
  const ac = await cookieHeader(P.context);
  const xa = {
    'Origin=https://evil.example': await raw('GET', LIST, { cookie: ac, headers: { 'X-PK-Admin': '1', Origin: 'https://evil.example' } }),
    'Sec-Fetch-Site: cross-site': await raw('GET', LIST, { cookie: ac, headers: { 'X-PK-Admin': '1', 'Sec-Fetch-Site': 'cross-site' } }),
    '缺少 X-PK-Admin（简单请求形态）': await raw('GET', LIST, { cookie: ac }),
    '跨站 POST 分配角色': await raw('POST', MEM, { cookie: ac, headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example', 'X-PK-Admin': '1' }, body: { username: normalUser, role: 'membership_lead' } }),
  };
  for (const [k, v] of Object.entries(xa)) check(`负责人会话 + ${k} → 403`, v.status === 403 && /来源/.test(v.text), `HTTP ${v.status}`);
  const xaPost = await raw('POST', LIST, { cookie: ac, headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example', 'X-PK-Admin': '1' }, body: {} });
  const xaPostNoHdr = await raw('POST', LIST, { cookie: ac, headers: { 'Content-Type': 'text/plain', Origin: ORIGIN }, body: {} });
  check('负责人会话 + 跨站 Origin 的 POST 签发 → 403', xaPost.status === 403 && xaPostNoHdr.status === 403, `HTTP ${xaPost.status}/${xaPostNoHdr.status}`);
  const xaPage = await raw('GET', '/admin', { cookie: ac, headers: { 'Sec-Fetch-Site': 'cross-site' } });
  check('负责人会话 + 跨站跳转到 /admin → 403', xaPage.status === 403, `HTTP ${xaPage.status}`);
  const ctl = await raw('GET', LIST, { cookie: ac, headers: { 'X-PK-Admin': '1', 'Sec-Fetch-Site': 'same-origin' } });
  check('对照组：负责人会话 + 同源特征 → 200', ctl.status === 200, `HTTP ${ctl.status}`);
  const wrongB = await raw('GET', LIST, { cookie: ac, headers: { 'X-PK-Admin': '1', Authorization: 'Bearer ' + 'z'.repeat(64) } });
  check('负责人会话 + 错误 Bearer → 401（不回退到会话）', wrongB.status === 401);
  check('会话 cookie 属性：__Host-、HttpOnly、Secure、SameSite=Lax', (await P.context.cookies()).some((c) => c.name === '__Host-pk_sess' && c.httpOnly && c.secure && c.sameSite === 'Lax'));

  // E11. 负责人退出后
  await budget('/api/logout');
  await P.page.goto(BASE + '/');
  await P.page.locator('#authed').waitFor();
  await P.page.click('#btn-logout');
  await P.page.locator('#anon').waitFor();
  const afterOut = await raw('GET', LIST, { cookie: ac, headers: { 'X-PK-Admin': '1' } });
  check('负责人退出后，旧会话 cookie 调用接口 → 401', afterOut.status === 401, `HTTP ${afterOut.status}`);
  await budget(PAGE);
  const aOut = await P.page.goto(BASE + '/admin');
  check('负责人退出后访问 /admin → 403', aOut.status() === 403);
}
await browser.close();

// ===== F. 清理 =====
// 反复“列出 → 撤销本脚本创建且仍在列表里的”，直到 list 一致（线上 list 可能滞后，新建的邀请也可能晚出现）
let revokedN = 0;
const all = await listUntil(async (l) => {
  const rest = l.filter((i) => created.has(i.id));
  for (const i of rest) { revokedN++; await bearerRevoke(i.id); }
  return !rest.length;
}, '清理');
const left = { length: revokedN };
check('清理：本脚本创建的邀请已全部撤销 / 用掉', !all.some((i) => created.has(i.id)), `本脚本创建 ${created.size} 个，撤销 ${left.length} 个；当前有效邀请总数 ${all.length}`);

const failed = results.filter((r) => !r.ok).length;
console.log(`\n结果：${results.length - failed}/${results.length} 通过；用时 ${Math.round((Date.now() - T0) / 1000)} 秒`);
if (LOCAL) await stopDev();
process.exit(failed ? 1 : 0);
