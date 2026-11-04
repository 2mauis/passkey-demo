// 账户过期 / 永不过期 / 账户分级与权限覆盖 / 岗位模板 / 审计 / 兜底恢复（预留接口）本地测试
// 用法：node tests/expiry-roles.mjs（脚本自己启动 wrangler dev，全新的本地 KV 目录，端口 8787 须空闲；只支持本地）
//   阶段 1：PRINCIPALS=t_nobody（默认关闭恢复）注册测试用户；
//   阶段 2：重启 --var PRINCIPALS:t_root,t_ghost RECOVERY_ENABLED:1 RECOVERY_ISSUER_TOKEN:<本次运行随机生成> EXPIRY_TEST_MIN_SECONDS:1
// 不打印任何 token、邀请码、恢复码、会话 cookie 明文。
import { chromium } from 'playwright';
import { readFileSync, mkdirSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';

const BASE = 'http://localhost:8787';
const ORIGIN = BASE;

const RECOVERY_TOKEN = randomBytes(32).toString('base64url'); // 仅本次运行，进程内存中，不写盘不打印
const PERSIST = `/tmp/pk-sess-${Date.now()}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = []; const T0 = Date.now();
const check = (name, ok, detail = '') => { results.push({ name, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`); };
const log = (...a) => console.log('     ', ...a);

let dev = null;
async function startDev(extra = []) {
  mkdirSync(PERSIST, { recursive: true });
  dev = spawn('npx', ['wrangler', 'dev', '--port', '8787', '--persist-to', PERSIST, ...extra], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; dev.stdout.on('data', (d) => { out += d; }); dev.stderr.on('data', (d) => { out += d; });
  for (let i = 0; i < 120; i++) { await sleep(500); if (/Ready on/.test(out)) { await sleep(500); return; } }
  console.log(out.slice(-800)); throw new Error('wrangler dev 启动超时');
}
async function stopDev() { if (!dev) return; try { process.kill(-dev.pid, 'SIGTERM'); } catch { /* */ } await sleep(2500); dev = null; }
process.on('exit', () => { if (dev) try { process.kill(-dev.pid, 'SIGTERM'); } catch { /* */ } });

// 限流节奏：每个路径 60 秒内最多 8 次
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
const TOKEN = /^ADMIN_TOKEN=(.+)$/m.exec(readFileSync('.dev.vars', 'utf8'))[1].trim();
const JH = { 'Content-Type': 'application/json', Origin: ORIGIN };
async function raw(method, path, { headers = {}, body } = {}) {
  await budget(path);
  const r = await fetch(BASE + path, { method, headers: { ...JH, ...headers }, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
  const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { /* */ }
  return { status: r.status, text, json, setCookie: r.headers.get('set-cookie') || '' };
}
const bearer = (path, body, tok = TOKEN) => raw(body === undefined ? 'GET' : 'POST', path, { headers: { Authorization: `Bearer ${tok}` }, body });

const browser = await chromium.launch();
async function newCtx(extraHTTPHeaders) {
  const context = await browser.newContext({ locale: 'zh-CN', extraHTTPHeaders });
  const page = await context.newPage();
  page.on('pageerror', (e) => log('pageerror:', e.message));
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.goto(BASE + '/');
  return { context, page, cdp, authenticatorId };
}
async function registerVia(page, link) {
  await budget('/api/register/options'); await budget('/api/register/verify');
  await page.goto(link.replace(/^https?:\/\/[^/]+/, BASE));
  await page.locator('#anon').waitFor();
  await page.waitForFunction(() => window.__pk && window.__pk.getTurnstileToken(), null, { timeout: 30000 });
  await page.click('#btn-register');
  await page.waitForFunction(() => /注册成功|注册失败/.test(document.getElementById('status').textContent), null, { timeout: 20000 });
  return page.locator('#authed').waitFor({ timeout: 10000 }).then(() => true).catch(() => false);
}
async function inPage(page, method, path, body) {
  await budget(path);
  return page.evaluate(async ([method, path, body]) => {
    const go = () => fetch(path, { method, headers: { 'X-PK-Admin': '1', 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    let r = await go();
    // 敏感操作返回 {stepUp:true} 时，用虚拟认证器做一次 step-up 再重试（与页面里的自动 step-up 行为一致）
    if (r.status === 403) { const j = await r.clone().json().catch(() => ({})); const su = (window.__pk && window.__pk.stepUp) || (window.__pkAdmin && window.__pkAdmin.stepUp); if (j.stepUp && su) { await su(); r = await go(); } }
    const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { /* */ }
    return { status: r.status, text, json };
  }, [method, path, body]);
}
// 在页面里用虚拟认证器完成一次 passkey 登录（返回 verify 的状态和响应）
async function apiLogin(page) {
  await budget('/api/login/options'); await budget('/api/login/verify');
  return page.evaluate(async () => {
    const H = { 'Content-Type': 'application/json' };
    const o = await (await fetch('/api/login/options', { method: 'POST', headers: H, body: '{}' })).json();
    const cred = await window.__pk.startAuthentication({ optionsJSON: o.options });
    const r = await fetch('/api/login/verify', { method: 'POST', headers: H, body: JSON.stringify({ credential: cred }) });
    return { status: r.status, json: await r.json() };
  });
}
async function apiLogout(page) { await budget('/api/logout'); await page.evaluate(() => fetch('/api/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })); }
const meOf = (page) => page.evaluate(async () => (await fetch('/api/me')).json());
const invite = async (username, extra = {}) => { const r = await bearer('/api/admin/invites', { username, ttlSeconds: 600, ...extra }); if (r.status !== 200) throw new Error('建邀请失败 ' + r.status); return r.json; };


// ===== 会话时长预设 / step-up / 会话表吊销 / 异常登录 / 强制 UV / challenge 一次性 =====
// 用法：node tests/session.mjs（自己启动 wrangler dev，全新本地状态；端口 8787 须空闲）
// 风险信号用本地专用测试头伪造（RP_ID=localhost 且 RISK_TEST_HEADERS=1 才生效），IP 只用文档保留段 192.0.2.0/24、198.51.100.0/24。
const RT = 's_root', LD = 's_lead', NM = 's_norm', TM = 's_temp', RK = 's_risk';
const tw = (asn = '64500', ip = '192.0.2.10', c = 'TW') => ({ 'X-Test-Country': c, 'X-Test-ASN': asn, 'X-Test-IP': ip });
const VARS = ['--var', 'RISK_TEST_HEADERS:1', '--var', 'STEPUP_TEST_WINDOW_SECONDS:4', '--var', 'EXPIRY_TEST_MIN_SECONDS:1'];
// 负责人名单里的用户名不能通过邀请注册（不新增管理员创建入口），所以先在名单外注册，再重启把 s_root 列入名单
await startDev(['--var', 'PRINCIPALS:s_nobody', ...VARS]);
const C = {};
for (const u of [RT, LD, NM, TM, RK]) {
  C[u] = await newCtx(tw());
  check(`${u} 注册并登录`, await registerVia(C[u].page, (await invite(u)).link));
}
await stopDev();
await startDev(['--var', `PRINCIPALS:${RT}`, ...VARS]);
const R = C[RT].page;
const SP = '/api/admin/session-preset';
const near = (a, b, tol = 15000) => Math.abs(a - b) < tol;
const H = 3600e3, D = 24 * H;

// 1. 默认预设与各档数值
const g = await inPage(R, 'GET', SP);
check('默认预设为 recommended', g.status === 200 && g.json.current === 'recommended', g.text);
const P = g.json.presets;
check('推荐：普通 7d/24h、管理员 12h/30m、临时 1d/1h', P.recommended.normal.abs === 7 * D && P.recommended.normal.idle === 24 * H && P.recommended.admin.abs === 12 * H && P.recommended.admin.idle === 30 * 60e3 && P.recommended.temp.abs === D && P.recommended.temp.idle === H);
check('NIST AAL2：24h/1h（各档）', ['normal', 'admin', 'temp'].every((t) => P.aal2[t].abs === D && P.aal2[t].idle === H));
check('宽松：30d/7d（各档）', ['normal', 'admin', 'temp'].every((t) => P.relaxed[t].abs === 30 * D && P.relaxed[t].idle === 7 * D));
const meN = await meOf(C[NM].page);
check('普通账户会话：绝对 ≈ 7 天，空闲 24 小时', meN.session.tier === 'normal' && near(meN.session.absoluteExpiresAt, Date.now() + 7 * D, 60000) && meN.session.idleTimeoutMs === 24 * H, JSON.stringify(meN.session));
const meR = await meOf(R);
check('管理员档（root）：绝对 ≈ 12 小时，空闲 30 分钟', meR.session.tier === 'admin' && near(meR.session.absoluteExpiresAt, Date.now() + 12 * H, 60000) && meR.session.idleTimeoutMs === 30 * 60e3, JSON.stringify(meR.session));
// 临时档：给 s_temp 设账户过期 → 已有会话按 min(原上限, 临时档上限) 收紧
const st = await inPage(R, 'POST', '/api/admin/expiry', { username: TM, mode: 'relative', duration: '20d' });
const meT = await meOf(C[TM].page);
check('临时档：设了账户过期后，已有会话收紧为 绝对 1 天 / 空闲 1 小时', st.status === 200 && meT.session.tier === 'temp' && meT.session.absoluteExpiresAt - Date.now() < D + 60000 && meT.session.idleTimeoutMs === H, JSON.stringify(meT.session));
// 管理员档（lead）
const gl = await inPage(R, 'POST', '/api/admin/members', { username: LD, role: 'membership_lead' });
const leadGone = (await meOf(C[LD].page)).loggedIn === false;
check('角色变化：被授予者的所有会话被吊销（服务端会话表）', gl.status === 200 && leadGone);
await apiLogin(C[LD].page);
const meL = await meOf(C[LD].page);
check('高级管理员重新登录：管理员档 12h/30m', meL.session.tier === 'admin' && meL.session.idleTimeoutMs === 30 * 60e3);

// 2. 切换：非 root 拒绝；无 step-up 拒绝；step-up 后成功；审计；已有会话收紧
const nl = await inPage(C[LD].page, 'POST', SP, { preset: 'aal2' });
check('非 root 切换预设 → 403', nl.status === 403, nl.text);
await sleep(5000); // 超过本地测试的 4 秒 step-up 窗口
const noStep = await R.evaluate(async (p) => { const r = await fetch(p, { method: 'POST', headers: { 'X-PK-Admin': '1', 'Content-Type': 'application/json' }, body: JSON.stringify({ preset: 'aal2' }) }); return { status: r.status, json: await r.json() }; }, SP);
check('root 未 step-up 切换 → 403 且带 stepUp 标志', noStep.status === 403 && noStep.json.stepUp === true, JSON.stringify(noStep));
await budget('/api/stepup/options'); await budget('/api/stepup/verify');
const sw = await R.evaluate(async (p) => { await window.__pk.stepUp(); const r = await fetch(p, { method: 'POST', headers: { 'X-PK-Admin': '1', 'Content-Type': 'application/json' }, body: JSON.stringify({ preset: 'aal2' }) }); return { status: r.status, json: await r.json() }; }, SP);
check('root step-up 后切换到 aal2 → 200', sw.status === 200 && sw.json.current === 'aal2', JSON.stringify(sw));
const meN2 = await meOf(C[NM].page);
check('已有普通会话被收紧到 min(7 天, 24 小时) 与空闲 1 小时', meN2.session.absoluteExpiresAt - Date.now() < D + 60000 && meN2.session.idleTimeoutMs === H, JSON.stringify(meN2.session));
const sw2 = await inPage(R, 'POST', SP, { preset: 'relaxed' });
const meN3 = await meOf(C[NM].page);
check('放宽到 relaxed 不会延长已有会话（仍 ≤ 24 小时）', sw2.status === 200 && meN3.session.absoluteExpiresAt - Date.now() < D + 60000 && meN3.session.idleTimeoutMs === 7 * D, JSON.stringify(meN3.session));
const bad = await inPage(R, 'POST', SP, { preset: 'forever' });
check('未知预设 → 400', bad.status === 400);
await inPage(R, 'POST', SP, { preset: 'recommended' });

// 3. 强制 UV / challenge 一次性
await budget('/api/login/options', 2); await budget('/api/login/verify', 2);
const uv = await C[NM].page.evaluate(async () => {
  const Hh = { 'Content-Type': 'application/json' };
  const o = await (await fetch('/api/login/options', { method: 'POST', headers: Hh, body: '{}' })).json();
  const cred = await window.__pk.startAuthentication({ optionsJSON: o.options });
  const a = await fetch('/api/login/verify', { method: 'POST', headers: Hh, body: JSON.stringify({ credential: cred }) });
  const b = await fetch('/api/login/verify', { method: 'POST', headers: Hh, body: JSON.stringify({ credential: cred }) });
  return { uv: o.options.userVerification, a: a.status, b: b.status, bj: await b.json() };
});
check('登录 options 要求 userVerification=required', uv.uv === 'required');
check('同一 challenge 第二次提交被拒（DO 原子作废，防重放）', uv.a === 200 && uv.b === 400, JSON.stringify(uv));
await C[NM].cdp.send('WebAuthn.setUserVerified', { authenticatorId: C[NM].authenticatorId, isUserVerified: false });
const noUv = await apiLogin(C[NM].page).catch((e) => ({ status: 'err', json: { error: String(e.message).slice(0, 80) } }));
check('认证器未做用户验证（UV=false）→ 登录失败', noUv.status !== 200, JSON.stringify(noUv));
await C[NM].cdp.send('WebAuthn.setUserVerified', { authenticatorId: C[NM].authenticatorId, isUserVerified: true });

// 4. 异常登录
const K = C[RK];
await K.context.setExtraHTTPHeaders(tw('64501', '198.51.100.20'));
await apiLogout(K.page);
const k1 = await apiLogin(K.page);
const mk = await meOf(K.page);
check('新 ASN 登录：会话标记 new_env，需要 step-up', k1.status === 200 && mk.session.risk === 'new_env' && mk.session.stepUpValid === false, JSON.stringify(mk.session));
await budget('/api/register/options');
const addPk = await K.page.evaluate(async () => { const r = await fetch('/api/register/options', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); return { status: r.status, json: await r.json() }; });
check('新环境会话添加 passkey（敏感操作）→ 403 stepUp', addPk.status === 403 && addPk.json.stepUp === true, JSON.stringify(addPk));
await budget('/api/stepup/options'); await budget('/api/stepup/verify');
await K.page.evaluate(() => window.__pk.stepUp());
const mk2 = await meOf(K.page);
check('step-up 后风险标记清除', mk2.session.risk === null && mk2.session.stepUpValid === true, JSON.stringify(mk2.session));
const K2 = await newCtx(tw('64501', '198.51.100.20'));
// 用 K 的会话之外再确认：短时间内换国家 → 不可能的旅行
await K.context.setExtraHTTPHeaders(tw('64502', '198.51.100.30', 'JP'));
const k3 = await apiLogin(K.page);
const mk3 = await meOf(K.page);
check('10 分钟内从 TW 到 JP：不可能的旅行 → 登录 403，已有会话全部吊销', k3.status === 403 && mk3.loggedIn === false, JSON.stringify({ s: k3.status, me: mk3.loggedIn }));
await K2.context.close();

// 4b. 一次性登录（OTP）账户：被风险规则拒绝的登录不能消耗唯一额度（Codex P2：风险判断在扣减额度之前）
const otpT = await inPage(R, 'POST', '/api/admin/templates', { action: 'save', id: 'otp', name: 'OTP', role: null, expiry: 'otp' });
const OT = await newCtx(tw());
check('OTP 账户注册（OTP 模板）', otpT.status === 200 && await registerVia(OT.page, (await invite('s_otp', { templateId: 'otp' })).link));
await apiLogout(OT.page);
await OT.context.setExtraHTTPHeaders(tw('64502', '198.51.100.30', 'JP'));
const ob = await apiLogin(OT.page);
const om = (await inPage(R, 'GET', '/api/admin/members')).json.members.find((m) => m.username === 's_otp');
check('OTP 账户不可能的旅行 → 403，且一次性登录额度未被消耗（剩余 1 次）', ob.status === 403 && om && /剩余 1 次/.test(om.expiry.label), JSON.stringify({ s: ob.status, label: om && om.expiry.label }));
await OT.context.setExtraHTTPHeaders(tw());
const ok1 = await apiLogin(OT.page);
await apiLogout(OT.page);
const ok2 = await apiLogin(OT.page);
check('OTP 账户回到原地区后仍可用唯一一次登录，之后再登录被拒', ok1.status === 200 && ok2.status === 403, `${ok1.status}/${ok2.status}`);
await OT.context.close();

// 5. 审计与隐私
const au = await inPage(R, 'GET', '/api/admin/audit');
const evs = new Set((au.json?.entries || []).map((e) => e.ev));
check('审计：session.preset / session.stepup / risk.new_env / risk.impossible_travel / role.set', ['session.preset', 'session.stepup', 'risk.new_env', 'risk.impossible_travel', 'role.set'].every((e) => evs.has(e)), [...evs].join(','));
const at = JSON.stringify(au.json);
check('审计不含测试用原始 IP', !/192\.0\.2\.|198\.51\.100\./.test(at));
const notify = (au.json.entries || []).filter((e) => e.ev.startsWith('risk.') && e.notify === true).length;
check('风险事件带 notify 标记（供通知通道消费）', notify >= 2, String(notify));
check('会话 cookie：__Host-、HttpOnly、Secure、SameSite=Lax', (await C[NM].context.cookies()).some((c) => c.name === '__Host-pk_sess' && c.httpOnly && c.secure && c.sameSite === 'Lax'));

await browser.close();
await stopDev();
const failed = results.filter((r) => !r.ok).length;
console.log(`结果：${results.length - failed}/${results.length} 通过；用时 ${Math.round((Date.now() - T0) / 1000)} 秒`);
process.exit(failed ? 1 : 0);
