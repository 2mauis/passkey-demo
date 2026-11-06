// 账户过期 / 永不过期 / 账户分级与权限覆盖 / 岗位模板 / 审计 / 兜底恢复（预留接口）本地测试
// 用法：node tests/expiry-roles.mjs（脚本自己启动 wrangler dev，全新的本地 KV 目录，端口 8787 须空闲；只支持本地）
//   阶段 1：PRINCIPALS=t_nobody（默认关闭恢复）注册测试用户；
//   阶段 2：重启 --var PRINCIPALS:t_root,t_ghost RECOVERY_ENABLED:1 RECOVERY_ISSUER_TOKEN:<本次运行随机生成> EXPIRY_TEST_MIN_SECONDS:1
// 不打印任何 token、邀请码、恢复码、会话 cookie 明文。
import { chromium } from 'playwright';
import { readFileSync, mkdirSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const APP_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

const BASE = 'http://localhost:8787';
const ORIGIN = BASE;
const ROOT = 't_root', GHOST = 't_ghost', LEAD = 't_lead', LEAD2 = 't_lead2', MAINT = 't_maint', MAINT2 = 't_maint2', TEMP = 't_temp', NORM = 't_norm';
const RECOVERY_TOKEN = randomBytes(32).toString('base64url'); // 仅本次运行，进程内存中，不写盘不打印
const PERSIST = `/tmp/pk-exp-${Date.now()}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = []; const T0 = Date.now();
const check = (name, ok, detail = '') => { results.push({ name, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`); };
const log = (...a) => console.log('     ', ...a);

let dev = null;
async function startDev(extra = []) {
  mkdirSync(PERSIST, { recursive: true });
  dev = spawn('npx', ['wrangler', 'dev', '--port', '8787', '--persist-to', PERSIST, ...extra], { cwd: APP_ROOT, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
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
const TOKEN = /^ADMIN_TOKEN=(.+)$/m.exec(readFileSync(join(APP_ROOT, '.dev.vars'), 'utf8'))[1].trim();
const JH = { 'Content-Type': 'application/json', Origin: ORIGIN };
async function raw(method, path, { headers = {}, body } = {}) {
  await budget(path);
  const r = await fetch(BASE + path, { method, headers: { ...JH, ...headers }, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
  const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { /* */ }
  return { status: r.status, text, json, setCookie: r.headers.get('set-cookie') || '' };
}
const bearer = (path, body, tok = TOKEN) => raw(body === undefined ? 'GET' : 'POST', path, { headers: { Authorization: `Bearer ${tok}` }, body });

const browser = await chromium.launch();
async function newCtx() {
  const context = await browser.newContext({ locale: 'zh-CN' });
  const page = await context.newPage();
  page.on('pageerror', (e) => log('pageerror:', e.message));
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.goto(BASE + '/');
  return { context, page };
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

// ===== 阶段 1 =====
await startDev(['--var', 'PRINCIPALS:t_nobody']);
const dis = await raw('POST', '/api/recovery/redeem', { body: { username: ROOT, code: 'x'.repeat(43) } });
check('恢复默认关闭：RECOVERY_ENABLED 未设置时 /api/recovery/redeem → 501（未实现）', dis.status === 501, `HTTP ${dis.status}`);
const disIssue = await bearer('/api/admin/recovery', { action: 'issue', username: ROOT });
check('恢复默认关闭：签发接口 → 501', disIssue.status === 501, `HTTP ${disIssue.status}`);
const C = {};
for (const u of [ROOT, LEAD, LEAD2, MAINT, MAINT2, TEMP, NORM]) {
  C[u] = await newCtx();
  const ok = await registerVia(C[u].page, (await invite(u)).link);
  check(`阶段 1：${u} 注册并登录`, ok);
}

// ===== 阶段 2 =====
await stopDev();
await startDev(['--var', `PRINCIPALS:${ROOT},${GHOST}`, '--var', 'RECOVERY_ENABLED:1', '--var', `RECOVERY_ISSUER_TOKEN:${RECOVERY_TOKEN}`, '--var', 'EXPIRY_TEST_MIN_SECONDS:1']);
for (const k of Object.keys(hits)) delete hits[k];
const R = C[ROOT].page, L = C[LEAD].page, L2 = C[LEAD2].page, M = C[MAINT].page, M2 = C[MAINT2].page, TP = C[TEMP].page, N = C[NORM].page;
const MEM = '/api/admin/members', EXP = '/api/admin/expiry', PERM = '/api/admin/permissions', TPL = '/api/admin/templates', INV = '/api/admin/invites';
for (const [u, role] of [[LEAD, 'membership_lead'], [LEAD2, 'membership_lead'], [MAINT, 'inviter'], [MAINT2, 'inviter'], [TEMP, 'inviter']]) {
  const r = await inPage(R, 'POST', MEM, { username: u, role });
  check(`root 授予 ${u} ${role}`, r.status === 200, `HTTP ${r.status}`);
}
// 角色变化会吊销该用户的全部会话：被授予者重新登录
for (const u of [LEAD, LEAD2, MAINT, MAINT2, TEMP]) {
  const gone = (await meOf(C[u].page)).loggedIn === false;
  const r = await apiLogin(C[u].page);
  check(gone ? `角色变化后` : `[未吊销!] `, gone && r.status === 200, `HTTP ${r.status}`); if (0) check(`角色变化后 ${u} 的旧会话被吊销，重新登录成功`, r.status === 200, `HTTP ${r.status}`);
}

// --- 1. 过期：相对 / 绝对 / 校验 ---
let t0 = Date.now();
const rel = await inPage(R, 'POST', EXP, { username: NORM, scope: 'account', mode: 'relative', duration: '1d' });
check('相对过期 1d：返回的过期时间 ≈ 现在 + 24 小时，台北时间显示带时区标注', rel.status === 200 && Math.abs(rel.json.expiry.accountExpiresAt - t0 - 86400e3) < 10000 && /台北时间 UTC\+8/.test(rel.json.expiry.accountExpiresAtTaipei), rel.text);
const rel12 = await inPage(R, 'POST', EXP, { username: NORM, scope: 'role', mode: 'relative', duration: '12h' });
check('相对过期 12h（角色范围）', rel12.status === 200 && Math.abs(rel12.json.expiry.roleExpiresAt - Date.now() - 12 * 3600e3) < 10000, rel12.text);
const abs = await inPage(R, 'POST', EXP, { username: NORM, scope: 'account', mode: 'absolute', at: '2030-01-01T09:00' });
check('绝对过期：不带时区按台北时间解释（2030-01-01 09:00 +08:00 = 01:00Z）', abs.status === 200 && abs.json.expiry.accountExpiresAt === Date.parse('2030-01-01T01:00:00Z') && abs.json.expiry.accountExpiresAtTaipei.startsWith('2030-01-01 09:00'), abs.text);
const absZ = await inPage(R, 'POST', EXP, { username: NORM, scope: 'account', mode: 'absolute', at: '2030-01-01T09:00Z' });
check('绝对过期：带 Z 按 UTC 解释，显示为台北 17:00', absZ.status === 200 && absZ.json.expiry.accountExpiresAtTaipei.startsWith('2030-01-01 17:00'), absZ.text);
const bad1 = await inPage(R, 'POST', EXP, { username: NORM, mode: 'relative', duration: '1y' });
const bad2 = await inPage(R, 'POST', EXP, { username: NORM, mode: 'absolute', at: '2020-01-01T00:00' });
const bad3 = await inPage(R, 'POST', EXP, { username: NORM, mode: 'relative', duration: '9999w' });
check('非法时长 / 过去时间 / 超过 5 年 → 400', bad1.status === 400 && bad2.status === 400 && bad3.status === 400, `${bad1.status}/${bad2.status}/${bad3.status}`);
const memList = await inPage(R, 'GET', MEM);
const normRow = memList.json.members.find((m) => m.username === NORM);
check('管理页成员列表能查看过期时间（无角色账户也列出）', !!normRow && normRow.role === null && /2030-01-01 17:00/.test(normRow.expiry.label), normRow && normRow.expiry.label);
const rootRow = memList.json.members.find((m) => m.username === ROOT);
check('成员列表：负责人显示永不过期、不可管理', rootRow.expiry.never === true && rootRow.canManage === false);

// --- 2. 负责人不能设过期（服务端强制） ---
const pe1 = await inPage(L, 'POST', EXP, { username: ROOT, mode: 'relative', duration: '1d' });
const pe2 = await inPage(R, 'POST', EXP, { username: ROOT, mode: 'relative', duration: '1d' });
const pe3 = await inPage(R, 'POST', EXP, { username: GHOST, mode: 'never' });
const pe4 = await bearer(EXP, { username: ROOT, mode: 'relative', duration: '1d' });
check('PRINCIPALS 不能被设过期：成员主管 / 负责人自己 / 另一位负责人 / 应急 token 全部 403', [pe1, pe2, pe3, pe4].every((r) => r.status === 403), [pe1, pe2, pe3, pe4].map((r) => r.status).join('/'));

// --- 3. 永不过期 ---
const nv = await inPage(R, 'POST', EXP, { username: NORM, mode: 'never' });
const nv2 = await inPage(R, 'POST', EXP, { username: NORM, mode: 'relative', duration: '1d' });
check('设为永不过期后，再设过期被拒（409，需先取消）', nv.status === 200 && nv.json.expiry.never === true && nv2.status === 409, `${nv.status}/${nv2.status}`);
const nv3 = await inPage(R, 'POST', EXP, { username: NORM, mode: 'none' });
check('取消永不过期（mode=none）→ 回到未设置', nv3.status === 200 && nv3.json.expiry.never === false && nv3.json.expiry.accountExpiresAt === null, nv3.text);

// --- 4. 过期后：管理接口拒绝（每次请求检查）、登录拒绝 ---
const before = await inPage(TP, 'GET', INV);
check('过期前：临时账户（维护者）可以访问管理接口', before.status === 200);
const setT = await inPage(R, 'POST', EXP, { username: TEMP, mode: 'relative', duration: '3s' });
check('给临时账户设 3 秒后过期（本地测试下限 1 秒）', setT.status === 200, setT.text);
await sleep(4000);
const after = await inPage(TP, 'GET', INV);
check('过期后：已有会话访问管理接口 → 401（每次请求都检查）', after.status === 401, `HTTP ${after.status}`);
const meT = await meOf(TP);
check('过期后：/api/me 视为未登录', meT.loggedIn === false);
const lg = await apiLogin(TP);
check('过期后：passkey 登录被拒（403 账户已过期）', lg.status === 403 && /已过期/.test(lg.json.error), JSON.stringify(lg));
// 角色过期（普通账户临时授权到期失效）
const rset = await inPage(R, 'POST', EXP, { username: MAINT2, scope: 'role', mode: 'relative', duration: '3s' });
check('维护者角色设 3 秒后过期', rset.status === 200);
await sleep(4000);
const ra = await inPage(M2, 'GET', INV);
const rme = await meOf(M2);
check('角色过期后：管理接口 401，但账户仍可正常使用（/api/me 已登录、无角色）', ra.status === 401 && rme.loggedIn === true && !rme.role, `HTTP ${ra.status}`);

// --- 5. 账户分级与“发邀请”权限覆盖 ---
const pre = await inPage(M, 'POST', INV, { ttlSeconds: 600 });
check('维护者撤权前可以发邀请', pre.status === 200);
const dv = await inPage(R, 'POST', PERM, { username: MAINT, permission: 'invite.create', action: 'revoke', revokePending: true });
check('root 撤销维护者的发邀请权限，并一并撤销其待使用邀请', dv.status === 200 && dv.json.revokedInvites === 1, dv.text);
const d1 = await inPage(M, 'POST', INV, { ttlSeconds: 600 });
const d2 = await inPage(M, 'GET', INV);
check('撤销后：发邀请被拒（403），查看邀请等其他权限照常（200）', d1.status === 403 && /撤销/.test(d1.text) && d2.status === 200, `${d1.status}/${d2.status}`);
const dl = await inPage(L, 'POST', PERM, { username: LEAD2, permission: 'invite.create', action: 'revoke' });
const dm = await inPage(M, 'POST', PERM, { username: LEAD, permission: 'invite.create', action: 'revoke' });
const dr = await inPage(L, 'POST', PERM, { username: ROOT, permission: 'invite.create', action: 'revoke' });
const drr = await inPage(R, 'POST', PERM, { username: ROOT, permission: 'invite.create', action: 'revoke' });
const dself = await inPage(L, 'POST', PERM, { username: LEAD, permission: 'invite.create', action: 'revoke' });
check('同级不能互撤（高级管理员→高级管理员 403）', dl.status === 403, dl.text);
check('下级不能撤上级（维护者→高级管理员 403）', dm.status === 403, dm.text);
check('root 的发邀请权不可撤回（高级管理员→root、root→自己 均 403）', dr.status === 403 && drr.status === 403, `${dr.status}/${drr.status}`);
check('不能撤自己（403）', dself.status === 403);
const lm = await inPage(L, 'POST', PERM, { username: MAINT2, permission: 'invite.create', action: 'revoke' });
check('上级可撤下级（高级管理员→维护者 200）', lm.status === 200, lm.text);
const rl = await inPage(R, 'POST', PERM, { username: LEAD, permission: 'invite.create', action: 'revoke' });
const rl2 = await inPage(L, 'POST', INV, { ttlSeconds: 600 });
const rl3 = await inPage(L, 'GET', MEM);
check('高级管理员的发邀请权只有 root 能撤：撤后发邀请 403，查看成员照常', rl.status === 200 && rl2.status === 403 && rl3.status === 200, `${rl.status}/${rl2.status}/${rl3.status}`);
await inPage(R, 'POST', PERM, { username: LEAD, permission: 'invite.create', action: 'restore' });
const rs = await inPage(R, 'POST', PERM, { username: MAINT, permission: 'invite.create', action: 'restore' });
const rs2 = await inPage(M, 'POST', INV, { ttlSeconds: 600 });
check('恢复后可以再发邀请', rs.status === 200 && rs2.status === 200, `${rs.status}/${rs2.status}`);
const up1 = await inPage(L, 'POST', MEM, { username: LEAD, role: 'membership_lead' });
const up2 = await inPage(L, 'POST', MEM, { username: NORM, role: 'membership_lead' });
const up3 = await inPage(M, 'POST', MEM, { username: NORM, role: 'inviter' });
check('不能自升级 / 不能授予与自己同级或更高的级别 / 维护者不能授予', up1.status === 403 && up2.status === 403 && up3.status === 403, `${up1.status}/${up2.status}/${up3.status}`);
const le = await inPage(L, 'POST', EXP, { username: LEAD2, mode: 'relative', duration: '1d' });
check('同级不能给对方设过期（高级管理员→高级管理员 403）', le.status === 403);

// --- 6. 岗位模板（只设默认有效期；带角色模板 = 新建/提升管理员入口，已禁用）---
const tl = await inPage(L, 'POST', TPL, { action: 'save', id: 'guest', name: '访客', role: null, expiry: 'd1' });
check('无权者（高级管理员）不能新建模板 → 403', tl.status === 403, tl.text);
const tp = await inPage(R, 'POST', TPL, { action: 'save', id: 'boss', name: '老板', role: 'principal', expiry: 'permanent' });
check('模板不能含负责人（root）权限 → 403', tp.status === 403 && /负责人/.test(tp.text), tp.text);
const tm = await inPage(R, 'POST', TPL, { action: 'save', id: 'maint30', name: '维护者30天', role: 'inviter', expiry: 'd30', scope: 'role' });
const tlead = await inPage(R, 'POST', TPL, { action: 'save', id: 'lead', name: '高级管理员', role: 'membership_lead', expiry: 'permanent' });
check('带角色模板已禁用（维护者 / 高级管理员模板 → 501 disabled）', tm.status === 501 && tm.json.disabled === true && tlead.status === 501, `${tm.status}/${tlead.status}`);
const g1 = await inPage(R, 'POST', MEM, { username: NORM, role: 'inviter', templateId: 'guest' });
check('授予角色时套用模板已禁用（501）', g1.status === 501 && g1.json.disabled === true, g1.text);
const tg = await inPage(R, 'POST', TPL, { action: 'save', id: 'guest', name: '访客', role: null, expiry: 'd1', desc: '临时访客' });
const tsg = await inPage(R, 'POST', TPL, { action: 'save', id: 'single', name: '单次', role: null, expiry: 'single' });
const tot = await inPage(R, 'POST', TPL, { action: 'save', id: 'otp', name: 'OTP', role: null, expiry: 'otp' });
check('root 新建无角色模板（访客 / 单次 / OTP）', [tg, tsg, tot].every((r) => r.status === 200 && r.json.template.v === 1));
const ap4 = await inPage(M, 'POST', INV, { ttlSeconds: 600, templateId: 'guest' });
const ap5 = await bearer(INV, { ttlSeconds: 600, templateId: 'guest' });
check('维护者 / 应急 token 可以套用无角色模板（访客）', ap4.status === 200 && ap5.status === 200, `${ap4.status}/${ap5.status}`);
const invS = await invite('t_single', { templateId: 'single' });
const invO = await invite('t_otp', { templateId: 'otp' });
const invG = await invite('t_newm', { templateId: 'guest' });
const tg2 = await inPage(R, 'POST', TPL, { action: 'save', id: 'guest', name: '访客', role: null, expiry: 'd30' });
check('修改模板 → 版本 v2', tg2.status === 200 && tg2.json.template.v === 2);
const S = await newCtx(), O = await newCtx(), G = await newCtx();
check('单次使用模板：注册成功', await registerVia(S.page, invS.link));
await apiLogout(S.page);
const sl = await apiLogin(S.page);
check('单次使用：注册会话结束后再次 passkey 登录被拒（403）', sl.status === 403 && /单次使用/.test(sl.json.error), JSON.stringify(sl.json));
check('OTP 模板：注册成功', await registerVia(O.page, invO.link));
await apiLogout(O.page);
const ol1 = await apiLogin(O.page);
await apiLogout(O.page);
const ol2 = await apiLogin(O.page);
check('OTP：第 1 次登录成功，第 2 次被拒（DO 原子扣减）', ol1.status === 200 && ol2.status === 403, `${ol1.status}/${ol2.status}`);
check('邀请套用访客模板：注册成功且没有角色', await registerVia(G.page, invG.link) && !(await meOf(G.page)).role);
const ml2 = await inPage(R, 'GET', MEM);
const gr = ml2.json.members.find((m) => m.username === 't_newm');
check('快照：邀请签发时是 guest@v1（1 天），之后改成 v2（30 天）不影响', gr && gr.expiry.template === 'guest@v1' && Math.abs(gr.expiry.accountExpiresAt - Date.now() - 86400e3) < 120000, gr && JSON.stringify(gr.expiry));

// --- 7. 兜底恢复：未实现，接口固定 501 ---
const ri1 = await bearer('/api/admin/recovery', { action: 'issue', username: ROOT }, RECOVERY_TOKEN);
const ri2 = await raw('POST', '/api/recovery/redeem', { body: { username: ROOT, code: randomBytes(32).toString('base64url') } });
const ri3 = await inPage(R, 'POST', '/api/admin/recovery', { action: 'cancel', username: ROOT });
check('兜底恢复已禁用：签发 / 兑换 / 作废（即使 RECOVERY_ENABLED=1 且持有恢复 token）全部 501', [ri1, ri2, ri3].every((r) => r.status === 501 && r.json && r.json.disabled === true), [ri1, ri2, ri3].map((r) => r.status).join('/'));
const X = { page: R };
const code = 'none', ri5 = { json: { code: 'none' } }, gi = { json: { code: 'none' } };

// --- 8. 审计 ---
const au = await inPage(X.page, 'GET', '/api/admin/audit');
const evs = new Set((au.json?.entries || []).map((e) => e.ev));
const need = ['expiry.set', 'permission.revoke', 'permission.restore', 'template.create', 'template.update', 'template.apply', 'role.set', 'login.denied_expired', 'invite.create'];
check('审计日志包含各类事件', au.status === 200 && need.every((e) => evs.has(e)), `缺少：${need.filter((e) => !evs.has(e)).join(',') || '无'}`);
const auText = JSON.stringify(au.json);
check('审计日志不含 token / 邀请码明文', ![RECOVERY_TOKEN, TOKEN, invS.code, invO.code].some((s) => auText.includes(s)));
const aul = await inPage(L, 'GET', '/api/admin/audit');
check('审计日志只有负责人可看（高级管理员 403）', aul.status === 403);

// --- 9. 管理页 UI ---
await budget('/admin'); await budget(INV); await budget(MEM); await budget(TPL);
const pg = await L.goto(BASE + '/admin');
await L.waitForSelector('#mem-list tr[data-user="t_maint"]', { timeout: 10000 }).catch(() => {});
await L.waitForSelector('#inv-tpl option[value="guest"]', { state: 'attached', timeout: 15000 }).catch(() => {});
const tplOpts = await L.$$eval('#inv-tpl option', (os) => os.map((o) => o.value));
check('管理页：高级管理员可见过期设置区和模板选择，模板列表只含无角色模板', pg.status() === 200 && !(await L.locator('#expiry').isHidden()) && tplOpts.includes('guest') && !tplOpts.includes('maint30') && !tplOpts.includes('lead'), tplOpts.join(','));
check('管理页：成员行显示发邀请权限并有切换按钮', (await L.locator('#mem-list tr[data-user="t_maint"] button.toggle-invite').count()) === 1 && /有|已撤销/.test(await L.locator('#mem-list tr[data-user="t_maint"] td.perm-invite').innerText()));
check('管理页：高级管理员看不到模板编辑表单和审计区', await L.locator('#tpl-form').isHidden() && await L.locator('#audit').isHidden());

await browser.close();
await stopDev();
const failed = results.filter((r) => !r.ok).length;
console.log(`结果：${results.length - failed}/${results.length} 通过；用时 ${Math.round((Date.now() - T0) / 1000)} 秒`);
process.exit(failed ? 1 : 0);
