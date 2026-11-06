// Passkey (WebAuthn) 登录演示 —— Cloudflare Worker（API + 静态资源）
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import {
  isoBase64URL,
  decodeClientDataJSON,
  parseAuthenticatorData,
  decodeAttestationObject,
} from '@simplewebauthn/server/helpers';
import { evaluateLogin, ipPrefix, uaFamily } from './risk.js';
export { AuthState } from './state.js';
import { makeOidc } from './oidc.js';
import { attachStore, consumeInvite } from './store.js';
import { issueMigrationTicket, redeemMigrationTicket, migrationRegisterPlan } from './migrate.js';

// ---------- 常量 ----------
const MAX_PASSKEYS = 5;
const CHAL_TTL = 300; // 秒：签名 challenge cookie 的有效期（exp = now + 5 分钟）
// 会话时长不再是单一常量：按“会话时长预设 × 账户档位（普通 / 管理员 / 临时）”计算，见 SESSION_PRESETS 与 docs/session.md
// 范围开关（编译期常量，非配置项）：不提供新建/提升管理员的新入口
const RECOVERY_IMPLEMENTED = false; // 兜底恢复：只保留设计
const ROLE_TEMPLATES_ENABLED = false; // 带角色的岗位模板
const STEPUP_WINDOW_MS = 5 * 60 * 1000; // 敏感操作要求 5 分钟内重新验证过
const MAX_BODY = 16 * 1024; // 16 KB
const USERNAME_RE = /^[a-zA-Z0-9_-]{3,32}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const SESS_COOKIE = '__Host-pk_sess';
const MIG_COOKIE = '__Host-pk_mig';
// 每种流程使用独立的 challenge cookie，避免条件式 UI 与普通登录互相覆盖
const CHAL_COOKIES = { reg: '__Host-pk_chal_reg', auth: '__Host-pk_chal_auth', cond: '__Host-pk_chal_cond', step: '__Host-pk_chal_step' };
const SIGNED_COOKIE_RE = /^[A-Za-z0-9_-]{1,900}\.[A-Za-z0-9_-]{43}$/;
const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
// 统一的注册失败提示：不区分“用户名已存在 / 凭据已登记 / 并发抢注”，避免泄露用户名是否存在
const REG_GENERIC_ERROR = '该用户名不可用或请求无效，请换一个用户名后重试。';
const LOGIN_GENERIC_ERROR = '该 passkey 无效或对应账号已不存在，请重试。';
const RATE_LIMIT_ERROR = '请求过于频繁，请稍后再试（每个 IP 每个接口每分钟最多 10 次）。';
// 邀请码统一错误：不区分“缺失 / 格式错误 / 不存在 / 已过期 / 已撤销 / 已使用 / 绑定的用户名不符”
const INVITE_GENERIC_ERROR = '邀请码无效或已失效，请向管理员索取新的邀请。';
const ADMIN_AUTH_ERROR = '未授权';
const ADMIN_CSRF_ERROR = '来源校验失败（疑似跨站请求）';
// 网页管理接口必须带的自定义请求头：跨站页面无法在不经过 CORS 预检的情况下设置它（本站不响应预检），作为 CSRF 的又一道防线
const ADMIN_CSRF_HEADER = 'X-PK-Admin';
const INVITE_RE = /^[A-Za-z0-9_-]{43}$/; // 32 字节随机数的 base64url（256 bit）
const INVITE_ID_RE = /^[0-9a-f]{16}$/;
const INVITE_TTL_DEFAULT = 72 * 3600; // 默认 72 小时
const INVITE_TTL_MIN = 60; // KV expiration 的最小值
const INVITE_TTL_MAX = 30 * 24 * 3600; // 最长 30 天
const INVITE_LIST_MAX = 200;
// 限流：每个接口按 IP 单独计数；必须在任何 KV 写入和 Turnstile siteverify 之前执行
const RATE_LIMITED = {
  'POST /api/register/options': 'RL_OPTIONS',
  'POST /api/login/options': 'RL_OPTIONS',
  'POST /api/register/verify': 'RL_VERIFY',
  'POST /api/login/verify': 'RL_VERIFY',
  'POST /api/logout': 'RL_VERIFY',
  // 管理接口：在校验 ADMIN_TOKEN 之前限流，防止暴力猜测
  'GET /api/admin/invites': 'RL_ADMIN',
  'POST /api/admin/invites': 'RL_ADMIN',
  'POST /api/admin/invites/revoke': 'RL_ADMIN',
  'GET /api/admin/members': 'RL_ADMIN',
  'POST /api/admin/members': 'RL_ADMIN',
  'POST /api/admin/expiry': 'RL_ADMIN',
  'GET /api/admin/audit': 'RL_ADMIN',
  'POST /api/admin/recovery': 'RL_ADMIN',
  'GET /api/admin/templates': 'RL_ADMIN',
  'POST /api/admin/templates': 'RL_ADMIN',
  'POST /api/admin/permissions': 'RL_ADMIN',
  'GET /api/admin/session-preset': 'RL_ADMIN',
  'POST /api/admin/session-preset': 'RL_ADMIN',
  'POST /api/stepup/options': 'RL_OPTIONS',
  'POST /api/stepup/verify': 'RL_VERIFY',
  'POST /api/migrate/ticket': 'RL_VERIFY',
  'POST /api/migrate/redeem': 'RL_VERIFY',
  // 恢复码兑换：未登录接口，按 IP 限流（另有按用户名的失败锁定）
  'POST /api/recovery/redeem': 'RL_VERIFY',
};
const ALLOWED_TRANSPORTS = new Set(['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb']);

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// ---------- 工具函数 ----------
function randomId(bytes = 32) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return isoBase64URL.fromBuffer(b);
}

function getRawCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}
function getCookie(request, name) {
  const v = getRawCookie(request, name); // nosemgrep: ajinabraham.njsscan.dos.regex_dos.regex_dos -- 单一字符类 + 锚定，线性匹配，且先做长度上限检查
  return v && v.length <= 64 && B64URL_RE.test(v) ? v : null;
}

function cookie(name, value, maxAge) {
  // __Host- 前缀 + Path=/ + Secure（无 Domain）；SameSite=Lax（从外部链接进入时保持登录）；CSRF 另由 Origin 校验 + X-PK-Admin 头 + Sec-Fetch-Site 防护
  return `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    // Turnstile 官方 CSP 要求：script-src 与 frame-src 放行 https://challenges.cloudflare.com
    "default-src 'none'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'publickey-credentials-get=(self), publickey-credentials-create=(self)',
  'Strict-Transport-Security': 'max-age=31536000',
};

function json(data, status = 200, setCookies = [], extraHeaders = {}) {
  const h = new Headers({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SECURITY_HEADERS, ...extraHeaders });
  for (const c of setCookies) h.append('Set-Cookie', c);
  return new Response(JSON.stringify(data), { status, headers: h });
}

function trunc(s, n = 16) {
  return typeof s === 'string' && s.length > n ? s.slice(0, n) + '…' : s;
}

async function readJson(request) {
  const ct = request.headers.get('Content-Type') || '';
  if (!ct.toLowerCase().startsWith('application/json')) throw new HttpError(415, '请求必须为 application/json');
  const len = Number(request.headers.get('Content-Length') || '0');
  if (len > MAX_BODY) throw new HttpError(413, '请求体过大');
  const text = await request.text();
  if (text.length > MAX_BODY) throw new HttpError(413, '请求体过大');
  if (!text) return {};
  try {
    const v = JSON.parse(text);
    if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new Error();
    return v;
  } catch {
    throw new HttpError(400, '请求体不是合法的 JSON 对象');
  }
}

function validUsername(u) {
  if (typeof u !== 'string' || !USERNAME_RE.test(u)) {
    throw new HttpError(400, '用户名须为 3–32 个字符，仅允许英文字母、数字、下划线和连字符');
  }
  return u;
}

function str(v, max) { return typeof v === 'string' && v.length > 0 && v.length <= max; }

// 对浏览器提交的 credential JSON 做基本结构校验（具体的密码学校验交给 SimpleWebAuthn）
function validateCredentialShape(c, kind) {
  if (typeof c !== 'object' || c === null) throw new HttpError(400, '缺少 credential');
  if (!str(c.id, 1400) || !B64URL_RE.test(c.id)) throw new HttpError(400, 'credential.id 无效'); // nosemgrep: ajinabraham.njsscan.dos.regex_dos.regex_dos -- 单一字符类 + 锚定，线性匹配，且先做长度上限检查
  if (c.rawId !== c.id) throw new HttpError(400, 'credential.rawId 无效');
  if (c.type !== 'public-key') throw new HttpError(400, 'credential.type 无效');
  const r = c.response;
  if (typeof r !== 'object' || r === null) throw new HttpError(400, 'credential.response 无效');
  if (!str(r.clientDataJSON, 4096) || !B64URL_RE.test(r.clientDataJSON)) throw new HttpError(400, 'clientDataJSON 无效');
  if (kind === 'reg') {
    if (!str(r.attestationObject, 12000) || !B64URL_RE.test(r.attestationObject)) throw new HttpError(400, 'attestationObject 无效');
    if (r.transports !== undefined && (!Array.isArray(r.transports) || r.transports.length > 8)) throw new HttpError(400, 'transports 无效');
  } else {
    if (!str(r.authenticatorData, 4096) || !B64URL_RE.test(r.authenticatorData)) throw new HttpError(400, 'authenticatorData 无效');
    if (!str(r.signature, 2048) || !B64URL_RE.test(r.signature)) throw new HttpError(400, 'signature 无效');
    if (r.userHandle !== undefined && r.userHandle !== null && (!str(r.userHandle, 128) || !B64URL_RE.test(r.userHandle))) throw new HttpError(400, 'userHandle 无效');
  }
  if (c.clientExtensionResults !== undefined && (typeof c.clientExtensionResults !== 'object' || c.clientExtensionResults === null)) {
    throw new HttpError(400, 'clientExtensionResults 无效');
  }
  return c;
}

function flagsOf(authData) {
  const p = parseAuthenticatorData(authData);
  return { flags: { UP: p.flags.up, UV: p.flags.uv, BE: p.flags.be, BS: p.flags.bs, AT: p.flags.at, ED: p.flags.ed }, signCount: p.counter };
}

function clientDataDebug(b64) {
  try {
    const c = decodeClientDataJSON(b64);
    return { type: c.type, origin: c.origin, challenge: trunc(c.challenge) };
  } catch { return { error: '无法解析' }; }
}

// ---------- KV 访问 ----------
async function getUser(env, username) {
  return env.KV.get(`user:${username}`, 'json');
}
async function putUser(env, user) {
  await env.KV.put(`user:${user.username}`, JSON.stringify(user));
}
const stateStub = (env) => env.STATE.get(env.STATE.idFromName('global'));

// ---------- 会话时长预设（root 可在管理页切换；对新会话生效，已有会话下次请求时按 min(原上限, 新上限) 收紧）----------
// abs = 绝对过期（从登录起算，不续期）；idle = 空闲过期（每次请求滑动续期）。单位毫秒。
const H = 3600e3, D = 24 * H;
const SESSION_PRESETS = {
  recommended: { label: '推荐（默认）', normal: { abs: 7 * D, idle: 24 * H }, admin: { abs: 12 * H, idle: 30 * 60e3 }, temp: { abs: D, idle: H } },
  aal2: { label: 'NIST AAL2', normal: { abs: D, idle: H }, admin: { abs: D, idle: H }, temp: { abs: D, idle: H } },
  relaxed: { label: '宽松（AAL1 上限）', normal: { abs: 30 * D, idle: 7 * D }, admin: { abs: 30 * D, idle: 7 * D }, temp: { abs: 30 * D, idle: 7 * D } },
};
async function currentPresetId(env) {
  const v = await env.KV.get('cfg:session_preset');
  if (Object.hasOwn(SESSION_PRESETS, v)) return v;
  return Object.hasOwn(SESSION_PRESETS, env.SESSION_PRESET) ? env.SESSION_PRESET : 'recommended';
}
// 档位：负责人 / 有 KV 角色（且未过期）→ admin；有账户过期或单次 / OTP 设置（非永不过期）→ temp；否则 normal
function tierOf(isPrincipal, role, e) {
  if (isPrincipal || role) return 'admin';
  if (e && !e.never && (e.ax || e.once)) return 'temp';
  return 'normal';
}
async function tierFor(env, username) {
  if (principals(env).has(username)) return 'admin';
  const [r, e] = await Promise.all([env.KV.get(`role:${username}`), getExpiry(env, username)]);
  const role = KV_ROLES.has(r) && !expiryState(e).roleExpired ? r : null;
  return tierOf(false, role, e);
}
async function sessionLimits(env, username) {
  const [pid, tier] = await Promise.all([currentPresetId(env), tierFor(env, username)]);
  return { pid, tier, ...SESSION_PRESETS[pid][tier] };
}

async function getSession(env, request) {
  const sid = getCookie(request, SESS_COOKIE);
  if (!sid) return null;
  const stub = stateStub(env);
  const s = await stub.sessGet(sid); // 服务端会话表（DO，强一致；吊销立即生效）
  if (!s) return null;
  const now = Date.now();
  // 每次请求都检查账户过期（不只在登录时检查）
  if (await accountExpired(env, s.username)) { await stub.sessDelete(sid); return null; }
  const lim = await sessionLimits(env, s.username);
  const absAt = Math.min(s.absAt, s.createdAt + lim.abs); // 预设收紧时立即生效；放宽不延长已有会话
  if (now >= absAt || now - s.lastSeen >= lim.idle) { await stub.sessDelete(sid); return null; }
  // 收紧是单向棘轮：把更早的绝对过期时间写回会话表，之后再放宽预设也不会延长这个会话
  const patch = {};
  if (absAt < s.absAt) patch.absAt = absAt;
  if (now - s.lastSeen > 30e3) patch.lastSeen = now; // 空闲过期滑动续期（30 秒节流）
  if (Object.keys(patch).length) await stub.sessUpdate(sid, patch);
  return { sid, ...s, absAt, idleMs: lim.idle, tier: lim.tier, preset: lim.pid };
}
async function createSession(env, username, { risk = null } = {}) {
  const sid = randomId(32);
  const now = Date.now();
  const lim = await sessionLimits(env, username);
  // uvAt：最近一次带用户验证（UV）的 passkey 验证时间；新环境登录时置 0，敏感操作前必须 step-up
  await stateStub(env).sessCreate(sid, { username, createdAt: now, lastSeen: now, absAt: now + lim.abs, uvAt: risk ? 0 : now, risk }, lim.abs);
  return cookie(SESS_COOKIE, sid, Math.ceil(lim.abs / 1000));
}
// ---------- 签名 challenge cookie（options 阶段零 KV 写入）----------
// 格式：base64url(payload JSON) + "." + base64url(HMAC-SHA256(payload 部分))
// payload：{ p: 'reg'|'auth', f: 流程(reg/auth/cond), c: challenge, u: 用户名, uid: userID, su: 发起时的登录用户, x: 过期时间(ms) }
let hmacCache = null;
async function hmacKey(env) {
  const src = env.CHAL_HMAC_KEY;
  if (!src) throw new HttpError(500, '服务器未配置签名密钥');
  if (hmacCache && hmacCache.src === src) return hmacCache.key;
  let raw;
  try { raw = Uint8Array.from(atob(src), (ch) => ch.charCodeAt(0)); } catch { throw new HttpError(500, '服务器签名密钥格式错误'); }
  if (raw.length < 32) throw new HttpError(500, '服务器签名密钥过短');
  const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  hmacCache = { src, key };
  return key;
}
const enc = new TextEncoder();
async function signChallenge(env, payload, flow) {
  // 一次性：challenge 同时登记到 DO，verify 时原子取出并删除（HMAC cookie 只证明“是我们签发的”，不防重放）
  await stateStub(env).issue(`ch:${payload.c}`, CHAL_TTL * 1000);
  const body = isoBase64URL.fromBuffer(enc.encode(JSON.stringify({ ...payload, f: flow, x: Date.now() + CHAL_TTL * 1000 })));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(body)));
  return cookie(CHAL_COOKIES[flow], `${body}.${isoBase64URL.fromBuffer(mac)}`, CHAL_TTL);
}
// 校验顺序：格式 → HMAC（crypto.subtle.verify，常量时间比较）→ 过期 → 用途/流程
async function readSignedChallenge(env, request, flow) {
  const v = getRawCookie(request, CHAL_COOKIES[flow]);
  if (!v) throw new HttpError(400, 'challenge 不存在或已过期，请重试');
  if (!SIGNED_COOKIE_RE.test(v)) throw new HttpError(400, 'challenge cookie 格式无效');
  const [body, sig] = v.split('.');
  const ok = await crypto.subtle.verify('HMAC', await hmacKey(env), isoBase64URL.toBuffer(sig), enc.encode(body));
  if (!ok) throw new HttpError(400, 'challenge cookie 签名无效（可能被篡改）');
  let p;
  try { p = JSON.parse(new TextDecoder().decode(isoBase64URL.toBuffer(body))); } catch { throw new HttpError(400, 'challenge cookie 内容无效'); }
  if (typeof p.x !== 'number' || Date.now() > p.x) throw new HttpError(400, 'challenge 已过期，请重试');
  const expectPurpose = flow === 'reg' ? 'reg' : 'auth';
  if (p.p !== expectPurpose || p.f !== flow || typeof p.c !== 'string') throw new HttpError(400, 'challenge 用途不匹配');
  if (!(await stateStub(env).consume(`ch:${p.c}`))) throw new HttpError(400, 'challenge 已被使用，请重试');
  return p;
}

// ---------- 邀请码 ----------
// KV 只存邀请码的 SHA-256（hex）：inv:<sha256hex>，值与 metadata 均为 {id, u, c, x}
//   id = 哈希前 16 位 hex（管理用的公开标识，无法反推邀请码），u = 绑定用户名（可选），c = 创建时间，x = 过期时间（ms）
// 用 KV 的 expiration 让过期邀请自动删除；撤销 / 使用后直接 delete。
async function sha256hex(text) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text)));
  return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('');
}
// 返回有效邀请记录 {h, id, u, x}；任何无效情况都抛出同一个错误（状态码与文本一致）
async function checkInvite(env, code, username) {
  if (typeof code !== 'string' || !INVITE_RE.test(code)) throw new HttpError(403, INVITE_GENERIC_ERROR);
  const h = await sha256hex(code);
  const inv = await env.KV.get(`inv:${h}`, 'json'); // 1 次 KV 读取
  if (!inv || typeof inv.x !== 'number' || Date.now() > inv.x) throw new HttpError(403, INVITE_GENERIC_ERROR);
  if (inv.u && inv.u !== username) throw new HttpError(403, INVITE_GENERIC_ERROR);
  return { h, ...inv };
}

// ---------- 角色与鉴权 ----------
// 三级角色（英文标识 / 中文显示名），参考 Stripe / Vercel / Notion / Linear 的“最高角色 + 成员管理角色 + 普通角色”模式：
//   principal       负责人   —— Worker vars PRINCIPALS 配置（逗号分隔），页面上不能授予或移除；全部权限，可分配 / 移除下面两种角色
//   membership_lead 成员主管 —— 由负责人在页面上授予（存 KV role:<用户名>）；签发、查看、撤销任何邀请；可分配 / 移除“邀请人”
//   inviter         邀请人   —— 由负责人或成员主管授予；签发、查看邀请；只能撤销自己签发的邀请
// 每次请求按会话里的用户名实时判断角色：负责人只看 vars（0 次 KV），其余角色 1 次 KV 读取；只有改角色时才写 KV。
//
// 两种入口，未登录 / 无角色一律 401 {"error":"未授权"}；有角色但权限不够 → 403 {"error":"权限不足：…"}：
//   1) 日常：网页会话（cookie __Host-pk_sess：HttpOnly; Secure; SameSite=Strict）+ 角色。
//      CSRF：Sec-Fetch-Site（如有）必须是 same-origin；Origin（如有；POST 必须有）必须等于 ORIGIN；
//      必须带自定义头 X-PK-Admin: 1（跨站页面无法不经 CORS 预检设置，本站不响应预检）；SameSite=Strict 下跨站请求本来也不带会话 cookie。
//   2) 应急：Authorization: Bearer <ADMIN_TOKEN>（命令行 scripts/invite.mjs），只能管理邀请（等同负责人的邀请权限），不能改角色。
//      带了 Authorization 头就只走这一条，不回退到会话；删除 ADMIN_TOKEN secret 即关闭（fail closed）。
const ROLES = {
  principal: { label: '负责人', revokeAny: true, viewMembers: true, assign: ['membership_lead', 'inviter'] },
  membership_lead: { label: '成员主管', revokeAny: true, viewMembers: true, assign: ['inviter'] },
  inviter: { label: '邀请人', revokeAny: false, viewMembers: false, assign: [] },
};
const KV_ROLES = new Set(['membership_lead', 'inviter']); // 可存 KV 的角色（负责人只能来自 vars）
const TOKEN_ACTOR = '#token'; // 应急入口签发的邀请的签发者标识（含 #，不可能与用户名冲突）
const FORBIDDEN = (msg) => new HttpError(403, `权限不足：${msg}`);

function principals(env) {
  return new Set(String(env.PRINCIPALS || '').split(',').map((x) => x.trim()).filter((x) => USERNAME_RE.test(x)));
}
async function getRole(env, username) {
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) return null;
  if (principals(env).has(username)) return 'principal'; // 负责人永不过期
  const [r, e] = await Promise.all([env.KV.get(`role:${username}`), getExpiry(env, username)]); // 2 次 KV 读取（并行）
  if (!KV_ROLES.has(r)) return null;
  if (expiryState(e).roleExpired) return null; // 角色已过期 → 视为无角色（每次请求实时判断）
  return r;
}
function rolePublic(role) {
  if (!role) return null;
  const R = ROLES[role];
  return { id: role, label: R.label, perms: { createInvite: true, listInvites: true, revokeAnyInvite: R.revokeAny, viewMembers: R.viewMembers, assignRoles: R.assign } };
}
// 浏览器跨站请求特征检查（不读 KV）
function sameOriginRequest(env, request) {
  const sfs = request.headers.get('Sec-Fetch-Site');
  if (sfs !== null && sfs !== 'same-origin') return false;
  const origin = request.headers.get('Origin');
  if (origin !== null && origin !== env.ORIGIN) return false;
  if (request.method !== 'GET' && origin !== env.ORIGIN) return false;
  return true;
}
// 会话 + 角色：1 次 KV 读取（会话）+ 非负责人再 1 次（角色）
async function sessionActor(env, request) {
  const s = await getSession(env, request);
  if (!s) return null;
  const [role, deny] = await Promise.all([getRole(env, s.username), getDeny(env, s.username)]);
  return role ? { username: s.username, role, token: false, deny, sid: s.sid, uvAt: s.uvAt || 0, risk: s.risk || null } : null;
}
// 返回操作者 { username, role, token }
async function requireStaff(env, request) {
  if (request.headers.has('Authorization')) {
    await requireAdminToken(env, request);
    return { username: TOKEN_ACTOR, role: 'principal', token: true, deny: new Set() };
  }
  if (!sameOriginRequest(env, request) || request.headers.get(ADMIN_CSRF_HEADER) !== '1') throw new HttpError(403, ADMIN_CSRF_ERROR);
  const a = await sessionActor(env, request);
  if (!a) throw new HttpError(401, ADMIN_AUTH_ERROR);
  return a;
}

// 应急入口：常量时间比较——两边先做 SHA-256（长度固定为 32 字节），再用 crypto.subtle.timingSafeEqual 比较
async function requireAdminToken(env, request) {
  const auth = request.headers.get('Authorization') || '';
  const m = /^Bearer ([\x21-\x7e]{1,512})$/.exec(auth);
  const expected = env.ADMIN_TOKEN;
  const given = m ? m[1] : '';
  const [a, b] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(given)),
    crypto.subtle.digest('SHA-256', enc.encode(typeof expected === 'string' ? expected : '')),
  ]);
  const same = crypto.subtle.timingSafeEqual(a, b);
  // 未配置 / 过短的 ADMIN_TOKEN 一律拒绝（fail closed）
  if (!m || typeof expected !== 'string' || expected.length < 32 || !same) throw new HttpError(401, ADMIN_AUTH_ERROR);
}

// step-up：敏感操作要求 5 分钟内做过带 UV 的 passkey 验证（新环境登录的会话必须先 step-up）。应急 token 是带外 secret，不适用。
// 本地测试可用 STEPUP_TEST_WINDOW_SECONDS 缩短窗口（仅 RP_ID=localhost 时生效）
const stepUpWindow = (env) => (env.RP_ID === 'localhost' && Number(env.STEPUP_TEST_WINDOW_SECONDS) > 0 ? Number(env.STEPUP_TEST_WINDOW_SECONDS) * 1000 : STEPUP_WINDOW_MS);
function requireStepUp(actorOrSession, env) {
  if (actorOrSession.token) return;
  const ok = actorOrSession.uvAt && Date.now() - actorOrSession.uvAt <= stepUpWindow(env) && !actorOrSession.risk;
  if (!ok) throw Object.assign(new HttpError(403, '此操作需要重新验证身份（step-up）：请用 passkey 再验证一次'), { stepUp: true });
}
async function stepupOptions(env, request) {
  await readJson(request);
  const s = await getSession(env, request);
  if (!s) throw new HttpError(401, ADMIN_AUTH_ERROR);
  const user = await getUser(env, s.username);
  if (!user) throw new HttpError(401, ADMIN_AUTH_ERROR);
  const options = await generateAuthenticationOptions({
    rpID: env.RP_ID, userVerification: 'required', timeout: 120000,
    allowCredentials: user.credentials.map((c) => ({ id: c.id, transports: c.transports })),
  });
  const setChal = await signChallenge(env, { p: 'auth', c: options.challenge, u: s.username, sid: s.sid }, 'step');
  return json({ options }, 200, [setChal]);
}
async function stepupVerify(env, request) {
  const body = await readJson(request);
  const response = validateCredentialShape(body.credential, 'auth');
  const rec = await readSignedChallenge(env, request, 'step');
  const clearChal = cookie(CHAL_COOKIES.step, '', 0);
  const s = await getSession(env, request);
  if (!s || s.sid !== rec.sid || s.username !== rec.u) return json({ error: '会话已改变，请重新登录' }, 401, [clearChal]);
  const user = await getUser(env, s.username);
  const cred = user && user.credentials.find((c) => c.id === response.id);
  if (!cred) return json({ error: LOGIN_GENERIC_ERROR }, 400, [clearChal]);
  let v;
  try {
    v = await verifyAuthenticationResponse({
      response, expectedChallenge: rec.c, expectedOrigin: env.ORIGIN, expectedRPID: env.RP_ID,
      credential: { id: cred.id, publicKey: isoBase64URL.toBuffer(cred.publicKey), counter: cred.counter, transports: cred.transports },
      requireUserVerification: true,
    });
  } catch (e) { return json({ error: `验证失败：${e.message}` }, 400, [clearChal]); }
  if (!v.verified || !assertUpUv(response)) return json({ error: '验证失败' }, 400, [clearChal]);
  cred.counter = v.authenticationInfo.newCounter;
  await putUser(env, user);
  await stateStub(env).sessUpdate(s.sid, { uvAt: Date.now(), risk: null });
  await audit(env, request, 'session.stepup', s.username, s.username, { cleared: s.risk || null });
  return json({ ok: true }, 200, [clearChal]);
}
// 服务端再次确认 authenticatorData 的 UP 与 UV 标志（SimpleWebAuthn 在 requireUserVerification=true 时也会校验，这里显式兜底）
function assertUpUv(response) {
  try {
    const f = parseAuthenticatorData(isoBase64URL.toBuffer(response.response.authenticatorData)).flags;
    return f.up === true && f.uv === true;
  } catch { return false; }
}

// 会话时长预设：GET 任何管理角色可看；POST 只有 root，且需 step-up
async function adminSessionPreset(env, request) {
  const actor = await requireStaff(env, request);
  const cur = await currentPresetId(env);
  if (request.method === 'GET') return json({ ok: true, current: cur, presets: SESSION_PRESETS, canSwitch: !actor.token && actor.role === 'principal' });
  if (actor.token || actor.role !== 'principal') throw FORBIDDEN('只有负责人（root）可以切换会话时长预设');
  requireStepUp(actor, env);
  const body = await readJson(request);
  if (!Object.hasOwn(SESSION_PRESETS, body.preset)) throw new HttpError(400, `preset 只能是 ${Object.keys(SESSION_PRESETS).join('、')}`);
  await env.KV.put('cfg:session_preset', body.preset);
  await audit(env, request, 'session.preset', actor.username, null, { from: cur, to: body.preset });
  return json({ ok: true, current: body.preset });
}

async function adminCreateInvite(env, request) {
  const actor = await requireStaff(env, request); // 三种角色都可以签发
  // 账户级权限覆盖（只做减法，优先级高于角色和模板）
  if (actor.deny.has('invite.create')) throw FORBIDDEN('你的“签发邀请”权限已被管理员撤销');
  requireStepUp(actor, env);
  const body = await readJson(request);
  let tp = null;
  if (body.templateId !== undefined && body.templateId !== null && body.templateId !== '') {
    const tpl = await getTemplate(env, body.templateId);
    if (!tpl) return json({ error: '岗位模板不存在' }, 404);
    assertCanApplyTemplate(actor, tpl);
    tp = snapshotTemplate(tpl); // 签发时复制快照：之后修改模板不影响这份邀请
  }
  let ttl = body.ttlSeconds === undefined ? INVITE_TTL_DEFAULT : body.ttlSeconds;
  if (!Number.isInteger(ttl) || ttl < INVITE_TTL_MIN || ttl > INVITE_TTL_MAX) {
    throw new HttpError(400, `ttlSeconds 须为 ${INVITE_TTL_MIN}–${INVITE_TTL_MAX} 之间的整数`);
  }
  let u = null;
  if (body.username !== undefined && body.username !== null && body.username !== '') u = validUsername(body.username);
  const code = randomId(32); // 256 bit
  const h = await sha256hex(code);
  const now = Date.now();
  const rec = { id: h.slice(0, 16), u, c: now, x: now + ttl * 1000, b: actor.username }; // b = 签发者（用户名或 #token）
  if (tp) rec.tp = tp;
  // 1 次 KV 写入；expiration 到期后 KV 自动删除（metadata 让 list 无需逐个读取）
  await env.KV.put(`inv:${h}`, JSON.stringify(rec), { expiration: Math.ceil(rec.x / 1000), metadata: rec });
  await audit(env, request, 'invite.create', actor.username, u, { id: rec.id, tpl: tp ? `${tp.id}@v${tp.v}` : null });
  // 明文邀请码只在这一次响应中返回，服务器不保存
  return json({ ok: true, code, id: rec.id, username: u, createdBy: rec.b, createdAt: rec.c, expiresAt: rec.x, link: `${env.ORIGIN}/#invite=${code}${u ? `&u=${encodeURIComponent(u)}` : ''}` });
}

async function adminListInvites(env, request) {
  const actor = await requireStaff(env, request);
  // 1 次 KV list（不逐个 get：信息都在 metadata 里）
  const r = await env.KV.list({ prefix: 'inv:', limit: INVITE_LIST_MAX });
  const now = Date.now();
  const revokeAny = ROLES[actor.role].revokeAny;
  const invites = r.keys
    .map((k) => k.metadata)
    .filter((m) => m && typeof m.x === 'number' && m.x > now)
    .map((m) => ({ id: m.id, username: m.u || null, status: 'pending', createdBy: m.b || null, createdAt: m.c, expiresAt: m.x, template: m.tp ? { id: m.tp.id, name: m.tp.n, version: m.tp.v } : null, canRevoke: revokeAny || m.b === actor.username }))
    .sort((a, b) => a.expiresAt - b.expiresAt);
  return json({ ok: true, me: { username: actor.token ? null : actor.username, role: rolePublic(actor.role), via: actor.token ? 'token' : 'session', deny: [...actor.deny] }, invites, truncated: !r.list_complete });
}

async function adminRevokeInvite(env, request) {
  const actor = await requireStaff(env, request);
  const body = await readJson(request);
  if (typeof body.id !== 'string' || !INVITE_ID_RE.test(body.id)) throw new HttpError(400, 'id 须为 16 位十六进制');
  // 1 次 KV list（按哈希前缀定位，metadata 里有签发者）+ 每个匹配键 1 次 delete（正常为 1）
  const r = await env.KV.list({ prefix: `inv:${body.id}`, limit: 10 });
  if (!r.keys.length) return json({ error: '没有找到该邀请（可能已使用、已撤销或已过期）' }, 404);
  if (!ROLES[actor.role].revokeAny && !r.keys.every((k) => k.metadata && k.metadata.b === actor.username)) {
    throw FORBIDDEN('邀请人只能撤销自己签发的邀请');
  }
  for (const k of r.keys) await env.KV.delete(k.name);
  await audit(env, request, 'invite.revoke', actor.username, null, { id: body.id });
  return json({ ok: true, revoked: r.keys.length });
}

// 成员角色列表：负责人、成员主管可见（1 次 KV list；负责人来自 vars）
async function adminListMembers(env, request) {
  const actor = await requireStaff(env, request);
  if (actor.token || !ROLES[actor.role].viewMembers) throw FORBIDDEN('只有负责人和成员主管可以查看成员角色');
  const r = await env.KV.list({ prefix: 'role:', limit: 1000 });
  const P = principals(env);
  const members = [...P].map((u) => ({ username: u, role: rolePublic('principal'), source: 'vars', grantedBy: null, grantedAt: null }));
  for (const k of r.keys) {
    const u = k.name.slice(5);
    const m = k.metadata || {};
    if (P.has(u) || !KV_ROLES.has(m.r)) continue;
    members.push({ username: u, role: rolePublic(m.r), source: 'kv', grantedBy: m.b || null, grantedAt: m.t || null });
  }
  // 只有过期设置 / 权限覆盖、没有角色的账户（如临时账户）也列出来
  const [er, dr] = await Promise.all([env.KV.list({ prefix: 'exp:', limit: 1000 }), env.KV.list({ prefix: 'deny:', limit: 1000 })]);
  const expMap = new Map(er.keys.map((k) => [k.name.slice(4), k.metadata || {}]));
  const denyMap = new Map(dr.keys.map((k) => [k.name.slice(5), k.metadata || {}]));
  for (const u of new Set([...expMap.keys(), ...denyMap.keys()])) {
    if (P.has(u) || members.some((m) => m.username === u)) continue;
    members.push({ username: u, role: null, source: 'none', grantedBy: null, grantedAt: null });
  }
  const now = Date.now();
  for (const m of members) {
    const isP = P.has(m.username);
    const roleId = m.role ? m.role.id : null;
    m.canEdit = !!m.role && !isP && m.username !== actor.username && ROLES[actor.role].assign.includes(roleId);
    m.canManage = canManageTarget(actor, m.username, roleId, P);
    m.expiry = isP ? { never: true, principal: true, label: '永不过期（负责人，由 PRINCIPALS 决定）' } : expiryPublic(expMap.get(m.username) || null, now);
    const d = denyMap.get(m.username);
    m.deny = isP ? [] : (d && Array.isArray(d.d) ? d.d : []);
  }
  return json({ ok: true, me: { username: actor.username, role: rolePublic(actor.role) }, members });
}

// 授予 / 变更 / 移除角色：{ username, role: 'membership_lead' | 'inviter' | null }
// KV：1 次读（目标当前角色）+ 授予时 1 次读（目标用户是否存在）+ 只有真正变化时才 1 次写 / 删
async function adminSetRole(env, request) {
  const actor = await requireStaff(env, request);
  if (actor.token) throw FORBIDDEN('应急 token 只能管理邀请，角色请由负责人在页面上分配');
  requireStepUp(actor, env);
  const body = await readJson(request);
  const target = validUsername(body.username);
  let next = body.role === null || body.role === undefined || body.role === '' ? null : body.role;
  let tp = null;
  if (body.templateId !== undefined && body.templateId !== null && body.templateId !== '') {
    // 已禁用：授予角色时套用模板（属于“提升管理员”的新入口）
    if (!ROLE_TEMPLATES_ENABLED) return json({ error: '授予角色时套用岗位模板已禁用；请直接选择角色授予', disabled: true }, 501);
    const tpl = await getTemplate(env, body.templateId);
    if (!tpl) return json({ error: '岗位模板不存在' }, 404);
    if (!tpl.role) throw new HttpError(400, '该模板没有基础角色，不能用于授予角色（可在签发邀请时使用）');
    assertCanApplyTemplate(actor, tpl);
    tp = snapshotTemplate(tpl);
    next = tpl.role;
  }
  if (next !== null && !KV_ROLES.has(next)) throw new HttpError(400, 'role 只能是 membership_lead、inviter 或 null（移除）');
  const allowed = ROLES[actor.role].assign;
  if (!allowed.length) throw FORBIDDEN('邀请人不能分配角色');
  if (principals(env).has(target)) throw FORBIDDEN('负责人由 Worker 配置（PRINCIPALS）决定，不能在页面上修改');
  if (target === actor.username) throw FORBIDDEN('不能修改自己的角色');
  if (next !== null && !allowed.includes(next)) throw FORBIDDEN(`${ROLES[actor.role].label}不能授予“${ROLES[next].label}”`);
  const cur = await env.KV.get(`role:${target}`);
  const current = KV_ROLES.has(cur) ? cur : null;
  if (current !== null && !allowed.includes(current)) throw FORBIDDEN(`${ROLES[actor.role].label}不能修改“${ROLES[current].label}”的角色`);
  if (current === next && !tp) return json({ ok: true, changed: false, username: target, role: rolePublic(next) });
  if (next === null) {
    await env.KV.delete(`role:${target}`);
  } else {
    if (!(await getUser(env, target))) return json({ error: '该用户不存在（只能给已注册的用户分配角色）' }, 404);
    if (current !== next) await env.KV.put(`role:${target}`, next, { metadata: { r: next, b: actor.username, t: Date.now(), tp: tp ? tp.id : undefined } });
  }
  let expiry = null;
  if (tp) expiry = expiryPublic(await applyTemplateExpiry(env, target, tp, actor.username), Date.now());
  // 角色 / 级别变化：吊销该用户全部会话（权限立即以新角色重新登录生效）
  const revokedSessions = current !== next ? await stateStub(env).sessRevokeUser(target) : 0;
  await audit(env, request, 'role.set', actor.username, target, { role: next, prev: current, tpl: tp ? `${tp.id}@v${tp.v}` : null, revokedSessions });
  return json({ ok: true, changed: true, username: target, role: rolePublic(next), expiry });
}

// ---------- 账户分级（与三级角色一一对应，代码保留原标识，向后兼容）----------
//   root        = principal（负责人，PRINCIPALS 配置）          level 3
//   高级管理员  = membership_lead（成员主管）                    level 2
//   维护者      = inviter（邀请人）                              level 1
//   普通账户    = 无角色                                         level 0
// 规则：只能管理（撤回权限 / 设过期 / 改角色）严格低于自己级别的账户；同级不能互相管理；不能管理自己；root 不能在页面上被管理。
const LEVEL = { principal: 3, membership_lead: 2, inviter: 1 };
const LEVEL_NAME = { 3: 'root', 2: '高级管理员', 1: '维护者', 0: '普通账户' };
const levelOf = (role) => LEVEL[role] || 0;
function canManageTarget(actor, target, targetRole, P) {
  if (actor.token) return false;
  if (P.has(target) || target === actor.username) return false;
  return levelOf(actor.role) > levelOf(targetRole);
}
async function assertManage(env, actor, target) {
  if (actor.token) throw FORBIDDEN('应急 token 不能管理账户，请由负责人在页面上操作');
  const P = principals(env);
  if (P.has(target)) throw FORBIDDEN('负责人（root）由 Worker 配置（PRINCIPALS）决定：永不过期、权限不可撤回，不能在页面上修改');
  if (target === actor.username) throw FORBIDDEN('不能修改自己的账户设置');
  const cur = await env.KV.get(`role:${target}`);
  const targetRole = KV_ROLES.has(cur) ? cur : null;
  if (!canManageTarget(actor, target, targetRole, P)) throw FORBIDDEN(`只能管理级别低于自己的账户（对方是${LEVEL_NAME[levelOf(targetRole)]}）`);
  return targetRole;
}

// ---------- 审计日志（KV audit:<倒序时间>:<随机>；不记录任何秘密：邀请码、恢复码、token、会话 id、IP 原文都不写）----------
const AUDIT_TTL = 90 * 24 * 3600;
async function audit(env, request, ev, actor, target, data = {}) {
  const t = Date.now();
  const rec = { t, ev, a: actor || null, u: target || null, ...data };
  const key = `audit:${String(9e15 - t).padStart(16, '0')}:${randomId(6)}`;
  try {
    const meta = JSON.stringify(rec).length <= 900 ? rec : { t, ev, a: rec.a, u: rec.u };
    await env.KV.put(key, JSON.stringify(rec), { expirationTtl: AUDIT_TTL, metadata: meta });
  } catch (e) { console.error('audit write failed', e); }
}
async function adminListAudit(env, request) {
  const actor = await requireStaff(env, request);
  if (actor.token || actor.role !== 'principal') throw FORBIDDEN('只有负责人可以查看审计日志');
  const r = await env.KV.list({ prefix: 'audit:', limit: 200 });
  return json({ ok: true, entries: r.keys.map((k) => k.metadata).filter(Boolean) });
}

// ---------- 过期时间（存储：KV exp:<用户名>，UTC 毫秒时间戳；显示：台北时间 UTC+8）----------
// 记录：{ ax: 账户过期(ms)|null, rx: 角色过期(ms)|null, never: 永不过期, once: 'single'|'otp'|undefined, ol: 剩余一次性登录次数, b, t, tp }
// never=true 时关闭一切过期检查；要重新设过期必须先显式 mode=none（取消永不过期）。负责人不读这条记录（永不过期）。
const EXP_MIN_MS = 5 * 60 * 1000; // 至少 5 分钟后
const EXP_MAX_MS = 5 * 365 * 24 * 3600 * 1000; // 最多 5 年
const DUR_RE = /^(\d{1,5})\s*(s|m|h|d|w)$/i;
const DUR_UNIT = { s: 1e3, m: 60e3, h: 3600e3, d: 86400e3, w: 7 * 86400e3 };
function parseDuration(v) {
  const m = typeof v === 'string' ? DUR_RE.exec(v.trim()) : null;
  if (!m) throw new HttpError(400, 'duration 格式应为 数字+单位（s 秒 / m 分钟 / h 小时 / d 天 / w 周），如 1d、12h');
  return Number(m[1]) * DUR_UNIT[m[2].toLowerCase()];
}
// 绝对时间：ISO 8601；不带时区的 "YYYY-MM-DDTHH:mm[:ss]" 按台北时间（+08:00）解释
function parseAbsolute(v) {
  if (typeof v !== 'string' || v.length > 40 || !/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})?$/.test(v.trim())) {
    throw new HttpError(400, 'at 须为日期时间，如 2026-12-31T18:00（按台北时间）或带时区的 ISO 8601');
  }
  let s = v.trim().replace(' ', 'T');
  if (!/(Z|[+-]\d{2}:\d{2})$/.test(s)) s += '+08:00';
  const t = Date.parse(s);
  if (!Number.isFinite(t)) throw new HttpError(400, 'at 不是有效的日期时间');
  return t;
}
// 本地测试：RP_ID=localhost 且 EXPIRY_TEST_MIN_SECONDS 设置时可缩短下限（线上 RP_ID 不是 localhost，永远是 5 分钟）
function expMinMs(env) {
  const v = Number.parseInt(env.EXPIRY_TEST_MIN_SECONDS || '', 10);
  return env.RP_ID === 'localhost' && v >= 1 ? v * 1000 : EXP_MIN_MS;
}
function checkExpRange(env, t, now) {
  if (t < now + expMinMs(env)) throw new HttpError(400, '过期时间须至少在 5 分钟之后');
  if (t > now + EXP_MAX_MS) throw new HttpError(400, '过期时间最多为 5 年之后');
  return t;
}
function taipei(t) {
  if (!t) return null;
  const d = new Date(t + 8 * 3600e3).toISOString();
  return `${d.slice(0, 10)} ${d.slice(11, 16)}（台北时间 UTC+8）`;
}
async function getExpiry(env, username) {
  return env.KV.get(`exp:${username}`, 'json');
}
async function putExpiry(env, username, e) {
  const meta = { ax: e.ax || null, rx: e.rx || null, never: !!e.never, once: e.once || null, ol: e.ol ?? null, b: e.b || null, t: e.t || null, tp: e.tp || null };
  await env.KV.put(`exp:${username}`, JSON.stringify(e), { metadata: meta });
}
function expiryState(e, now = Date.now()) {
  if (!e || e.never) return { accountExpired: false, roleExpired: false };
  const accountExpired = typeof e.ax === 'number' && now >= e.ax;
  return { accountExpired, roleExpired: accountExpired || (typeof e.rx === 'number' && now >= e.rx) };
}
async function accountExpired(env, username) {
  if (principals(env).has(username)) return false;
  return expiryState(await getExpiry(env, username)).accountExpired;
}
function expiryPublic(e, now) {
  if (!e) return { never: false, accountExpiresAt: null, roleExpiresAt: null, label: '未设置（不过期）' };
  if (e.never) return { never: true, accountExpiresAt: null, roleExpiresAt: null, label: '永不过期', template: e.tp || null };
  const st = expiryState(e, now);
  const parts = [];
  if (e.ax) parts.push(`账户 ${taipei(e.ax)}${st.accountExpired ? '（已过期）' : ''}`);
  if (e.rx) parts.push(`角色 ${taipei(e.rx)}${st.roleExpired ? '（已过期）' : ''}`);
  if (e.once === 'single') parts.push('单次使用');
  if (e.once === 'otp') parts.push(`一次性登录（剩余 ${e.ol > 0 ? e.ol : 0} 次）`);
  return {
    never: false, accountExpiresAt: e.ax || null, roleExpiresAt: e.rx || null,
    accountExpiresAtTaipei: taipei(e.ax), roleExpiresAtTaipei: taipei(e.rx),
    accountExpired: st.accountExpired, roleExpired: st.roleExpired, once: e.once || null,
    label: parts.join('；') || '未设置（不过期）', template: e.tp || null,
  };
}

// 设置 / 修改过期：{ username, scope: 'account'|'role', mode: 'relative'|'absolute'|'never'|'none'|'clear', duration?, at? }
async function adminSetExpiry(env, request) {
  const actor = await requireStaff(env, request);
  const body = await readJson(request);
  const target = validUsername(body.username);
  await assertManage(env, actor, target); // 负责人在这里被拒绝（服务端强制，不只是 UI 隐藏）
  const scope = body.scope === undefined ? 'account' : body.scope;
  if (scope !== 'account' && scope !== 'role') throw new HttpError(400, 'scope 只能是 account 或 role');
  const mode = body.mode;
  if (!['relative', 'absolute', 'never', 'none', 'clear'].includes(mode)) throw new HttpError(400, 'mode 只能是 relative、absolute、never、none、clear');
  if (!(await getUser(env, target))) return json({ error: '该用户不存在' }, 404);
  const now = Date.now();
  const cur = (await getExpiry(env, target)) || {};
  let next;
  if (mode === 'none') next = null;
  else if (mode === 'never') next = { never: true };
  else if (mode === 'clear') { next = { ...cur }; delete next[scope === 'account' ? 'ax' : 'rx']; if (scope === 'account') { delete next.once; delete next.ol; } }
  else {
    if (cur.never) return json({ error: '该账户已设为“永不过期”，请先取消永不过期（mode=none）再设置过期时间' }, 409);
    const t = checkExpRange(env, mode === 'relative' ? now + parseDuration(body.duration) : parseAbsolute(body.at), now);
    next = { ...cur, [scope === 'account' ? 'ax' : 'rx']: t };
  }
  if (next) { delete next.tp; next.b = actor.username; next.t = now; }
  if (!next || (!next.never && !next.ax && !next.rx && !next.once)) await env.KV.delete(`exp:${target}`);
  else await putExpiry(env, target, next);
  await audit(env, request, 'expiry.set', actor.username, target, { scope, mode, ax: next && next.ax || null, rx: next && next.rx || null, never: !!(next && next.never) });
  return json({ ok: true, username: target, expiry: expiryPublic(next && (next.never || next.ax || next.rx || next.once) ? next : null, now) });
}

// ---------- 岗位模板（角色模板）----------
// 模板 = 基础角色（null / inviter / membership_lead，不能是 principal）+ 默认过期类型 + 说明。
// 模板不创造新权限：权限仍来自硬编码的三级角色；账户级 deny 覆盖只做减法。只有负责人可以增删改模板。
// 套用时复制快照（id + 版本 + 内容）：之后修改 / 删除模板不影响已经套用的账户和已经发出的邀请。
const TPL_ID_RE = /^[a-z0-9_-]{2,32}$/;
const TPL_EXPIRY = { d30: '30 天', d1: '临时 1 天', otp: '一次性登录（OTP）', single: '单次使用', permanent: '永久' };
async function getTemplate(env, id) {
  if (typeof id !== 'string' || !TPL_ID_RE.test(id)) throw new HttpError(400, 'templateId 无效');
  return env.KV.get(`tpl:${id}`, 'json');
}
function snapshotTemplate(t) {
  return { id: t.id, v: t.v, n: t.name, r: t.role || null, e: t.expiry, s: t.scope || 'account' };
}
function assertCanApplyTemplate(actor, tpl) {
  if (!tpl.role) return; // 无基础角色的模板只带默认过期，任何能签发邀请的人都可以用
  if (actor.token || !ROLES[actor.role].assign.includes(tpl.role)) {
    throw FORBIDDEN(`不能套用高于自己权限的模板（模板角色：${ROLES[tpl.role].label}）`);
  }
}
function templateExpiry(tp, now, tempAbs = D) {
  const f = tp.s === 'role' && tp.r ? 'rx' : 'ax';
  switch (tp.e) {
    case 'd30': return { [f]: now + 30 * 86400e3 };
    case 'd1': return { [f]: now + 86400e3 };
    case 'permanent': return { never: true };
    case 'single': return { ax: now + tempAbs, once: 'single' }; // 只有注册时的那个会话（临时档绝对时长）
    case 'otp': return { ax: now + 86400e3, once: 'otp', ol: 1 }; // 注册会话 + 1 天内 1 次 passkey 登录
    default: return null;
  }
}
async function applyTemplateExpiry(env, username, tp, by) {
  const now = Date.now();
  const e = templateExpiry(tp, now, SESSION_PRESETS[await currentPresetId(env)].temp.abs);
  if (!e) return null;
  if (e.once === 'otp') await stateStub(env).setQuota(`otp:${username}`, 1, 86400e3); // OTP 额度放 DO：原子扣减，保证只用一次
  const rec = { ...e, b: by, t: now, tp: `${tp.id}@v${tp.v}` };
  await putExpiry(env, username, rec);
  return rec;
}
async function applyInviteTemplate(env, request, username, inv) {
  const tp = inv.tp;
  let roleApplied = null;
  if (tp.r && ROLE_TEMPLATES_ENABLED) { // 已禁用：邀请套用的模板不再授予角色（新账户不能直接成为管理员）
    // 再次确认签发者此刻仍有权授予该角色（签发后可能被降级 / 撤权）
    const issuerRole = inv.b === TOKEN_ACTOR ? null : await getRole(env, inv.b);
    const deny = inv.b === TOKEN_ACTOR ? new Set() : await getDeny(env, inv.b);
    if (issuerRole && ROLES[issuerRole].assign.includes(tp.r) && !deny.has('invite.create') && KV_ROLES.has(tp.r)) {
      await env.KV.put(`role:${username}`, tp.r, { metadata: { r: tp.r, b: inv.b, t: Date.now(), tp: tp.id } });
      roleApplied = tp.r;
    }
  }
  await applyTemplateExpiry(env, username, tp, inv.b);
  await audit(env, request, 'template.apply', inv.b, username, { tpl: `${tp.id}@v${tp.v}`, role: roleApplied, roleSkipped: tp.r && !roleApplied ? tp.r : null, expiry: tp.e });
}
async function adminListTemplates(env, request) {
  const actor = await requireStaff(env, request);
  const r = await env.KV.list({ prefix: 'tpl:', limit: 200 });
  const templates = r.keys.map((k) => k.metadata).filter(Boolean).map((t) => ({
    ...t, expiryLabel: TPL_EXPIRY[t.expiry], roleLabel: t.role ? ROLES[t.role].label : '普通账户（无角色）',
    canApply: !t.role || (!actor.token && ROLES[actor.role].assign.includes(t.role)),
  }));
  return json({ ok: true, canManage: !actor.token && actor.role === 'principal', expiryTypes: TPL_EXPIRY, templates });
}
// { action: 'save'|'delete', id, name, role, expiry, scope, desc }
async function adminSaveTemplate(env, request) {
  const actor = await requireStaff(env, request);
  if (actor.token || actor.role !== 'principal') throw FORBIDDEN('只有负责人可以新增、修改或删除岗位模板');
  const body = await readJson(request);
  const id = body.id;
  if (typeof id !== 'string' || !TPL_ID_RE.test(id)) throw new HttpError(400, 'id 须为 2–32 位小写字母、数字、下划线或连字符');
  if (body.action === 'delete') {
    await env.KV.delete(`tpl:${id}`);
    await audit(env, request, 'template.delete', actor.username, null, { tpl: id });
    return json({ ok: true, deleted: id });
  }
  if (body.action !== 'save') throw new HttpError(400, 'action 只能是 save 或 delete');
  const role = body.role === null || body.role === undefined || body.role === '' ? null : body.role;
  if (role === 'principal') throw FORBIDDEN('模板不能授予负责人（root）权限：负责人只能由 Worker 配置 PRINCIPALS 决定');
  if (role !== null && !KV_ROLES.has(role)) throw new HttpError(400, 'role 只能是 null（普通账户）、inviter 或 membership_lead');
  // 范围决定：不提供任何“新建 / 提升管理员”的新入口。带角色的模板 = 新账户直接成为管理员 / 套模板提升，因此禁用；成员页逐个授予角色保持不变。
  if (role !== null) return json({ error: '带角色的岗位模板已禁用（不提供新建或提升管理员的新入口）；角色请在成员列表中按现有方式授予', disabled: true }, 501);
  if (!Object.hasOwn(TPL_EXPIRY, body.expiry)) throw new HttpError(400, `expiry 只能是 ${Object.keys(TPL_EXPIRY).join('、')}`);
  const scope = body.scope === 'role' ? 'role' : 'account';
  if (!str(body.name, 32)) throw new HttpError(400, 'name 须为 1–32 个字符');
  const desc = typeof body.desc === 'string' ? body.desc.slice(0, 200) : '';
  const old = await env.KV.get(`tpl:${id}`, 'json');
  const t = { id, name: body.name, role, expiry: body.expiry, scope, desc, v: old ? old.v + 1 : 1, b: actor.username, t: Date.now() };
  await env.KV.put(`tpl:${id}`, JSON.stringify(t), { metadata: t });
  await audit(env, request, old ? 'template.update' : 'template.create', actor.username, null, { tpl: `${id}@v${t.v}`, role, expiry: t.expiry });
  return json({ ok: true, template: t });
}

// ---------- 账户级权限覆盖（只做减法）----------
// KV deny:<用户名> = { d: ['invite.create'], b, t }。最终权限 = 角色基础权限 − deny。对 root 不生效（也不能设置）。
const DENYABLE = new Set(['invite.create']);
async function getDeny(env, username) {
  if (principals(env).has(username)) return new Set();
  const d = await env.KV.get(`deny:${username}`, 'json');
  return new Set(d && Array.isArray(d.d) ? d.d.filter((x) => DENYABLE.has(x)) : []);
}
// { username, permission: 'invite.create', action: 'revoke'|'restore', revokePending?: boolean }
async function adminSetPermission(env, request) {
  const actor = await requireStaff(env, request);
  const body = await readJson(request);
  const target = validUsername(body.username);
  await assertManage(env, actor, target);
  requireStepUp(actor, env);
  if (!DENYABLE.has(body.permission)) throw new HttpError(400, 'permission 只能是 invite.create');
  if (body.action !== 'revoke' && body.action !== 'restore') throw new HttpError(400, 'action 只能是 revoke 或 restore');
  const cur = await getDeny(env, target);
  if (body.action === 'revoke') cur.add(body.permission); else cur.delete(body.permission);
  const now = Date.now();
  if (cur.size) await env.KV.put(`deny:${target}`, JSON.stringify({ d: [...cur], b: actor.username, t: now }), { metadata: { d: [...cur], b: actor.username, t: now } });
  else await env.KV.delete(`deny:${target}`);
  // 已发出未使用的邀请默认保留；revokePending=true 时一并撤销该账户签发的全部待使用邀请
  let revokedInvites = 0;
  if (body.action === 'revoke' && body.revokePending === true) {
    // 跟随 cursor 翻完所有页：只看第一页会漏掉 1000 条之后的邀请
    let cursor;
    do {
      const r = await env.KV.list({ prefix: 'inv:', limit: 1000, cursor });
      for (const k of r.keys) if (k.metadata && k.metadata.b === target) { await env.KV.delete(k.name); revokedInvites++; }
      cursor = r.list_complete ? undefined : r.cursor;
    } while (cursor);
  }
  await audit(env, request, `permission.${body.action}`, actor.username, target, { perm: body.permission, revokedInvites });
  return json({ ok: true, username: target, deny: [...cur], revokedInvites });
}

// ---------- 兜底恢复（break-glass）：一次性恢复码 → 只能重新登记 passkey，不发会话 ----------
// 详见 docs/recovery.md。默认关闭：RECOVERY_ENABLED 不是 "1" 时所有恢复接口返回 404（fail closed）。
// 签发恢复码需要独立 secret RECOVERY_ISSUER_TOKEN（不同于 ADMIN_TOKEN，≥32 字符，带外持有者）；只能为 PRINCIPALS 里的账户签发。
const RECOVERY_TTL_MS = 15 * 60 * 1000; // 恢复码有效期 15 分钟（从可用时刻起算）
const RECOVERY_MAX_FAIL = 5; // 连续失败 5 次 → 锁定 1 小时，并作废当前恢复码
const RECOVERY_LOCK_TTL = 3600;
const RECOVERY_ERROR = '恢复码无效或已失效。';
const recoveryEnabled = (env) => env.RECOVERY_ENABLED === '1';
async function timingSafeEqualStr(a, b) {
  const [x, y] = await Promise.all([crypto.subtle.digest('SHA-256', enc.encode(a)), crypto.subtle.digest('SHA-256', enc.encode(b))]);
  return crypto.subtle.timingSafeEqual(x, y);
}
async function requireRecoveryIssuer(env, request) {
  const m = /^Bearer ([\x21-\x7e]{1,512})$/.exec(request.headers.get('Authorization') || '');
  const expected = typeof env.RECOVERY_ISSUER_TOKEN === 'string' ? env.RECOVERY_ISSUER_TOKEN : '';
  const same = await timingSafeEqualStr(m ? m[1] : '', expected);
  if (!m || expected.length < 32 || !same) throw new HttpError(401, ADMIN_AUTH_ERROR);
}
// { action: 'issue'|'cancel', username }
//   issue：只接受 Authorization: Bearer <RECOVERY_ISSUER_TOKEN>（ADMIN_TOKEN 不行）
//   cancel：恢复 token 或负责人会话（负责人还能登录时可以作废别人发起的恢复）
// 兜底恢复（为负责人重建 passkey = “重建管理员”）：范围决定为不实现，接口固定返回 501。后续代码为预留设计，运行时不可达。
const RECOVERY_DISABLED = () => json({ error: '兜底恢复未实现（已禁用）：见 docs/recovery.md', disabled: true }, 501);
async function adminRecovery(env, request) {
  if (!RECOVERY_IMPLEMENTED) return RECOVERY_DISABLED();
  if (!recoveryEnabled(env)) return json({ error: '接口不存在' }, 404);
  const body = await readJson(request);
  const target = validUsername(body.username);
  let actorName;
  if (request.headers.has('Authorization')) { await requireRecoveryIssuer(env, request); actorName = '#recovery'; }
  else {
    const a = await requireStaff(env, request);
    if (body.action !== 'cancel' || a.role !== 'principal') throw FORBIDDEN('恢复码只能由带外的恢复 token 持有者签发；负责人会话只能作废恢复');
    actorName = a.username;
  }
  if (!principals(env).has(target)) throw FORBIDDEN('兜底恢复只适用于 PRINCIPALS 中的负责人账户');
  const stub = stateStub(env);
  if (body.action === 'cancel') {
    if (actorName !== '#recovery') { const s = await getSession(env, request); requireStepUp(s || {}, env); }
    await stub.remove(`rcv:${target}`);
    await audit(env, request, 'recovery.cancel', actorName, target);
    return json({ ok: true, cancelled: true });
  }
  if (body.action !== 'issue') throw new HttpError(400, 'action 只能是 issue 或 cancel');
  if (await stub.peek(`rcvlock:${target}`)) return json({ error: '该账户的恢复已被锁定（失败次数过多），请稍后再试' }, 423);
  const delay = Math.min(Math.max(Number.parseInt(env.RECOVERY_DELAY_SECONDS || '0', 10) || 0, 0), 7 * 86400);
  const code = randomId(32); // 256 bit；明文只在本次响应中出现
  const now = Date.now();
  const nb = now + delay * 1000;
  const rec = { h: await sha256hex(code), c: now, nb, x: nb + RECOVERY_TTL_MS };
  await stub.issue(`rcv:${target}`, rec.x - now, rec); // DO：一次性、强一致（KV 做不到原子“只用一次”）
  await audit(env, request, 'recovery.issue', actorName, target, { nb, x: rec.x });
  return json({ ok: true, username: target, code, usableFrom: nb, usableFromTaipei: taipei(nb), expiresAt: rec.x, expiresAtTaipei: taipei(rec.x) });
}
// 未登录：{ username, code } → 校验通过后返回 passkey 注册 options（challenge cookie 标记 rc=1）；不发会话
async function recoveryRedeem(env, request) {
  if (!RECOVERY_IMPLEMENTED) return RECOVERY_DISABLED();
  if (!recoveryEnabled(env)) return json({ error: '接口不存在' }, 404);
  const body = await readJson(request);
  const fail = () => json({ error: RECOVERY_ERROR }, 403);
  if (typeof body.username !== 'string' || !USERNAME_RE.test(body.username) || typeof body.code !== 'string' || !INVITE_RE.test(body.code)) return fail();
  const u = body.username;
  if (!principals(env).has(u)) { await sha256hex(body.code); return fail(); }
  const stub = stateStub(env);
  if (await stub.peek(`rcvlock:${u}`)) { await audit(env, request, 'recovery.redeem_locked', null, u); return fail(); }
  const rec = await stub.peek(`rcv:${u}`);
  const now = Date.now();
  const ok = await timingSafeEqualStr(await sha256hex(body.code), rec && typeof rec.h === 'string' ? rec.h : '0'.repeat(64));
  if (!rec || !ok || now < rec.nb || now > rec.x) {
    const n = await stub.incr(`rcvfail:${u}`, RECOVERY_LOCK_TTL * 1000); // 强一致计数
    if (n >= RECOVERY_MAX_FAIL) {
      await stub.issue(`rcvlock:${u}`, RECOVERY_LOCK_TTL * 1000);
      await stub.remove(`rcv:${u}`);
    }
    await audit(env, request, 'recovery.redeem_fail', null, u, { n, locked: n >= RECOVERY_MAX_FAIL, early: !!(rec && ok && now < rec.nb) });
    return fail();
  }
  // 一次性：原子取出并删除；并发兑换只有一个能拿到（注册失败需要重新签发）
  if (!(await stub.consume(`rcv:${u}`))) return fail();
  await stub.remove(`rcvfail:${u}`);
  const user = await getUser(env, u);
  const userIDB64 = user ? user.userID : randomId(32);
  const options = await generateRegistrationOptions({
    rpName: env.RP_NAME, rpID: env.RP_ID, userName: u, userDisplayName: u,
    userID: isoBase64URL.toBuffer(userIDB64), attestationType: 'none', excludeCredentials: [],
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, timeout: 120000,
  });
  const setChal = await signChallenge(env, { p: 'reg', c: options.challenge, u, uid: userIDB64, su: null, ih: null, rc: 1 }, 'reg');
  await audit(env, request, 'recovery.redeem_ok', null, u);
  return json({ ok: true, options }, 200, [setChal]);
}
async function recoveryRegisterFinish(env, request, rec, credential, deviceType, backedUp, aaguid, clearChal, debug) {
  const fail = (msg) => json({ error: msg }, 400, [clearChal]);
  if (!recoveryEnabled(env) || !principals(env).has(rec.u)) return fail(RECOVERY_ERROR);
  if (await env.KV.get(`cred:${credential.id}`)) return fail('该 passkey 已被登记');
  const now = Date.now();
  let user = await getUser(env, rec.u);
  if (user && user.userID !== rec.uid) return fail(RECOVERY_ERROR);
  const old = user ? user.credentials.map((c) => c.id) : [];
  if (!user) user = { username: rec.u, userID: rec.uid, createdAt: now, credentials: [] };
  // 丢失的认证器按“可能已被盗”处理（NIST SP 800-63B §4.2/4.3）：旧 passkey 全部作废，只保留新登记的
  user.credentials = [{
    id: credential.id, publicKey: isoBase64URL.fromBuffer(credential.publicKey), counter: credential.counter,
    transports: (credential.transports || []).filter((t) => ALLOWED_TRANSPORTS.has(t)),
    deviceType, backedUp, aaguid, createdAt: now, lastUsedAt: null,
  }];
  await putUser(env, user);
  await env.KV.put(`cred:${credential.id}`, user.username);
  for (const id of old) await env.KV.delete(`cred:${id}`);
  const revokedSessions = await stateStub(env).sessRevokeUser(user.username); // 旧会话可能来自被盗设备：全部吊销
  await audit(env, request, 'recovery.passkey_reset', null, user.username, { revokedCredentials: old.length, revokedSessions });
  // 不创建会话：恢复后必须用新 passkey 正常登录
  return json({ ok: true, recovered: true, username: user.username, revokedCredentials: old.length, debug: { ...debug, verified: true } }, 200, [clearChal]);
}

// ---------- Turnstile（仅用于未登录的注册）----------
async function verifyTurnstile(env, token, ip) {
  if (typeof token !== 'string' || token.length < 1 || token.length > 2048) {
    throw new HttpError(403, '请先完成人机验证（Turnstile）后再注册');
  }
  if (!env.TURNSTILE_SECRET) throw new HttpError(500, '服务器未配置人机验证');
  let data;
  try {
    const body = { secret: env.TURNSTILE_SECRET, response: token };
    if (ip) body.remoteip = ip;
    const r = await fetch(SITEVERIFY_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    data = await r.json();
  } catch {
    throw new HttpError(503, '人机验证服务暂时不可用，请稍后重试');
  }
  const codes = Array.isArray(data['error-codes']) ? data['error-codes'].join(',') : '';
  if (data.success !== true) throw new HttpError(403, `人机验证未通过，请重新验证${codes ? `（${codes}）` : ''}`);
  // 测试密钥（metadata.result_with_testing_key）只在本地 wrangler dev（RP_ID=localhost 且 .dev.vars 显式允许）时接受；
  // 线上 RP_ID 不是 localhost，这个分支永远不会放行。
  if (data.metadata && data.metadata.result_with_testing_key === true) {
    if (env.TURNSTILE_ALLOW_TEST_KEYS === '1' && env.RP_ID === 'localhost') return { test: true };
    throw new HttpError(403, '人机验证未通过（测试密钥不被接受）');
  }
  if (data.action !== 'register') throw new HttpError(403, '人机验证未通过（action 不匹配）');
  if (data.hostname !== env.RP_ID) throw new HttpError(403, '人机验证未通过（hostname 不匹配）');
  return { test: false };
}

function publicCred(c) {
  return {
    idSuffix: c.id.slice(-8),
    createdAt: c.createdAt,
    lastUsedAt: c.lastUsedAt || null,
    transports: c.transports || [],
    counter: c.counter,
    deviceType: c.deviceType,
    backedUp: c.backedUp,
  };
}

// ---------- 路由处理 ----------
async function me(env, request) {
  const s = await getSession(env, request);
  const anon = { loggedIn: false, turnstileSitekey: env.TURNSTILE_SITEKEY || null };
  if (!s) return json(anon);
  const user = await getUser(env, s.username);
  if (!user) return json(anon);
  return json({ loggedIn: true, username: user.username, role: rolePublic(await getRole(env, user.username)), maxPasskeys: MAX_PASSKEYS, credentials: user.credentials.map(publicCred),
    session: { tier: s.tier, preset: s.preset, absoluteExpiresAt: s.absAt, idleTimeoutMs: s.idleMs, stepUpValid: !!(s.uvAt && Date.now() - s.uvAt <= stepUpWindow(env) && !s.risk), risk: s.risk || null } });
}

async function registerOptions(env, request) {
  const body = await readJson(request);
  const session = await getSession(env, request);
  let username, user = null, debugExtra = {}, invite = null;
  if (session) {
    // 已登录：只能给自己的账号添加 passkey（忽略请求体中的用户名）
    user = await getUser(env, session.username);
    if (!user) throw new HttpError(401, '会话无效，请重新登录');
    username = user.username;
    if (user.credentials.length >= MAX_PASSKEYS) {
      throw new HttpError(400, `每个用户最多只能绑定 ${MAX_PASSKEYS} 个 passkey，已达上限。`);
    }
    requireStepUp(session, env); // 新增 passkey 是敏感操作
  } else {
    // 未登录：用户名格式 → 邀请码（格式 + 1 次 KV 读取 + 绑定用户名）→ Turnstile，全部通过后才生成 challenge。
    // 邀请无效时不调用 siteverify；所有邀请失败返回同一个 403 + 同一段文字。
    // 这里刻意【不查询】用户名是否存在：对任何用户名都返回同样形态的 options（随机 userID、空 excludeCredentials），
    // 是否可用到 verify 阶段才判断，并返回统一的失败信息 —— 状态码、响应体和耗时都不依赖用户名是否存在。
    username = validUsername(body.username);
    invite = await checkInvite(env, body.invite, username);
    const ts = await verifyTurnstile(env, body.turnstileToken, request.headers.get('CF-Connecting-IP'));
    debugExtra = { turnstile: ts.test ? 'passed（本地测试密钥）' : 'passed', invite: 'valid' };
  }
  const userIDB64 = user ? user.userID : randomId(32);
  const options = await generateRegistrationOptions({
    rpName: env.RP_NAME,
    rpID: env.RP_ID,
    userName: username,
    userDisplayName: username,
    userID: isoBase64URL.toBuffer(userIDB64),
    attestationType: 'none',
    excludeCredentials: (user ? user.credentials : []).map((c) => ({ id: c.id, transports: c.transports })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    timeout: 120000,
  });
  const setChal = await signChallenge(env, {
    p: 'reg',
    c: options.challenge,
    u: username,
    uid: userIDB64,
    su: session ? session.username : null,
    ih: invite ? invite.h : null, // 邀请码哈希：verify 时再次校验并在成功后删除
  }, 'reg');
  return json({ options, debug: debugExtra }, 200, [setChal]);
}

async function registerVerify(env, request) {
  const body = await readJson(request);
  const response = validateCredentialShape(body.credential, 'reg');
  const rec = await readSignedChallenge(env, request, 'reg');
  const clearChal = cookie(CHAL_COOKIES.reg, '', 0); // 验签后立即清除（每个响应都带上）
  const fail = (msg, debug) => json(debug ? { error: msg, debug } : { error: msg }, 400, [clearChal]);

  // challenge 与会话绑定：发起时的登录状态必须与提交时一致
  const session = await getSession(env, request);
  if ((session ? session.username : null) !== rec.su) return fail('登录状态已改变，请重试');

  const debug = { clientData: clientDataDebug(response.response.clientDataJSON) };
  try {
    const att = decodeAttestationObject(isoBase64URL.toBuffer(response.response.attestationObject));
    debug.fmt = att.get('fmt');
    Object.assign(debug, flagsOf(att.get('authData')));
  } catch { debug.authData = '无法解析'; }

  // 先做密码学校验（与用户名是否存在无关），再查 KV：两种用户名走同样的代码路径
  let v;
  try {
    v = await verifyRegistrationResponse({
      response,
      expectedChallenge: rec.c,
      expectedOrigin: env.ORIGIN,
      expectedRPID: env.RP_ID,
      requireUserVerification: true, // 强制 UV：服务端校验 UP + UV 标志
    });
  } catch (e) {
    return fail(`注册验证失败：${e.message}`, { ...debug, verified: false });
  }
  if (!v.verified || !(debug.flags && debug.flags.UP && debug.flags.UV)) return fail('注册验证失败（需要用户验证 UV）', { ...debug, verified: false });
  const { credential, credentialDeviceType, credentialBackedUp, aaguid } = v.registrationInfo;

  // 兜底恢复：恢复码兑换后签发的注册 challenge（rc=1）。只重新登记 passkey，不发会话。
  if (rec.rc === 1 && !RECOVERY_IMPLEMENTED) return RECOVERY_DISABLED();
  if (rec.rc === 1) return recoveryRegisterFinish(env, request, rec, credential, credentialDeviceType, credentialBackedUp, aaguid, clearChal, debug);

  // 未登录注册：在任何写入之前原子消费邀请（D1 上并发只有一次成功）。迁移票据则绑定到原 userID。
  let inv = null;
  let migPlan = null;
  if (!rec.su) {
    const migId = getCookie(request, MIG_COOKIE);
    const pending = migId ? await stateStub(env).peek(`mg:${migId}`) : null;
    if (pending) {
      migPlan = migrationRegisterPlan({ pending, user: await getUser(env, pending.username) });
      if (migPlan.kind !== 'add-passkey') return fail(REG_GENERIC_ERROR);
    } else {
      if (typeof rec.ih !== 'string' || !/^[0-9a-f]{64}$/.test(rec.ih)) return json({ error: INVITE_GENERIC_ERROR }, 403, [clearChal]);
      inv = await env.KV.get(`inv:${rec.ih}`, 'json');
      if (!inv || typeof inv.x !== 'number' || Date.now() > inv.x || (inv.u && inv.u !== rec.u)) {
        return json({ error: INVITE_GENERIC_ERROR }, 403, [clearChal]);
      }
    }
  }

  let user = migPlan ? migPlan.user : await getUser(env, rec.u);
  const credTaken = await env.KV.get(`cred:${credential.id}`);
  if (migPlan) {
    if (!user || user.userID !== migPlan.user.userID) return fail(REG_GENERIC_ERROR);
    if (user.credentials.length >= MAX_PASSKEYS) return fail(`每个用户最多只能绑定 ${MAX_PASSKEYS} 个 passkey，已达上限。`);
    if (credTaken) return fail('该 passkey 已被登记');
  } else if (rec.su) {
    // 已登录添加：必须仍是同一个用户
    if (!user || user.username !== rec.su || user.userID !== rec.uid) return fail('会话与账号不匹配，请重新登录');
    if (user.credentials.length >= MAX_PASSKEYS) return fail(`每个用户最多只能绑定 ${MAX_PASSKEYS} 个 passkey，已达上限。`);
    if (credTaken) return fail('该 passkey 已被登记');
  } else if (user || credTaken || principals(env).has(rec.u)) {
    // 负责人用户名（vars）不能被新注册：即使账号数据丢失，也不会被别人用邀请抢注成负责人
    // 未登录：用户名已存在 / 凭据已登记（含重放）→ 统一失败，不说明具体原因
    return fail(REG_GENERIC_ERROR);
  }

  const now = Date.now();
  if (!rec.su && !migPlan) {
    inv = await consumeInvite(env, rec.ih);
    if (!inv || typeof inv.x !== 'number' || Date.now() > inv.x || (inv.u && inv.u !== rec.u)) {
      return json({ error: INVITE_GENERIC_ERROR }, 403, [clearChal]);
    }
  }
  if (!user) user = { username: rec.u, userID: rec.uid, createdAt: now, credentials: [] };
  user.credentials.push({
    id: credential.id,
    publicKey: isoBase64URL.fromBuffer(credential.publicKey),
    counter: credential.counter,
    transports: (credential.transports || []).filter((t) => ALLOWED_TRANSPORTS.has(t)),
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
    aaguid,
    createdAt: now,
    lastUsedAt: null,
  });
  await putUser(env, user);
  await env.KV.put(`cred:${credential.id}`, user.username);
  // 邀请已在写入前原子消费。迁移登记完成后清掉一次性上下文。
  if (migPlan) {
    const migId = getCookie(request, MIG_COOKIE);
    if (migId) await stateStub(env).consume(`mg:${migId}`);
  }
  if (!rec.su && !migPlan && inv && inv.tp) await applyInviteTemplate(env, request, user.username, inv);

  const cookies = [clearChal];
  if (!session) {
    await recordLoginEnv(env, request, user.username); // 首次环境记录（注册即首个登录环境）
    cookies.push(await createSession(env, user.username));
  }
  return json({ ok: true, username: user.username, debug: { ...debug, verified: true, credIdSuffix: credential.id.slice(-8) } }, 200, cookies);
}

async function loginOptions(env, request) {
  const body = await readJson(request);
  const kind = body.conditional === true ? 'cond' : 'auth';
  const options = await generateAuthenticationOptions({
    rpID: env.RP_ID,
    allowCredentials: [], // 可发现凭据：不需要用户名
    userVerification: 'required',
    timeout: kind === 'cond' ? 300000 : 120000,
  });
  // 可发现凭据登录：不绑定用户名（u 为空）
  const setChal = await signChallenge(env, { p: 'auth', c: options.challenge, u: '' }, kind);
  return json({ options }, 200, [setChal]);
}

async function loginVerify(env, request) {
  const body = await readJson(request);
  const kind = body.conditional === true ? 'cond' : 'auth';
  const response = validateCredentialShape(body.credential, 'auth');
  const rec = await readSignedChallenge(env, request, kind);
  const clearChal = cookie(CHAL_COOKIES[kind], '', 0); // 验签后立即清除
  // 重放防护：readSignedChallenge 已在 DO 里原子消费该 challenge（一次性，无论本次成功与否）

  const debug = { clientData: clientDataDebug(response.response.clientDataJSON) };
  try { Object.assign(debug, flagsOf(isoBase64URL.toBuffer(response.response.authenticatorData))); } catch { debug.authData = '无法解析'; }

  const username = await env.KV.get(`cred:${response.id}`);
  if (!username) return json({ error: LOGIN_GENERIC_ERROR, debug: { ...debug, verified: false } }, 400, [clearChal]);
  const user = await getUser(env, username);
  const cred = user && user.credentials.find((c) => c.id === response.id);
  if (!cred) return json({ error: LOGIN_GENERIC_ERROR, debug: { ...debug, verified: false } }, 400, [clearChal]);
  if (response.response.userHandle && response.response.userHandle !== user.userID) {
    return json({ error: LOGIN_GENERIC_ERROR, debug: { ...debug, verified: false } }, 400, [clearChal]);
  }

  let v;
  try {
    v = await verifyAuthenticationResponse({
      response,
      expectedChallenge: rec.c,
      expectedOrigin: env.ORIGIN,
      expectedRPID: env.RP_ID,
      credential: { id: cred.id, publicKey: isoBase64URL.toBuffer(cred.publicKey), counter: cred.counter, transports: cred.transports },
      requireUserVerification: true,
    });
  } catch (e) {
    return json({ error: `登录验证失败：${e.message}`, debug: { ...debug, verified: false } }, 400, [clearChal]);
  }
  if (!v.verified || !assertUpUv(response)) return json({ error: '登录验证失败（需要用户验证 UV）', debug: { ...debug, verified: false } }, 400, [clearChal]);

  let otpPending = null;
  // 账户过期 / 单次使用 / 一次性登录：签名校验通过之后才判断（不向未持有 passkey 的人泄露账户状态）
  if (!principals(env).has(user.username)) {
    const e = await getExpiry(env, user.username);
    const now = Date.now();
    const st = expiryState(e, now);
    let denyMsg = null;
    if (st.accountExpired) denyMsg = '该账户已过期，无法登录。如需继续使用，请联系管理员。';
    else if (e && e.once === 'single') denyMsg = '该账户为单次使用账户，注册时的会话结束后不能再次登录。';
    else if (e && e.once === 'otp' && !(e.ol > 0)) denyMsg = '该账户的一次性登录已用完，无法再次登录。';
    if (denyMsg) {
      await audit(env, request, 'login.denied_expired', user.username, user.username, { once: e && e.once || null });
      return json({ error: denyMsg }, 403, [clearChal]);
    }
    if (e && e.once === 'otp') otpPending = { e, now };
  }
  // 异常登录评估（必须在扣减一次性登录额度之前，被拒绝的登录不能消耗唯一额度）：新国家 / 新 ASN → 会话需 step-up 并记录通知事件；不可能的旅行 → 吊销全部会话并拒绝
  const risk = await recordLoginEnv(env, request, user.username);
  if (risk.action === 'block') {
    const n = await stateStub(env).sessRevokeUser(user.username);
    await audit(env, request, 'risk.impossible_travel', null, user.username, { notify: true, revokedSessions: n, reasons: risk.reasons });
    return json({ error: '检测到异常登录（短时间内跨地区），已强制下线该账户的所有会话。请稍后重试或联系管理员。' }, 403, [clearChal]);
  }
  if (otpPending) {
    const { e, now } = otpPending;
    // 用掉唯一一次登录：DO 原子扣减（并发也只放行一次）；账户在本次会话（临时档）结束时过期
    if (!(await stateStub(env).takeQuota(`otp:${user.username}`))) {
      await audit(env, request, 'login.denied_expired', user.username, user.username, { once: 'otp' });
      return json({ error: '该账户的一次性登录已用完，无法再次登录。' }, 403, [clearChal]);
    }
    await putExpiry(env, user.username, { ...e, ol: 0, ax: Math.min(e.ax || Infinity, now + SESSION_PRESETS[await currentPresetId(env)].temp.abs) });
  }
  // signCount 兜底：SimpleWebAuthn 在 newCounter <= 已存 counter（且不全为 0）时会抛错；很多平台认证器/虚拟认证器始终为 0
  cred.counter = v.authenticationInfo.newCounter;
  cred.backedUp = v.authenticationInfo.credentialBackedUp;
  cred.lastUsedAt = Date.now();
  await putUser(env, user);
  if (risk.action === 'stepup') await audit(env, request, 'risk.new_env', null, user.username, { notify: true, reasons: risk.reasons });
  const sessCookie = await createSession(env, user.username, { risk: risk.action === 'stepup' ? 'new_env' : null });
  return json({ ok: true, username: user.username, debug: { ...debug, verified: true, newCounter: cred.counter, credIdSuffix: cred.id.slice(-8) } }, 200, [clearChal, sessCookie]);
}

// 登录环境：request.cf 的 country / asn + IP 前缀与 UA 大类的 HMAC 指纹（不存原始 IP）。
// 本地测试（RP_ID=localhost 且 RISK_TEST_HEADERS=1）可用 X-Test-Country / X-Test-ASN / X-Test-IP 伪造；线上永远读 request.cf。
async function loginSignal(env, request) {
  const cf = request.cf || {};
  const test = env.RP_ID === 'localhost' && env.RISK_TEST_HEADERS === '1';
  const country = (test && request.headers.get('X-Test-Country')) || cf.country || 'XX';
  const asn = (test && request.headers.get('X-Test-ASN')) || cf.asn || 'unknown';
  const ip = (test && request.headers.get('X-Test-IP')) || request.headers.get('CF-Connecting-IP') || '';
  const key = await hmacKey(env);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(`risk-fp|${country}|${asn}|${ipPrefix(ip)}|${uaFamily(request.headers.get('User-Agent'))}`)));
  return { country: String(country).slice(0, 2).toUpperCase(), asn: String(asn).slice(0, 12), fp: isoBase64URL.fromBuffer(mac).slice(0, 22) };
}
function riskRetentionMs(env) {
  const d = Number.parseInt(env.RISK_RETENTION_DAYS || '30', 10);
  return Math.min(Math.max(Number.isFinite(d) ? d : 30, 30), 90) * 86400e3;
}
async function recordLoginEnv(env, request, username) {
  const stub = stateStub(env);
  const retentionMs = riskRetentionMs(env);
  const sig = await loginSignal(env, request);
  const r = evaluateLogin(await stub.envGet(username), sig, Date.now(), { retentionMs, impossibleTravelMs: (Number.parseInt(env.RISK_TRAVEL_WINDOW_MIN || '60', 10) || 60) * 60e3 });
  if (r.action !== 'block') await stub.envPut(username, r.history, retentionMs);
  return r;
}

async function migrateTicket(env, request) {
  const s = await getSession(env, request);
  if (!s) throw new HttpError(401, ADMIN_AUTH_ERROR);
  requireStepUp(s, env);
  const user = await getUser(env, s.username);
  if (!user) throw new HttpError(401, ADMIN_AUTH_ERROR);
  const issued = await issueMigrationTicket(env, stateStub(env), { userID: user.userID, username: user.username, sid: s.sid });
  if (!issued) throw new HttpError(503, '迁移票据不可用');
  await audit(env, request, 'migrate.ticket', s.username, s.username, {});
  return json({ ok: true, url: issued.url });
}
async function migrateRedeem(env, request) {
  const body = await readJson(request);
  const redeemed = await redeemMigrationTicket(env, stateStub(env), typeof body.ticket === 'string' ? body.ticket : '');
  if (!redeemed) return json({ error: '迁移票据无效或已失效' }, 400);
  const user = await getUser(env, redeemed.username);
  if (!user || user.userID !== redeemed.userID) return json({ error: '迁移票据无效或已失效' }, 400);
  const id = randomId(32);
  await stateStub(env).issue(`mg:${id}`, 10 * 60 * 1000, { username: user.username, userID: user.userID });
  return json({ ok: true, username: user.username }, 200, [cookie(MIG_COOKIE, id, 600)]);
}

async function logout(env, request) {
  await readJson(request);
  const sid = getCookie(request, SESS_COOKIE);
  if (sid) await stateStub(env).sessDelete(sid);
  return json({ ok: true }, 200, [cookie(SESS_COOKIE, '', 0)]);
}

const ROUTES = {
  'GET /api/me': me,
  'POST /api/register/options': registerOptions,
  'POST /api/register/verify': registerVerify,
  'POST /api/login/options': loginOptions,
  'POST /api/login/verify': loginVerify,
  'POST /api/logout': logout,
  'GET /api/admin/invites': adminListInvites,
  'POST /api/admin/invites': adminCreateInvite,
  'POST /api/admin/invites/revoke': adminRevokeInvite,
  'GET /api/admin/members': adminListMembers,
  'POST /api/admin/members': adminSetRole,
  'POST /api/admin/expiry': adminSetExpiry,
  'GET /api/admin/audit': adminListAudit,
  'POST /api/admin/recovery': adminRecovery,
  'POST /api/recovery/redeem': recoveryRedeem,
  'GET /api/admin/templates': adminListTemplates,
  'POST /api/admin/templates': adminSaveTemplate,
  'POST /api/admin/permissions': adminSetPermission,
  'GET /api/admin/session-preset': adminSessionPreset,
  'POST /api/admin/session-preset': adminSessionPreset,
  'POST /api/stepup/options': stepupOptions,
  'POST /api/stepup/verify': stepupVerify,
  'POST /api/migrate/ticket': migrateTicket,
  'POST /api/migrate/redeem': migrateRedeem,
};

// ---------- 管理页面 ----------
const ADMIN_PAGE_RE = /^\/admin(?:\.html|\/.*)?$/i;
function htmlResponse(body, status) {
  return new Response(body, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...SECURITY_HEADERS } });
}
const ADMIN_DENIED_HTML = '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>无权访问</title><link rel="stylesheet" href="/style.css"></head><body><main><h1>无权访问</h1><p class="status err">需要以有邀请管理权限的账号（负责人 / 成员主管 / 邀请人）登录后才能访问。</p><p><a href="/">返回首页登录</a></p></main></body></html>';
async function adminPage(env, request, url) {
  // 与管理接口共用 RL_ADMIN（按路径 + IP 计数），在读 KV 之前
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const { success } = await env.RL_ADMIN.limit({ key: `/admin|${ip}` });
  if (!success) return htmlResponse('<!doctype html><meta charset="utf-8"><p>' + RATE_LIMIT_ERROR + '</p>', 429);
  const sfs = request.headers.get('Sec-Fetch-Site');
  // 页面导航允许 none（地址栏直接打开 / 书签）和 same-origin；其他站点跳转过来一律拒绝（会话 cookie 本来也不会带上）
  if (sfs !== null && sfs !== 'same-origin' && sfs !== 'none') return htmlResponse(ADMIN_DENIED_HTML, 403);
  if (!(await sessionActor(env, request))) return htmlResponse(ADMIN_DENIED_HTML, 403);
  if (url.pathname !== '/admin') return Response.redirect(`${env.ORIGIN}/admin`, 302); // nosemgrep: ajinabraham.njsscan.redirect.open_redirect.express_open_redirect -- 目标是固定配置 env.ORIGIN，不含用户输入
  // assets 默认的 html_handling 会把 /admin 映射到 public/admin.html
  const res = await env.ASSETS.fetch(new Request(new URL('/admin', url), { method: request.method }));
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
  out.headers.set('Cache-Control', 'no-store');
  return out;
}

const oidc = makeOidc({ json, getSession, getUser, accountExpired, getRole, getExpiry, stateStub, stepUpWindow, audit, securityHeaders: SECURITY_HEADERS });

export default {
  async fetch(request, env) {
    env = attachStore(env);
    const url = new URL(request.url);
    // 不盲信 Host：只为配置的 RP_ID 提供服务
    if (url.hostname !== env.RP_ID) return new Response('Misdirected Request', { status: 421 });
    // OIDC 端点（/.well-known/openid-configuration、/oauth/*）：不在 /api/ 下，不做 Origin 校验，见 src/oidc.js
    const o = await oidc(env, request, url);
    if (o) return o;

    if (url.pathname.startsWith('/api/')) {
      const handler = ROUTES[`${request.method} ${url.pathname}`];
      if (!handler) return json({ error: '接口不存在' }, 404);
      const route = `${request.method} ${url.pathname}`;
      const rl = RATE_LIMITED[route];
      if (rl) {
        // 第一道防线：限流（在读请求体、KV 读写、Turnstile siteverify 之前）
        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        const { success } = await env[rl].limit({ key: `${url.pathname}|${ip}` });
        if (!success) return json({ error: RATE_LIMIT_ERROR }, 429, [], { 'Retry-After': '60' });
      }
      if (request.method === 'POST' && request.headers.get('Origin') !== env.ORIGIN) {
        return json({ error: '来源（Origin）不被允许' }, 403);
      }
      try {
        return await handler(env, request);
      } catch (e) {
        if (e instanceof HttpError) return json(e.stepUp ? { error: e.message, stepUp: true } : { error: e.message }, e.status);
        console.error(e);
        return json({ error: '服务器内部错误' }, 500);
      }
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') return new Response('Method Not Allowed', { status: 405 });
    // 管理页面：服务端判断“已登录 + 管理员角色”后才返回 HTML（admin.html 的所有别名路径都经过这里）
    if (ADMIN_PAGE_RE.test(url.pathname)) return adminPage(env, request, url);
    const res = await env.ASSETS.fetch(request);
    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
    return out;
  },
};
