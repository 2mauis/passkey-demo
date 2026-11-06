// @pkauth/core — WebCrypto only. No runtime dependencies. jose is not used here (D21).
const enc = new TextEncoder();
const ALG = { name: 'ECDSA', namedCurve: 'P-256' };
const SIG = { name: 'ECDSA', hash: 'SHA-256' };

export const CLOCK_TOLERANCE_SECONDS = 0;
export const ALGORITHMS = ['ES256'];

export function b64u(bytes) {
  let s = '';
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64u(str) {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  const pad = s + '='.repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(pad), (c) => c.charCodeAt(0));
}
const b64uJson = (o) => b64u(enc.encode(JSON.stringify(o)));

export async function sha256b64u(str) {
  return b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(str))));
}
export const pkceS256 = sha256b64u;
export const randomToken = (n = 32) => b64u(crypto.getRandomValues(new Uint8Array(n)));

export function publicJwk(jwk) {
  const { kty, crv, x, y, kid } = jwk;
  return { kty, crv, x, y, kid, alg: 'ES256', use: 'sig' };
}

export async function importSigningKey(json) {
  const jwk = JSON.parse(json);
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.d || !jwk.kid) throw new Error('bad signing key');
  const { kid, alg, use, key_ops, ...raw } = jwk;
  const key = await crypto.subtle.importKey('jwk', raw, ALG, false, ['sign']);
  return { key, kid, jwk: publicJwk(jwk) };
}

export async function signJwt(sk, payload, typ = 'JWT') {
  const input = `${b64uJson({ alg: 'ES256', typ, kid: sk.kid })}.${b64uJson(payload)}`;
  const sig = new Uint8Array(await crypto.subtle.sign(SIG, sk.key, enc.encode(input)));
  return `${input}.${b64u(sig)}`;
}

function fail(code) {
  const e = new Error(code);
  e.code = code;
  return e;
}

// opt: { issuer, audience, typ?, now?(ms), leewaySec? }
// 时钟容差默认 0，且 CLOCK_TOLERANCE_SECONDS ≤ 5（S-4：早 1 秒即拒绝）。
export async function verifyJwt(token, jwks, opt = {}) {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 3 || parts.some((p) => !p)) throw fail('malformed');
  const [h, p, s] = parts;
  let header;
  try { header = JSON.parse(new TextDecoder().decode(unb64u(h))); } catch { throw fail('malformed'); }
  if (!header || header.alg !== 'ES256') throw fail('alg');
  if (opt.typ && header.typ !== opt.typ) throw fail('typ');
  const list = Array.isArray(jwks) ? jwks : [];
  const jwk = list.find((k) => k && k.kid === header.kid);
  if (!jwk) throw fail('kid');
  const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, ALG, false, ['verify']);
  let ok = false;
  try { ok = await crypto.subtle.verify(SIG, key, unb64u(s), enc.encode(`${h}.${p}`)); } catch { ok = false; }
  if (!ok) throw fail('signature');
  let c;
  try { c = JSON.parse(new TextDecoder().decode(unb64u(p))); } catch { throw fail('malformed'); }
  const nowMs = typeof opt.now === 'number' ? opt.now : Date.now();
  const now = Math.floor(nowMs / 1000);
  const lw = opt.leewaySec ?? CLOCK_TOLERANCE_SECONDS;
  if (typeof c.exp !== 'number' || c.exp + lw < now) throw fail('expired');
  if (opt.issuer != null && c.iss !== opt.issuer) throw fail('iss');
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (opt.audience != null && !aud.includes(opt.audience)) throw fail('aud');
  return c;
}

// ---------- 路径规范化与规则（§4.3）----------
export function normalizePath(input) {
  const raw = String(input ?? '').split('?')[0].split('#')[0];
  let decoded;
  try { decoded = decodeURIComponent(raw); } catch { return { ok: false, path: raw }; }
  let path = decoded.toLowerCase();
  if (!path.startsWith('/')) path = `/${path}`;
  path = path.replace(/\/{2,}/g, '/');
  return { ok: true, path };
}

function normPrefix(prefix) {
  const n = normalizePath(prefix);
  if (!n.ok) return null;
  return n.path.length > 1 && n.path.endsWith('/') ? n.path.slice(0, -1) : n.path;
}

export function pathMatchesPrefix(path, prefix) {
  const p = normPrefix(prefix);
  if (!p) return false;
  const cur = path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
  // 前缀 "/" 覆盖全部路径。更长前缀仍按段边界优先（selectRule 取最长）。
  if (p === '/') return cur.startsWith('/');
  return cur === p || cur.startsWith(`${p}/`);
}

// 返回 { kind: 'none'|'method'|'rule'|'decode-error', rule?, path?, methods? }
export function selectRule(pathname, method, rules) {
  const n = normalizePath(pathname);
  if (!n.ok) return { kind: 'decode-error' };
  const list = Array.isArray(rules) ? rules : [];
  const matches = [];
  for (const rule of list) {
    if (!rule || typeof rule.prefix !== 'string') continue;
    if (!pathMatchesPrefix(n.path, rule.prefix)) continue;
    const p = normPrefix(rule.prefix);
    matches.push({ rule, len: p.length });
  }
  if (!matches.length) return { kind: 'none', path: n.path };
  const max = Math.max(...matches.map((m) => m.len));
  const top = matches.filter((m) => m.len === max).map((m) => m.rule);
  const methods = [...new Set(top.flatMap((r) => (r.methods || []).map((x) => String(x).toUpperCase())))];
  const hit = top.find((r) => (r.methods || []).map((x) => String(x).toUpperCase()).includes(String(method || '').toUpperCase()));
  if (!hit) return { kind: 'method', path: n.path, methods };
  return { kind: 'rule', rule: hit, path: n.path };
}

// 只接受同源路径。绝对 URL、协议相对 URL（//host）一律落到 /。
export function safeReturnTo(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return '/';
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\') || value.includes('://')) return '/';
  if (value.includes('\n') || value.includes('\r') || value.includes('\0')) return '/';
  const path = value.split('?')[0];
  if (path.split('/').some((seg) => seg === '.' || seg === '..')) return '/';
  return value;
}

// ---------- cookie：AES-256-GCM + HKDF（加密钥 / 绑定钥）----------
async function hkdf(secret, info, usage) {
  const base = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  const params = { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('pkauth-v1'), info: enc.encode(info) };
  if (usage === 'aes') {
    return crypto.subtle.deriveKey(params, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  return crypto.subtle.deriveKey(params, base, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export function decodeCookieSecret(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return null;
  try {
    const bytes = unb64u(raw.trim());
    return bytes.length === 32 ? bytes : null;
  } catch { return null; }
}

const concat = (...parts) => {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

export async function sealCookie(secret, name, payload) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aes = await hkdf(secret, 'enc', 'aes');
  const macK = await hkdf(secret, 'bind', 'hmac');
  const aad = enc.encode(String(name));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, aes, enc.encode(JSON.stringify(payload))));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', macK, concat(aad, iv, ct)));
  return `v1.${b64u(iv)}.${b64u(ct)}.${b64u(mac)}`;
}

export async function openCookie(secret, name, token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') return null;
  let iv, ct, mac;
  try { iv = unb64u(parts[1]); ct = unb64u(parts[2]); mac = unb64u(parts[3]); } catch { return null; }
  if (iv.length !== 12) return null;
  try {
    const macK = await hkdf(secret, 'bind', 'hmac');
    const aad = enc.encode(String(name));
    const good = await crypto.subtle.verify('HMAC', macK, mac, concat(aad, iv, ct));
    if (!good) return null;
    const aes = await hkdf(secret, 'enc', 'aes');
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, aes, ct);
    const payload = JSON.parse(new TextDecoder().decode(plain));
    if (!payload || payload.v !== 1) return null;
    return payload;
  } catch { return null; }
}

// ---------- 配置 schema（§4.3）----------
const REQUIRED_NONEMPTY = ['PKAUTH_ISSUER', 'PKAUTH_CLIENT_ID', 'PKAUTH_RESOURCE', 'PKAUTH_RULES', 'PKAUTH_DEFAULT', 'PKAUTH_MODE', 'PKAUTH_COOKIE_SECRET'];

export function loadConfig(env = {}) {
  const missing = [];
  for (const k of REQUIRED_NONEMPTY) if (env[k] == null || String(env[k]).trim() === '') missing.push(k);
  if (env.PKAUTH_ALLOWED_HOSTS == null) missing.push('PKAUTH_ALLOWED_HOSTS');
  let rules = [];
  if (!missing.includes('PKAUTH_RULES')) {
    try {
      rules = JSON.parse(env.PKAUTH_RULES);
      if (!Array.isArray(rules)) missing.push('PKAUTH_RULES');
    } catch { missing.push('PKAUTH_RULES'); }
  }
  const secret = missing.includes('PKAUTH_COOKIE_SECRET') ? null : decodeCookieSecret(String(env.PKAUTH_COOKIE_SECRET));
  if (!missing.includes('PKAUTH_COOKIE_SECRET') && !secret) missing.push('PKAUTH_COOKIE_SECRET');
  const mode = String(env.PKAUTH_MODE || '');
  if (!missing.includes('PKAUTH_MODE') && mode !== 'enforce' && mode !== 'off') missing.push('PKAUTH_MODE');
  const def = String(env.PKAUTH_DEFAULT || '');
  if (!missing.includes('PKAUTH_DEFAULT') && def !== 'public' && def !== 'protected') missing.push('PKAUTH_DEFAULT');
  let inject = {};
  if (env.PKAUTH_UPSTREAM_INJECT != null && String(env.PKAUTH_UPSTREAM_INJECT).trim() !== '') {
    try {
      inject = JSON.parse(env.PKAUTH_UPSTREAM_INJECT);
      if (!inject || typeof inject !== 'object' || Array.isArray(inject)) missing.push('PKAUTH_UPSTREAM_INJECT');
    } catch { missing.push('PKAUTH_UPSTREAM_INJECT'); }
  }
  const hosts = String(env.PKAUTH_ALLOWED_HOSTS ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const uniqueMissing = [...new Set(missing)];
  return {
    ok: uniqueMissing.length === 0,
    missing: uniqueMissing,
    issuer: String(env.PKAUTH_ISSUER || '').replace(/\/$/, ''),
    clientId: String(env.PKAUTH_CLIENT_ID || ''),
    resource: String(env.PKAUTH_RESOURCE || ''),
    hosts,
    rules: Array.isArray(rules) ? rules : [],
    defaultAccess: def === 'protected' ? 'protected' : 'public',
    mode: mode === 'off' ? 'off' : 'enforce',
    secret,
    inject: inject && typeof inject === 'object' && !Array.isArray(inject) ? inject : {},
  };
}
