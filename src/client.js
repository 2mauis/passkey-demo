import {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  WebAuthnAbortService,
} from '@simplewebauthn/browser';

const $ = (id) => document.getElementById(id);
const USERNAME_RE = /^[a-zA-Z0-9_-]{3,32}$/;
const INVITE_RE = /^[A-Za-z0-9_-]{43}$/;
let busy = false;
let condStarted = false;
// Turnstile（仅注册使用）：显式渲染，action = 'register'
let tsWidgetId = null;
let tsToken = null;
let tsLoading = null;

function loadTurnstile() {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (tsLoading) return tsLoading;
  tsLoading = new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    s.onload = () => resolve(window.turnstile);
    s.onerror = () => { tsLoading = null; reject(new Error('人机验证脚本加载失败')); };
    document.head.append(s);
  });
  return tsLoading;
}

async function renderTurnstile(sitekey) {
  if (!sitekey || tsWidgetId !== null) return;
  try {
    const ts = await loadTurnstile();
    tsWidgetId = ts.render('#ts-widget', {
      sitekey,
      action: 'register',
      language: 'zh-cn',
      callback: (t) => { tsToken = t; $('btn-register').disabled = false; },
      'expired-callback': () => { tsToken = null; $('btn-register').disabled = true; },
      'error-callback': () => { tsToken = null; $('btn-register').disabled = true; setStatus('人机验证出错，请刷新页面重试', 'err'); },
    });
  } catch (e) { setStatus(e.message, 'err'); }
}

function resetTurnstile() {
  tsToken = null;
  $('btn-register').disabled = true;
  if (window.turnstile && tsWidgetId !== null) window.turnstile.reset(tsWidgetId); // token 一次性：用过就重置
}

function setStatus(msg, kind = '') {
  const el = $('status');
  el.textContent = msg;
  el.className = 'status ' + kind;
}

function trunc(s, n = 16) { return typeof s === 'string' && s.length > n ? s.slice(0, n) + '…' : s; }
function fmtTime(t) { return t ? new Date(t).toLocaleString('zh-CN', { hour12: false }) : '—'; }

function debug(title, obj) {
  const box = document.createElement('div');
  box.className = 'dbg';
  const h = document.createElement('h4');
  h.textContent = `${new Date().toLocaleTimeString('zh-CN', { hour12: false })} · ${title}`;
  const pre = document.createElement('pre');
  pre.textContent = JSON.stringify(obj);
  box.append(h, pre);
  const log = $('debug-log');
  log.prepend(box);
  while (log.children.length > 8) log.lastElementChild.remove(); // 只保留最近 8 条
}

function b64urlToStr(s) {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return new TextDecoder().decode(Uint8Array.from(b, (c) => c.charCodeAt(0)));
}
function clientDataSummary(b64) {
  try { const c = JSON.parse(b64urlToStr(b64)); return { type: c.type, origin: c.origin, challenge: trunc(c.challenge) }; } catch { return '无法解析'; }
}

// step-up：服务端返回 {stepUp:true} 时，用当前账户的 passkey 再验证一次（UV），然后重试原请求一次
async function stepUp() {
  const { options } = await rawApi('/api/stepup/options', {});
  const cred = await startAuthentication({ optionsJSON: options });
  await rawApi('/api/stepup/verify', { credential: cred });
}
async function api(path, body, retried = false) {
  try { return await rawApi(path, body); } catch (e) {
    if (!retried && e.status === 403 && e.data && e.data.stepUp) { await stepUp(); return api(path, body, true); }
    throw e;
  }
}
async function rawApi(path, body) {
  const init = body === undefined
    ? { method: 'GET', credentials: 'same-origin' }
    : { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  const res = await fetch(path, init);
  let data = {};
  try { data = await res.json(); } catch { /* ignore */ }
  if (!res.ok) {
    const err = new Error(data.error || `请求失败（HTTP ${res.status}）`);
    err.status = res.status; err.data = data;
    throw err;
  }
  return data;
}

function regOptionsSummary(o) {
  return {
    challenge: trunc(o.challenge), rpId: o.rp?.id, rpName: o.rp?.name,
    'user.id': trunc(o.user?.id), 'user.name': o.user?.name,
    excludeCredentials: (o.excludeCredentials || []).length,
    authenticatorSelection: o.authenticatorSelection, attestation: o.attestation,
    pubKeyCredParams: (o.pubKeyCredParams || []).map((p) => p.alg),
  };
}
function authOptionsSummary(o) {
  return { challenge: trunc(o.challenge), rpId: o.rpId, allowCredentials: (o.allowCredentials || []).length, userVerification: o.userVerification };
}

function webauthnErr(e) {
  if (e?.name === 'NotAllowedError') return '操作被取消或超时';
  if (e?.name === 'InvalidStateError') return '这个认证器上已经有该账号的 passkey 了（excludeCredentials 生效）';
  if (e?.name === 'AbortError') return '操作已中止';
  return e?.message || String(e);
}

async function refresh() {
  const me = await api('/api/me');
  if (me.loggedIn) {
    $('anon').hidden = true;
    $('authed').hidden = false;
    $('me-name').textContent = me.username;
    $('admin-link').hidden = !me.role;
    $('admin-role').textContent = me.role ? me.role.label : '';
    $('me-count').textContent = me.credentials.length;
    $('me-max').textContent = me.maxPasskeys;
    const tb = $('me-creds');
    tb.replaceChildren();
    for (const c of me.credentials) {
      const tr = document.createElement('tr');
      for (const v of [`…${c.idSuffix}`, fmtTime(c.createdAt), fmtTime(c.lastUsedAt), (c.transports || []).join(', ') || '—', String(c.counter), `${c.deviceType || '?'} / ${c.backedUp ? '已备份' : '未备份'}`]) {
        const td = document.createElement('td'); td.textContent = v; tr.append(td);
      }
      tb.append(tr);
    }
    $('btn-add').disabled = me.credentials.length >= me.maxPasskeys;
    $('btn-add').title = me.credentials.length >= me.maxPasskeys ? '已达上限' : '';
  } else {
    $('authed').hidden = true;
    $('anon').hidden = false;
    renderTurnstile(me.turnstileSitekey);
  }
  return me;
}

async function doRegister(username) {
  if (busy) return;
  busy = true;
  WebAuthnAbortService.cancelCeremony();
  try {
    setStatus('正在获取注册参数…');
    let resp;
    try {
      resp = await api('/api/register/options', username ? { username, invite: $('reg-invite').value.trim(), turnstileToken: tsToken } : {});
    } finally {
      if (username) resetTurnstile();
    }
    const { options } = resp;
    debug('注册 options（服务端 → 浏览器）', { ...regOptionsSummary(options), ...(resp.debug || {}) });
    setStatus('请在设备上确认创建 passkey…');
    let cred;
    try { cred = await startRegistration({ optionsJSON: options }); } catch (e) { throw new Error(webauthnErr(e)); }
    debug('注册 response（浏览器 → 服务端）', {
      id: '…' + cred.id.slice(-8), transports: cred.response.transports,
      authenticatorAttachment: cred.authenticatorAttachment, clientDataJSON: clientDataSummary(cred.response.clientDataJSON),
    });
    try {
      const r = await api('/api/register/verify', { credential: cred });
      debug('注册验证结果（服务端）', r.debug);
      setStatus(`注册成功：${r.username}`, 'ok');
      if (username) $('reg-invite').value = ''; // 邀请码是一次性的，用后清空
    } catch (e) {
      if (e.data?.debug) debug('注册验证结果（服务端）', e.data.debug);
      throw e;
    }
    await refresh();
  } catch (e) {
    setStatus(`注册失败：${e.message}`, 'err');
    debug('注册错误', { message: e.message });
  } finally {
    busy = false;
  }
}

async function doLogin() {
  if (busy) return;
  busy = true;
  WebAuthnAbortService.cancelCeremony();
  try {
    setStatus('正在获取登录参数…');
    const { options } = await api('/api/login/options', {});
    debug('登录 options（可发现凭据，无用户名）', authOptionsSummary(options));
    setStatus('请在设备上选择 passkey…');
    let cred;
    try { cred = await startAuthentication({ optionsJSON: options }); } catch (e) { throw new Error(webauthnErr(e)); }
    await finishLogin(cred, false);
  } catch (e) {
    setStatus(`登录失败：${e.message}`, 'err');
    debug('登录错误', { message: e.message });
  } finally {
    busy = false;
  }
}

async function finishLogin(cred, conditional) {
  debug(`登录 response（${conditional ? '自动填充' : '按钮'}）`, {
    id: '…' + cred.id.slice(-8), userHandle: trunc(cred.response.userHandle),
    clientDataJSON: clientDataSummary(cred.response.clientDataJSON),
  });
  try {
    const r = await api('/api/login/verify', { credential: cred, conditional });
    debug('登录验证结果（服务端）', r.debug);
    setStatus(`登录成功：${r.username}`, 'ok');
  } catch (e) {
    if (e.data?.debug) debug('登录验证结果（服务端）', e.data.debug);
    throw e;
  }
  await refresh();
}

// 条件式 UI（自动填充）：为节省 KV 写入，仅在用户聚焦输入框时才向服务端申请 challenge
async function startConditional() {
  if (condStarted || busy) return;
  condStarted = true;
  try {
    const { options } = await api('/api/login/options', { conditional: true });
    if (busy) { condStarted = false; return; }
    debug('自动填充登录 options（conditional mediation）', authOptionsSummary(options));
    const cred = await startAuthentication({ optionsJSON: options, useBrowserAutofill: true });
    busy = true;
    try { await finishLogin(cred, true); } finally { busy = false; }
  } catch (e) {
    if (e?.name !== 'AbortError' && !/abort/i.test(e?.message || '')) {
      setStatus(`自动填充登录失败：${e.message}`, 'err');
    }
  } finally {
    condStarted = false;
  }
}

async function doLogout() {
  try {
    await api('/api/logout', {});
    setStatus('已退出登录', 'ok');
    debug('退出登录', { ok: true });
    await refresh();
  } catch (e) { setStatus(`退出失败：${e.message}`, 'err'); }
}

// 邀请链接：https://…/#invite=<邀请码>[&u=<绑定的用户名>]（也兼容 ?invite=）。
// 读取后立即从地址栏移除，避免留在浏览器历史 / 截图里；用 # 片段时邀请码不会发给服务器日志。
function readInviteFromUrl() {
  const hash = new URLSearchParams(location.hash.replace(/^#/, ''));
  const query = new URLSearchParams(location.search);
  const code = hash.get('invite') || query.get('invite');
  const u = hash.get('u') || query.get('u');
  if (!code && !u) return;
  if (code && INVITE_RE.test(code)) $('reg-invite').value = code;
  if (u && USERNAME_RE.test(u)) { $('reg-username').value = u; }
  history.replaceState(null, '', location.pathname);
  setStatus(code && INVITE_RE.test(code) ? '已从邀请链接自动填入邀请码' + (u ? '和用户名' : '') + '，完成人机验证后即可注册。' : '邀请链接格式不正确', code && INVITE_RE.test(code) ? 'ok' : 'err');
}

async function init() {
  window.__pk = { startRegistration, startAuthentication, stepUp, getTurnstileToken: () => tsToken }; // 供端到端测试使用
  if (!browserSupportsWebAuthn()) {
    $('support').textContent = '当前浏览器不支持 WebAuthn / passkey。';
  }
  const autofill = await browserSupportsWebAuthnAutofill().catch(() => false);
  $('support').textContent += autofill ? '✅ 此浏览器支持 passkey 自动填充（Conditional UI）。' : '（此浏览器不支持自动填充式 passkey 登录，请使用按钮登录。）';

  $('reg-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const u = $('reg-username').value.trim();
    if (!USERNAME_RE.test(u)) { setStatus('用户名须为 3–32 个字符，仅允许英文字母、数字、下划线和连字符', 'err'); return; }
    if (!INVITE_RE.test($('reg-invite').value.trim())) { setStatus('请填写管理员发给你的邀请码（或直接打开邀请链接）', 'err'); return; }
    if (!tsToken) { setStatus('请先完成上方的人机验证（Turnstile）', 'err'); return; }
    doRegister(u);
  });
  $('cond-form').addEventListener('submit', (ev) => ev.preventDefault());
  $('btn-login').addEventListener('click', doLogin);
  $('btn-add').addEventListener('click', () => doRegister(null));
  $('btn-logout').addEventListener('click', doLogout);
  if (autofill) $('login-autofill').addEventListener('focus', startConditional);
  readInviteFromUrl();
  window.addEventListener('hashchange', readInviteFromUrl);
  try { await refresh(); } catch (e) { setStatus(`加载失败：${e.message}`, 'err'); }
}

init();
