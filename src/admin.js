// 邀请管理页面（/admin）：仅在服务端确认“已登录 + 管理员角色”后才会返回本页面；接口同样逐次鉴权。
// 所有请求带自定义头 X-PK-Admin: 1（CSRF 防线之一），使用同源 cookie 会话。
import { startAuthentication } from '@simplewebauthn/browser';
const $ = (id) => document.getElementById(id);
const USERNAME_RE = /^[a-zA-Z0-9_-]{3,32}$/;
const ROLE_LABEL = { principal: '负责人', membership_lead: '成员主管', inviter: '邀请人' };
let ME = null; // { username, role: { id, label, perms } }
// 统一按台北时间显示（不依赖浏览器本地时区）
const fmt = (t) => (t ? new Date(t).toLocaleString('zh-CN', { hour12: false, timeZone: 'Asia/Taipei' }) + '（台北）' : '—');
const LEVEL_NAME = { principal: 'root', membership_lead: '高级管理员', inviter: '维护者' };
let TPLS = [];

function setStatus(msg, kind = '') {
  const el = $('status');
  el.textContent = msg;
  el.className = 'status ' + kind;
}

// step-up：敏感操作（发邀请、改角色、撤销权限、切换会话预设等）要求 5 分钟内用 passkey 重新验证过
async function stepUp() {
  const { options } = await rawApi('/api/stepup/options', {});
  const cred = await startAuthentication({ optionsJSON: options });
  await rawApi('/api/stepup/verify', { credential: cred });
}
window.__pkAdmin = { stepUp, startAuthentication }; // 供测试使用
async function api(path, body, retried = false) {
  try { return await rawApi(path, body); } catch (e) {
    if (!retried && e.status === 403 && e.stepUp) { setStatus('需要重新验证身份：请在系统弹窗中确认 passkey…'); await stepUp(); return api(path, body, true); }
    throw e;
  }
}
async function rawApi(path, body) {
  const headers = { 'X-PK-Admin': '1' };
  const init = { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', headers };
  if (body !== undefined) { headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
  const res = await fetch(path, init);
  let data = {};
  try { data = await res.json(); } catch { /* ignore */ }
  if (!res.ok) {
    const err = new Error(res.status === 401 ? '未授权：请以管理员身份重新登录' : data.error || `请求失败（HTTP ${res.status}）`);
    err.status = res.status;
    err.stepUp = !!data.stepUp;
    throw err;
  }
  return data;
}

function remaining(x) {
  const s = Math.max(0, Math.round((x - Date.now()) / 1000));
  if (s >= 86400) return `${Math.floor(s / 86400)} 天 ${Math.floor((s % 86400) / 3600)} 小时`;
  if (s >= 3600) return `${Math.floor(s / 3600)} 小时 ${Math.floor((s % 3600) / 60)} 分`;
  return `${Math.ceil(s / 60)} 分钟`;
}

function showRole(me) {
  ME = me;
  $('adm-name').textContent = me.username || '（应急 token）';
  $('adm-role').textContent = `${me.role.label}（${me.role.id}）`;
  const p = me.role.perms;
  $('adm-perms').textContent = `你可以：签发邀请、查看邀请、${p.revokeAnyInvite ? '撤销任何邀请' : '只撤销自己签发的邀请'}` +
    (p.assignRoles.length ? `、分配 / 移除${p.assignRoles.map((r) => ROLE_LABEL[r]).join('和')}` : '') + '。';
  // 没有权限的功能直接隐藏（服务端同样会拒绝）
  $('members').hidden = !p.viewMembers;
  const sel = $('mem-role');
  sel.replaceChildren();
  for (const r of p.assignRoles) { const o = document.createElement('option'); o.value = r; o.textContent = ROLE_LABEL[r]; sel.append(o); }
  $('mem-form').hidden = !p.assignRoles.length;
  $('expiry').hidden = !p.viewMembers;
  $('templates').hidden = false;
  $('audit').hidden = me.role.id !== 'principal';
  if (me.deny && me.deny.includes('invite.create')) { $('btn-create').disabled = true; $('adm-perms').textContent += '（你的“签发邀请”权限已被撤销）'; }
}

async function loadList() {
  const d = await api('/api/admin/invites');
  showRole(d.me);
  const tb = $('inv-list');
  tb.replaceChildren();
  for (const i of d.invites) {
    const tr = document.createElement('tr');
    tr.dataset.id = i.id;
    const expired = i.expiresAt <= Date.now();
    const by = i.createdBy === '#token' ? '应急 token' : i.createdBy || '—';
    const cells = [i.id, i.username || '（不限）', expired ? '已过期' : `待使用（剩余 ${remaining(i.expiresAt)}）`, fmt(i.createdAt), fmt(i.expiresAt), by];
    cells.forEach((v, k) => {
      const td = document.createElement('td');
      if (k === 0) { const c = document.createElement('code'); c.textContent = v; td.append(c); } else td.textContent = v;
      tr.append(td);
    });
    const td = document.createElement('td');
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'danger revoke'; b.textContent = '撤销';
    if (i.canRevoke) b.addEventListener('click', () => revoke(i.id, b));
    else { b.disabled = true; b.title = '邀请人只能撤销自己签发的邀请'; }
    td.append(b); tr.append(td);
    tb.append(tr);
  }
  if (!d.invites.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td'); td.colSpan = 7; td.className = 'muted'; td.textContent = '当前没有待使用的邀请。';
    tr.append(td); tb.append(tr);
  }
  $('inv-count').textContent = `（${d.invites.length} 个${d.truncated ? '，仅显示前 200 个' : ''}）`;
}

async function revoke(id, btn) {
  if (!confirm(`确定撤销邀请 ${id}？撤销后该邀请码立即失效（其他地区最长约 60 秒内生效）。`)) return;
  btn.disabled = true;
  try {
    await api('/api/admin/invites/revoke', { id });
    setStatus(`已撤销邀请 ${id}`, 'ok');
  } catch (e) {
    setStatus(`撤销失败：${e.message}`, 'err');
  }
  await loadList().catch((e) => setStatus(`刷新列表失败：${e.message}`, 'err'));
}

async function loadMembers() {
  if (!ME || !ME.role.perms.viewMembers) return;
  const d = await api('/api/admin/members');
  const tb = $('mem-list');
  tb.replaceChildren();
  for (const m of d.members) {
    const tr = document.createElement('tr');
    tr.dataset.user = m.username;
    const roleTxt = m.role ? `${LEVEL_NAME[m.role.id]} · ${m.role.label}` : '普通账户（无角色）';
    const src = m.source === 'vars' ? 'Worker 配置（不可在页面修改）' : m.source === 'kv' ? '页面分配' : '—';
    const denied = (m.deny || []).includes('invite.create');
    const inv = m.role && m.role.id === 'principal' ? '有（不可撤回）' : !m.role ? '无（普通账户）' : denied ? '已撤销' : '有';
    for (const v of [m.username, roleTxt, src, m.grantedBy || '—', fmt(m.grantedAt), m.expiry ? m.expiry.label : '—', inv]) {
      const td = document.createElement('td'); td.textContent = v; tr.append(td);
    }
    tr.children[6].className = 'perm-invite';
    const td = document.createElement('td');
    if (m.canManage && m.role) {
      const b = document.createElement('button');
      b.type = 'button'; b.className = 'secondary toggle-invite'; b.textContent = denied ? '恢复发邀请' : '撤销发邀请';
      b.addEventListener('click', () => toggleInvite(m.username, denied, b));
      td.append(b);
    }
    if (m.canEdit) {
      const b = document.createElement('button');
      b.type = 'button'; b.className = 'danger remove-role'; b.textContent = '移除角色';
      b.addEventListener('click', () => setRole(m.username, null, b));
      td.append(b);
    }
    if (!td.childNodes.length) td.textContent = '—';
    tr.append(td);
    tb.append(tr);
  }
}

async function toggleInvite(username, denied, btn) {
  let revokePending = false;
  if (!denied) {
    if (!confirm(`确定撤销 ${username} 的“签发邀请”权限？其他权限不受影响。`)) return;
    revokePending = confirm('是否一并撤销该账户已发出、尚未使用的邀请？（取消 = 保留这些邀请）');
  }
  btn.disabled = true;
  try {
    const d = await api('/api/admin/permissions', { username, permission: 'invite.create', action: denied ? 'restore' : 'revoke', revokePending });
    setStatus(denied ? `已恢复 ${username} 的发邀请权限` : `已撤销 ${username} 的发邀请权限${d.revokedInvites ? `，并撤销 ${d.revokedInvites} 个待使用邀请` : ''}`, 'ok');
  } catch (e) { setStatus(`操作失败：${e.message}`, 'err'); }
  await loadMembers().catch(() => {});
}

async function loadTemplates() {
  const d = await api('/api/admin/templates');
  TPLS = d.templates;
  const tb = $('tpl-list');
  tb.replaceChildren();
  for (const t of d.templates) {
    const tr = document.createElement('tr'); tr.dataset.id = t.id;
    for (const v of [t.id, t.name, t.roleLabel, t.expiryLabel + (t.scope === 'role' && t.role ? '（角色）' : ''), t.desc || '—', 'v' + t.v]) {
      const td = document.createElement('td'); td.textContent = v; tr.append(td);
    }
    const td = document.createElement('td');
    if (d.canManage) {
      const e = document.createElement('button'); e.type = 'button'; e.className = 'secondary'; e.textContent = '编辑';
      e.addEventListener('click', () => { $('tpl-id').value = t.id; $('tpl-name').value = t.name; $('tpl-exp').value = t.expiry; $('tpl-scope').value = t.scope; $('tpl-desc').value = t.desc || ''; });
      const x = document.createElement('button'); x.type = 'button'; x.className = 'danger'; x.textContent = '删除';
      x.addEventListener('click', async () => { if (!confirm(`删除模板 ${t.id}？已套用的账户不受影响。`)) return; try { await api('/api/admin/templates', { action: 'delete', id: t.id }); setStatus(`已删除模板 ${t.id}`, 'ok'); } catch (err) { setStatus(err.message, 'err'); } loadTemplates(); });
      td.append(e, x);
    } else td.textContent = '—';
    tr.append(td); tb.append(tr);
  }
  $('tpl-form').hidden = !d.canManage;
  const es = $('tpl-exp'); if (!es.options.length) for (const [k, v] of Object.entries(d.expiryTypes)) { const o = document.createElement('option'); o.value = k; o.textContent = v; es.append(o); }
  for (const [sel, needRole] of [['inv-tpl', false]]) {
    const s = $(sel); const keep = s.value;
    while (s.options.length > 1) s.remove(1);
    for (const t of d.templates) {
      if (!t.canApply || (needRole && !t.role)) continue;
      const o = document.createElement('option'); o.value = t.id; o.textContent = `${t.name}（${t.roleLabel} · ${t.expiryLabel}）`; s.append(o);
    }
    s.value = keep;
  }
}

async function loadAudit() {
  if (!ME || ME.role.id !== 'principal') return;
  const d = await api('/api/admin/audit');
  const tb = $('audit-list'); tb.replaceChildren();
  for (const e of d.entries) {
    const tr = document.createElement('tr');
    const { t, ev, a, u, ...rest } = e;
    for (const v of [fmt(t), ev, a || '—', u || '—', JSON.stringify(rest)]) { const td = document.createElement('td'); td.textContent = v; tr.append(td); }
    tb.append(tr);
  }
}

async function setRole(username, role, btn, templateId) {
  if (role === null && !confirm(`确定移除 ${username} 的角色？移除后对方立即失去邀请管理权限。`)) return;
  if (btn) btn.disabled = true;
  try {
    const d = await api('/api/admin/members', { username, role, templateId: templateId || undefined });
    if (templateId) role = d.role && d.role.id;
    setStatus(d.changed ? (role ? `已授予 ${username}「${ROLE_LABEL[role]}」` : `已移除 ${username} 的角色`) : '角色没有变化', 'ok');
  } catch (e) {
    setStatus(`修改角色失败：${e.message}`, 'err');
  }
  if (btn) btn.disabled = false;
  await loadMembers().catch((e) => setStatus(`刷新成员失败：${e.message}`, 'err'));
}

function hideResult() {
  $('res-code').value = '';
  $('res-link').value = '';
  $('inv-result').hidden = true;
}

async function copy(inputId, label) {
  const v = $(inputId).value;
  if (!v) return;
  try {
    await navigator.clipboard.writeText(v);
  } catch {
    $(inputId).select();
    document.execCommand('copy'); // 旧浏览器兜底
  }
  setStatus(`已复制${label}`, 'ok');
}

async function create(ev) {
  ev.preventDefault();
  const username = $('inv-user').value.trim();
  if (username && !USERNAME_RE.test(username)) { setStatus('用户名须为 3–32 个字符，仅允许英文字母、数字、下划线和连字符', 'err'); return; }
  const btn = $('btn-create');
  btn.disabled = true;
  hideResult();
  try {
    const d = await api('/api/admin/invites', { ttlSeconds: Number($('inv-ttl').value), username: username || undefined, templateId: $('inv-tpl').value || undefined });
    // 明文只放在这两个输入框里：不写 localStorage / 不进日志；隐藏或离开页面即丢弃
    $('res-code').value = d.code;
    $('res-link').value = d.link;
    $('res-id').textContent = d.id;
    $('res-user').textContent = d.username || '（不限）';
    $('res-exp').textContent = fmt(d.expiresAt);
    $('inv-result').hidden = false;
    $('inv-user').value = '';
    setStatus(`已生成邀请 ${d.id}`, 'ok');
  } catch (e) {
    setStatus(`生成失败：${e.message}`, 'err');
  } finally {
    btn.disabled = false;
  }
  await loadList().catch((e) => setStatus(`刷新列表失败：${e.message}`, 'err'));
}

async function init() {
  $('inv-form').addEventListener('submit', create);
  $('copy-code').addEventListener('click', () => copy('res-code', '邀请码'));
  $('copy-link').addEventListener('click', () => copy('res-link', '邀请链接'));
  $('btn-done').addEventListener('click', hideResult);
  $('btn-refresh').addEventListener('click', () => loadList().then(() => setStatus('列表已刷新', 'ok')).catch((e) => setStatus(e.message, 'err')));
  window.addEventListener('pagehide', hideResult);
  $('mem-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const u = $('mem-user').value.trim();
    if (!USERNAME_RE.test(u)) { setStatus('用户名须为 3–32 个字符，仅允许英文字母、数字、下划线和连字符', 'err'); return; }
    setRole(u, $('mem-role').value, $('btn-grant')).then(() => { $('mem-user').value = ''; });
  });
  $('exp-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const username = $('exp-user').value.trim();
    if (!USERNAME_RE.test(username)) { setStatus('请输入有效的用户名', 'err'); return; }
    const mode = $('exp-mode').value;
    const body = { username, scope: $('exp-scope').value, mode };
    if (mode === 'relative') body.duration = $('exp-dur').value.trim();
    if (mode === 'absolute') body.at = $('exp-at').value; // 不带时区 → 服务端按台北时间解释
    try {
      const d = await api('/api/admin/expiry', body);
      setStatus(`已更新 ${username} 的过期设置：${d.expiry.label}`, 'ok');
    } catch (e) { setStatus(`过期设置失败：${e.message}`, 'err'); }
    await loadMembers().catch(() => {});
  });
  $('tpl-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const d = await api('/api/admin/templates', { action: 'save', id: $('tpl-id').value.trim(), name: $('tpl-name').value.trim(), role: null, expiry: $('tpl-exp').value, scope: $('tpl-scope').value, desc: $('tpl-desc').value });
      setStatus(`已保存模板 ${d.template.id}（v${d.template.v}）`, 'ok');
    } catch (e) { setStatus(`保存模板失败：${e.message}`, 'err'); }
    await loadTemplates().catch(() => {});
  });
  $('btn-audit').addEventListener('click', () => loadAudit().catch((e) => setStatus(e.message, 'err')));
  try {
    await loadList();
    await loadMembers();
    // 模板 / 审计是附加信息：加载失败（如被限流）不覆盖主状态提示
    await loadTemplates().catch(() => {});
    await loadAudit().catch(() => {});
  } catch (e) {
    setStatus(`加载失败：${e.message}`, 'err');
  }
}
init();
