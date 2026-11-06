const status = document.getElementById('status');
const ticket = new URLSearchParams((location.hash || '').replace(/^#/, '')).get('ticket');
if (!ticket) {
  status.textContent = '缺少迁移票据。请从旧站已登录页面的“迁移到新站”进入。';
} else {
  const res = await fetch('/api/migrate/redeem', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ticket }),
  });
  const data = await res.json().catch(() => ({}));
  status.textContent = res.ok
    ? `票据有效。账户 ${data.username || ''} 已绑定到这个浏览器，请登记一把新的 passkey。`
    : (data.error || '票据无效、已使用或已过期。');
}
