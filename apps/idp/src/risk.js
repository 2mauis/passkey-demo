// 登录风险评估（纯函数，便于用伪造的 cf 对象做单元测试）。
// 信号：request.cf.country / asn（Cloudflare 提供）+ IP 前缀（IPv4 /24、IPv6 /48）和 UA 大类的 HMAC 指纹。
// 不存原始 IP：只存国家代码、ASN 和 HMAC 指纹，保留期 30–90 天可配置。
// 依据：NIST SP 800-63B §2 欺诈迹象（MAY 使用，不替代认证因子）；具体规则是工程取舍（见 docs/session.md）。

export function ipPrefix(ip) {
  if (typeof ip !== 'string' || !ip) return 'unknown';
  if (ip.includes(':')) {
    const parts = ip.split('::')[0].split(':').concat(['0', '0', '0']).slice(0, 3);
    return parts.map((p) => p || '0').join(':') + '::/48';
  }
  const o = ip.split('.');
  return o.length === 4 ? `${o[0]}.${o[1]}.${o[2]}.0/24` : 'unknown';
}
export function uaFamily(ua) {
  const s = String(ua || '');
  const br = /Edg\//.test(s) ? 'edge' : /Firefox\//.test(s) ? 'firefox' : /Chrome\//.test(s) ? 'chrome' : /Safari\//.test(s) ? 'safari' : 'other';
  const os = /Windows/.test(s) ? 'windows' : /Android/.test(s) ? 'android' : /iPhone|iPad/.test(s) ? 'ios' : /Mac OS X/.test(s) ? 'macos' : /Linux/.test(s) ? 'linux' : 'other';
  return `${br}/${os}`;
}
// signal = { country, asn, fp }；history = { countries: {CC: t}, asns: {asn: t}, fps: {fp: t}, last: { country, t } } | null
// 返回 { action: 'allow' | 'stepup' | 'block', reasons: [...], history: 更新后的历史 }
export function evaluateLogin(history, signal, now, { impossibleTravelMs = 3600e3, retentionMs = 30 * 86400e3 } = {}) {
  const h = history ? structuredClone(history) : { countries: {}, asns: {}, fps: {}, last: null };
  for (const k of ['countries', 'asns', 'fps']) for (const [x, t] of Object.entries(h[k] || {})) if (now - t > retentionMs) delete h[k][x];
  const reasons = [];
  let action = 'allow';
  const first = !history || (!Object.keys(h.countries).length && !Object.keys(h.asns).length);
  const c = signal.country || 'XX';
  const a = String(signal.asn ?? 'unknown');
  if (!first) {
    if (h.last && h.last.country && h.last.country !== c && c !== 'XX' && h.last.country !== 'XX' && now - h.last.t < impossibleTravelMs) {
      action = 'block'; reasons.push('impossible_travel');
    } else {
      if (!h.countries[c]) reasons.push('new_country');
      if (!h.asns[a]) reasons.push('new_asn');
      if (reasons.length) action = 'stepup';
    }
  }
  if (action !== 'block') {
    h.countries[c] = now; h.asns[a] = now; if (signal.fp) h.fps[signal.fp] = now;
    h.last = { country: c, t: now };
  }
  return { action, reasons, history: h };
}
