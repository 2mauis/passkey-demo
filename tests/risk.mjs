// 登录风险评估单元测试（纯函数，无网络）。只使用文档保留 IP 段 192.0.2.0/24、198.51.100.0/24 与伪造的 cf 对象。
// 用法：node tests/risk.mjs
import { evaluateLogin, ipPrefix, uaFamily } from '../src/risk.js';
const results = [];
const check = (n, ok, d = '') => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${d ? '  — ' + d : ''}`); };
const fakeCf = (country, asn) => ({ country, asn });
const sig = (cf, ip) => ({ country: cf.country, asn: cf.asn, fp: `fp-${ipPrefix(ip)}` });
const t0 = Date.UTC(2026, 0, 1);
const H = 3600e3, D = 24 * H;

check('IPv4 前缀 /24', ipPrefix('192.0.2.77') === '192.0.2.0/24');
check('IPv4 另一段', ipPrefix('198.51.100.9') === '198.51.100.0/24');
check('IPv6 前缀 /48', ipPrefix('2001:db8:1:2::5') === '2001:db8:1::/48');
check('空 IP', ipPrefix('') === 'unknown');
check('UA 大类', uaFamily('Mozilla/5.0 (Windows NT 10.0) Chrome/130 Safari/537') === 'chrome/windows');

let r = evaluateLogin(null, sig(fakeCf('TW', 64500), '192.0.2.10'), t0);
check('首次登录：放行', r.action === 'allow' && r.reasons.length === 0);
const h1 = r.history;
check('历史里不含原始 IP', !JSON.stringify(h1).includes('192.0.2.10'));
r = evaluateLogin(h1, sig(fakeCf('TW', 64500), '192.0.2.11'), t0 + 2 * H);
check('同国家同 ASN：放行', r.action === 'allow');
r = evaluateLogin(h1, sig(fakeCf('TW', 64501), '198.51.100.3'), t0 + 2 * H);
check('新 ASN：要求 step-up', r.action === 'stepup' && r.reasons.includes('new_asn'));
r = evaluateLogin(h1, sig(fakeCf('JP', 64500), '198.51.100.3'), t0 + 5 * H);
check('新国家（超过旅行窗口）：要求 step-up', r.action === 'stepup' && r.reasons.includes('new_country'));
r = evaluateLogin(h1, sig(fakeCf('JP', 64502), '198.51.100.3'), t0 + 10 * 60e3);
check('10 分钟内换国家：不可能的旅行 → block', r.action === 'block' && r.reasons.includes('impossible_travel'));
check('block 时不把新环境写进历史', !r.history.countries.JP);
r = evaluateLogin(h1, sig(fakeCf('JP', 64502), '198.51.100.3'), t0 + 10 * 60e3, { impossibleTravelMs: 5 * 60e3 });
check('旅行窗口可配置（5 分钟）', r.action === 'stepup');
r = evaluateLogin(h1, sig(fakeCf('TW', 64501), '192.0.2.10'), t0 + 40 * D, { retentionMs: 30 * D });
check('超过保留期的历史被清理（相当于首次）', r.action === 'allow' && Object.keys(r.history.asns).length === 1);
r = evaluateLogin(h1, sig(fakeCf('XX', 'unknown'), '192.0.2.10'), t0 + 60e3);
check('未知国家不触发不可能的旅行', r.action !== 'block');

const fail = results.filter((x) => !x).length;
console.log(`\n合计 ${results.length} 项：通过 ${results.length - fail}，失败 ${fail}`);
process.exit(fail ? 1 : 0);
