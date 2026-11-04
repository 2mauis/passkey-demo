// 工作流脚本单元测试：privacy-scan 规则、agent-trailer、spec-requires-tests（纯函数，不需要网络）
// 用法：node tests/workflow-scripts.mjs
import { scanText } from '../scripts/privacy-scan.mjs';
import { checkAgentTrailer } from '../scripts/agent-trailer.mjs';
import { checkSpecTests } from '../scripts/check-spec-tests.mjs';
const R = []; const check = (n, ok) => { R.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}`); };
const hit = (t) => scanText(t, 'x').map((h) => h.split(' ')[1]);
check('privacy：普通邮箱命中', hit('mail a.b@' + 'gmail.com').includes('email'));
check('privacy：noreply / example.com 邮箱放行', hit('x@users.noreply.github.com a@example.com').length === 0);
check('privacy：公网 IPv4 命中', hit('ip 8.8.' + '4.4').includes('ipv4'));
check('privacy：文档保留段 IP 放行', hit('192.0.2.1 198.51.100.7 203.0.113.9 127.0.0.1').length === 0);
check('privacy：真实 workers.dev 子域命中，example 放行', hit('https://app.someone' + '.workers.dev').includes('workers-dev-subdomain') && hit('https://app.example.workers.dev').length === 0);
check('privacy：32 位十六进制 id 命中，全 0 放行', hit('id = "' + 'ab'.repeat(16) + '"').includes('kv-or-account-id') && hit('0'.repeat(32)).length === 0);
check('privacy：Turnstile 生产 sitekey 命中', hit('0x4' + 'A'.repeat(20)).includes('turnstile-sitekey'));
check('privacy：GitHub token 样式命中', hit('ghp_' + 'a1B2'.repeat(9)).includes('github-token'));
check('privacy：tailnet 主机名命中；JS 属性 flags.local 不误报', hit('box.tail1234' + '.ts.net').includes('tailnet-or-lan-host') && hit('flags.local ? 1 : 2').length === 0);
check('privacy：显式豁免注释生效', hit('8.8.' + '4.4 // privacy-scan: allow').length === 0);
const msg = 'feat: x\n\nbody\n\nAgent: grok-code-assistant\n';
const A = 'Grok Bot Friday (for 2mauis)', E = '2908005+2mauis@users.noreply.github.com';
check('trailer：正确署名通过', checkAgentTrailer({ message: msg, authorName: A, authorEmail: E }).length === 0);
check('trailer：缺 Agent 失败', checkAgentTrailer({ message: 'feat: x\n', authorName: A, authorEmail: E }).includes('missing-or-duplicate-agent-trailer'));
check('trailer：非 noreply 邮箱失败', checkAgentTrailer({ message: msg, authorName: A, authorEmail: 'a@example.com' }).includes('author-email-not-noreply'));
check('trailer：author 与 Agent 不匹配失败', checkAgentTrailer({ message: msg, authorName: 'Someone', authorEmail: E }).includes('author-does-not-match-agent'));
check('spec：改 spec 不改测试失败', checkSpecTests(['docs/specs/a.md']) === false);
check('spec：改 spec 同时改 tests/*.mjs 通过', checkSpecTests(['docs/specs/a.md', 'tests/a.mjs']) === true);
check('spec：TEMPLATE.md 豁免；删除 spec 不触发', checkSpecTests(['docs/specs/TEMPLATE.md']) && checkSpecTests(['docs/specs/a.md'], []));
const f = R.filter((x) => !x).length; console.log(`结果：${R.length - f}/${R.length} 通过`); process.exit(f ? 1 : 0);
