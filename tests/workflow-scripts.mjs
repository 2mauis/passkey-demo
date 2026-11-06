// 工作流脚本单元测试：privacy-scan 规则、agent-trailer、spec-requires-tests（纯函数，不需要网络）
// 用法：node tests/workflow-scripts.mjs
import { scanText, shouldSkip } from '../scripts/privacy-scan.mjs';
import { assertSafeBase } from '../scripts/safe-base.mjs';
import { loadAdminToken } from '../scripts/load-admin-token.mjs';
import { readFileSync, readdirSync, mkdtempSync, writeFileSync, rmSync, statSync, symlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { checkAgentTrailer } from '../scripts/agent-trailer.mjs';
import { checkSpecTests } from '../scripts/check-spec-tests.mjs';
import { injectDeployConfig, placeholderIssues } from '../scripts/inject-deploy-config.mjs';
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
check('spec：改 spec 同时改 tests/*.mjs 通过', checkSpecTests(['docs/specs/a.md', 'tests/a.mjs']) === true && checkSpecTests(['docs/specs/a.md', 'packages/workers/tests/a.mjs']) === true && checkSpecTests(['docs/specs/a.md', 'apps/idp/tests/a.mjs']) === true);
check('spec：TEMPLATE.md 豁免；删除 spec 不触发', checkSpecTests(['docs/specs/TEMPLATE.md']) && checkSpecTests(['docs/specs/a.md'], []));
check('privacy：跳过 node_modules / .wrangler / package-lock.json 与图片，不误跳相似文件名', shouldSkip('node_modules/a.js') && shouldSkip('x/.wrangler/s.json') && shouldSkip('package-lock.json') && shouldSkip('shots/a.PNG') && !shouldSkip('docs/node_modules-notes.md') && !shouldSkip('src/package-lock.json.md') && !shouldSkip('src/worker.js'));
const throws = (fn) => { try { fn(); return false; } catch { return true; } };
check('invite：非 localhost 的 http 目标被拒绝（不发送 token）', throws(() => assertSafeBase('http://app.example.com')) && throws(() => assertSafeBase('http://localhost.example.com')) && assertSafeBase('https://app.example.com/x') === 'https://app.example.com' && assertSafeBase('http://localhost:8787') === 'http://localhost:8787');
check('tests 不使用非加密随机数', readdirSync(new URL('.', import.meta.url)).filter((f) => f.endsWith('.mjs')).every((f) => !readFileSync(new URL(f, import.meta.url), 'utf8').includes('Math.' + 'random')));

const srcOf = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const keygenSrc = srcOf('../scripts/oidc-keygen.mjs');
const tokenSrc = srcOf('../scripts/load-admin-token.mjs');
check('oidc-keygen：单次 open，fd 上读写真，不再按路径 exists/readFile/writeFile', !/\b(existsSync|readFileSync|readFile|writeFileSync|writeFile|chmodSync)\b/.test(keygenSrc) && keygenSrc.includes('openSync(') && keygenSrc.includes('readSync(') && keygenSrc.includes('writeSync(') && keygenSrc.includes('O_NOFOLLOW'));
check('load-admin-token：先校验目标再读文件，且不用 readFile/readFileSync', /function loadAdminToken[\s\S]*assertSafeBase\(base\)[\s\S]*readTextViaFd\(/.test(tokenSrc) && !/\breadFile(Sync)?\b/.test(tokenSrc) && tokenSrc.includes('readSync('));
for (const rel of ['../apps/idp/tests/conditional.mjs', '../apps/idp/tests/oidc.mjs', '../apps/idp/tests/online-checks.mjs']) {
  check(`管理 token 不再从文件读进请求：${rel.split('/').pop()}`, srcOf(rel).includes('loadAdminToken(') && !srcOf(rel).includes('readFileSync') && !srcOf(rel).includes('readFile('));
}
check('管理 token 不再从文件读进请求：e2e.mjs', srcOf('../apps/idp/tests/e2e.mjs').includes('loadAdminToken(') && !/readFileSync\([\s\S]{0,180}ADMIN_TOKEN|ADMIN_TOKEN[\s\S]{0,80}readFileSync/.test(srcOf('../apps/idp/tests/e2e.mjs')));

const dir = mkdtempSync(join(tmpdir(), 'pk-codeql-'));
try {
  const token = randomBytes(32).toString('base64');
  const raw = join(dir, 'admin-token');
  writeFileSync(raw, `${token}\n`, { mode: 0o600 });
  const vars = join(dir, 'dev.vars');
  writeFileSync(vars, `OTHER=keep\nADMIN_TOKEN=${token}  \nOIDC_SIGNING_KEY=not-the-token\n`, { mode: 0o600 });
  const missing = join(dir, 'missing-token');
  const badUrl = () => { try { loadAdminToken('http://app.example.com', missing); return ''; } catch (e) { return e.message; } };
  check('token：非 localhost 的 http 在打开文件前拒绝', badUrl().includes('拒绝发送管理 token') && !badUrl().includes('ENOENT'));
  check('token：localhost 与 127.0.0.1 读取原始 token 文件', loadAdminToken('http://localhost:8787', raw) === token && loadAdminToken('http://127.0.0.1:8787', raw) === token);
  check('token：https 只取出 dotenv 的 ADMIN_TOKEN', loadAdminToken('https://app.example.com/admin', vars, { dotenv: true }) === token);
  check('token：过短内容与整份 dotenv 都不能当 token 发送', throws(() => loadAdminToken('http://[::1]:8787', vars)) && throws(() => { const short = join(dir, 'short'); writeFileSync(short, 'too-short\n'); loadAdminToken('http://localhost:9', short); }));

  const keygen = fileURLToPath(new URL('../scripts/oidc-keygen.mjs', import.meta.url));
  const runKeygen = (p) => spawnSync(process.execPath, [keygen, p], { encoding: 'utf8' });
  const envFile = join(dir, 'oidc.env');
  writeFileSync(envFile, 'ADMIN_TOKEN=keep\n', { mode: 0o644 });
  const r1 = runKeygen(envFile);
  const body1 = readFileSync(envFile, 'utf8');
  const r2 = runKeygen(envFile);
  const body2 = readFileSync(envFile, 'utf8');
  const keyLines = (s) => s.split('\n').filter((l) => l.startsWith('OIDC_SIGNING_KEY='));
  check('oidc-keygen：保留其它行、0600、再次运行只替换密钥行且不打印私钥', r1.status === 0 && r2.status === 0 && body1.startsWith('ADMIN_TOKEN=keep\n') && body2.startsWith('ADMIN_TOKEN=keep\n') && keyLines(body1).length === 1 && keyLines(body2).length === 1 && keyLines(body1)[0] !== keyLines(body2)[0] && (statSync(envFile).mode & 0o777) === 0o600 && !r1.stdout.includes('"d"') && !r1.stderr.includes('"d"') && !r2.stdout.includes('"d"'));
  const fresh = join(dir, 'fresh.env');
  const r3 = runKeygen(fresh);
  const freshLines = readFileSync(fresh, 'utf8').split('\n').filter((l) => l.length);
  check('oidc-keygen：文件不存在时创建且权限 0600', r3.status === 0 && freshLines.length === 1 && freshLines[0].startsWith("OIDC_SIGNING_KEY='{") && (statSync(fresh).mode & 0o777) === 0o600 && !r3.stdout.includes('"d"'));
  const linkTarget = join(dir, 'link-target.env');
  writeFileSync(linkTarget, 'KEEP=1\n', { mode: 0o600 });
  const link = join(dir, 'link.env');
  symlinkSync(linkTarget, link);
  const r4 = runKeygen(link);
  check('oidc-keygen：拒绝顺着符号链接写入', r4.status !== 0 && readFileSync(linkTarget, 'utf8') === 'KEEP=1\n');
} finally {
  rmSync(dir, { recursive: true, force: true });
}

const wranglerToml = srcOf('../apps/idp/wrangler.toml');
const committedIssues = placeholderIssues(wranglerToml);
check('部署配置：提交的 wrangler.toml 仍是占位', committedIssues.includes('worker-name') && committedIssues.includes('rp-id') && committedIssues.includes('origin') && committedIssues.includes('kv-id') && committedIssues.includes('principals') && committedIssues.includes('turnstile-sitekey') && wranglerToml.startsWith('name = "pkauth-idp"\n'));
const kvId = 'ab'.repeat(16);
const sitekey = '0x4' + 'B'.repeat(22);
const leak = 'ZZLEAK' + '9'.repeat(8);
const goodEnv = {
  DEPLOY_WORKER_NAME: 'passkey-demo',
  DEPLOY_RP_ID: 'id.example.test',
  DEPLOY_ORIGIN: 'https://id.example.test',
  DEPLOY_RP_NAME: 'Passkey Demo',
  DEPLOY_PRINCIPALS: 'alice_demo,bob_demo',
  DEPLOY_KV_ID: kvId,
  DEPLOY_TURNSTILE_SITEKEY: sitekey,
};
const injected = injectDeployConfig(wranglerToml, goodEnv);
const tail = (s) => s.slice(s.indexOf('[[durable_objects.bindings]]'));
const frozenOk = injected.ok && tail(injected.toml) === tail(wranglerToml);
const changed = injected.ok ? wranglerToml.split('\n').filter((line, i) => line !== injected.toml.split('\n')[i]) : [];
check('部署配置：只替换七个占位行，限流与 DO 段不变', frozenOk && changed.length === 7 && injected.toml.includes('name = "passkey-demo"') && injected.toml.includes('RP_ID = "id.example.test"') && injected.toml.includes('ORIGIN = "https://id.example.test"') && injected.toml.includes('RP_NAME = "Passkey Demo"') && injected.toml.includes('PRINCIPALS = "alice_demo,bob_demo"') && injected.toml.includes(`id = "${kvId}"`) && injected.toml.includes(`TURNSTILE_SITEKEY = "${sitekey}"`) && injected.toml.includes('# database_id = "00000000000000000000000000000000"') && injected.toml.includes('namespace_id = "26102601"') && injected.toml.includes('namespace_id = "26102602"') && injected.toml.includes('namespace_id = "26102603"') && injected.toml.includes('class_name = "AuthState"') && injected.toml.includes('tag = "v1-authstate"') && injected.toml.includes('new_sqlite_classes = ["AuthState"]') && placeholderIssues(injected.toml).length === 0);
check('部署配置：与占位文本相同的合法 RP_NAME 仍可注入', injectDeployConfig(wranglerToml, { ...goodEnv, DEPLOY_RP_NAME: 'pkauth' }).ok);
const bad = (patch) => injectDeployConfig(wranglerToml, { ...goodEnv, ...patch });
const badOut = (patch) => { const r = bad(patch); return r.ok ? '' : r.errors.join(','); };
check('部署配置：空 secret、占位值与非法字符都失败且不回显值', !bad({ DEPLOY_WORKER_NAME: '' }).ok && badOut({ DEPLOY_WORKER_NAME: '   ' }).includes('missing:DEPLOY_WORKER_NAME') && badOut({ DEPLOY_WORKER_NAME: 'pkauth-idp' }).includes('invalid:DEPLOY_WORKER_NAME') && badOut({ DEPLOY_WORKER_NAME: 'other-worker' }).includes('invalid:DEPLOY_WORKER_NAME') && badOut({ DEPLOY_RP_ID: 'id.example.com' }).includes('invalid:DEPLOY_RP_ID') && badOut({ DEPLOY_ORIGIN: 'https://id.example.com' }).includes('invalid:DEPLOY_ORIGIN') && badOut({ DEPLOY_KV_ID: '0'.repeat(32) }).includes('invalid:DEPLOY_KV_ID') && badOut({ DEPLOY_PRINCIPALS: 'root_example' }).includes('invalid:DEPLOY_PRINCIPALS') && badOut({ DEPLOY_TURNSTILE_SITEKEY: '1x00000000000000000000AA' }).includes('invalid:DEPLOY_TURNSTILE_SITEKEY') && badOut({ DEPLOY_WORKER_NAME: `passkey-${leak}` }).includes('invalid:DEPLOY_WORKER_NAME') && !badOut({ DEPLOY_WORKER_NAME: `passkey-${leak}` }).includes(leak) && !bad({ DEPLOY_ORIGIN: 'https://id.example.test\nname = "other"' }).ok);
const deployYml = srcOf('../.github/workflows/deploy.yml');
const injectAt = deployYml.indexOf('node scripts/inject-deploy-config.mjs apps/idp/wrangler.toml');
const checkAt = deployYml.indexOf('node scripts/inject-deploy-config.mjs --check apps/idp/wrangler.toml');
const dryAt = deployYml.indexOf('npx wrangler deploy --dry-run --outdir /tmp/dry --config wrangler.toml');
const realAt = deployYml.indexOf('npx wrangler deploy --config wrangler.toml');
const secretNames = ['DEPLOY_WORKER_NAME', 'DEPLOY_RP_ID', 'DEPLOY_ORIGIN', 'DEPLOY_RP_NAME', 'DEPLOY_PRINCIPALS', 'DEPLOY_KV_ID', 'DEPLOY_TURNSTILE_SITEKEY', 'CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'];
check('部署配置：workflow 在注入之后检查占位，dry-run 与 deploy 使用注入文件', injectAt > 0 && checkAt > injectAt && dryAt > checkAt && realAt > dryAt && secretNames.every((n) => deployYml.includes(`secrets.${n}`)) && !deployYml.includes('grep -q') && !deployYml.includes('echo "$DEPLOY') && !deployYml.includes('echo ${{ secrets') && deployYml.includes("echo \"go=0\" >> \"$GITHUB_OUTPUT\""));
const cfgDir = mkdtempSync(join(tmpdir(), 'pk-deploy-'));
try {
  const cfg = join(cfgDir, 'wrangler.toml');
  writeFileSync(cfg, wranglerToml);
  const cli = fileURLToPath(new URL('../scripts/inject-deploy-config.mjs', import.meta.url));
  const runCli = (args, env) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });
  const skipped = runCli([cfg], { DEPLOY_WORKER_NAME: '' });
  check('部署配置：CLI 缺 secret 时不改文件、不打印值', skipped.status !== 0 && readFileSync(cfg, 'utf8') === wranglerToml && !skipped.stdout.includes(kvId) && !skipped.stderr.includes(kvId) && !skipped.stdout.includes(sitekey) && !skipped.stderr.includes(sitekey));
  const wrote = runCli([cfg], goodEnv);
  const after = readFileSync(cfg, 'utf8');
  const checked = runCli(['--check', cfg], {});
  check('部署配置：CLI 注入后占位检查通过，且输出不含 KV id 与 sitekey', wrote.status === 0 && checked.status === 0 && after === injected.toml && !wrote.stdout.includes(kvId) && !wrote.stderr.includes(kvId) && !wrote.stdout.includes(sitekey) && !wrote.stderr.includes(sitekey) && !checked.stdout.includes(kvId) && !checked.stderr.includes(sitekey));
  const linkCfg = join(cfgDir, 'link.toml');
  symlinkSync(cfg, linkCfg);
  const linked = runCli([linkCfg], goodEnv);
  check('部署配置：拒绝顺着符号链接写入', linked.status !== 0 && readFileSync(cfg, 'utf8') === after);
} finally {
  rmSync(cfgDir, { recursive: true, force: true });
}

const f = R.filter((x) => !x).length; console.log(`结果：${R.length - f}/${R.length} 通过`); process.exit(f ? 1 : 0);
