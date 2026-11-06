// 尝试验证条件式 UI（自动填充）登录。headless + 虚拟认证器下自动填充下拉框无法被“点击”，
// 因此本脚本仅作探索：聚焦输入框后观察是否会自动完成登录。
// 加固版：注册前需等待 Turnstile 小组件给出 token（本地为测试密钥 dummy token，线上为真实 managed 挑战）。
import { assertSafeBase } from '../../../scripts/safe-base.mjs';
import { randomBytes } from 'node:crypto';
import { chromium } from 'playwright';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const APP_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const REPO_ROOT = dirname(dirname(APP_ROOT));
const BASE = (process.env.BASE_URL || 'http://localhost:8787').replace(/\/$/, '');
assertSafeBase(BASE); // 管理 token 只发往 https 或本机 http
const browser = await chromium.launch({ headless: process.env.HEADED !== '1' });
const context = await browser.newContext();
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
const user = 'demo_c' + randomBytes(3).toString('hex');
// 通过管理接口创建一个绑定该用户名的一次性邀请（token 不打印；注册成功后邀请自动失效）
const LOCAL = new URL(BASE).hostname === 'localhost';
const ADMIN_TOKEN = LOCAL ? /^ADMIN_TOKEN=(.+)$/m.exec(readFileSync(join(APP_ROOT, '.dev.vars'), 'utf8'))[1].trim() : readFileSync(join(REPO_ROOT, '.admin-token'), 'utf8').trim();
const ir = await fetch(BASE + '/api/admin/invites', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: new URL(BASE).origin, Authorization: `Bearer ${ADMIN_TOKEN}` }, body: JSON.stringify({ username: user, ttlSeconds: 600 }) });
const inv = await ir.json();
if (ir.status !== 200) { console.log('FAIL 创建邀请失败 HTTP', ir.status); process.exit(1); }
await page.goto(BASE + '/');
const tok = await page.waitForFunction(() => window.__pk && window.__pk.getTurnstileToken(), null, { timeout: 45000, polling: 250 }).then(() => true).catch(() => false);
console.log(tok ? 'Turnstile token 已获取' : 'FAIL Turnstile 45 秒内未给出 token');
if (!tok) { await page.screenshot({ path: 'shots/turnstile-fail-cond.png' }); await browser.close(); process.exit(1); }
await page.fill('#reg-invite', inv.code);
await page.fill('#reg-username', user);
await page.click('#btn-register');
await page.locator('#authed').waitFor();
await page.click('#btn-logout');
await page.locator('#anon').waitFor();
const avail = await page.evaluate(() => PublicKeyCredential.isConditionalMediationAvailable());
console.log('isConditionalMediationAvailable =', avail);
await page.focus('#login-autofill');
const ok = await page.locator('#authed').waitFor({ timeout: 10000 }).then(() => true).catch(() => false);
console.log('用户:', user);
console.log(ok ? 'PASS 条件式 UI：聚焦后自动完成登录' : 'NOT VERIFIED 条件式 UI：10 秒内未自动完成（headless 无法选择自动填充项）');
console.log('status:', await page.locator('#status').innerText());
await browser.close();
