// OIDC 纯函数单元测试（无网络、无 wrangler）：PKCE、ES256 JWT、redirect_uri 精确匹配、continue 校验
import { webcrypto } from 'node:crypto';
import { pkceS256, signJwt, verifyJwt, importSigningKey, publicJwk, redirectAllowed, safeContinue } from '../src/oidc-core.js';

const R = [];
const check = (name, ok) => { R.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`); };

// RFC 7636 附录 B（公开测试向量，拼接写法避免被 token 扫描误报）
const RFC_VERIFIER = ['dBjftJeZ4CVP', 'mB92K27uhbUJU' + '1p1r_wW1gFWFOEjXk'].join('-');
const RFC_CHALLENGE = ['E9Melhoa2OwvFrEMTJ' + 'guCHaoeK1t8URWbuGJSstw', 'cM'].join('-');
check('PKCE S256 与 RFC 7636 附录 B 向量一致', (await pkceS256(RFC_VERIFIER)) === RFC_CHALLENGE);

const kp = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const jwk = { ...(await webcrypto.subtle.exportKey('jwk', kp.privateKey)), kid: 'test-k1' };
const key = await importSigningKey(JSON.stringify(jwk));
const pub = publicJwk(jwk);
const now = Math.floor(Date.now() / 1000);
const claims = { iss: 'https://idp.example.com', aud: ['a', 'b'], sub: 'u1', iat: now, exp: now + 60 };
const t = await signJwt(key, claims, 'at+jwt');
const opt = { issuer: 'https://idp.example.com', audience: 'b' };
check('ES256 签名可被公钥 JWK 验证', (await verifyJwt(t, [pub], opt)).sub === 'u1' && !('d' in pub));
const [h, p, s] = t.split('.');
const forged = [h, Buffer.from(JSON.stringify({ ...claims, sub: 'admin' })).toString('base64url'), s].join('.');
const rej = async (tok, o) => { try { await verifyJwt(tok, [pub], o); return false; } catch { return true; } };
check('篡改 payload 后验签失败', await rej(forged, opt));
const expired = await signJwt(key, { ...claims, exp: now - 120 });
check('过期 / iss / aud 不符被拒', (await rej(expired, opt)) && (await rej(t, { ...opt, issuer: 'https://evil.example.com' })) && (await rej(t, { ...opt, audience: 'c' })) && (await rej(p, opt)));

const client = { redirectUris: ['https://app.example.com/cb'] };
check('redirect_uri 逐字匹配（尾斜杠、大小写、查询串都算不同）', redirectAllowed(client, 'https://app.example.com/cb') && !redirectAllowed(client, 'https://app.example.com/cb/') && !redirectAllowed(client, 'https://APP.example.com/cb') && !redirectAllowed(client, 'https://app.example.com/cb?x=1') && !redirectAllowed(client, undefined));
const O = 'https://idp.example.com';
check('continue 只接受同源 /oauth/authorize?', safeContinue('/oauth/authorize?client_id=a', O) === '/oauth/authorize?client_id=a' && safeContinue('//evil.example.com/oauth/authorize?x', O) === null && safeContinue('https://evil.example.com/oauth/authorize?x', O) === null && safeContinue('/oauth/token?x', O) === null && safeContinue('/oauth/authorize/../../x?', O) === null && safeContinue(null, O) === null);

const f = R.filter((x) => !x).length; console.log(`结果：${R.length - f}/${R.length} 通过`); process.exit(f ? 1 : 0);
