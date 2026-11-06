// D21：生产代码不依赖 jose；测试向量用 jose 交叉验证 ES256（P-1363）。
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { SignJWT, jwtVerify, importJWK } from 'jose';
import { signJwt, verifyJwt, importSigningKey, publicJwk } from '@pkauth/core';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

test('jose 签的 ES256 能被 @pkauth/core 验过，反过来也一样', async () => {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = { ...(await crypto.subtle.exportKey('jwk', kp.privateKey)), kid: 'jose-k1' };
  const sk = await importSigningKey(JSON.stringify(jwk));
  const pub = publicJwk(jwk);
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: 'https://id.example.com', aud: 'https://ainews.example.com/api', sub: 'cross-1' };
  const fromCore = await signJwt(sk, { ...claims, iat: now, exp: now + 60 }, 'at+jwt');
  const joseKey = await importJWK(pub, 'ES256');
  const checked = await jwtVerify(fromCore, joseKey, { issuer: claims.iss, audience: claims.aud, typ: 'at+jwt' });
  assert.equal(checked.payload.sub, 'cross-1');
  const fromJose = await new SignJWT({ sub: 'cross-2' })
    .setProtectedHeader({ alg: 'ES256', kid: 'jose-k1', typ: 'at+jwt' })
    .setIssuer(claims.iss)
    .setAudience(claims.aud)
    .setSubject('cross-2')
    .setIssuedAt(now)
    .setExpirationTime(now + 60)
    .sign(await importJWK(jwk, 'ES256'));
  const back = await verifyJwt(fromJose, [pub], { issuer: claims.iss, audience: claims.aud, typ: 'at+jwt', now: now * 1000 });
  assert.equal(back.sub, 'cross-2');
});
