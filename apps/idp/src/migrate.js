// §5.5 旧 passkey 迁移票据。票据绑定 userID，5 分钟，DO 一次性消费。不访问线上 KV / D1。
import { b64u, unb64u } from '@pkauth/core';

export const TICKET_TTL_MS = 5 * 60 * 1000;
const enc = new TextEncoder();

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(String(secret)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export function migrationRedirect(env, ticket) {
  const dest = env && env.RP_ID === 'localhost' ? env.ORIGIN : 'https://id.example.com';
  return `${String(dest).replace(/\/$/, '')}/migrate#ticket=${encodeURIComponent(ticket)}`;
}

export function migrationRegisterPlan({ pending, user }) {
  if (!pending) return { kind: 'normal' };
  if (!user || user.userID !== pending.userID || user.username !== pending.username) return { kind: 'reject' };
  return { kind: 'add-passkey', user };
}

async function signPayload(secret, payload) {
  const body = b64u(enc.encode(JSON.stringify(payload)));
  const mac = b64u(new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(body))));
  return `${body}.${mac}`;
}

async function readPayload(secret, token) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [body, mac] = token.split('.');
  if (!body || !mac) return null;
  const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), unb64u(mac), enc.encode(body));
  if (!ok) return null;
  try { return JSON.parse(new TextDecoder().decode(unb64u(body))); } catch { return null; }
}

export async function issueMigrationTicket(env, state, { userID, username, sid }, now = Date.now()) {
  if (!env.CHAL_HMAC_KEY || typeof userID !== 'string' || typeof username !== 'string') return null;
  const exp = now + TICKET_TTL_MS;
  const ticket = await signPayload(env.CHAL_HMAC_KEY, { v: 1, userID, username, sid: sid || null, exp });
  const hash = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(ticket))));
  await state.issue(`mt:${hash}`, TICKET_TTL_MS, { userID, username });
  return { ticket, exp, url: migrationRedirect(env, ticket) };
}

export async function redeemMigrationTicket(env, state, ticket, now = Date.now()) {
  const payload = await readPayload(env.CHAL_HMAC_KEY, ticket);
  if (!payload || payload.v !== 1 || typeof payload.exp !== 'number' || now > payload.exp) return null;
  if (typeof payload.userID !== 'string' || typeof payload.username !== 'string') return null;
  const hash = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(ticket))));
  const consumed = await state.consume(`mt:${hash}`);
  if (!consumed || consumed.data.userID !== payload.userID || consumed.data.username !== payload.username) return null;
  return { userID: payload.userID, username: payload.username };
}
