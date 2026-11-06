import { protect } from './index.js';

// Pages Functions：`export { onRequest } from '@pkauth/workers/pages'`
export function pagesMiddleware(upstreamFetch) {
  return protect({ fetch: (request, env, ctx) => upstreamFetch(request, env, ctx) });
}

export async function onRequest(context) {
  const worker = pagesMiddleware((request) => context.next(request));
  return worker.fetch(context.request, context.env, context);
}
