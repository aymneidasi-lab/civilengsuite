/**
 * Cloudflare Pages Function — /api/csp-report
 * CSP violation receiver — Cloudflare-native version of api/csp-report.js
 */

const MAX_BYTES = 8192;

export async function onRequestPost(context) {
  const body = await context.request.text();

  if (body.length > MAX_BYTES)
    return new Response('Payload Too Large', { status: 413 });

  let report;
  try {
    const parsed = JSON.parse(body);
    report = Array.isArray(parsed) ? parsed[0] : parsed;
  } catch {
    return new Response('Bad Request', { status: 400 });
  }

  console.error(JSON.stringify({
    type: 'csp-violation',
    ts:   new Date().toISOString(),
    ip:   (context.request.headers.get('CF-Connecting-IP') || '').split(',')[0].trim(),
    ua:   (context.request.headers.get('User-Agent') || '').slice(0, 200),
    report,
  }));

  return new Response('', { status: 204 });
}

export async function onRequest(context) {
  if (context.request.method !== 'POST')
    return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'POST' } });
  return onRequestPost(context);
}
