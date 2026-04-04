/**
 * netlify/functions/csp-report.js
 * CSP violation receiver — same logic as api/csp-report.js
 */
'use strict';

const MAX_BYTES = 8192;

exports.handler = async function netlifyCSPReport(event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: { Allow: 'POST' }, body: 'Method Not Allowed' };
  }

  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body || '', 'base64').toString('utf-8')
    : (event.body || '');

  if (rawBody.length > MAX_BYTES) {
    return { statusCode: 413, body: 'Payload Too Large' };
  }

  let report;
  try {
    const parsed = JSON.parse(rawBody);
    report = Array.isArray(parsed) ? parsed[0] : parsed;
  } catch {
    return { statusCode: 400, body: 'Bad Request' };
  }

  console.error(JSON.stringify({
    type: 'csp-violation',
    ts: new Date().toISOString(),
    ip: (event.headers['x-nf-client-connection-ip'] || event.headers['x-real-ip'] || event.headers['x-forwarded-for'] || '').split(',')[0].trim(),
    ua: (event.headers['user-agent'] || '').slice(0, 200),
    report,
  }));

  return { statusCode: 204, body: '' };
};
