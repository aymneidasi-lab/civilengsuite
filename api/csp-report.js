/**
 * /api/csp-report — CSP Violation Report Receiver
 * ─────────────────────────────────────────────────────────────────────────────
 * Receives Content-Security-Policy violation reports from browsers (both the
 * legacy report-uri format and the modern Report-To / Reporting-API format).
 *
 * All data is logged to Vercel function logs (console.error) and never stored
 * persistently here. For persistent storage, pipe the logs to a log drain
 * (Vercel integrations → Logtail, Datadog, Axiom, etc.).
 *
 * Why a dedicated endpoint instead of a third-party service?
 *   - No third-party receives your violation data
 *   - No additional connect-src domain needed in CSP
 *   - Simple, auditable, zero-dependency
 *
 * Report formats handled:
 *   POST application/csp-report          — legacy report-uri format
 *   POST application/reports+json        — modern Reporting API format
 */

'use strict';

// Maximum body size accepted — prevents memory exhaustion from oversized reports.
const MAX_BYTES = 8_192;

export default async function handler(req, res) {

  // Only POST is valid for CSP reports.
  if (req.method !== 'POST') {
    return res.status(405).set('Allow', 'POST').send('Method Not Allowed');
  }

  // Read raw body with a size cap.
  let body = '';
  try {
    body = await new Promise((resolve, reject) => {
      let data = '';
      req.on('data', chunk => {
        data += chunk;
        if (data.length > MAX_BYTES) reject(new Error('body too large'));
      });
      req.on('end',   () => resolve(data));
      req.on('error', reject);
    });
  } catch (e) {
    return res.status(413).send('Payload Too Large');
  }

  // Parse — accept both CSP report-uri and Reporting API payloads.
  let report;
  try {
    const parsed = JSON.parse(body);
    // Reporting API wraps reports in an array.
    report = Array.isArray(parsed) ? parsed[0] : parsed;
  } catch {
    return res.status(400).send('Bad Request');
  }

  // Log to Vercel function output (visible in dashboard → Functions → Logs).
  // Structured JSON makes it searchable in any log drain.
  console.error(JSON.stringify({
    type:    'csp-violation',
    ts:      new Date().toISOString(),
    ip:      (req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || '').split(',')[0].trim(),
    ua:      (req.headers['user-agent'] || '').slice(0, 200),
    report,
  }));

  // 204 No Content — correct response for report-uri receivers per spec.
  return res.status(204).end();
}
