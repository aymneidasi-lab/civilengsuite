/**
 * Civil Engineering Suite — Client-Side Analytics Ingest Endpoint
 * POST /api/track
 *
 * Receives page-view and custom-event data from:
 *   1. bootstrapBeacon (sendBeacon from bootstrap, before document.write)
 *   2. In-page GA4/Clarity events from decoded source HTML (not via this endpoint)
 *
 * Writes to Cloudflare Analytics Engine (binding: CES_ANALYTICS).
 * Optionally relays page_view to GA4 Measurement Protocol if
 * CES_GA4_ID + CES_GA4_SECRET env vars are both set.
 *
 * ── BINDINGS (Cloudflare Pages → Settings → Functions) ─────────────────────
 *   CES_ANALYTICS   — Analytics Engine dataset (variable: CES_ANALYTICS)
 *
 * ── ENV VARS (optional) ─────────────────────────────────────────────────────
 *   CES_GA4_ID      — GA4 Measurement ID, e.g. G-XXXXXXXXXX
 *   CES_GA4_SECRET  — GA4 Measurement Protocol API Secret
 *   CANONICAL_HOST  — override canonical hostname (default: civilengsuite.pages.dev)
 *
 * ── ANALYTICS ENGINE SCHEMA ─────────────────────────────────────────────────
 *   blobs[0] = page pathname       e.g. /footing-pro
 *   blobs[1] = event name          e.g. pageview | cta_click | scroll_depth
 *   blobs[2] = CF-IPCountry        e.g. EG
 *   blobs[3] = device type         mobile | desktop
 *   blobs[4] = referrer URL        (trimmed 200 chars)
 *   blobs[5] = browser language    e.g. ar-EG
 *   blobs[6] = session ID          from sessionStorage._ces_sid (v23)
 *   doubles[0] = Unix timestamp ms
 *   doubles[1] = viewport width px
 *   indexes[0] = page pathname     (for per-page AE SQL queries)
 *
 * ── CHANGE LOG ──────────────────────────────────────────────────────────────
 * v1  — initial release (page, event, country, device, referrer, lang)
 * v2  — [V23-SID] added blobs[6] = session ID from body.s
 *        GA4 client_id now uses session ID instead of time-bucketed fallback
 */

const DEFAULT_HOST = 'civilengsuite.pages.dev';
const GA4_ENDPOINT = 'https://www.google-analytics.com/mp/collect';

/**
 * Returns true if origin is allowed to POST to this endpoint.
 * Accepts same-origin, CF preview subdomains, localhost, and
 * empty Origin (sendBeacon on same-origin sometimes omits it).
 */
function isAllowedOrigin(origin, canonicalHost) {
  if (!origin) return true;
  if (origin === `https://${canonicalHost}`) return true;
  // Cloudflare Pages preview deployments: *.civilengsuite.pages.dev
  const escaped = canonicalHost.replace(/\./g, '\\.');
  if (new RegExp(`^https://[\\w-]+\\.${escaped}$`).test(origin)) return true;
  // Local dev
  if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return true;
  return false;
}

function corsHeaders(origin, canonicalHost) {
  const allowed = isAllowedOrigin(origin, canonicalHost);
  return {
    'Access-Control-Allow-Origin':  allowed
      ? (origin || `https://${canonicalHost}`)
      : `https://${canonicalHost}`,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

// ── Preflight ─────────────────────────────────────────────────────────────────
export async function onRequestOptions({ request, env }) {
  const host   = (env.CANONICAL_HOST || DEFAULT_HOST).trim();
  const origin = request.headers.get('Origin') || '';
  return new Response(null, {
    status: 204,
    headers: { ...corsHeaders(origin, host), 'Cache-Control': 'no-store' },
  });
}

// ── POST handler ──────────────────────────────────────────────────────────────
export async function onRequestPost({ request, env, ctx }) {
  const canonicalHost = (env.CANONICAL_HOST || DEFAULT_HOST).trim();
  const origin        = request.headers.get('Origin') || '';

  // Reject requests from disallowed origins
  if (origin && !isAllowedOrigin(origin, canonicalHost)) {
    return new Response(null, { status: 403 });
  }

  // Reject non-same-origin fetch context (belt-and-suspenders)
  const secFetchSite = request.headers.get('Sec-Fetch-Site') || '';
  if (secFetchSite && secFetchSite !== 'same-origin' && secFetchSite !== 'none') {
    return new Response(null, { status: 403 });
  }

  // Parse body — sendBeacon sends Content-Type: text/plain; keep lenient
  let body;
  try {
    const raw = await request.text();
    if (!raw || raw.length > 4096) return new Response(null, { status: 400 });
    body = JSON.parse(raw);
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      return new Response(null, { status: 400 });
    }
  } catch (e) {
    return new Response(null, { status: 400 });
  }

  // ── Extract and sanitize all fields ──────────────────────────────────────
  const page      = String(body.p || body.page    || '').slice(0, 100)  || '/unknown';
  const event     = String(body.e || body.event   || 'pageview').slice(0, 50);
  const referrer  = String(body.r || body.referrer|| '').slice(0, 200);
  const lang      = String(body.l || body.lang    || '').slice(0, 20);
  const width     = Math.min(Math.max(Number(body.w || body.width)  || 0, 0), 9999);
  // [V23-SID] session ID from sessionStorage._ces_sid (set by bootstrapBeacon)
  const sessionId = String(body.s || body.session || '').replace(/[^a-z0-9]/gi, '').slice(0, 32);

  // Server-enriched context (never trust client for these)
  const country   = request.headers.get('CF-IPCountry') || 'XX';
  const ua        = (request.headers.get('User-Agent') || '').slice(0, 200);
  const isMobile  = /mobile|android|iphone|ipad|phone/i.test(ua);
  const device    = isMobile ? 'mobile' : 'desktop';

  // ── Write to Cloudflare Analytics Engine ──────────────────────────────────
  // writeDataPoint() is synchronous — no await, no latency on response path
  if (env.CES_ANALYTICS) {
    try {
      env.CES_ANALYTICS.writeDataPoint({
        blobs:   [page, event, country, device, referrer, lang, sessionId],
        doubles: [Date.now(), width],
        indexes: [page],
      });
    } catch (e) {
      // AE failure must never break the 204 response
      console.warn('[ces:track] AE write failed:', e && e.message);
    }
  }

  // ── Optional: GA4 Measurement Protocol relay ──────────────────────────────
  // Only for pageview events. client_id = session ID (v23) or country fallback.
  // Uses ctx.waitUntil so the fetch completes without blocking the 204 response.
  if (env.CES_GA4_ID && env.CES_GA4_SECRET && event === 'pageview') {
    const ga4ClientId = sessionId
      ? `ces.${sessionId}`
      : `anon.${country}.${Math.floor(Date.now() / 86400000)}`; // daily bucket fallback

    ctx.waitUntil(
      fetch(
        `${GA4_ENDPOINT}?measurement_id=${encodeURIComponent(env.CES_GA4_ID)}`
        + `&api_secret=${encodeURIComponent(env.CES_GA4_SECRET)}`,
        {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client_id: ga4ClientId,
            events: [{
              name: 'page_view',
              params: {
                page_location:         `https://${canonicalHost}${page}`,
                page_referrer:         referrer,
                language:              lang,
                screen_width:          width,
                session_id:            sessionId || undefined,
                engagement_time_msec:  100,
              },
            }],
          }),
        }
      ).catch(e => console.warn('[ces:track] GA4 relay failed:', e && e.message))
    );
  }

  return new Response(null, {
    status: 204,
    headers: {
      ...corsHeaders(origin, canonicalHost),
      'Cache-Control': 'no-store',
    },
  });
}
