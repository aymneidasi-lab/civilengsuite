/**
 * Civil Engineering Suite — Cloudflare Pages Function
 * ─────────────────────────────────────────────────────────────────────────────
 * Handles only exact encrypted page routes: /, /footing-pro, /beam-pro, etc.
 * Sub‑app images (e.g., /footing-pro/images/…) are NOT caught and will be
 * served as static files via _redirects.
 *
 * Environment variables:
 *   CES_DECRYPT_KEY — 64-character hex AES-256-GCM key (required)
 *   CES_XOR_KEY     — 2-character hex XOR key (optional, default 0x5A)
 *   ALLOWED_ORIGINS — comma-separated extra origins (optional)
 *
 * ─── CHANGE LOG ──────────────────────────────────────────────────────────────
 * 2026-04-14 v2 — SEO infrastructure fixes (F1–F6):
 *   [F1] BOT_RE: added googlebot-image, adsbot-google, perplexitybot, ia_archiver
 *   [F2] botHtml: strip <noscript><style>body{display:none} (hid page from crawler)
 *   [F3] botHtml: rewrite /footing-pro/og-image.png → /footing-pro/images/og-image.png
 *   [F4] bot response: add Vary:User-Agent (CDN cache-poisoning guard)
 *   [F5] bot response: Cache-Control public→private (prevent decrypted HTML leaking)
 *   [F6] all responses: SHARED_SECURITY_HEADERS (HSTS, Referrer-Policy, Permissions)
 *
 * 2026-04-14 v3 — Bot path optimization (B1–B7):
 *   [B1] botHtml: strip "CONTENT PROTECTION SYSTEM" IIFE (setInterval + DevTools check)
 *   [B2] botHtml: strip "© Footing Pro v.2026 - Eng. Aymn Asi - All Rights Reserved" IIFE
 *   [B3] botHtml: strip "© Footing Pro v.2026 - Eng. Aymn Asi - Protected" (obfuscated)
 *   [B4] botHtml: strip "_CES_COPYRIGHT_HTML" (showSaveFilePicker override)
 *   [B5] botHtml: strip "ENGINE TRANSFER + SECURITY UPGRADE" (footing-pro only)
 *   [B6] botHtml: minify inline <style> blocks (collapse whitespace, strip comments)
 *   [B7] botHtml: strip oncontextmenu attribute from <body> tag
 *   SECURITY NOTE: Human path is completely unchanged. All protection active for
 *   real users. Only the bot response branch is touched.
 *
 * 2026-04-15 v4 — Critical bug fixes (X1–X2):
 *   [X1] CRITICAL: B1–B5 regexes used [\s\S]*? which crossed </script> boundaries.
 *        Fix: replaced [\s\S]*? with (?:(?!<\/script>)[\s\S])*? in all 5 patterns.
 *   [X2] Permissions-Policy: removed 'ambient-light-sensor=()' and 'usb=()'.
 *
 * 2026-04-17 v5 — Payment gateway integration (P1–P3):
 *   [P1] STATIC_PASSTHROUGH: added /payment/* and /api/payment/*
 *   [P2] CSP_COMMON: form-action expanded to include site origin explicitly.
 *   [P3] SHARED_SECURITY_HEADERS: removed payment=() from Permissions-Policy.
 *
 * 2026-06-08 v14 — Runtime allowed-origins (M3a):
 *   [M3a] Runtime _allowedOriginsJs replaces hardcoded origin string in all guards.
 *         ALLOWED_ORIGINS env var for custom domains without code redeploy.
 *   NOTE: M3b (gsuite_redirect_worker.js) was a dead-end analysis item.
 *         There is no gsuite.pages.dev project. Single repo, single project.
 *
 * 2026-06-07 v13 — Mobile download protection: bootstrap hardening (M1–M2):
 *   [M1a] bootstrapOriginGuard — synchronous parser-blocking <script> in bootstrap <head>.
 *   [M1b] bootstrapCopyrightBody — first <body> child; visible to text editors.
 *   [M1c] xorDecoderOriginGuard — third-layer origin check inside XOR decoder.
 *   [M2]  htmlOriginGuard — injected into decoded HTML (Scenario B coverage).
 *
 * 2026-06-03 v11 — /download redirect (D1).
 * 2026-06-03 v10 — Inline handler CSP fix + landing page 404 fix (H1–H2).
 * 2026-04-28 v9  — PSI font + LCP + CSP fixes (F1–F3).
 * 2026-04-25 v8  — Bot-path OG tag injection + favicon guard (V2-BOT, V4-FAV).
 * 2026-04-25 v7  — Sitemap + OG image fixes (V1–V3).
 * 2026-04-23 v6  — Agent-readiness infrastructure (A1–A7).
 *
 * 2026-06-09 v15 — Split-payload bootstrap: zero-payload download protection (N1–N4):
 *
 *   ROOT CAUSE CONFIRMED: Chrome Android's native Download button saves the bootstrap
 *   HTTP response to disk. The bootstrap contained the full XOR-encoded real HTML as an
 *   embedded base64 blob. When the saved file was opened (file:// context), the M1a/M1c
 *   origin guards should have fired — but a combination of Chrome Android's non-standard
 *   document.open() parser-abort behaviour in file:// context and possible document.write
 *   re-entry quirks caused the XOR decoder to still execute, rendering the real page.
 *
 *   THE FIX — ARCHITECTURAL CHANGE:
 *   The XOR payload is NEVER embedded in the bootstrap response. The downloaded file
 *   is now a pure copyright HTML page with no decodable content whatsoever.
 *   Real content is delivered only as a second same-origin programmatic fetch that
 *   cannot succeed from a file:// context (CORS blocks cross-origin XHR).
 *
 *   [N1] Zero-payload copyright bootstrap:
 *        Bootstrap HTTP response is now a self-contained copyright page (dark background,
 *        lock icon, official URL). No XOR blob. No base64 payload. ~2 KB instead of ~333 KB.
 *        Downloaded file = copyright page only. Text editor opens = copyright HTML only.
 *        No JS needed to see the copyright message (pure HTML+CSS content).
 *        Loading indicator shown via JS when authorized origin detected.
 *
 *   [N2] Payload delivery endpoint (same URL, detected by request headers):
 *        Worker detects same-origin programmatic XHR by checking three independent guards:
 *          (a) X-CES-Context: payload       — our custom marker header
 *          (b) Sec-Fetch-Dest: empty        — only set by fetch()/XHR, NOT by native download
 *          (c) Sec-Fetch-Site: same-origin  — only set when request originates from same origin
 *        Sec-Fetch-* are "forbidden request headers" in the Fetch spec — browsers prevent JS
 *        from overriding them. Chrome's native Download button sets Sec-Fetch-Dest: document
 *        (navigation), not 'empty' — so it NEVER receives the payload, only the copyright page.
 *        When all three checks pass: decrypt .enc, process, XOR-encode, return JSON {p: payload}.
 *
 *   [N3] Client-nonce echo for CSP continuity:
 *        Bootstrap response has CSP header: script-src 'nonce-{cspNonce}'.
 *        After document.write(decodedHtml), the new document inherits this CSP.
 *        Decoded HTML scripts must carry nonce="{cspNonce}" to execute.
 *        Bootstrap JS sends its own nonce in X-CES-Nonce header with the payload request.
 *        Payload endpoint stamps decoded HTML scripts with this echoed nonce, ensuring
 *        nonce continuity: bootstrap CSP nonce === decoded HTML script nonces. ✓
 *
 *   [N4] Decryption optimization:
 *        AES-256-GCM decryption now runs ONLY for bot UAs and payload fetches.
 *        Normal bootstrap requests (copyright page delivery) skip decryption entirely.
 *        Reduces worker CPU time and .enc I/O for the common case.
 *
 *   SECURITY LAYERS FOR DOWNLOADED FILE:
 *     Layer 1 — No payload in file:   nothing to decode, copyright page is all there is.
 *     Layer 2 — Origin check in JS:   window.location.origin === 'null' → loader exits.
 *     Layer 3 — CORS blocks XHR:      file:// → https:// is cross-origin, browser blocks.
 *     Layer 4 — Sec-Fetch-Dest check: even if XHR somehow reached server, 'document'≠'empty'.
 *     Layer 5 — M2 guard in payload:  decoded HTML still has M2 origin guard for Scenario B.
 *
 *   THREAT MODEL UNCHANGED FOR DETERMINED DEVELOPERS:
 *     A developer with DevTools on the live site can still inspect the payload XHR response,
 *     extract the base64+XOR content, and decode it. XOR obfuscation is not encryption.
 *     This is an inherent limitation of client-side protection and is unchanged from v13/v14.
 *     The goal of v15 is stopping CASUAL MOBILE DOWNLOAD, which is fully achieved.
 */

// ── Bot / crawler UA pattern ──────────────────────────────────────────────────
const BOT_RE = /googlebot|googlebot-image|google-inspectiontool|googleother|adsbot-google|bingbot|yandexbot|duckduckbot|baiduspider|applebot|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|slackbot|discordbot|perplexitybot|ia_archiver/i;

// ── Route table ───────────────────────────────────────────────────────────────
const ROUTES = [
  {
    prefix: '/', exact: true,
    encFile: 'pc_suite.enc',
    baseHref: '/',
    pageFilename: 'civil-engineering-suite.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
    ogTitle:       'Civil Engineering Suite — 8-App ACI 318 Structural Engineering Software by Eng. Aymn Asi',
    ogDescription: '8 professional structural engineering apps by Eng. Aymn Asi. Footing Pro (Combined, Trapezoidal, Strap — Live Now) + Beam Pro, Column Pro, Deflection Pro, Earthquake Pro, Mur Pro, Add Reft Pro, Section Property Pro. ACI 318-compliant, 100% offline.',
    ogImage:       '/images/og-image.png',
    ogUrl:         'https://civilengsuite.pages.dev/',
  },
  {
    prefix: '/footing-pro',
    encFile: 'footing_pro.enc',
    baseHref: '/footing-pro/',
    pageFilename: 'footing-pro.html',
    faviconLinks: '<link rel="icon" type="image/png" sizes="32x32"   href="/footing-pro/images/favicon-32.png">'
                + '<link rel="icon" type="image/png" sizes="192x192" href="/footing-pro/images/favicon-192.png">'
                + '<link rel="apple-touch-icon" sizes="180x180"      href="/footing-pro/images/apple-touch-icon.png">',
    ogTitle:       'Footing Pro v.2026 — Free Combined Footing Design Software (ACI 318-19)',
    ogDescription: 'The most advanced free combined footing design application. 17 engineering modules, ACI 318-19 compliant, 100% offline. Rectangular, Trapezoidal, and Strap footings. By Eng. Aymn Asi.',
    ogImage:       '/footing-pro/images/og-image.png',
    ogUrl:         'https://civilengsuite.pages.dev/footing-pro/',
  },
  {
    prefix: '/column-pro',
    encFile: 'column_pro.enc',
    baseHref: '/column-pro/',
    pageFilename: 'column-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
    ogTitle:       'Column Pro — RC Column Design Software (ACI 318-19)',
    ogDescription: 'RC column design per ACI 318-19. P-M interaction, biaxial bending, slenderness checks, punching shear. By Eng. Aymn Asi. Part of Civil Engineering Suite.',
    ogImage:       '/images/og-image.png',
    ogUrl:         'https://civilengsuite.pages.dev/column-pro/',
  },
  {
    prefix: '/beam-pro',
    encFile: 'beam_pro.enc',
    baseHref: '/beam-pro/',
    pageFilename: 'beam-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
    ogTitle:       'Beam Pro — RC Beam Design Software (ACI 318-19)',
    ogDescription: 'ACI 318 reinforced concrete beam design software by Eng. Aymn Asi. Part of Civil Engineering Suite.',
    ogImage:       '/images/og-image.png',
    ogUrl:         'https://civilengsuite.pages.dev/beam-pro/',
  },
  {
    prefix: '/deflection-pro',
    encFile: 'deflection_pro.enc',
    baseHref: '/deflection-pro/',
    pageFilename: 'deflection-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
    ogTitle:       'Deflection Pro — ACI 318 Deflection Checks for RC Beams and Slabs',
    ogDescription: 'Short and long-term deflection serviceability analysis per ACI 318. By Eng. Aymn Asi. Part of Civil Engineering Suite.',
    ogImage:       '/images/og-image.png',
    ogUrl:         'https://civilengsuite.pages.dev/deflection-pro/',
  },
  {
    prefix: '/earthquake-pro',
    encFile: 'earthquake_pro.enc',
    baseHref: '/earthquake-pro/',
    pageFilename: 'earthquake-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
    ogTitle:       'Earthquake Pro — Seismic Design Software',
    ogDescription: 'Seismic design per ACI 318 — base shear, lateral load distribution, structural period. By Eng. Aymn Asi. Part of Civil Engineering Suite.',
    ogImage:       '/images/og-image.png',
    ogUrl:         'https://civilengsuite.pages.dev/earthquake-pro/',
  },
  {
    prefix: '/mur-pro',
    encFile: 'mur_pro.enc',
    baseHref: '/mur-pro/',
    pageFilename: 'mur-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
    ogTitle:       'Mur Pro — Ultimate Resistance Moment (ECP)',
    ogDescription: 'Ultimate Resistance Moment (Mur) calculator per Egyptian Code (ECP) for RC flat and ribbed slabs. By Eng. Aymn Asi.',
    ogImage:       '/images/og-image.png',
    ogUrl:         'https://civilengsuite.pages.dev/mur-pro/',
  },
  {
    prefix: '/add-reft-pro',
    encFile: 'add_reft_pro.enc',
    baseHref: '/add-reft-pro/',
    pageFilename: 'add-reft-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
    ogTitle:       'Add Reft Pro — Additional Reinforcement for Flat Slab Openings',
    ogDescription: 'Additional reinforcement design for flat slab openings and penetrations. By Eng. Aymn Asi. Part of Civil Engineering Suite.',
    ogImage:       '/images/og-image.png',
    ogUrl:         'https://civilengsuite.pages.dev/add-reft-pro/',
  },
  {
    prefix: '/section-property-pro',
    encFile: 'section_property_pro.enc',
    baseHref: '/section-property-pro/',
    pageFilename: 'section-property-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
    ogTitle:       'Section Property Pro — Cross-Section Properties Calculator',
    ogDescription: 'Cross-section properties: area, centroid, Ix/Iy, section modulus, radius of gyration. By Eng. Aymn Asi. Part of Civil Engineering Suite.',
    ogImage:       '/images/og-image.png',
    ogUrl:         'https://civilengsuite.pages.dev/section-property-pro/',
  },
];

// ── CSP common ────────────────────────────────────────────────────────────────
const CSP_COMMON = [
  "default-src 'self'",
  "object-src 'none'",
  "worker-src 'none'",
  "manifest-src 'none'",
  "media-src 'none'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self' https://civilengsuite.is-a.dev",
  "upgrade-insecure-requests",
  "report-uri /api/csp-report",
].join('; ');

// ── Shared security headers ───────────────────────────────────────────────────
const SHARED_SECURITY_HEADERS = {
  'X-Content-Type-Options':            'nosniff',
  'X-Frame-Options':                   'DENY',
  'Strict-Transport-Security':         'max-age=31536000; includeSubDomains; preload',
  'Referrer-Policy':                   'strict-origin-when-cross-origin',
  'Permissions-Policy':                'camera=(), microphone=(), geolocation=(), accelerometer=(), gyroscope=(), magnetometer=(), display-capture=(), screen-wake-lock=(), autoplay=(), clipboard-read=()',
  'Cross-Origin-Opener-Policy':        'same-origin',
  'X-DNS-Prefetch-Control':            'off',
  'X-Permitted-Cross-Domain-Policies': 'none',
};

// ── RFC 8288 Link header ──────────────────────────────────────────────────────
const HOMEPAGE_LINK_HEADER = [
  '</.well-known/api-catalog>; rel="api-catalog"',
  '</.well-known/agent-skills/index.json>; rel="https://agentskills.io/rel/skills-index"',
  '</.well-known/mcp/server-card.json>; rel="mcp-server-card"',
  '</.well-known/oauth-authorization-server>; rel="oauth-authorization-server"',
  '</.well-known/oauth-protected-resource>; rel="oauth-protected-resource"',
  '</.well-known/security.txt>; rel="security-policy"',
  '</sitemap.xml>; rel="sitemap"',
].join(', ');

// ── Homepage markdown ─────────────────────────────────────────────────────────
const HOMEPAGE_MARKDOWN = `# Civil Engineering Suite

> Professional-grade ACI 318-compliant structural and civil engineering software by **Eng. Aymn Asi** — Structural Engineer.
> Free. Offline. No installation required.

**URL:** https://civilengsuite.pages.dev/
**Contact:** aymneidasi@gmail.com
**License:** Proprietary (device-locked personal license)
**Standard:** ACI 318-19

---

## Applications

### \u2705 Live Now

#### [Footing Pro v.2026](https://civilengsuite.pages.dev/footing-pro/)
Combined footing design application — the most advanced free tool of its kind.

- **Modules:** 17 engineering calculation modules
- **Coverage:** Rectangular combined footing \xB7 Trapezoidal combined footing \xB7 Strap footing
- **Checks:** Soil pressure \xB7 Column load transfer \xB7 One-way shear \xB7 Punching shear \xB7 Flexural reinforcement \xB7 Development length \xB7 Load combinations
- **Platform:** Microsoft Excel on Windows (single-file, no installation)
- **Mode:** 100% offline after download
- **Languages:** English + Arabic (\u0639\u0631\u0628\u064A)
- **Price:** Free (personal license required)

#### [Section Property Pro](https://civilengsuite.pages.dev/section-property-pro/)
Cross-section properties calculator \u2014 area, centroid, Ix/Iy, section modulus, radius of gyration.

---

### \uD83D\uDD27 In Development \u2014 Coming 2026

| App | Description |
|---|---|
| [Beam Pro](https://civilengsuite.pages.dev/beam-pro/) | ACI 318 RC beam design \u2014 shallow beam bending |
| [Column Pro](https://civilengsuite.pages.dev/column-pro/) | RC column design \u2014 P-M interaction, biaxial bending, slenderness, punching shear (17 sub-modules) |
| [Deflection Pro](https://civilengsuite.pages.dev/deflection-pro/) | ACI 318 deflection checks for RC beams and slabs |
| [Earthquake Pro](https://civilengsuite.pages.dev/earthquake-pro/) | Seismic design \u2014 base shear, lateral load distribution, structural period |
| [Mur Pro](https://civilengsuite.pages.dev/mur-pro/) | Ultimate Resistance Moment (Mur) \u2014 Egyptian Code (ECP) |
| [Add Reft Pro](https://civilengsuite.pages.dev/add-reft-pro/) | Additional reinforcement for flat slab openings |

---

## Agent Discovery

- **API Catalog (RFC 9727):** https://civilengsuite.pages.dev/.well-known/api-catalog
- **Agent Skills Index:** https://civilengsuite.pages.dev/.well-known/agent-skills/index.json
- **MCP Server Card (SEP-1649):** https://civilengsuite.pages.dev/.well-known/mcp/server-card.json
- **OAuth Resource Metadata (RFC 9728):** https://civilengsuite.pages.dev/.well-known/oauth-protected-resource
- **Security Contact (RFC 9116):** https://civilengsuite.is-a.dev/.well-known/security.txt
- **Sitemap:** https://civilengsuite.pages.dev/sitemap.xml

---

## Keywords

combined footing design \xB7 foundation design software \xB7 ACI 318 \xB7 structural engineering software \xB7 free civil engineering tools \xB7 footing calculator \xB7 reinforced concrete design \xB7 offline engineering software \xB7 Excel structural design \xB7 \u062A\u0635\u0645\u064A\u0645 \u0627\u0644\u0642\u0648\u0627\u0639\u062F \xB7 \u0628\u0631\u0646\u0627\u0645\u062C \u062A\u0635\u0645\u064A\u0645 \u0627\u0644\u0623\u0633\u0627\u0633\u0627\u062A

---

*\xA9 2026 Civil Engineering Suite \u2014 Eng. Aymn Asi \u2014 All Rights Reserved.*
`;

// ── Utility helpers ───────────────────────────────────────────────────────────
function hexToU8(hex) {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < hex.length; i += 2) out[i >> 1] = parseInt(hex.slice(i, i + 2), 16);
  return out;
}
function b64ToU8(b64) {
  const bin = atob(b64); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function u8ToB64(bytes) {
  const CHUNK = 0x8000; let s = '';
  for (let i = 0; i < bytes.length; i += CHUNK)
    s += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + CHUNK, bytes.length)));
  return btoa(s);
}
function generateNonce() {
  return u8ToB64(crypto.getRandomValues(new Uint8Array(16)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
                  .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function injectNonces(html, nonce) {
  return html.replace(/<script(\b[^>]*?)>/gi, (match, attrs) => {
    if (/\bnonce\s*=/.test(attrs)) return match;
    return `<script${attrs} nonce="${nonce}">`;
  });
}

// ── AES-256-GCM decrypt ───────────────────────────────────────────────────────
async function decryptEnc(encData, keyHex) {
  const dot = encData.indexOf('.');
  if (dot === -1) throw new Error('Bad .enc format');
  const iv = b64ToU8(encData.slice(0, dot));
  const ct = b64ToU8(encData.slice(dot + 1));
  const key = await crypto.subtle.importKey('raw', hexToU8(keyHex), 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ct);
  return new TextDecoder().decode(pt);
}

// ── Error response helper ─────────────────────────────────────────────────────
function errResponse(status, title, message) {
  const nonce = generateNonce();
  return new Response(
    `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">`
    + `<style nonce="${nonce}">body{font-family:sans-serif;padding:40px;margin:0}</style>`
    + `<title>${escHtml(title)}</title></head><body>`
    + `<h2>${escHtml(title)}</h2><p>${escHtml(message)}</p></body></html>`,
    { status, headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': `default-src 'none'; style-src 'nonce-${nonce}'`,
      'Cache-Control': 'no-store',
      ...SHARED_SECURITY_HEADERS,
    }}
  );
}

// ── Client-side protection bundle (human browsers ONLY) ──────────────────────
function buildProtectionBundle(pageFilename) {
  const crHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Protected</title></head>`
    + `<body style="margin:0;background:#0A1A2E;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif">`
    + `<div style="text-align:center;padding:40px"><div style="font-size:3rem;margin-bottom:20px">&#x1F512;</div>`
    + `<h2 style="color:#C17B1A;margin-bottom:12px">&#169; Civil Engineering Suite</h2>`
    + `<p style="color:#8AA3C7;line-height:1.8">Eng. Aymn Asi &#8212; All Rights Reserved<br>Unauthorized copying or reproduction is strictly prohibited.</p>`
    + `</div></body></html>`;
  const crB64 = u8ToB64(new TextEncoder().encode(crHtml));
  return `(function(){'use strict';`
    + `var _ov=null,_do=false;`
    + `function _sov(){if(_ov)return;_ov=document.createElement('div');`
    + `_ov.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;background:#0A1A2E;z-index:2147483647;display:flex;align-items:center;justify-content:center;';`
    + `_ov.innerHTML='<div style="text-align:center;color:#C17B1A;font-family:sans-serif;padding:40px"><div style="font-size:4rem;margin-bottom:16px">&#x1F512;</div><h2>Developer Tools Detected</h2><p style="color:#8AA3C7;margin-top:12px">Please close DevTools to continue.</p></div>';`
    + `document.body.appendChild(_ov);}`
    + `function _hov(){if(_ov){document.body.removeChild(_ov);_ov=null;}}`
    + `function _ck(){var t=false;var d=new Date();debugger;if(new Date()-d>100)t=true;`
    + `if(window.outerWidth-window.innerWidth>160||window.outerHeight-window.innerHeight>160)t=true;`
    + `if(t&&!_do){_do=true;_sov();}else if(!t&&_do){_do=false;_hov();}}`
    + `_ck();setInterval(_ck,1500);`
    + `window.addEventListener('resize',_ck,true);`
    + `document.addEventListener('visibilitychange',function(){if(!document.hidden)_ck();},true);`
    + `document.addEventListener('contextmenu',function(e){e.preventDefault();e.stopPropagation();return false;},true);`
    + `document.addEventListener('keydown',function(e){`
    + `var c=e.keyCode||e.which,ctrl=e.ctrlKey||e.metaKey;`
    + `if(ctrl&&(c===85||c===83||c===65||c===80)){e.preventDefault();e.stopPropagation();return false;}`
    + `if(ctrl&&e.shiftKey&&(c===73||c===74||c===67||c===75)){e.preventDefault();e.stopPropagation();return false;}`
    + `if(c===123){e.preventDefault();e.stopPropagation();return false;}},true);`
    + `document.addEventListener('copy',function(e){`
    + `if(e.target&&(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA'||e.target.isContentEditable))return;`
    + `e.preventDefault();e.stopPropagation();`
    + `try{e.clipboardData.setData('text/plain','\\u00a9 Civil Engineering Suite \\u2014 Eng. Aymn Asi. All Rights Reserved.');}catch(ex){}`
    + `return false;},true);`
    + `document.addEventListener('cut',function(e){`
    + `if(e.target&&(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA'||e.target.isContentEditable))return;`
    + `e.preventDefault();e.stopPropagation();return false;},true);`
    + `document.addEventListener('selectstart',function(e){`
    + `if(e.target&&(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA'||e.target.isContentEditable))return;`
    + `e.preventDefault();return false;},true);`
    + `document.addEventListener('keydown',function(e){`
    + `if((e.ctrlKey||e.metaKey)&&(e.keyCode===83||e.which===83)){`
    + `e.preventDefault();e.stopPropagation();`
    + `try{var _eb='${crB64}';var _bn=atob(_eb);var _ba=new Uint8Array(_bn.length);`
    + `for(var i=0;i<_bn.length;i++)_ba[i]=_bn.charCodeAt(i);var _dc=new TextDecoder('utf-8').decode(_ba);`
    + `var _bl=new Blob([_dc],{type:'text/html'});var _ul=URL.createObjectURL(_bl);`
    + `var _al=document.createElement('a');_al.href=_ul;_al.download='${pageFilename}';_al.click();`
    + `setTimeout(function(){URL.revokeObjectURL(_ul);},1000);}catch(ex){}`
    + `return false;}},true);`
    + `try{console.clear();`
    + `console.log('%c\\u26d4 STOP','color:red;font-size:48px;font-weight:bold');`
    + `console.log('%cThis browser feature is intended for developers.\\nIf someone told you to paste something here, they may be trying to compromise this application.\\n\\n\\u00a9 Civil Engineering Suite \\u2014 Eng. Aymn Asi. All Rights Reserved.','color:#C17B1A;font-size:16px;font-weight:bold');}catch(ex){}`
    + `try{var _wm=document.getElementById('ces-watermark');if(_wm){var _ws=_wm.style.cssText;`
    + `var _mo=new MutationObserver(function(){if(!document.getElementById('ces-watermark'))document.body.appendChild(_wm);_wm.style.cssText=_ws;});`
    + `_mo.observe(document.body,{childList:true,subtree:false});_mo.observe(_wm,{attributes:true,attributeFilter:['style','class','hidden']});`
    + `setInterval(function(){var cs=window.getComputedStyle(_wm);`
    + `if(cs.opacity==='0'||cs.visibility==='hidden'||cs.display==='none')_wm.style.cssText=_ws;},2000);}}catch(ex){}`
    + `})();`;
}

// ── Strip protection scripts from bot HTML ────────────────────────────────────
function stripProtectionScripts(html) {
  function safeScriptRe(marker) {
    return new RegExp(
      '<script\\b[^>]*>(?:(?!<\\/script>)[\\s\\S])*?' + marker + '(?:(?!<\\/script>)[\\s\\S])*?<\\/script>',
      'gi'
    );
  }
  html = html.replace(safeScriptRe('CONTENT PROTECTION SYSTEM'), '');
  html = html.replace(safeScriptRe('\u00A9 Footing Pro v\\.2026 - Eng\\. Aymn Asi - All Rights Reserved'), '');
  html = html.replace(safeScriptRe('\u00A9 Footing Pro v\\.2026 - Eng\\. Aymn Asi - Protected'), '');
  html = html.replace(safeScriptRe('_CES_COPYRIGHT_HTML'), '');
  html = html.replace(safeScriptRe('FOOTING PRO v\\.2026 \u2014 ENGINE TRANSFER'), '');
  html = html.replace(/<body([^>]*)\soncontextmenu="[^"]*"/gi, '<body$1');
  return html;
}

// ── Minify inline <style> blocks ──────────────────────────────────────────────
function minifyBotCSS(html) {
  return html.replace(/<style([^>]*)>([\s\S]*?)<\/style>/gi, (match, attrs, css) => {
    const minified = css
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\s+/g, ' ')
      .replace(/\s*([{};,])\s*/g, '$1')
      .replace(/(\w)\s*:\s*/g, '$1:')
      .trim();
    return `<style${attrs}>${minified}</style>`;
  });
}

// ── WebMCP script for bot path ────────────────────────────────────────────────
function buildWebMCPScript() {
  return `<script>
(function(){
  if(!navigator.modelContext||typeof navigator.modelContext.provideContext!=='function')return;
  try{
    navigator.modelContext.provideContext({
      name:'civil-engineering-suite',
      description:'Civil Engineering Suite \u2014 Free ACI 318-19 structural engineering tools by Eng. Aymn Asi. Combined footing design, section properties, beam, column, deflection, seismic design.',
      tools:[
        {
          name:'open_footing_pro',
          description:'Open Footing Pro v.2026 \u2014 ACI 318-19 combined footing design. 17 modules: soil pressure, shear/moment diagrams, punching shear, flexural reinforcement, development length.',
          inputSchema:{type:'object',properties:{},required:[]},
          execute:function(){window.location.href='/footing-pro/';return{success:true,url:'/footing-pro/'};}
        },
        {
          name:'open_section_property_pro',
          description:'Open Section Property Pro \u2014 cross-section calculator. Computes area, centroid, Ix/Iy, section modulus, radius of gyration.',
          inputSchema:{type:'object',properties:{},required:[]},
          execute:function(){window.location.href='/section-property-pro/';return{success:true,url:'/section-property-pro/'};}
        },
        {
          name:'get_suite_info',
          description:'Returns structured metadata about all Civil Engineering Suite tools, their status, and agent discovery endpoints.',
          inputSchema:{type:'object',properties:{},required:[]},
          execute:function(){
            return{
              suite:'Civil Engineering Suite',
              author:'Eng. Aymn Asi',
              standard:'ACI 318-19',
              tools:[
                {name:'Footing Pro v.2026',url:'/footing-pro/',status:'live',modules:17},
                {name:'Section Property Pro',url:'/section-property-pro/',status:'live'},
                {name:'Beam Pro',url:'/beam-pro/',status:'coming-2026'},
                {name:'Column Pro',url:'/column-pro/',status:'coming-2026'},
                {name:'Deflection Pro',url:'/deflection-pro/',status:'coming-2026'},
                {name:'Earthquake Pro',url:'/earthquake-pro/',status:'coming-2026'},
                {name:'Mur Pro',url:'/mur-pro/',status:'coming-2026'},
                {name:'Add Reft Pro',url:'/add-reft-pro/',status:'coming-2026'}
              ],
              agentDiscovery:{
                apiCatalog:'/.well-known/api-catalog',
                mcpServerCard:'/.well-known/mcp/server-card.json',
                agentSkills:'/.well-known/agent-skills/index.json',
                oauthResource:'/.well-known/oauth-protected-resource'
              }
            };
          }
        }
      ]
    });
  }catch(e){}
})();
</script>`;
}

// ── Shared CSP script-src hashes (used in both bot and human path responses) ──
const CSP_SCRIPT_HASHES = [
  "'sha256-707X5+NAXR96e1UzENjwpPf416b6sJGW3mMwS4KSCqw='",
  "'sha256-9Z5YUtj2GDOBykVWUu8jxOyhx6HrrXGwO4FEHHSUtqQ='",
  "'unsafe-hashes'",
  "'sha256-nAiI7XK5Mt/SgNQUZPqTuikvwxIVHV3se6mHGQue+88='",
  "'sha256-Jag+ZHPii6iUmMQWlnwms/mnjM8gRPTOJA2KIyTQQRk='",
  "'sha256-uLUdJIdD3+8SpL4nHNFN9YmyHRRmrseSQKwzj3ECn2I='",
  "'sha256-akyHNuxwVvvLQ11iHoDrpca0qH3TU3LfGbtdQ8kNdwI='",
  "'sha256-UOhLo4NRrWG89b3vpgtU0dc/C8aWLS+MQ2Lf9vW/4Fk='",
  "'sha256-jHF5hTIlMDyGZRAsNK0HO/WFYrwPvI2I1q0o1xKKB6I='",
  "'sha256-wflfhEeJWTAjAK0hnm9/OICxAQ8fVnj3168JrJ/m91k='",
  "'sha256-oTzV9+pQ7IAxC4NoAc7dH4+0Is4KloZ9u7cMJC7UDrE='",
  "'sha256-bTpi/7w0Cd8ihAWpwcZJIdz49sMq0d73fWWDzp5Ju2Q='",
].join(' ');

// ── Build shared copyright page HTML ─────────────────────────────────────────
// Used by M2 guard (decoded HTML) and copyright bootstrap body.
// pageTitle: the page title string (already html-escaped at call site).
// canonicalPath: route prefix or '' for homepage.
// canonicalOrigin: 'https://civilengsuite.pages.dev' or request host.
function buildCopyrightHtml(pageTitle, canonicalPath, canonicalOrigin) {
  const url   = `${canonicalOrigin}${canonicalPath}/`;
  const label = `${canonicalOrigin.replace(/^https?:\/\//,'')}${canonicalPath}/`;
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<title>\u00A9 Protected \u2014 ${pageTitle}<\/title>`
    + `<style>*{box-sizing:border-box;margin:0;padding:0}`
    + `body{background:#0A1A2E;display:flex;align-items:center;justify-content:center;`
    + `min-height:100vh;font-family:sans-serif;text-align:center;padding:24px}`
    + `.card{max-width:440px}.icon{font-size:3.5rem;margin-bottom:18px}`
    + `.title{color:#C17B1A;font-size:1.35rem;font-weight:700;margin-bottom:12px;line-height:1.4}`
    + `.msg{color:#8AA3C7;font-size:0.9rem;line-height:1.8;margin-bottom:22px}`
    + `a{color:#C17B1A;font-size:0.88rem;text-decoration:none}`
    + `a:hover{text-decoration:underline}<\/style><\/head><body>`
    + `<div class="card"><div class="icon">&#x1F512;<\/div>`
    + `<div class="title">\u00A9 Civil Engineering Suite \u2014 Protected Content<\/div>`
    + `<div class="msg">Unauthorized copying is prohibited.<br>`
    + `This page must be accessed from the official website.<\/div>`
    + `<a href="${url}">${label}<\/a>`
    + `<\/div><\/body><\/html>`;
}

// ── Main request handler ──────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;
  const url  = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';

  // ── Static passthrough ────────────────────────────────────────────────────
  const STATIC_PASSTHROUGH = /^\/(?:robots\.txt|manifest\.json|favicon\.ico|og-image\.png|images\/.*|footing-pro\/images\/.*|footing-pro\/engineers\/?.*|footing-pro\/offices\/?.*|footing-pro\/students\/?.*|beam-pro\/images\/.*|column-pro\/images\/.*|deflection-pro\/images\/.*|earthquake-pro\/images\/.*|mur-pro\/images\/.*|add-reft-pro\/images\/.*|section-property-pro\/images\/.*|google[0-9a-f]+\.html|sitemap\.xsl|fonts\/.*|\.well-known\/.*|payment(?:\/.*)?|api\/payment\/.*)$/i;
  if (STATIC_PASSTHROUGH.test(path)) return context.next();

  // ── [S1] Sitemap ──────────────────────────────────────────────────────────
  if (path === '/sitemap.xml') {
    try {
      const sitemapResp = await env.ASSETS.fetch(new URL('/sitemap.xml', url.origin));
      if (!sitemapResp.ok) return new Response('Not Found', { status: 404 });
      const sitemapXml = await sitemapResp.text();
      return new Response(sitemapXml, {
        status: 200,
        headers: {
          'Content-Type':  'application/xml; charset=utf-8',
          'Cache-Control': 'public, max-age=3600, must-revalidate',
        },
      });
    } catch (e) {
      console.error('[ces:sitemap] ASSETS fetch error:', e.message);
      return new Response('Not Found', { status: 404 });
    }
  }

  // ── [D1] /download ────────────────────────────────────────────────────────
  if (path === '/download') {
    return new Response(null, {
      status: 302,
      headers: {
        'Location':      'https://drive.google.com/uc?export=download&id=1EQ6UaHvwrchiV0U5vRdXR5YktOZMnfrQ&confirm=t',
        'Cache-Control': 'no-store',
        ...SHARED_SECURITY_HEADERS,
      },
    });
  }

  // ── Route matching ────────────────────────────────────────────────────────
  const route = (path === '' || path === '/' || path === '/index.html')
    ? ROUTES[0]
    : ROUTES.slice(1).find(r => path === r.prefix);

  if (!route) return context.next();

  const { encFile, baseHref, faviconLinks, pageFilename } = route;

  // ── Markdown negotiation ──────────────────────────────────────────────────
  const acceptHeader = request.headers.get('Accept') || '';
  if (path === '/' && acceptHeader.includes('text/markdown')) {
    const tokenEstimate = String(Math.round(HOMEPAGE_MARKDOWN.split(/\s+/).length * 1.3));
    return new Response(HOMEPAGE_MARKDOWN, {
      status: 200,
      headers: {
        'Content-Type':      'text/markdown; charset=utf-8',
        'x-markdown-tokens': tokenEstimate,
        'Vary':              'Accept',
        'Cache-Control':     'public, max-age=3600, must-revalidate',
        'Link':              HOMEPAGE_LINK_HEADER,
        ...SHARED_SECURITY_HEADERS,
      },
    });
  }

  // ── Per-request nonce (shared across all paths below) ─────────────────────
  const cspNonce = generateNonce();

  // ── Runtime allowed-origins (v14 M3a) ────────────────────────────────────
  const _canonicalOrigin = `https://${url.host}`;
  const _extraOrigins = (env.ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim()).filter(s => s.length > 0 && /^https?:\/\//.test(s));
  const _allAllowedOrigins = [_canonicalOrigin, ...new Set(_extraOrigins)];
  const _allowedOriginsJs  = JSON.stringify(_allAllowedOrigins);

  // ── XOR key (needed by payload handler and copyright bootstrap loader) ────
  const xorHex = (env.CES_XOR_KEY || '').trim();
  const XOR_KEY = (xorHex.length === 2 && /^[0-9A-Fa-f]{2}$/.test(xorHex))
    ? parseInt(xorHex, 16) : 0x5A;

  // ── Shared CSS for response headers ──────────────────────────────────────
  const CSP_FULL = `${CSP_COMMON}; script-src 'nonce-${cspNonce}' ${CSP_SCRIPT_HASHES}`;

  // ═══════════════════════════════════════════════════════════════════════════
  // BOT PATH — decrypted HTML served to crawlers
  // [N4] Decryption now runs ONLY here (and in the payload handler below).
  // ═══════════════════════════════════════════════════════════════════════════
  const ua = request.headers.get('User-Agent') || '';
  if (BOT_RE.test(ua)) {
    const keyHex = (env.CES_DECRYPT_KEY || '').trim();
    if (!keyHex || keyHex.length !== 64)
      return errResponse(500, 'Config Error', 'CES_DECRYPT_KEY missing or invalid.');

    let encData;
    try {
      const encResp = await env.ASSETS.fetch(new URL(`/public/${encFile}`, url.origin));
      if (!encResp.ok) throw new Error(`HTTP ${encResp.status}`);
      encData = (await encResp.text()).trim();
    } catch (e) {
      console.error('[ces:bot] File read error:', encFile, e.message);
      return errResponse(500, 'Server Error', 'A configuration error occurred. Please try again later.');
    }

    let html;
    try {
      html = await decryptEnc(encData, keyHex);
    } catch (e) {
      console.error('[ces:bot] Decryption failed for', encFile, '—', e.message);
      return errResponse(500, 'Server Error', 'A configuration error occurred. Please try again later.');
    }

    try {
      html = html.replace(/(<head[^>]*>)/i, `$1<base href="${baseHref}">`);
      if (faviconLinks && !/<link[^>]+rel=["'](?:icon|shortcut icon|apple-touch-icon)["']/i.test(html)) {
        html = html.replace(/(<\/head>)/i, `${faviconLinks}$1`);
      }

      const host = url.host;
      let botHtml = html;

      botHtml = botHtml.replace(
        /<meta\s+name="robots"\s+content="noindex[^"]*"/gi,
        '<meta name="robots" content="index, follow"'
      );
      botHtml = botHtml.replace(
        /(<meta\s+(?:property|name)="(?:og:image|og:image:secure_url|twitter:image)"\s+content=")https:\/\/[^/]+(\/[^"]*")/gi,
        `$1https://${host}$2`
      );
      botHtml = botHtml.replace(
        /(https?:\/\/[^"']+)\/footing-pro\/og-image\.png/gi,
        '$1/footing-pro/images/og-image.png'
      );
      botHtml = botHtml.replace(
        /(content="https?:\/\/[^"]+\/)og-image\.png"/gi,
        (match, prefix) => {
          if (/\/images\//.test(prefix)) return match;
          return `${prefix}images/og-image.png"`;
        }
      );
      if (!/<meta[^>]+property="og:image:secure_url"/i.test(botHtml)) {
        botHtml = botHtml.replace(
          /(<meta[^>]+property="og:image"[^>]*\/?>)/i,
          (m) => {
            const urlMatch = m.match(/content="([^"]+)"/i);
            if (!urlMatch) return m;
            const imgUrl = urlMatch[1];
            return m
              + `<meta property="og:image:secure_url" content="${imgUrl}">`
              + `<meta property="og:image:type" content="image/png">`
              + `<meta property="og:image:width" content="1200">`
              + `<meta property="og:image:height" content="630">`;
          }
        );
      }
      botHtml = botHtml.replace(
        /(<noscript>)\s*<style>[^<]*?body\s*\{[^}]*?display\s*:\s*none[^}]*?\}[^<]*?<\/style>/gi,
        '$1'
      );
      botHtml = stripProtectionScripts(botHtml);
      botHtml = minifyBotCSS(botHtml);
      botHtml = injectNonces(botHtml, cspNonce);
      botHtml = botHtml.replace(/<\/body>/i,
        injectNonces(buildWebMCPScript(), cspNonce) + '</body>');

      return new Response(botHtml, { status: 200, headers: {
        'Content-Type':            'text/html; charset=utf-8',
        'Cache-Control':           'private, max-age=3600, must-revalidate',
        'Vary':                    route.prefix === '/' ? 'User-Agent, Accept' : 'User-Agent',
        'X-Robots-Tag':            'index, follow',
        'Content-Security-Policy': CSP_FULL,
        'Link':                    HOMEPAGE_LINK_HEADER,
        ...SHARED_SECURITY_HEADERS,
      }});

    } catch (e) {
      console.error('[ces:bot] Runtime exception:', e && e.message, e && e.stack);
      return errResponse(500, 'Server Error', 'An internal error occurred. Please refresh or try again.');
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // [N2] PAYLOAD FETCH — Same-origin programmatic XHR from bootstrap loader JS.
  //
  // THREE INDEPENDENT GUARDS (all must pass):
  //   (a) X-CES-Context: payload   — our custom marker (unknown to external callers)
  //   (b) Sec-Fetch-Dest: empty    — only XHR/fetch() sets this; native Download = 'document'
  //   (c) Sec-Fetch-Site: same-origin — request originates from civilengsuite.pages.dev
  //
  // Sec-Fetch-* are "forbidden request headers" — JS cannot override them.
  // Chrome Android's Download button: Sec-Fetch-Dest=document → guard (b) fails → copyright.
  // file:// opened bootstrap JS trying XHR: Sec-Fetch-Site=cross-site → guard (c) fails.
  // CORS also blocks the response at the browser level for cross-origin XHR independently.
  // ═══════════════════════════════════════════════════════════════════════════
  const isPayloadFetch =
    request.headers.get('X-CES-Context')  === 'payload'      // (a)
    && request.headers.get('Sec-Fetch-Dest')  === 'empty'     // (b)
    && request.headers.get('Sec-Fetch-Site')  === 'same-origin'; // (c)

  if (isPayloadFetch) {
    const keyHex = (env.CES_DECRYPT_KEY || '').trim();
    if (!keyHex || keyHex.length !== 64) {
      return new Response('{"error":"config"}', { status: 500, headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        ...SHARED_SECURITY_HEADERS,
      }});
    }

    let encData;
    try {
      const encResp = await env.ASSETS.fetch(new URL(`/public/${encFile}`, url.origin));
      if (!encResp.ok) throw new Error(`HTTP ${encResp.status}`);
      encData = (await encResp.text()).trim();
    } catch (e) {
      console.error('[ces:payload] File read error:', encFile, e.message);
      return new Response('{"error":"file"}', { status: 500, headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        ...SHARED_SECURITY_HEADERS,
      }});
    }

    let html;
    try {
      html = await decryptEnc(encData, keyHex);
    } catch (e) {
      console.error('[ces:payload] Decryption failed for', encFile, '—', e.message);
      return new Response('{"error":"decrypt"}', { status: 500, headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        ...SHARED_SECURITY_HEADERS,
      }});
    }

    try {
      // Inject base href and favicons
      html = html.replace(/(<head[^>]*>)/i, `$1<base href="${baseHref}">`);
      if (faviconLinks && !/<link[^>]+rel=["'](?:icon|shortcut icon|apple-touch-icon)["']/i.test(html)) {
        html = html.replace(/(<\/head>)/i, `${faviconLinks}$1`);
      }

      // [N3] Client-nonce echo: bootstrap JS sends its own CSP nonce in X-CES-Nonce.
      // We stamp decoded HTML scripts with this echoed nonce so they match the
      // bootstrap response's CSP header (script-src 'nonce-{cspNonce}').
      // Regex validates nonce format: URL-safe base64, 16–64 chars.
      const clientNonce = request.headers.get('X-CES-Nonce') || '';
      const payloadNonce = /^[A-Za-z0-9_\-]{16,64}$/.test(clientNonce) ? clientNonce : cspNonce;

      // Inject protection bundle (Ctrl+S intercept, DevTools, copy/cut/paste)
      const bundle = `<script nonce="${payloadNonce}">${buildProtectionBundle(pageFilename)}</script>`;
      html = html.replace(/<\/body>/i, bundle + '</body>');

      // Minify (HTML comments + inter-tag whitespace)
      html = html
        .replace(/<!--[\s\S]*?-->/g, '')
        .replace(/>\s+</g, '><')
        .replace(/\s{2,}/g, ' ')
        .trim();

      // [M2] Decoded-HTML origin guard (Scenario B: Chrome saves rendered DOM)
      // Injected right after <meta charset="UTF-8">, before injectNonces.
      // Protects the decoded HTML if it is ever saved to disk and opened as file://.
      const _sharedCrRP    = route.prefix === '/' ? '' : route.prefix;
      const _sharedCrTM    = html.match(/<title>([^<]*)<\/title>/i);
      const _sharedCrPT    = escHtml(_sharedCrTM ? _sharedCrTM[1] : (route.ogTitle || 'Civil Engineering Suite'));
      const _sharedCrHtml  = buildCopyrightHtml(_sharedCrPT, _sharedCrRP, _canonicalOrigin);
      const _sharedCrB64   = u8ToB64(new TextEncoder().encode(_sharedCrHtml));

      const _m2Code =
          `(function(){'use strict';`
        + `var _aos=${_allowedOriginsJs};`
        + `var _o=(typeof window!=='undefined')?window.location.origin:'';`
        + `var _dev=/^https?:\\/\\/(localhost|127\\.0\\.0\\.1)(:\\d+)?$/.test(_o);`
        + `if(_aos.indexOf(_o)===-1&&!_dev){`
        + `var _b='${_sharedCrB64}';`
        + `var _n=atob(_b);var _ba=new Uint8Array(_n.length);`
        + `for(var i=0;i<_n.length;i++)_ba[i]=_n.charCodeAt(i);`
        + `var _cr=new TextDecoder('utf-8').decode(_ba);`
        + `try{document.open();document.write(_cr);document.close();}`
        + `catch(e){window.location.replace(_aos[0]+'${_sharedCrRP}/');}`
        + `}`
        + `})();`;
      html = html.replace(/(<meta charset="UTF-8">)/i, `$1<script>${_m2Code}<\/script>`);

      // Stamp nonces + minify CSS
      html = injectNonces(html, payloadNonce);
      html = minifyBotCSS(html);

      // XOR + base64 encode
      const raw   = new TextEncoder().encode(html);
      const xored = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) xored[i] = raw[i] ^ XOR_KEY;
      const payload = u8ToB64(xored);

      // Return JSON payload. XOR key is intentionally NOT in the response —
      // it is embedded in the bootstrap loader script (_xk variable) so it
      // stays in the bootstrap HTML that the user already has.
      return new Response(JSON.stringify({ p: payload }), { status: 200, headers: {
        'Content-Type':   'application/json; charset=utf-8',
        'Cache-Control':  'no-store',
        'Vary':           'X-CES-Context, Sec-Fetch-Dest',
        ...SHARED_SECURITY_HEADERS,
      }});

    } catch (e) {
      console.error('[ces:payload] Processing error:', e && e.message, e && e.stack);
      return new Response('{"error":"processing"}', { status: 500, headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        ...SHARED_SECURITY_HEADERS,
      }});
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // [N1] COPYRIGHT BOOTSTRAP — Default response for ALL human browsers.
  //
  // WHAT CHANGED FROM v13/v14:
  //   Before: Bootstrap = copyright guard + XOR payload blob (~333 KB).
  //           Downloaded file contained the full decoded HTML as XOR+base64.
  //           M1a/M1c guards were supposed to block file:// opens but
  //           Chrome Android's document.open() parser-abort behaviour in
  //           file:// context was unreliable — real page rendered on open.
  //
  //   Now:    Bootstrap = copyright page HTML only (~2 KB, no payload).
  //           Downloaded file IS the copyright page. Nothing to decode.
  //           JS origin check → if authorized, XHR fetches payload (above).
  //           If unauthorized (file:// or different domain): copyright stays.
  //           CORS independently blocks any XHR from file:// to https://.
  //
  // RESULT: Downloaded file opened = copyright page, always, unconditionally.
  // Text editor opened = copyright HTML source text, no engineering content.
  // ═══════════════════════════════════════════════════════════════════════════
  try {

    const _sharedCrRP    = route.prefix === '/' ? '' : route.prefix;
    const _crUrl         = `${_canonicalOrigin}${_sharedCrRP}/`;
    const _crLabel       = `${url.host}${_sharedCrRP}/`;
    const pageTitle      = route.ogTitle || 'Civil Engineering Suite';

    // OG meta block (social previews: iMessage, WhatsApp bootstrap shell)
    const ogImageAbsolute = `https://${url.host}${route.ogImage}`;
    const ogMetaBlock = route.ogTitle ? [
      `<meta property="og:type" content="website">`,
      `<meta property="og:site_name" content="Civil Engineering Suite">`,
      `<meta property="og:title" content="${escHtml(route.ogTitle)}">`,
      `<meta property="og:description" content="${escHtml(route.ogDescription)}">`,
      `<meta property="og:url" content="${escHtml(route.ogUrl)}">`,
      `<meta property="og:image" content="${escHtml(ogImageAbsolute)}">`,
      `<meta property="og:image:secure_url" content="${escHtml(ogImageAbsolute)}">`,
      `<meta property="og:image:type" content="image/png">`,
      `<meta property="og:image:width" content="1200">`,
      `<meta property="og:image:height" content="630">`,
      `<meta property="og:image:alt" content="${escHtml(route.ogTitle)}">`,
      `<meta name="twitter:card" content="summary_large_image">`,
      `<meta name="twitter:title" content="${escHtml(route.ogTitle)}">`,
      `<meta name="twitter:description" content="${escHtml(route.ogDescription)}">`,
      `<meta name="twitter:image" content="${escHtml(ogImageAbsolute)}">`,
    ].join('') : '';

    // [PERF] Route-specific LCP preload (footing-pro hero image)
    const lcpPreload = route.prefix === '/footing-pro'
      ? '<link rel="preload" as="image" href="/footing-pro/images/hero-bg.avif"'
        + ' imagesrcset="/footing-pro/images/hero-bg.avif 1x,/footing-pro/images/hero-bg.webp 1x"'
        + ' imagesizes="100vw" fetchpriority="high">'
      : '';

    // [A6] WebMCP: fires for any JS-executing client before content loads.
    // Feature-detect guard makes it a no-op in browsers without modelContext.
    const webMCPBootstrap = `<script nonce="${cspNonce}">`
      + `(function(){`
      + `if(!navigator.modelContext||typeof navigator.modelContext.provideContext!=='function')return;`
      + `try{navigator.modelContext.provideContext({`
      + `name:'civil-engineering-suite',`
      + `description:'Civil Engineering Suite \u2014 Free ACI 318-19 structural engineering tools by Eng. Aymn Asi.',`
      + `tools:[`
      + `{name:'open_footing_pro',description:'Footing Pro v.2026 \u2014 ACI 318-19 combined footing design, 17 modules.',`
      + `inputSchema:{type:'object',properties:{},required:[]},`
      + `execute:function(){window.location.href='/footing-pro/';return{success:true,url:'/footing-pro/'};}},`
      + `{name:'open_section_property_pro',description:'Section Property Pro \u2014 area, centroid, Ix/Iy, section modulus, radius of gyration.',`
      + `inputSchema:{type:'object',properties:{},required:[]},`
      + `execute:function(){window.location.href='/section-property-pro/';return{success:true,url:'/section-property-pro/'};}},`
      + `{name:'get_suite_info',description:'Returns metadata about all Civil Engineering Suite tools and agent discovery endpoints.',`
      + `inputSchema:{type:'object',properties:{},required:[]},`
      + `execute:function(){return{`
      + `suite:'Civil Engineering Suite',author:'Eng. Aymn Asi',standard:'ACI 318-19',`
      + `tools:[`
      + `{name:'Footing Pro v.2026',url:'/footing-pro/',status:'live',modules:17},`
      + `{name:'Section Property Pro',url:'/section-property-pro/',status:'live'},`
      + `{name:'Beam Pro',url:'/beam-pro/',status:'coming-2026'},`
      + `{name:'Column Pro',url:'/column-pro/',status:'coming-2026'},`
      + `{name:'Deflection Pro',url:'/deflection-pro/',status:'coming-2026'},`
      + `{name:'Earthquake Pro',url:'/earthquake-pro/',status:'coming-2026'},`
      + `{name:'Mur Pro',url:'/mur-pro/',status:'coming-2026'},`
      + `{name:'Add Reft Pro',url:'/add-reft-pro/',status:'coming-2026'}`
      + `],`
      + `agentDiscovery:{`
      + `apiCatalog:'/.well-known/api-catalog',`
      + `mcpServerCard:'/.well-known/mcp/server-card.json',`
      + `agentSkills:'/.well-known/agent-skills/index.json',`
      + `oauthServer:'/.well-known/oauth-authorization-server',`
      + `oauthResource:'/.well-known/oauth-protected-resource'`
      + `}};}}]});}catch(e){}})();`
      + `\u003c/script>`;

    // [N1] Copyright bootstrap loader:
    // 1. Checks window.location.origin against allowed origins.
    // 2. Unauthorized (file://, etc.): exits immediately — copyright stays visible.
    // 3. Authorized: shows loading indicator, fires XHR with three custom markers.
    // 4. XHR success: XOR-decode payload → document.open()/write()/close() → real page.
    // 5. XHR error (CORS block, network failure): loading indicator shows error message.
    //
    // _xk (XOR key) is embedded here in the bootstrap JS, NOT in the JSON payload.
    // This keeps the same security posture as v13/v14 — key visible to anyone who
    // reads the bootstrap source, same as before.
    const bootstrapLoaderScript =
      `<script nonce="${cspNonce}">`
      + `(function(){'use strict';`
      // Origin check — same three-guard logic as M1a/M1c in prior versions
      + `var _aos=${_allowedOriginsJs};`
      + `var _o=window.location.origin;`
      + `var _dev=/^https?:\\/\\/(localhost|127\\.0\\.0\\.1)(:\\d+)?$/.test(_o);`
      // Unauthorized: copyright stays, JS exits — nothing further happens
      + `if(_aos.indexOf(_o)===-1&&!_dev)return;`
      // Authorized: reveal loading indicator
      + `var _ld=document.getElementById('_ces_ld');if(_ld)_ld.style.display='block';`
      + `var _cr=document.getElementById('_ces_cr');if(_cr)_cr.style.display='none';`
      // Nonce to echo back so decoded HTML scripts match this response's CSP
      + `var _pn='${cspNonce}';`
      // XOR key for decoding the payload
      + `var _xk=${XOR_KEY};`
      // Payload fetch — same-origin XHR with three custom headers
      + `var _x=new XMLHttpRequest();`
      + `_x.open('GET',window.location.href,true);`
      + `_x.setRequestHeader('X-CES-Context','payload');`     // marker (a)
      + `_x.setRequestHeader('X-CES-Nonce',_pn);`            // nonce echo [N3]
      // Sec-Fetch-* are set by the browser automatically — we cannot set them,
      // but the XHR context guarantees Sec-Fetch-Dest=empty, Sec-Fetch-Site=same-origin
      + `_x.responseType='text';`
      + `_x.timeout=30000;`
      + `_x.onload=function(){`
      + `if(_x.status!==200){`
      + `if(_ld)_ld.textContent='Error loading content. Please refresh.';`
      + `if(_cr)_cr.style.display='block';`
      + `return;}`
      + `try{`
      + `var _d=JSON.parse(_x.responseText);`
      + `var _b=atob(_d.p);`
      + `var _u=new Uint8Array(_b.length);`
      + `for(var i=0;i<_b.length;i++)_u[i]=_b.charCodeAt(i)^_xk;`
      + `var _h=new TextDecoder('utf-8').decode(_u);`
      + `document.open();document.write(_h);document.close();`
      + `}catch(_e){`
      + `if(_ld)_ld.textContent='Error loading content. Please refresh.';`
      + `if(_cr)_cr.style.display='block';`
      + `}};`
      + `_x.onerror=_x.ontimeout=function(){`
      + `if(_ld)_ld.textContent='Error loading content. Please refresh.';`
      + `if(_cr)_cr.style.display='block';`
      + `};`
      + `_x.send();`
      + `})();`
      + `\u003c/script>`;

    // Copyright body: visible by default (no JS required), hidden when loading
    // _ces_cr: copyright card — hidden when authorized JS fetch starts
    // _ces_ld: loading/error indicator — shown when authorized JS fetch starts
    const copyrightBody =
      `<style>`
      + `*{box-sizing:border-box;margin:0;padding:0}`
      + `body{background:#0A1A2E;display:flex;align-items:center;justify-content:center;`
      + `min-height:100vh;font-family:sans-serif;text-align:center;padding:24px}`
      + `.ces-card{max-width:440px}`
      + `.ces-icon{font-size:3.5rem;margin-bottom:18px}`
      + `.ces-title{color:#C17B1A;font-size:1.35rem;font-weight:700;margin-bottom:12px;line-height:1.4}`
      + `.ces-msg{color:#8AA3C7;font-size:0.9rem;line-height:1.8;margin-bottom:22px}`
      + `.ces-link{color:#C17B1A;font-size:0.88rem;text-decoration:none;display:block;margin-top:8px}`
      + `.ces-link:hover{text-decoration:underline}`
      + `.ces-loading{color:#8AA3C7;font-size:0.85rem;margin-top:16px;display:none}`
      + `<\/style>`
      + `<noscript><style>body{display:flex!important}<\/style><\/noscript>`
      + `<div class="ces-card" id="_ces_cr">`
      + `<div class="ces-icon">&#x1F512;<\/div>`
      + `<div class="ces-title">&#169; Civil Engineering Suite<\/div>`
      + `<div class="ces-msg">Protected Content.<br>Unauthorized copying is prohibited.<\/div>`
      + `<a class="ces-link" href="${escHtml(_crUrl)}">${escHtml(_crLabel)}<\/a>`
      + `<\/div>`
      + `<div class="ces-loading" id="_ces_ld">Loading\u2026<\/div>`;

    const bootstrap =
      `<!DOCTYPE html><html><head>`
      + `<meta charset="UTF-8">`
      + `<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0">`
      + (route.ogDescription ? `<meta name="description" content="${escHtml(route.ogDescription)}">` : '')
      + lcpPreload
      + `<link rel="preload" href="/fonts/inter-400.woff2" as="font" type="font/woff2" crossorigin>`
      + `<link rel="preload" href="/fonts/inter-700.woff2" as="font" type="font/woff2" crossorigin>`
      + `<link rel="preload" href="/fonts/playfair-700.woff2" as="font" type="font/woff2" crossorigin>`
      + `<link rel="preload" href="/fonts/cairo-700.woff2" as="font" type="font/woff2" crossorigin>`
      + `<link rel="preload" href="/fonts/cairo-400.woff2" as="font" type="font/woff2" crossorigin>`
      + `<link rel="preload" href="/fonts/inter-500.woff2" as="font" type="font/woff2" crossorigin>`
      + `<link rel="preload" href="/fonts/inter-600.woff2" as="font" type="font/woff2" crossorigin>`
      + `<link rel="preload" href="/fonts/playfair-400.woff2" as="font" type="font/woff2" crossorigin>`
      + `<link rel="preload" href="/fonts/playfair-900.woff2" as="font" type="font/woff2" crossorigin>`
      + `<link rel="preload" href="/fonts/jetbrains-mono-400.woff2" as="font" type="font/woff2" crossorigin>`
      + `<link rel="preload" href="/fonts/jetbrains-mono-600.woff2" as="font" type="font/woff2" crossorigin>`
      + `<title>${escHtml(pageTitle)}</title>`
      + ogMetaBlock
      + faviconLinks
      + `</head><body>`
      + copyrightBody
      + webMCPBootstrap
      + bootstrapLoaderScript
      + `</body></html>`;

    return new Response(bootstrap, { status: 200, headers: {
      'Content-Type':            'text/html; charset=utf-8',
      'Cache-Control':           'no-store',
      'Content-Security-Policy': CSP_FULL,
      // [A1] RFC 8288 Link header on homepage
      ...(route.prefix === '/' ? {
        'Link': HOMEPAGE_LINK_HEADER,
        'Vary': 'Accept',
      } : {}),
      ...SHARED_SECURITY_HEADERS,
    }});

  } catch (e) {
    console.error('[ces:runtime] Uncaught exception:', e && e.message, e && e.stack);
    return errResponse(500, 'Server Error', 'An internal error occurred. Please refresh or try again.');
  }
}
