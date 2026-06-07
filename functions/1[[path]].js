/**
 * Civil Engineering Suite — Cloudflare Pages Function
 * ─────────────────────────────────────────────────────────────────────────────
 * Handles only exact encrypted page routes: /, /footing-pro, /beam-pro, etc.
 * Sub‑app images (e.g., /footing-pro/images/…) are NOT caught and will be
 * served as static files via _redirects.
 *
 * Environment variables:
 *   CES_DECRYPT_KEY — 64-character hex AES-256-GCM key (required)
 *
 * KV Bindings:
 *   CES_SESSIONS    — KV namespace for one-time session payloads (required for human path)
 *                     Bind in Cloudflare Pages → Settings → Functions → KV Namespace Bindings
 *                     Variable name: CES_SESSIONS
 *
 * ─── CHANGE LOG ──────────────────────────────────────────────────────────────
 * 2026-06-07 v14 — Session-based protection: eliminate XOR payload from bootstrap (S1–S4):
 *
 *   ROOT CAUSE (why v13 M1a/M2 was insufficient):
 *     v13 embedded the XOR-encoded full HTML payload inside the bootstrap as a
 *     base64 string. Even with M1a (file:// guard) blocking JS execution, the
 *     raw base64 XOR blob resided in the saved .html file. A technically capable
 *     user could extract the base64 string, XOR-decode it (key=0x5A), and recover
 *     the full HTML — no browser required. Additionally, on specific Android Chrome
 *     versions / WebViews, the "Save page" function can serialize the rendered
 *     DOM (post document.write state) rather than the HTTP response, producing a
 *     saved file that IS the real decoded HTML with only M2 as protection.
 *     M2 relies on window.location.origin === 'null' for file:// detection, which
 *     some embedded Android WebViews do not report consistently.
 *
 *   [S1] XOR obfuscation removed — CES_XOR_KEY environment variable no longer
 *        read or used. The .enc file is still AES-256-GCM encrypted; decryption
 *        continues server-side using CES_DECRYPT_KEY. XOR was a second layer of
 *        obfuscation applied after decryption; it is no longer needed because the
 *        decrypted HTML never leaves the server as a client-side payload.
 *
 *   [S2] KV session store — CES_SESSIONS KV namespace introduced.
 *        After decryption and full HTML processing (bundle injection, minify,
 *        M2 guard, nonce stamping, CSS minify), the ready-to-serve HTML is stored
 *        in KV under key `session:${token}` with expirationTtl = 60 seconds.
 *        The token is a cryptographically random 64-hex-char string (32 bytes).
 *        The KV entry is DELETED immediately after the first successful retrieval
 *        (one-time use). Expired entries are purged automatically by KV TTL.
 *
 *   [S3] New route /api/session?token=... — single-use HTML payload endpoint.
 *        Returns the full processed HTML for the given token, then deletes the
 *        KV entry. Returns 403 if token is absent, malformed, or already consumed.
 *        Returns 500 if CES_SESSIONS binding is missing. Method: GET only (405
 *        on all other methods). Token validated against /^[0-9a-f]{64}$/ before
 *        any KV access. X-Robots-Tag: noindex to prevent search engine indexing.
 *
 *   [S4] Bootstrap shell redesigned — contains ONLY:
 *        · M1a origin guard (same as v13, parser-blocking in <head>)
 *        · M1b copyright body (same as v13, noscript fallback)
 *        · WebMCP registration (same as v13)
 *        · Fetch script: calls /api/session?token=TOKEN with 9-second AbortController
 *          timeout. On success: document.write(html). On any failure (network error,
 *          403, timeout): shows copyright page from base64-encoded fallback.
 *        The bootstrap contains ZERO recoverable application content. A saved copy
 *        opened offline fails the fetch → copyright. Opened online after 60 seconds
 *        → token expired → 403 → copyright. No XOR blob to extract.
 *
 *   M2 guard (decoded-HTML origin guard) preserved and still injected into the
 *   KV-stored HTML as an extra defense layer: if Chrome Android saves the rendered
 *   DOM (post document.write) and that file is opened as file://, M2 fires and shows
 *   copyright. This is defense-in-depth on top of the primary session mechanism.
 *
 *   buildProtectionBundle() preserved unchanged — injected into the HTML before
 *   KV storage so the real page (delivered via /api/session) retains all
 *   client-side protections (DevTools detection, Ctrl+S copyright save, etc.).
 *
 * 2026-06-07 v13 — Mobile download protection: bootstrap hardening + decoded-HTML guard (M1–M2):
 *   [M1a] bootstrapOriginGuard — synchronous parser-blocking <script> in bootstrap <head>.
 *   [M1b] bootstrapCopyrightBody — first <body> child; noscript copyright fallback.
 *   [M2]  htmlOriginGuard — origin guard injected into decoded HTML payload (Scenario B).
 *
 * 2026-06-03 v11 — /download redirect (D1).
 * 2026-06-03 v10 — Inline handler CSP fix + landing page 404 fix (H1–H2).
 * 2026-04-28 v9  — PSI font + LCP + CSP fixes (F1–F3).
 * 2026-04-25 v8  — Bot-path OG tag injection + favicon guard (V2-BOT, V4-FAV).
 * 2026-04-25 v7  — Sitemap + OG image fixes (V1–V3).
 * 2026-04-23 v6  — Agent-readiness infrastructure (A1–A7).
 * 2026-04-17 v5  — Payment gateway integration (P1–P3).
 * 2026-04-15 v4  — Critical bug fixes (X1–X2).
 * 2026-04-14 v3  — Bot path optimization (B1–B7).
 * 2026-04-14 v2  — SEO infrastructure fixes (F1–F6).
 */

// ── Bot / crawler UA pattern ──────────────────────────────────────────────────
// [F1] ADDED: googlebot-image, adsbot-google, perplexitybot, ia_archiver
const BOT_RE = /googlebot|googlebot-image|google-inspectiontool|googleother|adsbot-google|bingbot|yandexbot|duckduckbot|baiduspider|applebot|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|slackbot|discordbot|perplexitybot|ia_archiver/i;

// ── Route table — only the app root paths (no sub‑paths like /footing-pro/images) ──
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
// [P2] form-action: added site origin explicitly to support payment initiation
//      fetch() calls from encrypted app pages.
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

// [F6] Shared security headers applied to EVERY response this function emits.
// NOTE: _headers does NOT apply to Cloudflare Pages Function responses.
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

// [A1] RFC 8288 Link response header — agent discovery.
const HOMEPAGE_LINK_HEADER = [
  '</.well-known/api-catalog>; rel="api-catalog"',
  '</.well-known/agent-skills/index.json>; rel="https://agentskills.io/rel/skills-index"',
  '</.well-known/mcp/server-card.json>; rel="mcp-server-card"',
  '</.well-known/oauth-authorization-server>; rel="oauth-authorization-server"',
  '</.well-known/oauth-protected-resource>; rel="oauth-protected-resource"',
  '</.well-known/security.txt>; rel="security-policy"',
  '</sitemap.xml>; rel="sitemap"',
].join(', ');

// [A2] Static curated markdown for the homepage.
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

// ── [S2] Session TTL — seconds a KV session entry lives before auto-expiry ───
// One-time use: the entry is also DELETED immediately after first retrieval.
// 60 seconds is generous for a normal page load (fetch runs in <1 second).
const SESSION_TTL = 60;

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

// ── [S2] Cryptographically random 64-hex-char session token (32 bytes) ───────
function generateToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── AES-256-GCM decrypt using Web Crypto ─────────────────────────────────────
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

// ── Client-side protection bundle (injected for human browsers ONLY) ──────────
// [SECURITY] This bundle is NEVER sent to crawlers. The BOT_RE branch returns
// before this function is ever called in the bot path.
// In v14: injected into the HTML BEFORE KV storage, so the real page delivered
// via /api/session retains all client-side protections.
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
// [B1–B5] Removes only the protection IIFEs. Every pattern is anchored to a
// unique comment string that appears ONLY inside the protection scripts and
// NEVER in JSON-LD, translation, or navigation code.
//
// [X1] CRITICAL FIX: All patterns use (?:(?!<\/script>)[\s\S])*? instead of
// [\s\S]*?. The lazy [\s\S]*? crosses </script> boundaries — it starts from the
// FIRST <script> before the marker (which could be a JSON-LD block many lines
// earlier) and consumes through that block's </script> to find the marker in the
// NEXT script block. This silently deletes all preceding JSON-LD structured data.
// The negative lookahead (?!<\/script>) prevents the quantifier from ever
// consuming a </script> sequence, confining each match to a single script block.
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
// [B6] Used for both bot path and human path (before KV storage).
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

// [A3] WebMCP script — exposes CES tools to AI agents via navigator.modelContext.
// Injected into bot path HTML (before </body>) and into the human bootstrap shell.
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

// ── [S3] Session payload handler ──────────────────────────────────────────────
// Serves the one-time HTML payload from KV. Called only for GET /api/session.
// Token must be a 64-hex-char string (32 random bytes). Entry is deleted
// immediately after retrieval (one-time use). TTL provides automatic cleanup
// of any entry the client never fetches (e.g., bot scrapes the bootstrap URL).
async function handleSession(request, env) {
  // Method guard — only GET is valid for this endpoint
  if (request.method !== 'GET') {
    return new Response('Method Not Allowed', {
      status: 405,
      headers: { 'Allow': 'GET', 'Cache-Control': 'no-store', ...SHARED_SECURITY_HEADERS },
    });
  }

  // KV binding guard — should always be present in production
  if (!env.CES_SESSIONS) {
    console.error('[ces:session] CES_SESSIONS KV binding is not configured.');
    return errResponse(500, 'Server Error', 'Session store not configured.');
  }

  const url = new URL(request.url);
  const token = (url.searchParams.get('token') || '').trim();

  // Token format validation — 64 lowercase hex chars (32 bytes)
  if (!token || !/^[0-9a-f]{64}$/.test(token)) {
    return new Response('Bad Request', {
      status: 400,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', ...SHARED_SECURITY_HEADERS },
    });
  }

  const kvKey = `session:${token}`;
  let payload;
  try {
    payload = await env.CES_SESSIONS.get(kvKey);
  } catch (e) {
    console.error('[ces:session] KV get error for key', kvKey, '—', e.message);
    return errResponse(500, 'Server Error', 'Session retrieval failed. Please refresh the page.');
  }

  // Token not found: either already consumed (one-time use) or expired (TTL)
  if (!payload) {
    return new Response('Invalid or expired session', {
      status: 403,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Robots-Tag': 'noindex',
        ...SHARED_SECURITY_HEADERS,
      },
    });
  }

  // Consume immediately — one-time use. Failure here is non-fatal:
  // the TTL will clean up the entry within SESSION_TTL seconds regardless.
  try {
    await env.CES_SESSIONS.delete(kvKey);
  } catch (e) {
    console.error('[ces:session] KV delete error for key', kvKey, '—', e.message, '— entry will expire via TTL.');
  }

  // Return the fully processed HTML. Security headers applied; no CSP set here
  // because this response is consumed via fetch + document.write in the bootstrap
  // context, where the bootstrap's CSP governs script execution.
  return new Response(payload, {
    status: 200,
    headers: {
      'Content-Type':  'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Robots-Tag':  'noindex',
      ...SHARED_SECURITY_HEADERS,
    },
  });
}

// ── Main request handler ──────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;
  const url  = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';

  // ── Always pass through static/SEO files — never intercept these ──────────
  // [P1] ADDED: payment(?:\/.*)? and api\/payment\/.* — payment checkout pages
  //      are static HTML served directly by Cloudflare Pages file serving.
  // [S1] NOTE: sitemap.xml is intentionally NOT in STATIC_PASSTHROUGH — it is
  //      handled explicitly below with controlled headers.
  // [L1] ADDED: footing-pro\/engineers\/? footing-pro\/offices\/?
  //      footing-pro\/students\/? — persona landing pages are static HTML files.
  // NOTE: /api/session is intentionally NOT in STATIC_PASSTHROUGH — it is
  //       handled explicitly below by handleSession().
  const STATIC_PASSTHROUGH = /^\/(?:robots\.txt|manifest\.json|favicon\.ico|og-image\.png|images\/.*|footing-pro\/images\/.*|footing-pro\/engineers\/?.*|footing-pro\/offices\/?.*|footing-pro\/students\/?.*|beam-pro\/images\/.*|column-pro\/images\/.*|deflection-pro\/images\/.*|earthquake-pro\/images\/.*|mur-pro\/images\/.*|add-reft-pro\/images\/.*|section-property-pro\/images\/.*|google[0-9a-f]+\.html|sitemap\.xsl|fonts\/.*|\.well-known\/.*|payment(?:\/.*)?|api\/payment\/.*)$/i;
  if (STATIC_PASSTHROUGH.test(path)) return context.next();

  // ── [S1] Sitemap — explicit handler with clean minimal headers ───────────
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

  // ── [D1] /download — 302 redirect to activation tool installer ───────────
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

  // ── [S3] /api/session — one-time HTML payload endpoint ───────────────────
  // Handled here, before route matching, so it never falls through to context.next()
  // (which would attempt static file serving and 404).
  if (path === '/api/session') {
    return handleSession(request, env);
  }

  // ── Route matching: exact app root paths only ─────────────────────────────
  const route = (path === '' || path === '/' || path === '/index.html')
    ? ROUTES[0]
    : ROUTES.slice(1).find(r => path === r.prefix);

  if (!route) return context.next();

  const { encFile, baseHref, faviconLinks, pageFilename } = route;

  // ── Markdown negotiation (RFC 9110 content negotiation) ────────────────────
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

  // ── Validate key ───────────────────────────────────────────────────────────
  const keyHex = (env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64)
    return errResponse(500, 'Config Error', 'CES_DECRYPT_KEY missing or invalid.');

  // ── [S1] CES_XOR_KEY is no longer read or used (removed in v14). ──────────
  // XOR obfuscation eliminated: decrypted HTML is stored directly in KV.
  // CES_XOR_KEY environment variable can be left in place or removed — it
  // has no effect and is never referenced by this version of the function.

  // ── Read .enc file via Cloudflare ASSETS binding ───────────────────────────
  let encData;
  try {
    const encResp = await env.ASSETS.fetch(new URL(`/public/${encFile}`, url.origin));
    if (!encResp.ok) throw new Error(`HTTP ${encResp.status}`);
    encData = (await encResp.text()).trim();
  } catch (e) {
    console.error('[ces:decrypt] File read error:', encFile, e.message);
    return errResponse(500, 'Server Error', 'A configuration error occurred. Please try again later.');
  }

  // ── Decrypt ────────────────────────────────────────────────────────────────
  let html;
  try {
    html = await decryptEnc(encData, keyHex);
  } catch (e) {
    console.error('[ces:decrypt] Decryption failed for', encFile, '—', e.message);
    return errResponse(500, 'Server Error', 'A configuration error occurred. Please try again later.');
  }

  // ── Inject base href ───────────────────────────────────────────────────────
  html = html.replace(/(<head[^>]*>)/i, `$1<base href="${baseHref}">`);

  // ── [V4-FAV] Inject favicon links into decrypted HTML if absent ────────────
  if (faviconLinks && !/<link[^>]+rel=["'](?:icon|shortcut icon|apple-touch-icon)["']/i.test(html)) {
    html = html.replace(/(<\/head>)/i, `${faviconLinks}$1`);
  }

  // ── Per-request nonce ──────────────────────────────────────────────────────
  // IMPORTANT (v14): This nonce is used for BOTH the bootstrap shell scripts AND
  // the nonces stamped into the KV-stored HTML via injectNonces(). When the client
  // does document.write(kvHtml), the browser enforces the bootstrap's CSP — which
  // contains 'nonce-{cspNonce}'. All scripts in kvHtml carry this same nonce →
  // they execute correctly. The nonce must therefore be generated ONCE and used
  // for both the bootstrap response headers and the injectNonces() call below.
  const cspNonce = generateNonce();

  // ═══════════════════════════════════════════════════════════════════════════
  // BOT PATH — Ultra-clean, lightweight HTML served to crawlers
  // [SECURITY] Nothing in this block affects the human path. The human path
  // receives only a bootstrap shell; the full HTML is stored in KV.
  // ═══════════════════════════════════════════════════════════════════════════
  const ua = request.headers.get('User-Agent') || '';
  if (BOT_RE.test(ua)) {
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
      'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}' 'sha256-707X5+NAXR96e1UzENjwpPf416b6sJGW3mMwS4KSCqw=' 'sha256-9Z5YUtj2GDOBykVWUu8jxOyhx6HrrXGwO4FEHHSUtqQ=' 'unsafe-hashes' 'sha256-nAiI7XK5Mt/SgNQUZPqTuikvwxIVHV3se6mHGQue+88=' 'sha256-Jag+ZHPii6iUmMQWlnwms/mnjM8gRPTOJA2KIyTQQRk=' 'sha256-uLUdJIdD3+8SpL4nHNFN9YmyHRRmrseSQKwzj3ECn2I=' 'sha256-akyHNuxwVvvLQ11iHoDrpca0qH3TU3LfGbtdQ8kNdwI=' 'sha256-UOhLo4NRrWG89b3vpgtU0dc/C8aWLS+MQ2Lf9vW/4Fk=' 'sha256-jHF5hTIlMDyGZRAsNK0HO/WFYrwPvI2I1q0o1xKKB6I=' 'sha256-wflfhEeJWTAjAK0hnm9/OICxAQ8fVnj3168JrJ/m91k=' 'sha256-oTzV9+pQ7IAxC4NoAc7dH4+0Is4KloZ9u7cMJC7UDrE=' 'sha256-bTpi/7w0Cd8ihAWpwcZJIdz49sMq0d73fWWDzp5Ju2Q='`,
      'Link':                    HOMEPAGE_LINK_HEADER,
      ...SHARED_SECURITY_HEADERS,
    }});
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HUMAN PATH — Session-based protection (v14)
  // The real HTML is NEVER embedded in the bootstrap response.
  // Processing pipeline: inject bundle → minify → M2 guard → nonces → CSS minify
  // → store in KV → return bootstrap with fetch script.
  // ═══════════════════════════════════════════════════════════════════════════

  // ── KV binding guard ───────────────────────────────────────────────────────
  if (!env.CES_SESSIONS) {
    console.error('[ces:session] CES_SESSIONS KV binding is not configured. Deploy requires KV binding.');
    return errResponse(500, 'Server Error', 'Session store not configured. Please contact support.');
  }

  // ── Inject protection bundle at end of body ────────────────────────────────
  // buildProtectionBundle() is injected INTO the HTML before KV storage.
  // The real page delivered via /api/session will contain all client-side
  // protections: DevTools detection, right-click block, Ctrl+S copyright save.
  const bundle = `<script nonce="${cspNonce}">${buildProtectionBundle(pageFilename)}</script>`;
  html = html.replace(/<\/body>/i, bundle + '</body>');

  // ── Minify ─────────────────────────────────────────────────────────────────
  html = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/>\s+</g, '><')
    .replace(/\s{2,}/g, ' ')
    .trim();

  // ── [M2] Decoded-HTML origin guard — extra defense layer ─────────────────
  // Purpose: if Chrome Android saves the rendered DOM (post document.write —
  // the real page HTML) and that file is later opened as file://, this guard
  // fires before any content renders and replaces the document with copyright.
  // On legitimate access (origin === 'https://civilengsuite.pages.dev'):
  //   guard condition is false → no-op → page renders normally. ✓
  // On file:// open (origin === 'null') or unauthorized host:
  //   guard fires → copyright shown. ✓
  // Injected right after <meta charset="UTF-8"> so injectNonces() below
  // stamps it with cspNonce — required for correct CSP evaluation after
  // document.write() (CSP context is inherited from bootstrap response).
  const _sharedCrRP    = route.prefix === '/' ? '' : route.prefix;
  const _sharedCrTM    = html.match(/<title>([^<]*)<\/title>/i);
  const _sharedCrPT    = escHtml(_sharedCrTM ? _sharedCrTM[1] : (route.ogTitle || 'Civil Engineering Suite'));
  const _sharedCrUrl   = `https://civilengsuite.pages.dev${_sharedCrRP}/`;
  const _sharedCrLabel = `civilengsuite.pages.dev${_sharedCrRP}/`;
  const _sharedCrHtml  =
    `<!DOCTYPE html><html><head><meta charset="UTF-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<title>\u00A9 Protected \u2014 ${_sharedCrPT}<\/title>`
    + `<style>*{box-sizing:border-box;margin:0;padding:0}`
    + `body{background:#0A1A2E;display:flex;align-items:center;justify-content:center;`
    + `min-height:100vh;font-family:sans-serif;text-align:center;padding:24px}`
    + `.card{max-width:440px}.icon{font-size:3.5rem;margin-bottom:18px}`
    + `.title{color:#C17B1A;font-size:1.35rem;font-weight:700;margin-bottom:12px;line-height:1.4}`
    + `.msg{color:#8AA3C7;font-size:0.9rem;line-height:1.8;margin-bottom:22px}`
    + `a{color:#C17B1A;font-size:0.88rem;text-decoration:none}`
    + `a:hover{text-decoration:underline}<\/style><\/head><body>`
    + `<div class="card"><div class="icon">&#x1F512;<\/div>`
    + `<div class="title">&#169; Eng. Aymn Asi &#8212; ${_sharedCrPT}<\/div>`
    + `<div class="msg">Unauthorized copying is prohibited.<br>`
    + `This page must be accessed from the official website.<\/div>`
    + `<a href="${_sharedCrUrl}">${_sharedCrLabel}<\/a>`
    + `<\/div><\/body><\/html>`;
  const _sharedCrB64 = u8ToB64(new TextEncoder().encode(_sharedCrHtml));
  const _m2Code =
      `(function(){'use strict';`
    + `var _ao='https://civilengsuite.pages.dev';`
    + `var _o=(typeof window!=='undefined')?window.location.origin:'';`
    + `var _dev=/^https?:\\/\\/(localhost|127\\.0\\.0\\.1)(:\\d+)?$/.test(_o);`
    + `if(_o!==_ao&&!_dev){`
    + `var _b='${_sharedCrB64}';`
    + `var _n=atob(_b);var _ba=new Uint8Array(_n.length);`
    + `for(var i=0;i<_n.length;i++)_ba[i]=_n.charCodeAt(i);`
    + `var _cr=new TextDecoder('utf-8').decode(_ba);`
    + `try{document.open();document.write(_cr);document.close();}`
    + `catch(e){window.location.replace(_ao+'${_sharedCrRP}/');}`
    + `}`
    + `})();`;
  html = html.replace(/(<meta charset="UTF-8">)/i, `$1<script>${_m2Code}<\/script>`);

  // ── Stamp nonce on every <script> tag in the KV-stored HTML ──────────────
  // CRITICAL: Must use the SAME cspNonce as the bootstrap response CSP header.
  // After document.write(), the browser enforces the bootstrap's CSP policy
  // ('nonce-{cspNonce}'). Scripts with this nonce → execute. Others → blocked.
  html = injectNonces(html, cspNonce);

  // ── Minify inline <style> blocks ──────────────────────────────────────────
  html = minifyBotCSS(html);

  // ── [S2] Store processed HTML in KV — one-time session ────────────────────
  // token: 64 hex chars (32 random bytes) — unguessable
  // expirationTtl: SESSION_TTL (60 seconds) — auto-deleted by KV after expiry
  // One-time use: handleSession() deletes the entry on first successful retrieval
  const sessionToken = generateToken();
  try {
    await env.CES_SESSIONS.put(`session:${sessionToken}`, html, { expirationTtl: SESSION_TTL });
  } catch (e) {
    console.error('[ces:session] KV put error:', e.message);
    return errResponse(500, 'Server Error', 'Could not initialize session. Please refresh the page.');
  }

  // ── Extract page title for bootstrap shell ────────────────────────────────
  const titleM    = html.match(/<title>([^<]*)<\/title>/i);
  const pageTitle = titleM ? titleM[1] : 'Civil Engineering Suite';

  // ── [M1a] Bootstrap origin guard — parser-blocking <script> in <head> ────
  // Fires BEFORE <body> is parsed → fetch script never runs on unauthorized opens.
  // file:// protocol: window.location.origin === 'null' → guard fires → copyright.
  // Wrong origin: guard fires → copyright.
  // Correct origin: guard is a no-op → page proceeds to fetch step.
  const bootstrapOriginGuard =
    `<script nonce="${cspNonce}">`
    + `(function(){'use strict';`
    + `var _ao='https://civilengsuite.pages.dev';`
    + `var _o=(typeof window!=='undefined')?window.location.origin:'';`
    + `var _dev=/^https?:\\/\\/(localhost|127\\.0\\.0\\.1)(:\\d+)?$/.test(_o);`
    + `if(_o!==_ao&&!_dev){`
    + `var _b='${_sharedCrB64}';`
    + `var _n=atob(_b);var _ba=new Uint8Array(_n.length);`
    + `for(var i=0;i<_n.length;i++)_ba[i]=_n.charCodeAt(i);`
    + `var _cr=new TextDecoder('utf-8').decode(_ba);`
    + `try{document.open();document.write(_cr);document.close();}`
    + `catch(e){window.location.replace(_ao+'${_sharedCrRP}/');}`
    + `}`
    + `})();`
    + `\u003c/script>`;

  // ── [M1b] Bootstrap copyright body ────────────────────────────────────────
  // display:none on legitimate access (fetch script immediately replaces doc).
  // <noscript> makes it display:flex when JS is disabled → copyright shown.
  // Text editors opening the bootstrap .html file see this copyright HTML
  // FIRST, before encountering any script content.
  const bootstrapCopyrightBody =
    `<style>`
    + `#_ces_cr_body{display:none;margin:0;background:#0A1A2E;color:#C17B1A;`
    + `font-family:sans-serif;align-items:center;justify-content:center;`
    + `min-height:100vh;text-align:center;position:fixed;top:0;left:0;`
    + `width:100%;height:100%;z-index:2147483647}`
    + `</style>`
    + `<noscript><style>#_ces_cr_body{display:flex!important}</style></noscript>`
    + `<div id="_ces_cr_body">`
    + `<div style="padding:40px;max-width:440px">`
    + `<div style="font-size:3.5rem;margin-bottom:18px">&#x1F512;</div>`
    + `<h2 style="font-size:1.35rem;font-weight:700;margin-bottom:12px;line-height:1.4">`
    + `&#169; Eng. Aymn Asi &#8212; ${escHtml(pageTitle)}</h2>`
    + `<p style="color:#8AA3C7;font-size:0.9rem;line-height:1.8;margin-bottom:22px">`
    + `Unauthorized copying is prohibited.<br>`
    + `This page must be accessed from the official website.</p>`
    + `<a href="${_sharedCrUrl}" style="color:#C17B1A;font-size:0.88rem">${_sharedCrLabel}</a>`
    + `</div></div>`;

  // ── [B9] OG meta block for bootstrap shell ────────────────────────────────
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

  // ── [A6] WebMCP registration in bootstrap shell ───────────────────────────
  // Runs before fetch script; fires for any JS-executing client. No-op in
  // browsers without navigator.modelContext.
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

  // ── [PERF] LCP preload for footing-pro hero image ─────────────────────────
  const lcpPreload = route.prefix === '/footing-pro'
    ? '<link rel="preload" as="image" href="/footing-pro/images/hero-bg.avif"'
      + ' imagesrcset="/footing-pro/images/hero-bg.avif 1x,/footing-pro/images/hero-bg.webp 1x"'
      + ' imagesizes="100vw" fetchpriority="high">'
    : '';

  // ── [S4] Fetch script — REPLACES XOR decoder ─────────────────────────────
  // Fetches the real HTML from /api/session?token=TOKEN.
  // On success: document.write(html) → full page renders.
  // On any failure (network, 403 token expired, 9-second timeout):
  //   → copyright page shown via _sharedCrB64 fallback.
  // AbortController: present in all modern browsers; graceful feature-detect
  // guard ensures no crash on older environments (just no timeout).
  // credentials:'same-origin': belt-and-suspenders for cookie-based future auth.
  const fetchScript =
    `<script nonce="${cspNonce}">`
    + `(function(){'use strict';`
    // AbortController for 9-second timeout — prevents infinite spinner on
    // connectivity issues (token already valid but server unreachable)
    + `var _ctrl=typeof AbortController!=='undefined'?new AbortController():null;`
    + `var _timer=setTimeout(function(){if(_ctrl)_ctrl.abort();},9000);`
    + `var _opts={credentials:'same-origin'};`
    + `if(_ctrl)_opts.signal=_ctrl.signal;`
    // Fetch the one-time session payload
    + `fetch('/api/session?token=${sessionToken}',_opts)`
    + `.then(function(r){clearTimeout(_timer);if(!r.ok)throw new Error('s');return r.text();})`
    + `.then(function(h){document.open();document.write(h);document.close();})`
    // Any failure: network error, 403 (expired/invalid token), timeout abort
    + `.catch(function(){`
    + `clearTimeout(_timer);`
    + `var _b='${_sharedCrB64}';`
    + `var _n=atob(_b);var _ba=new Uint8Array(_n.length);`
    + `for(var i=0;i<_n.length;i++)_ba[i]=_n.charCodeAt(i);`
    + `var _cr=new TextDecoder('utf-8').decode(_ba);`
    + `try{document.open();document.write(_cr);document.close();}`
    + `catch(e){window.location.replace('https://civilengsuite.pages.dev${_sharedCrRP}/');}`
    + `});`
    + `})();`
    + `\u003c/script>`;

  // ── Bootstrap shell ────────────────────────────────────────────────────────
  // Contains ZERO recoverable application content.
  // Saved file analysis: a captured bootstrap.html contains only:
  //   · Meta tags (OG, description, title)
  //   · Font preload hints
  //   · M1a origin guard (blocks file:// execution before fetch runs)
  //   · M1b copyright div (visible in text editors; hidden in browser)
  //   · WebMCP registration (no-op in standard browsers)
  //   · Fetch script referencing an expired/invalid token → 403 → copyright
  // No XOR blob. No recoverable content. Offline or post-expiry → copyright. ✓
  const bootstrap = `<!DOCTYPE html><html><head>`
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
    + `<title>${pageTitle}</title>`
    + ogMetaBlock
    + faviconLinks
    + bootstrapOriginGuard
    + `</head><body>`
    + bootstrapCopyrightBody
    + webMCPBootstrap
    + fetchScript
    + `</body></html>`;

  return new Response(bootstrap, { status: 200, headers: {
    'Content-Type':            'text/html; charset=utf-8',
    'Cache-Control':           'no-store',
    'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}' 'sha256-707X5+NAXR96e1UzENjwpPf416b6sJGW3mMwS4KSCqw=' 'sha256-9Z5YUtj2GDOBykVWUu8jxOyhx6HrrXGwO4FEHHSUtqQ=' 'unsafe-hashes' 'sha256-nAiI7XK5Mt/SgNQUZPqTuikvwxIVHV3se6mHGQue+88=' 'sha256-Jag+ZHPii6iUmMQWlnwms/mnjM8gRPTOJA2KIyTQQRk=' 'sha256-uLUdJIdD3+8SpL4nHNFN9YmyHRRmrseSQKwzj3ECn2I=' 'sha256-akyHNuxwVvvLQ11iHoDrpca0qH3TU3LfGbtdQ8kNdwI=' 'sha256-UOhLo4NRrWG89b3vpgtU0dc/C8aWLS+MQ2Lf9vW/4Fk=' 'sha256-jHF5hTIlMDyGZRAsNK0HO/WFYrwPvI2I1q0o1xKKB6I=' 'sha256-wflfhEeJWTAjAK0hnm9/OICxAQ8fVnj3168JrJ/m91k=' 'sha256-oTzV9+pQ7IAxC4NoAc7dH4+0Is4KloZ9u7cMJC7UDrE=' 'sha256-bTpi/7w0Cd8ihAWpwcZJIdz49sMq0d73fWWDzp5Ju2Q='`,
    // [A1] Link header: homepage gets full agent discovery headers
    // [A4] Vary: Accept on homepage so CDN separates markdown/HTML caches
    ...(route.prefix === '/' ? {
      'Link': HOMEPAGE_LINK_HEADER,
      'Vary': 'Accept',
    } : {}),
    ...SHARED_SECURITY_HEADERS,
  }});
}
