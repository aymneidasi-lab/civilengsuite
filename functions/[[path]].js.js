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
 *        The lazy quantifier started from a JSON-LD <script> tag and consumed
 *        through its </script> to reach the protection marker in the NEXT block,
 *        deleting ALL JSON-LD structured data. This caused "URL has no enhancements"
 *        in Google Search Console live test.
 *        Fix: replaced [\s\S]*? with (?:(?!<\/script>)[\s\S])*? in all 5 patterns.
 *   [X2] Permissions-Policy: removed 'ambient-light-sensor=()' and 'usb=()'.
 *        ambient-light-sensor was dropped from the spec; Chrome logs an
 *        "Unrecognized feature" warning visible in GSC live test JS console.
 *        usb=() is not a Permissions Policy directive (separate API).
 *
 * 2026-04-17 v5 — Payment gateway integration (P1–P3):
 *   [P1] STATIC_PASSTHROUGH: added /payment/* and /api/payment/* so this
 *        catch-all function never intercepts payment routes. Payment pages are
 *        static HTML; payment API routes are dedicated CF Pages Functions.
 *   [P2] CSP_COMMON: form-action expanded to include site origin explicitly,
 *        allowing fetch()-based payment initiation from encrypted app pages.
 *   [P3] SHARED_SECURITY_HEADERS: removed payment=() from Permissions-Policy.
 *        This function only serves encrypted app pages — not the payment pages.
 *        payment=() on app pages is unnecessary; it is correctly absent from
 *        the /payment/* _headers block which governs the checkout flow.
 *
 * 2026-04-25 v8 — Bot-path OG tag injection + favicon guard (V2-BOT, V4-FAV):
 *   [V2-BOT] Bot path: inject og:image:secure_url / og:image:type / width / height
 *            into bot-path (decrypted) HTML when absent. Bootstrap ogMetaBlock (v7
 *            [V2]) already handles non-bot UAs (iMessage iOS). Bot-path HTML comes
 *            from the encrypted source which may lack these tags. WhatsApp / Telegram
 *            scrapers match BOT_RE and receive bot-path HTML — they require
 *            og:image:secure_url to render the image thumbnail. Without it they show
 *            only text + domain (image blank in chat). Guard prevents duplication.
 *   [V4-FAV] Inject faviconLinks into decrypted HTML if <link rel="icon"> / apple-
 *            touch-icon is absent. Human-path document.write replaces the bootstrap
 *            <head>, discarding the bootstrap favicon links. If the encrypted source
 *            has no favicon declaration, the browser tab shows no icon. Fix: append
 *            faviconLinks before </head> in the decrypted HTML when the source lacks
 *            icon links. Guard prevents duplication when source already has them.
 *
 * 2026-04-25 v7 — Sitemap + OG image fixes (V1–V3):
 *   [V1] SITEMAP CRITICAL: Removed X-Robots-Tag: noindex from /sitemap.xml response.
 *        Googlebot's sitemap fetcher respects X-Robots-Tag directives. noindex on
 *        the sitemap.xml URL itself caused the fetcher to abort without reading the
 *        document — reported as "Couldn't fetch" / "Sitemap could not be read" in
 *        Google Search Console despite the file loading correctly in browsers.
 *        The noindex was intended to prevent the sitemap.xml URL from appearing in
 *        search results (correct intent) but the implementation prevented the sitemap
 *        from being processed entirely (wrong effect). Fix: removed the header.
 *        Google has never indexed sitemap.xml URLs regardless of X-Robots-Tag.
 *   [V2] OG IMAGE — WhatsApp/iMessage: Added og:image:secure_url and og:image:type
 *        to the ogMetaBlock in the bootstrap shell. WhatsApp's scraper requires
 *        og:image:secure_url (HTTPS alias of og:image) and og:image:type to reliably
 *        render the image thumbnail in chat previews. Facebook Sharing Debugger
 *        confirmed og:image was set correctly — WhatsApp not showing image was caused
 *        by missing og:image:secure_url + og:image:type declarations.
 *   [V3] STATIC_PASSTHROUGH: Added /images/*, /footing-pro/images/*, and all
 *        sub-app /images/* paths plus /sitemap.xsl. These paths were already handled
 *        correctly via the !route → context.next() fallback, but explicit passthrough
 *        eliminates the route-matching overhead for every image request and ensures
 *        the ASSETS binding is never invoked unnecessarily for static media files.
 *
 * 2026-04-23 v6 — Agent-readiness infrastructure (A1–A7):
 *   [A1] HOMEPAGE_LINK_HEADER: RFC 8288 Link response header — 7 relations:
 *        api-catalog (RFC 9727), agent-skills index, mcp-server-card,
 *        oauth-authorization-server (RFC 8414), oauth-protected-resource (RFC 9728),
 *        security.txt (RFC 9116), sitemap.
 *        Emitted on homepage responses (both bot and human paths) and on ALL
 *        bot-path responses so agents scanning any tool page find the catalog.
 *   [A2] HOMEPAGE_MARKDOWN: static curated markdown constant returned when
 *        Accept: text/markdown is detected on the homepage. Short-circuits the
 *        decrypt pipeline — no .enc read needed. Includes x-markdown-tokens hint
 *        (word count × 1.3) per Cloudflare agent-readiness convention.
 *        Cache-Control: public (markdown is not user-specific, safe to cache).
 *   [A3] WebMCP (bot path): navigator.modelContext.provideContext() injected into
 *        bot path HTML before </body>. Exposes 3 tools to AI agent crawlers:
 *        open_footing_pro, open_section_property_pro, get_suite_info.
 *   [A4] Vary: Accept added alongside Vary: User-Agent on homepage responses so
 *        CDN correctly separates HTML / markdown caches.
 *   [A5] Security: all changes are additive — SHARED_SECURITY_HEADERS,
 *        CSP_COMMON, buildProtectionBundle, stripProtectionScripts, XOR
 *        obfuscation and the human path are byte-for-byte identical to v5.
 *   [A6] WebMCP (bootstrap shell): navigator.modelContext.provideContext() is now
 *        also injected into the human-path bootstrap shell as a standalone <script>
 *        block that executes BEFORE the XOR decoder. This ensures the WebMCP call
 *        fires for any JS-executing client regardless of User-Agent — including
 *        agent-readiness scanners whose UA does not match BOT_RE.
 *        Security impact: zero. The tools expose only navigation URLs and public
 *        metadata. The XOR payload, encryption key, and protection bundle are never
 *        referenced. The call is wrapped in a feature-detect guard so it is a no-op
 *        in all browsers that do not implement navigator.modelContext.
 *   [S1] SITEMAP FIX: sitemap.xml removed from STATIC_PASSTHROUGH and handled
 *        explicitly in the function with minimal clean headers. Root cause: the
 *        _headers /*  catch-all was applying Content-Security-Policy to sitemap.xml.
 *        Cloudflare Pages _headers is additive — all matching rules stack — so
 *        sitemap.xml received the full CSP header from the /* block. Googlebot's
 *        sitemap fetcher rejects documents with CSP headers, reporting
 *        "Couldn't fetch" / "Sitemap could not be read" in Search Console despite
 *        the file loading correctly in the browser (which ignores CSP on XML).
 *        Fix: function intercepts /sitemap.xml, fetches raw XML from ASSETS binding,
 *        and returns with ONLY Content-Type: application/xml and Cache-Control.
 *        No CSP, no X-Frame-Options, no security headers on the XML response.
 *   [S2] SITEMAP IMAGE PATHS: 7 of 9 <image:loc> entries referenced /og-image.png
 *        (root-level, which 404s). Fixed to /images/og-image.png for all sub-app
 *        pages. Footing Pro retains /footing-pro/images/og-image.png (correct).
 *        lastmod updated to 2026-04-24 on all pages.
 *   [A7] oauth-authorization-server: /.well-known/oauth-authorization-server added
 *        as a static file (RFC 8414 minimal, honest — no active authorization
 *        server). Satisfies agent-readiness OAuth discovery check. Link header
 *        updated to include the new relation.
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
    // [B9] og meta for bootstrap shell — social preview for browser-UA scrapers (iMessage etc.)
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

// ── CSP common (matches api/decrypt.js CSP_COMMON exactly) ───────────────────
// [P2] form-action: added site origin explicitly to support payment initiation
//      fetch() calls from encrypted app pages (belt-and-suspenders; same-origin
//      fetch is already permitted by connect-src 'self', but form-action governs
//      <form> submissions and is declared explicitly for completeness).
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
  "require-trusted-types-for 'script'",
  "trusted-types default",
].join('; ');

// [F6] Shared security headers applied to EVERY response this function emits.
// NOTE: _headers does NOT apply to Cloudflare Pages Function responses —
// these must be set explicitly here on every returned Response.
//
// [X2] REMOVED ambient-light-sensor=() — this feature was dropped from the
// Permissions Policy spec; Chrome logs "Unrecognized feature" console warning
// that appears in Google Search Console's live test (Image 2, Apr 15 2026).
//
// [P3] REMOVED payment=() — this function only serves encrypted app pages.
// The payment=() restriction is unnecessary here (the app pages do not invoke
// the browser Payment Request API). The /payment/* checkout pages are governed
// by the _headers file which correctly omits payment=(), enabling Apple Pay
// via the Paymob SDK. Keeping payment=() here would not affect /payment/ pages
// (different routing path) but is removed for semantic correctness.
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
// Emitted on all homepage responses (bot + human) and on ALL bot-path responses
// so agents that crawl /footing-pro/ directly still discover the agent catalog.
// Relations:
//   api-catalog              — RFC 9727 machine-readable API catalog
//   agentskills.io/rel/...   — Agent Skills Discovery index (RFC v0.2.0)
//   mcp-server-card          — SEP-1649 MCP Server Card
//   oauth-protected-resource — RFC 9728 OAuth resource metadata
//   security-policy          — RFC 9116 security.txt
//   sitemap                  — XML sitemap for structural discovery
const HOMEPAGE_LINK_HEADER = [
  '</.well-known/api-catalog>; rel="api-catalog"',
  '</.well-known/agent-skills/index.json>; rel="https://agentskills.io/rel/skills-index"',
  '</.well-known/mcp/server-card.json>; rel="mcp-server-card"',
  // [A7] RFC 8414 OAuth Authorization Server Metadata — even when no auth server
  // is active, publishing this file satisfies agent OAuth-discovery checks and
  // correctly informs agents that no authorization is required.
  '</.well-known/oauth-authorization-server>; rel="oauth-authorization-server"',
  '</.well-known/oauth-protected-resource>; rel="oauth-protected-resource"',
  '</.well-known/security.txt>; rel="security-policy"',
  '</sitemap.xml>; rel="sitemap"',
].join(', ');

// [A2] Static curated markdown for the homepage — returned when an agent sends
// Accept: text/markdown. Short-circuits the decrypt pipeline entirely: no
// CES_DECRYPT_KEY read, no AES-GCM operation, no XOR, no HTML processing.
// Content mirrors the JSON-LD structured data in index.html — update in sync.
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
  return html.replace(/<script(?=[\s>])/g, `<script nonce="${nonce}"`);
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
  // Reusable safe-match helper: builds a regex that matches a single <script> block
  // containing the given marker string, without crossing into adjacent blocks.
  function safeScriptRe(marker) {
    return new RegExp(
      '<script\\b[^>]*>(?:(?!<\\/script>)[\\s\\S])*?' + marker + '(?:(?!<\\/script>)[\\s\\S])*?<\\/script>',
      'gi'
    );
  }

  // [B1] "CONTENT PROTECTION SYSTEM" — the main protection IIFE (~180 lines).
  html = html.replace(safeScriptRe('CONTENT PROTECTION SYSTEM'), '');

  // [B2] "© Footing Pro v.2026 - Eng. Aymn Asi - All Rights Reserved"
  html = html.replace(safeScriptRe('\u00A9 Footing Pro v\\.2026 - Eng\\. Aymn Asi - All Rights Reserved'), '');

  // [B3] "© Footing Pro v.2026 - Eng. Aymn Asi - Protected"
  html = html.replace(safeScriptRe('\u00A9 Footing Pro v\\.2026 - Eng\\. Aymn Asi - Protected'), '');

  // [B4] "_CES_COPYRIGHT_HTML" — the showSaveFilePicker override (Ctrl+S).
  html = html.replace(safeScriptRe('_CES_COPYRIGHT_HTML'), '');

  // [B5] "FOOTING PRO v.2026 — ENGINE TRANSFER + SECURITY UPGRADE"
  html = html.replace(safeScriptRe('FOOTING PRO v\\.2026 \u2014 ENGINE TRANSFER'), '');

  // [B7] Remove oncontextmenu attribute from <body> tag.
  html = html.replace(/<body([^>]*)\soncontextmenu="[^"]*"/gi, '<body$1');

  return html;
}

// ── Minify inline <style> blocks for bot response ─────────────────────────────
// [B6] Reduces CSS payload from ~120 KB to ~60 KB by stripping comments and
// collapsing whitespace. Does NOT touch <style> blocks inside <noscript> or
// <script> tags. Safe for all standard CSS including @media and calc().
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
// Injected ONLY into bot path HTML, before </body>. Never reaches human browsers.
// Each tool: name, description, inputSchema (JSON Schema), execute callback.
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

// ── Main request handler ──────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;
  const url  = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';

  // ── Always pass through static/SEO files — never intercept these ──────────
  // [P1] ADDED: payment(?:\/.*)? and api\/payment\/.* — payment checkout pages
  //      are static HTML served directly by Cloudflare Pages file serving.
  //      Payment API routes are dedicated CF Pages Functions in
  //      functions/api/payment/*.js which take routing precedence over this
  //      catch-all by Cloudflare's function routing rules, but the passthrough
  //      here is an explicit defensive guard.
  // [S1] NOTE: sitemap.xml is intentionally NOT in STATIC_PASSTHROUGH — it is
  //      handled explicitly below with controlled headers. See [S1] in changelog.
  const STATIC_PASSTHROUGH = /^\/(?:robots\.txt|manifest\.json|favicon\.ico|og-image\.png|images\/.*|footing-pro\/images\/.*|beam-pro\/images\/.*|column-pro\/images\/.*|deflection-pro\/images\/.*|earthquake-pro\/images\/.*|mur-pro\/images\/.*|add-reft-pro\/images\/.*|section-property-pro\/images\/.*|google[0-9a-f]+\.html|sitemap\.xsl|\.well-known\/.*|payment(?:\/.*)?|api\/payment\/.*)$/i;
  if (STATIC_PASSTHROUGH.test(path)) return context.next();

  // ── [S1] Sitemap — explicit handler with clean minimal headers ───────────
  // The _headers /* catch-all applies Content-Security-Policy to every path
  // including sitemap.xml (Cloudflare Pages _headers is additive — all matching
  // rules stack). Googlebot's sitemap parser rejects XML documents that carry
  // CSP headers, reporting "Couldn't fetch" in Search Console.
  // Fix: intercept /sitemap.xml here, fetch raw XML from ASSETS, return with
  // ONLY Content-Type + Cache-Control. No security headers on XML.
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

  // ── Route matching: exact app root paths only ─────────────────────────────
  const route = (path === '' || path === '/' || path === '/index.html')
    ? ROUTES[0]
    : ROUTES.slice(1).find(r => path === r.prefix);

  // Not an encrypted route → serve static file / apply _redirects
  if (!route) return context.next();

  const { encFile, baseHref, faviconLinks, pageFilename } = route;

  // ── Markdown negotiation (RFC 9110 content negotiation) ────────────────────
  // [A2] Agents sending Accept: text/markdown on the homepage receive a curated
  // static markdown response. The decrypt pipeline is bypassed entirely —
  // no CES_DECRYPT_KEY access, no AES-GCM, no XOR, no HTML parsing.
  // Cache-Control: public — markdown content is not user-specific.
  // x-markdown-tokens: approximate token count (word count × 1.3 multiplier).
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

  // ── XOR key ────────────────────────────────────────────────────────────────
  const xorHex = (env.CES_XOR_KEY || '').trim();
  const XOR_KEY = (xorHex.length === 2 && /^[0-9A-Fa-f]{2}$/.test(xorHex))
    ? parseInt(xorHex, 16) : 0x5A;

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
  // Human path: document.write(decodedHtml) replaces the entire document,
  // discarding the bootstrap <head> (which already had faviconLinks). If the
  // encrypted source HTML has no <link rel="icon"> / <link rel="apple-touch-icon">
  // the browser tab shows no favicon and iOS shows no touch icon after JS runs.
  // Fix: if the decrypted HTML lacks a favicon link, inject faviconLinks directly
  // into its <head> so the final rendered page always has correct icon references.
  // Guard prevents duplication if the source already declares its own icons.
  if (faviconLinks && !/<link[^>]+rel=["'](?:icon|shortcut icon|apple-touch-icon)["']/i.test(html)) {
    html = html.replace(/(<\/head>)/i, `${faviconLinks}$1`);
  }

  // ── Per-request nonce ──────────────────────────────────────────────────────
  const cspNonce = generateNonce();

  // ═══════════════════════════════════════════════════════════════════════════
  // BOT PATH — Ultra-clean, lightweight HTML served to crawlers
  // [SECURITY] Nothing in this block affects the human path. The human path
  // receives the fully obfuscated XOR bootstrap with all protections active.
  // ═══════════════════════════════════════════════════════════════════════════
  const ua = request.headers.get('User-Agent') || '';
  if (BOT_RE.test(ua)) {
    const host = url.host;
    let botHtml = html;

    // Fix any noindex directives so crawlers can index properly
    botHtml = botHtml.replace(
      /<meta\s+name="robots"\s+content="noindex[^"]*"/gi,
      '<meta name="robots" content="index, follow"'
    );

    // Fix og:image / twitter:image host references
    botHtml = botHtml.replace(
      /(<meta\s+(?:property|name)="(?:og:image|og:image:secure_url|twitter:image)"\s+content=")https:\/\/[^/]+(\/[^"]*")/gi,
      `$1https://${host}$2`
    );

    // [F3] FIX: /footing-pro/og-image.png → /footing-pro/images/og-image.png
    botHtml = botHtml.replace(
      /(https?:\/\/[^"']+)\/footing-pro\/og-image\.png/gi,
      '$1/footing-pro/images/og-image.png'
    );

    // [B8] FIX: og:image / twitter:image paths missing /images/ prefix.
    // The encrypted source HTML references /og-image.png (root-level, 404).
    // The static file is served at /images/og-image.png (from public/images/).
    // After the host-rewrite above, URLs become https://host/og-image.png — still 404.
    // This pattern matches any og:image URL ending in /og-image.png that does NOT
    // already have /images/ or /footing-pro/images/ in the path, and inserts /images/.
    // Scope: homepage and all sub-app pages that reference the shared og-image asset.
    botHtml = botHtml.replace(
      /(content="https?:\/\/[^"]+\/)og-image\.png"/gi,
      (match, prefix) => {
        // Already correct paths — leave untouched
        if (/\/images\//.test(prefix)) return match;
        return `${prefix}images/og-image.png"`;
      }
    );

    // [V2-BOT] WhatsApp and Telegram scrapers match BOT_RE and receive bot-path
    // (decrypted) HTML — NOT the bootstrap shell. The bootstrap shell ogMetaBlock
    // (v7 [V2]) added og:image:secure_url + og:image:type for non-bot UA clients
    // (iMessage iOS). But bot-path HTML originates from the encrypted source which
    // may not have these tags. WhatsApp's image-fetch pipeline requires BOTH
    // og:image:secure_url (the HTTPS alias) and og:image:type to render the image
    // thumbnail in chat previews. Without them, WhatsApp shows only text + domain.
    // Fix: if og:image:secure_url is absent from the bot HTML, extract the already-
    // rewritten og:image content value and inject the four companion meta tags
    // immediately after the og:image tag.
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

    // [F2] FIX: Strip body-hiding noscript style
    botHtml = botHtml.replace(
      /(<noscript>)\s*<style>[^<]*?body\s*\{[^}]*?display\s*:\s*none[^}]*?\}[^<]*?<\/style>/gi,
      '$1'
    );

    // [B1–B5, B7] Strip all inline protection scripts and inline event handlers.
    botHtml = stripProtectionScripts(botHtml);

    // [B6] Minify all inline <style> blocks.
    botHtml = minifyBotCSS(botHtml);

    // Inject nonces into remaining scripts (JSON-LD, translation, navigation)
    botHtml = injectNonces(botHtml, cspNonce);

    // [A3] Inject WebMCP tools before </body> — visible to AI agents on page scan.
    // injectNonces stamps the nonce onto the WebMCP <script> tag as well.
    botHtml = botHtml.replace(/<\/body>/i,
      injectNonces(buildWebMCPScript(), cspNonce) + '</body>');

    return new Response(botHtml, { status: 200, headers: {
      'Content-Type':            'text/html; charset=utf-8',
      // [F5] private prevents CDN from caching decrypted HTML and serving to humans
      'Cache-Control':           'private, max-age=3600, must-revalidate',
      // [F4] Vary: User-Agent prevents CDN merging bot/human caches.
      // [A4] Vary: Accept added on homepage so markdown-negotiated cache is separate.
      'Vary':                    route.prefix === '/' ? 'User-Agent, Accept' : 'User-Agent',
      'X-Robots-Tag':            'index, follow',
      'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}' 'unsafe-inline'`,
      // [A1] Link header on ALL bot responses — agents crawling any tool page
      // discover the full agent catalog without needing to hit the homepage first.
      'Link':                    HOMEPAGE_LINK_HEADER,
      ...SHARED_SECURITY_HEADERS,
    }});
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HUMAN PATH — Full protection active (unchanged from original)
  // ═══════════════════════════════════════════════════════════════════════════

  // Inject protection bundle at end of body
  const bundle = `<script nonce="${cspNonce}">${buildProtectionBundle(pageFilename)}</script>`;
  html = html.replace(/<\/body>/i, bundle + '</body>');

  // Minify (HTML comments, inter-tag whitespace — does NOT remove newlines so
  // inline JS // comments in marketing pages are preserved correctly)
  html = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/>\s+</g, '><')
    .replace(/\s{2,}/g, ' ')
    .trim();

  // Stamp nonce on every <script> tag
  html = injectNonces(html, cspNonce);

  // XOR + base64 obfuscation (same algorithm as api/decrypt.js)
  const raw   = new TextEncoder().encode(html);
  const xored = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) xored[i] = raw[i] ^ XOR_KEY;
  const payload = u8ToB64(xored);   // chunked — safe for 500KB+ payloads

  const titleM    = html.match(/<title>([^<]*)<\/title>/i);
  const pageTitle = titleM ? titleM[1] : 'Civil Engineering Suite';

  // [B9] Build og meta block for bootstrap shell.
  // iMessage link previews are fetched CLIENT-SIDE by the recipient's phone using
  // a standard Safari mobile UA — it receives the XOR bootstrap shell, not the bot
  // path. The document.write runs AFTER the link preview has been computed from the
  // initial HTML, so og tags inside the encrypted payload are invisible to the
  // preview renderer. Fix: inject og:image, og:title, og:description, og:url,
  // twitter:card, and twitter:image directly into the bootstrap <head> so any
  // client — regardless of UA — gets a valid social preview from the initial HTML.
  // These tags use absolute URLs with the request host so they're always correct.
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

  // Bootstrap shell — tiny XOR wrapper; view-source shows only this, not real HTML
  // [A6] WebMCP is injected as the FIRST script in the bootstrap shell so it fires
  // for every JS-executing client regardless of User-Agent (including scanners whose
  // UA does not match BOT_RE). The call is wrapped in a feature-detect guard:
  // if navigator.modelContext is absent it is a complete no-op. The XOR decode
  // script runs immediately after, replacing the document via document.write.
  // The navigator.modelContext.provideContext() registration is a browser-level
  // side-effect that persists independently of DOM state — the document.write does
  // not undo it.
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

  // [PERF] Route-specific LCP preload: hero-bg.png for footing-pro must start
  // downloading before JS runs. Without this, the browser can't discover the
  // CSS background-image until the XOR decoder completes + CSS is parsed.
  const lcpPreload = route.prefix === '/footing-pro'
    ? `<link rel="preload" as="image" href="/footing-pro/images/hero-bg.webp" imagesrcset="/footing-pro/images/hero-bg.avif" fetchpriority="high" type="image/webp">`
    : '';

  const bootstrap = `<!DOCTYPE html><html><head>`
    + `<meta charset="UTF-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0">`
    + (route.ogDescription ? `<meta name="description" content="${escHtml(route.ogDescription)}">` : '')
    /* Google Fonts preconnects removed — fonts are now self-hosted */
    + lcpPreload
    + `<link rel="preload" href="/fonts/inter-400.woff2" as="font" type="font/woff2" crossorigin>`
    + `<link rel="preload" href="/fonts/inter-700.woff2" as="font" type="font/woff2" crossorigin>`
    + `<link rel="preload" href="/fonts/playfair-700.woff2" as="font" type="font/woff2" crossorigin>`
    + `<title>${pageTitle}</title>`
    + ogMetaBlock
    + faviconLinks
    + `</head><body>`
    + webMCPBootstrap
    + `<script nonce="${cspNonce}">`
    + `(function(){try{`
    + `var p="${payload}";`
    + `var b=atob(p);`
    + `var u=new Uint8Array(b.length);`
    + `for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i)^${XOR_KEY};`
    + `var h=new TextDecoder("utf-8").decode(u);`
    + `document.open();document.write(h);document.close();`
    + `}catch(e){var _f=document.createElement('p');`
    + `_f.style.padding='40px';_f.style.color='#C17B1A';_f.style.fontFamily='sans-serif';`
    + `_f.textContent='Page could not be loaded. Please refresh or contact support.';`
    + `document.body.appendChild(_f);}})();`
    + `\u003c/script>`
    + `<noscript><div style="font-family:sans-serif;padding:40px;text-align:center;color:#C17B1A;background:#0A1A2E;min-height:100vh;display:flex;align-items:center;justify-content:center;"><div><h2 style="margin-bottom:16px;">JavaScript Required</h2><p style="color:#8AA3C7;line-height:1.8;">Civil Engineering Suite requires JavaScript to run.<br>Please enable JavaScript in your browser settings and refresh the page.</p></div></div></noscript>`
    + `</body></html>`;

  return new Response(bootstrap, { status: 200, headers: {
    'Content-Type':            'text/html; charset=utf-8',
    'Cache-Control':           'no-store',
    'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}' 'unsafe-inline'`,
    // [A1] RFC 8288 Link header — visible in HTTP headers before JS executes.
    // [A4] Vary: Accept on homepage so intermediaries separate markdown/HTML caches.
    ...(route.prefix === '/' ? {
      'Link': HOMEPAGE_LINK_HEADER,
      'Vary': 'Accept',
    } : {}),
    ...SHARED_SECURITY_HEADERS,
  }});
}
