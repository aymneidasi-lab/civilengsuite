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
  },
  {
    prefix: '/footing-pro',
    encFile: 'footing_pro.enc',
    baseHref: '/footing-pro/',
    pageFilename: 'footing-pro.html',
    faviconLinks: '<link rel="icon" type="image/png" sizes="32x32"   href="/footing-pro/images/favicon-32.png">'
                + '<link rel="icon" type="image/png" sizes="192x192" href="/footing-pro/images/favicon-192.png">'
                + '<link rel="apple-touch-icon" sizes="180x180"      href="/footing-pro/images/apple-touch-icon.png">',
  },
  {
    prefix: '/column-pro',
    encFile: 'column_pro.enc',
    baseHref: '/column-pro/',
    pageFilename: 'column-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
  },
  {
    prefix: '/beam-pro',
    encFile: 'beam_pro.enc',
    baseHref: '/beam-pro/',
    pageFilename: 'beam-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
  },
  {
    prefix: '/deflection-pro',
    encFile: 'deflection_pro.enc',
    baseHref: '/deflection-pro/',
    pageFilename: 'deflection-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
  },
  {
    prefix: '/earthquake-pro',
    encFile: 'earthquake_pro.enc',
    baseHref: '/earthquake-pro/',
    pageFilename: 'earthquake-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
  },
  {
    prefix: '/mur-pro',
    encFile: 'mur_pro.enc',
    baseHref: '/mur-pro/',
    pageFilename: 'mur-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
  },
  {
    prefix: '/add-reft-pro',
    encFile: 'add_reft_pro.enc',
    baseHref: '/add-reft-pro/',
    pageFilename: 'add-reft-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
  },
  {
    prefix: '/section-property-pro',
    encFile: 'section_property_pro.enc',
    baseHref: '/section-property-pro/',
    pageFilename: 'section-property-pro.html',
    faviconLinks: '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">',
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
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self' https://civilengsuite.is-a.dev",
  "upgrade-insecure-requests",
  "report-uri /api/csp-report",
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
  // Equivalent to: <script...> [content that never includes </script>] MARKER [same] </script>
  function safeScriptRe(marker) {
    return new RegExp(
      '<script\\b[^>]*>(?:(?!<\\/script>)[\\s\\S])*?' + marker + '(?:(?!<\\/script>)[\\s\\S])*?<\\/script>',
      'gi'
    );
  }

  // [B1] "CONTENT PROTECTION SYSTEM" — the main protection IIFE (~180 lines).
  // Present in both homepage and footing-pro. Contains setInterval DevTools loop.
  html = html.replace(safeScriptRe('CONTENT PROTECTION SYSTEM'), '');

  // [B2] "© Footing Pro v.2026 - Eng. Aymn Asi - All Rights Reserved" — the
  // secondary protection IIFE with Disable Right-Click / keyboard shortcuts.
  // Comment appears verbatim as first line of the script block.
  // Note: © is U+00A9, escaped as \\u00A9 in the regex string.
  html = html.replace(safeScriptRe('\u00A9 Footing Pro v\\.2026 - Eng\\. Aymn Asi - All Rights Reserved'), '');

  // [B3] "© Footing Pro v.2026 - Eng. Aymn Asi - Protected" — the obfuscated
  // atob-encoded protection block (footing-pro only, ~5 lines).
  html = html.replace(safeScriptRe('\u00A9 Footing Pro v\\.2026 - Eng\\. Aymn Asi - Protected'), '');

  // [B4] "_CES_COPYRIGHT_HTML" — the showSaveFilePicker override that intercepts
  // Ctrl+S. Present in both homepage and footing-pro.
  html = html.replace(safeScriptRe('_CES_COPYRIGHT_HTML'), '');

  // [B5] "FOOTING PRO v.2026 — ENGINE TRANSFER + SECURITY UPGRADE" — the
  // footing-pro download engine bundled with DevTools + MutationObserver code.
  // PATTERN SAFETY: the em dash (U+2014, —) makes this pattern unique to the
  // footing-pro protection script. The homepage NAV script has "ENGINE TRANSFER
  // SYSTEM" with no em dash or "FOOTING PRO v.2026" prefix.
  html = html.replace(safeScriptRe('FOOTING PRO v\\.2026 \u2014 ENGINE TRANSFER'), '');

  // [B7] Remove oncontextmenu attribute from <body> tag (inline event handler
  // that blocks right-click; irrelevant for bots, wastes parse time).
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
      // Strip CSS block comments /* … */
      .replace(/\/\*[\s\S]*?\*\//g, '')
      // Collapse runs of whitespace (spaces, tabs, newlines) to single space
      .replace(/\s+/g, ' ')
      // Remove spaces around CSS structural characters
      .replace(/\s*([{};,])\s*/g, '$1')
      // Remove space after colon ONLY in property declarations (not in :root, ::before etc.)
      // Strategy: remove space after colon when preceded by a word character
      .replace(/(\w)\s*:\s*/g, '$1:')
      // Trim leading/trailing whitespace
      .trim();
    return `<style${attrs}>${minified}</style>`;
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
  //      Payment API routes are dedicated CF Pages Functions in
  //      functions/api/payment/*.js which take routing precedence over this
  //      catch-all by Cloudflare's function routing rules, but the passthrough
  //      here is an explicit defensive guard.
  const STATIC_PASSTHROUGH = /^\/(?:sitemap\.xml|robots\.txt|manifest\.json|favicon\.ico|og-image\.png|google[0-9a-f]+\.html|\.well-known\/.*|payment(?:\/.*)?|api\/payment\/.*)$/i;
  if (STATIC_PASSTHROUGH.test(path)) return context.next();

  // ── Route matching: exact app root paths only ─────────────────────────────
  // Strip trailing slashes first (done above), then require the path to be
  // exactly equal to the route prefix — nothing more, nothing less.
  // This means /footing-pro/images/screenshot.png is NOT matched and falls
  // through to context.next() so Cloudflare serves it as a static asset.
  const route = (path === '' || path === '/' || path === '/index.html')
    ? ROUTES[0]
    : ROUTES.slice(1).find(r => path === r.prefix);

  // Not an encrypted route → serve static file / apply _redirects
  if (!route) return context.next();

  const { encFile, baseHref, faviconLinks, pageFilename } = route;

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

    // [F3] FIX: /footing-pro/og-image.png has no _redirects entry → 404.
    // Rewrite to the correct path served by /footing-pro/images/* redirect.
    botHtml = botHtml.replace(
      /(https?:\/\/[^"']+)\/footing-pro\/og-image\.png/gi,
      '$1/footing-pro/images/og-image.png'
    );

    // [F2] FIX: Strip the body-hiding noscript style that blinds Googlebot's
    // first-pass HTML-only crawl. Matches both homepage and footing-pro variants.
    // SECURITY-SAFE: only touches the <noscript> fallback, zero impact on JS paths.
    botHtml = botHtml.replace(
      /(<noscript>)\s*<style>[^<]*?body\s*\{[^}]*?display\s*:\s*none[^}]*?\}[^<]*?<\/style>/gi,
      '$1'
    );

    // [B1–B5, B7] Strip all inline protection scripts and inline event handlers.
    // These add ~200 KB of JS that Googlebot must parse before reaching content.
    // SECURITY-SAFE: only modifies botHtml (local variable), human path untouched.
    botHtml = stripProtectionScripts(botHtml);

    // [B6] Minify all inline <style> blocks.
    // Reduces CSS from ~120 KB raw to ~55 KB minified — faster crawl rendering.
    botHtml = minifyBotCSS(botHtml);

    // Inject nonces into remaining scripts (JSON-LD, translation, navigation)
    botHtml = injectNonces(botHtml, cspNonce);

    return new Response(botHtml, { status: 200, headers: {
      'Content-Type':            'text/html; charset=utf-8',
      // [F5] private prevents CDN from caching decrypted HTML and serving to humans
      'Cache-Control':           'private, max-age=3600, must-revalidate',
      // [F4] Vary:User-Agent belt-and-suspenders: CDN must not merge bot/human caches
      'Vary':                    'User-Agent',
      'X-Robots-Tag':            'index, follow',
      'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}'`,
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

  // Bootstrap shell — tiny XOR wrapper; view-source shows only this, not real HTML
  const bootstrap = `<!DOCTYPE html><html><head>`
    + `<meta charset="UTF-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0">`
    + `<meta name="robots" content="noindex">`
    + `<title>${pageTitle}</title>`
    + `${faviconLinks}`
    + `</head><body>`
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
    'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}'`,
    ...SHARED_SECURITY_HEADERS,
  }});
}
