/**
 * Civil Engineering Suite — Cloudflare Pages Function
 * FINAL v4.1 — Safe property access, no runtime exceptions
 *
 * FIX: Replaced optional chaining with safe guard to prevent Worker 1101 errors.
 * All other logic unchanged.
 */

// ── Bot / crawler UA pattern (expanded coverage) ─────────────────────────────
const BOT_UA_PATTERN = /googlebot|googlebot-image|google-inspectiontool|googleother|adsbot-google|bingbot|yandexbot|duckduckbot|baiduspider|applebot|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|slackbot|discordbot|perplexitybot|ia_archiver/i;

/**
 * Determine if the request is from a legitimate search engine crawler.
 * Uses Cloudflare Bot Management when available, falling back to User‑Agent.
 * SAFE VERSION: no optional chaining, guards against missing `cf` object.
 */
function isVerifiedBot(request) {
  try {
    // Primary: Cloudflare's verified bot flag (most reliable)
    if (request.cf && request.cf.bot_management && request.cf.bot_management.verified_bot === true) {
      return true;
    }
  } catch (e) {
    // Ignore errors accessing cf object – fall back to UA
  }

  // Secondary: User‑Agent pattern match
  const ua = request.headers.get('User-Agent') || '';
  return BOT_UA_PATTERN.test(ua);
}

// ── Route table — exact app root paths only ───────────────────────────────────
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

// ── CSP common ────────────────────────────────────────────────────────────────
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
  "form-action 'self'",
  "upgrade-insecure-requests",
  "report-uri /api/csp-report",
].join('; ');

// ── Shared security headers (applied to ALL responses) ────────────────────────
const SHARED_SECURITY_HEADERS = {
  'X-Content-Type-Options':          'nosniff',
  'X-Frame-Options':                 'DENY',
  'Strict-Transport-Security':       'max-age=31536000; includeSubDomains; preload',
  'Referrer-Policy':                 'strict-origin-when-cross-origin',
  // ambient-light-sensor REMOVED — causes console warning in Chrome
  'Permissions-Policy':              'camera=(), microphone=(), geolocation=(), payment=(), accelerometer=(), gyroscope=(), magnetometer=(), usb=(), display-capture=(), screen-wake-lock=(), autoplay=(), clipboard-read=()',
  'Cross-Origin-Opener-Policy':      'same-origin',
  'X-DNS-Prefetch-Control':          'off',
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

// ── AES-256-GCM decrypt using Web Crypto (with robust error handling) ─────────
async function decryptEnc(encData, keyHex) {
  const dot = encData.indexOf('.');
  if (dot === -1) throw new Error('Bad .enc format: missing dot separator');
  const ivB64 = encData.slice(0, dot);
  const ctB64 = encData.slice(dot + 1);
  if (!ivB64 || !ctB64) throw new Error('Bad .enc format: empty IV or ciphertext');

  let iv, ct;
  try {
    iv = b64ToU8(ivB64);
    ct = b64ToU8(ctB64);
  } catch (e) {
    throw new Error(`Base64 decode failed: ${e.message}`);
  }

  const keyBytes = hexToU8(keyHex);
  let key;
  try {
    key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  } catch (e) {
    throw new Error(`Key import failed: ${e.message}`);
  }

  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      key,
      ct
    );
    return new TextDecoder().decode(pt);
  } catch (e) {
    throw new Error(`WebCrypto decrypt failed: ${e.message}`);
  }
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

// ── Strip protection scripts from bot HTML ────────────────────────────────────
function stripProtectionScripts(html) {
  // Patterns are anchored to unique comment strings present ONLY in protection scripts.
  // Each pattern uses lazy matching to stop at the FIRST </script> after the marker.

  // "CONTENT PROTECTION SYSTEM" — main protection IIFE (homepage & footing-pro)
  html = html.replace(
    /<script\b[^>]*>[\s\S]*?CONTENT PROTECTION SYSTEM[\s\S]*?<\/script>/gi,
    ''
  );

  // "© Footing Pro v.2026 - Eng. Aymn Asi - All Rights Reserved" — secondary protection
  html = html.replace(
    /<script\b[^>]*>[\s\S]*?© Footing Pro v\.2026 - Eng\. Aymn Asi - All Rights Reserved[\s\S]*?<\/script>/gi,
    ''
  );

  // "© Footing Pro v.2026 - Eng. Aymn Asi - Protected" — obfuscated atob block
  html = html.replace(
    /<script\b[^>]*>[\s\S]*?© Footing Pro v\.2026 - Eng\. Aymn Asi - Protected[\s\S]*?<\/script>/gi,
    ''
  );

  // "_CES_COPYRIGHT_HTML" — showSaveFilePicker override (Ctrl+S intercept)
  html = html.replace(
    /<script\b[^>]*>[\s\S]*?_CES_COPYRIGHT_HTML[\s\S]*?<\/script>/gi,
    ''
  );

  // "FOOTING PRO v.2026 — ENGINE TRANSFER" — footing-pro specific protection
  html = html.replace(
    /<script\b[^>]*>[\s\S]*?FOOTING PRO v\.2026 — ENGINE TRANSFER[\s\S]*?<\/script>/gi,
    ''
  );

  // Remove oncontextmenu attribute from <body> tag (inline right‑click blocker)
  html = html.replace(/<body([^>]*)\soncontextmenu="[^"]*"/gi, '<body$1');

  return html;
}

// ── Minify inline <style> blocks for bot response ─────────────────────────────
function minifyBotCSS(html) {
  return html.replace(/<style([^>]*)>([\s\S]*?)<\/style>/gi, (match, attrs, css) => {
    const minified = css
      .replace(/\/\*[\s\S]*?\*\//g, '')   // strip CSS comments
      .replace(/\s+/g, ' ')               // collapse whitespace
      .replace(/\s*([{};,])\s*/g, '$1')   // remove spaces around structural chars
      .replace(/(\w)\s*:\s*/g, '$1:')     // remove space after colon in declarations
      .trim();
    return `<style${attrs}>${minified}</style>`;
  });
}

// ── Wrap remaining scripts in try/catch to prevent render halts ───────────────
function wrapScriptsWithErrorHandling(html) {
  return html.replace(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi, (match, attrs, code) => {
    // Skip JSON-LD (type="application/ld+json")
    if (/type=["']application\/ld\+json["']/i.test(attrs)) return match;
    // Skip empty scripts
    if (!code.trim()) return match;
    const wrappedCode = `try{${code}}catch(e){console.warn('[CES] Script error (non‑critical):',e);}`;
    return `<script${attrs}>${wrappedCode}</script>`;
  });
}

// ── Client-side protection bundle (for HUMAN browsers ONLY) ───────────────────
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

// ── Main request handler ──────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;
  const url  = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';

  // ── Pass through static/SEO files ───────────────────────────────────────────
  const STATIC_PASSTHROUGH = /^\/(?:sitemap\.xml|robots\.txt|manifest\.json|favicon\.ico|og-image\.png|google[0-9a-f]+\.html|\.well-known\/.*)$/i;
  if (STATIC_PASSTHROUGH.test(path)) return context.next();

  // ── Route matching: exact app root paths only ───────────────────────────────
  const route = (path === '' || path === '/' || path === '/index.html')
    ? ROUTES[0]
    : ROUTES.slice(1).find(r => path === r.prefix);

  if (!route) return context.next();

  const { encFile, baseHref, faviconLinks, pageFilename } = route;

  // ── Validate key ───────────────────────────────────────────────────────────
  const keyHex = (env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64) {
    return errResponse(500, 'Config Error', 'CES_DECRYPT_KEY missing or invalid.');
  }

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
    // For verified bots, serve a lightweight 503 page so Google retries later.
    if (isVerifiedBot(request)) {
      const fallbackHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${route.prefix === '/' ? 'Civil Engineering Suite' : route.prefix.slice(1)}</title></head><body><h1>Content Temporarily Unavailable</h1><p>Please try again in a few minutes.</p></body></html>`;
      return new Response(fallbackHtml, {
        status: 503,
        headers: { 'Content-Type': 'text/html', ...SHARED_SECURITY_HEADERS }
      });
    }
    return errResponse(500, 'Server Error', 'A configuration error occurred.');
  }

  // ── Inject base href ───────────────────────────────────────────────────────
  html = html.replace(/(<head[^>]*>)/i, `$1<base href="${baseHref}">`);

  // ── Per-request nonce ──────────────────────────────────────────────────────
  const cspNonce = generateNonce();

  // ═══════════════════════════════════════════════════════════════════════════
  // BOT PATH — Ultra‑clean, lightweight HTML served to crawlers
  // ═══════════════════════════════════════════════════════════════════════════
  if (isVerifiedBot(request)) {
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

    // Fix /footing-pro/og-image.png → /footing-pro/images/og-image.png
    botHtml = botHtml.replace(
      /(https?:\/\/[^"']+)\/footing-pro\/og-image\.png/gi,
      '$1/footing-pro/images/og-image.png'
    );

    // Strip the body‑hiding noscript style
    botHtml = botHtml.replace(
      /(<noscript>)\s*<style>[^<]*?body\s*\{[^}]*?display\s*:\s*none[^}]*?\}[^<]*?<\/style>/gi,
      '$1'
    );

    // Remove all protection scripts (right‑click blockers, DevTools detection, etc.)
    botHtml = stripProtectionScripts(botHtml);

    // Minify inline CSS (reduces payload size for faster crawl rendering)
    botHtml = minifyBotCSS(botHtml);

    // Wrap remaining scripts in try/catch to prevent unhandled exceptions
    botHtml = wrapScriptsWithErrorHandling(botHtml);

    // Inject nonces into remaining scripts (JSON‑LD, translation, navigation)
    botHtml = injectNonces(botHtml, cspNonce);

    return new Response(botHtml, {
      status: 200,
      headers: {
        'Content-Type':            'text/html; charset=utf-8',
        'Cache-Control':           'private, max-age=3600, must-revalidate',
        'Vary':                    'User-Agent',
        'X-Robots-Tag':            'index, follow',
        'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}'`,
        ...SHARED_SECURITY_HEADERS,
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HUMAN PATH — Full protection active (unchanged)
  // ═══════════════════════════════════════════════════════════════════════════

  // Inject protection bundle at end of body
  const bundle = `<script nonce="${cspNonce}">${buildProtectionBundle(pageFilename)}</script>`;
  html = html.replace(/<\/body>/i, bundle + '</body>');

  // Minify HTML (comments, inter‑tag whitespace)
  html = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/>\s+</g, '><')
    .replace(/\s{2,}/g, ' ')
    .trim();

  // Stamp nonce on every <script> tag
  html = injectNonces(html, cspNonce);

  // XOR + base64 obfuscation (human path only)
  const raw   = new TextEncoder().encode(html);
  const xored = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) xored[i] = raw[i] ^ XOR_KEY;
  const payload = u8ToB64(xored);

  const titleM    = html.match(/<title>([^<]*)<\/title>/i);
  const pageTitle = titleM ? titleM[1] : 'Civil Engineering Suite';

  // Bootstrap shell — XOR wrapper
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

  return new Response(bootstrap, {
    status: 200,
    headers: {
      'Content-Type':            'text/html; charset=utf-8',
      'Cache-Control':           'no-store',
      'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}'`,
      ...SHARED_SECURITY_HEADERS,
    }
  });
}