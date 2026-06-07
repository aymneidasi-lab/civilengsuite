/**
Civil Engineering Suite — Cloudflare Pages Function
─────────────────────────────────────────────────────────────────────────────
Handles only exact encrypted page routes: /, /footing-pro, /beam-pro, etc.
Sub‑app images (e.g., /footing-pro/images/…) are NOT caught and will be
served as static files via _redirects.
Environment variables:
CES_DECRYPT_KEY — 64-character hex AES-256-GCM key (required)
CES_XOR_KEY     — 2-character hex XOR key (optional, default 0x5A)
*/

// ── Bot / crawler UA pattern ──────────────────────────────────────────────────
const BOT_RE = /googlebot|googlebot-image|google-inspectiontool|googleother|adsbot-google|bingbot|yandexbot|duckduckbot|baiduspider|applebot|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|slackbot|discordbot|perplexitybot|ia_archiver/i;

// ── Route table ─────────────────────────────────────────────────────────────
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
    faviconLinks: '<link rel="icon" type="image/png" sizes="32x32" href="/footing-pro/images/favicon-32.png">'
                + '<link rel="icon" type="image/png" sizes="192x192" href="/footing-pro/images/favicon-192.png">'
                + '<link rel="apple-touch-icon" sizes="180x180" href="/footing-pro/images/apple-touch-icon.png">',
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

// ── CSP common ───────────────────────────────────────────────────────────────
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

// ── Shared security headers ──────────────────────────────────────────────────
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

// ── Agent Discovery Link Header ──────────────────────────────────────────────
const HOMEPAGE_LINK_HEADER = [
  '</.well-known/api-catalog>; rel="api-catalog"',
  '</.well-known/agent-skills/index.json>; rel="https://agentskills.io/rel/skills-index"',
  '</.well-known/mcp/server-card.json>; rel="mcp-server-card"',
  '</.well-known/oauth-authorization-server>; rel="oauth-authorization-server"',
  '</.well-known/oauth-protected-resource>; rel="oauth-protected-resource"',
  '</.well-known/security.txt>; rel="security-policy"',
  '</sitemap.xml>; rel="sitemap"',
].join(', ');

// ── Static Markdown for Agents ───────────────────────────────────────────────
const HOMEPAGE_MARKDOWN = `# Civil Engineering Suite
Professional-grade ACI 318-compliant structural and civil engineering software by Eng. Aymn Asi — Structural Engineer.
Free. Offline. No installation required.
URL: https://civilengsuite.pages.dev/
Contact: aymneidasi@gmail.com
License: Proprietary (device-9locked personal license)
Standard: ACI 318-19

Applications
✅ Live Now
[Footing Pro v.2026](https://civilengsuite.pages.dev/footing-pro/)
Combined footing design application — the most advanced free tool of its kind.
Modules: 17 engineering calculation modules
Coverage: Rectangular combined footing · Trapezoidal combined footing · Strap footing
Checks: Soil pressure · Column load transfer · One-way shear · Punching shear · Flexural reinforcement · Development length · Load combinations
Platform: Microsoft Excel on Windows (single-file, no installation)
Mode: 100% offline after download
Languages: English + Arabic (عربي)
Price: Free (personal license required)

[Section Property Pro](https://civilengsuite.pages.dev/section-property-pro/)
Cross-section properties calculator — area, centroid, Ix/Iy, section modulus, radius of gyration.

🔧 In Development — Coming 2026
| App | Description |
| --- | --- |
| [Beam Pro](https://civilengsuite.pages.dev/beam-pro/) | ACI 318 RC beam design — shallow beam bending |
| [Column Pro](https://civilengsuite.pages.dev/column-pro/) | RC column design — P-M interaction, biaxial bending, slenderness, punching shear (17 sub-modules) |
| [Deflection Pro](https://civilengsuite.pages.dev/deflection-pro/) | ACI 318 deflection checks for RC beams and slabs |
| [Earthquake Pro](https://civilengsuite.pages.dev/earthquake-pro/) | Seismic design — base shear, lateral load distribution, structural period |
| [Mur Pro](https://civilengsuite.pages.dev/mur-pro/) | Ultimate Resistance Moment (Mur) — Egyptian Code (ECP) |
| [Add Reft Pro](https://civilengsuite.pages.dev/add-reft-pro/) | Additional reinforcement for flat slab openings |

Agent Discovery
API Catalog (RFC 9727): https://civilengsuite.pages.dev/.well-known/api-catalog
Agent Skills Index: https://civilengsuite.pages.dev/.well-known/agent-skills/index.json
MCP Server Card (SEP-1649): https://civilengsuite.pages.dev/.well-known/mcp/server-card.json
OAuth Resource Metadata (RFC 9728): https://civilengsuite.pages.dev/.well-known/oauth-protected-resource
Security Contact (RFC 9116): https://civilengsuite.is-a.dev/.well-known/security.txt
Sitemap: https://civilengsuite.pages.dev/sitemap.xml

Keywords
combined footing design · foundation design software · ACI 318 · structural engineering software · free civil engineering tools · footing calculator · reinforced concrete design · offline engineering software · Excel structural design · تصميم القواعد · برنامج تصميم الأساسات

© 2026 Civil Engineering Suite — Eng. Aymn Asi — All Rights Reserved.
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
  return new Response(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">` 
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
    return new RegExp('<script\\b[^>]*>(?:(?!<\\/script>)[\\s\\S])*?' + marker + '(?:(?!<\\/script>)[\\s\\S])*?<\\/script>', 'gi');
  }
  html = html.replace(safeScriptRe('CONTENT PROTECTION SYSTEM'), '');
  html = html.replace(safeScriptRe('\u00A9 Footing Pro v\.2026 - Eng\. Aymn Asi - All Rights Reserved'), '');
  html = html.replace(safeScriptRe('\u00A9 Footing Pro v\.2026 - Eng\. Aymn Asi - Protected'), '');
  html = html.replace(safeScriptRe('_CES_COPYRIGHT_HTML'), '');
  html = html.replace(safeScriptRe('FOOTING PRO v\.2026 — ENGINE TRANSFER'), '');
  html = html.replace(/<body([^>]*)\soncontextmenu="[^"]*"/gi, '<body$1');
  return html;
}

// ── Minify inline <style> blocks for bot response ─────────────────────────────
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

// ── WebMCP script for AI agents ───────────────────────────────────────────────
function buildWebMCPScript() {
  return `<script>(function(){if(!navigator.modelContext||typeof navigator.modelContext.provideContext!=='function')return;try{navigator.modelContext.provideContext({name:'civil-engineering-suite',description:'Civil Engineering Suite — Free ACI 318-19 structural engineering tools by Eng. Aymn Asi. Combined footing design, section properties, beam, column, deflection, seismic design.',tools:[{name:'open_footing_pro',description:'Open Footing Pro v.2026 — ACI 318-19 combined footing design. 17 modules: soil pressure, shear/moment diagrams, punching shear, flexural reinforcement, development length.',inputSchema:{type:'object',properties:{},required:[]},execute:function(){window.location.href='/footing-pro/';return{success:true,url:'/footing-pro/'};}},{name:'open_section_property_pro',description:'Open Section Property Pro — cross-section calculator. Computes area, centroid, Ix/Iy, section modulus, radius of gyration.',inputSchema:{type:'object',properties:{},required:[]},execute:function(){window.location.href='/section-property-pro/';return{success:true,url:'/section-property-pro/'};}},{name:'get_suite_info',description:'Returns structured metadata about all Civil Engineering Suite tools, their status, and agent discovery endpoints.',inputSchema:{type:'object',properties:{},required:[]},execute:function(){return{suite:'Civil Engineering Suite',author:'Eng. Aymn Asi',standard:'ACI 318-19',tools:[{name:'Footing Pro v.2026',url:'/footing-pro/',status:'live',modules:17},{name:'Section Property Pro',url:'/section-property-pro/',status:'live'},{name:'Beam Pro',url:'/beam-pro/',status:'coming-2026'},{name:'Column Pro',url:'/column-pro/',status:'coming-2026'},{name:'Deflection Pro',url:'/deflection-pro/',status:'coming-2026'},{name:'Earthquake Pro',url:'/earthquake-pro/',status:'coming-2026'},{name:'Mur Pro',url:'/mur-pro/',status:'coming-2026'},{name:'Add Reft Pro',url:'/add-reft-pro/',status:'coming-2026'}],agentDiscovery:{apiCatalog:'/.well-known/api-catalog',mcpServerCard:'/.well-known/mcp/server-card.json',agentSkills:'/.well-known/agent-skills/index.json',oauthResource:'/.well-known/oauth-protected-resource'}};}}]});}catch(e){}})();</script>`;
}

// ── Main request handler ──────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';

  // ── Always pass through static/SEO files ──────────────────────────────────
  const STATIC_PASSTHROUGH = /^\/(?:robots\.txt|manifest\.json|favicon\.ico|og-image\.png|images\/.*|footing-pro\/images\/.*|footing-pro\/engineers\/?.*|footing-pro\/offices\/?.*|footing-pro\/students\/?.*|beam-pro\/images\/.*|column-pro\/images\/.*|deflection-pro\/images\/.*|earthquake-pro\/images\/.*|mur-pro\/images\/.*|add-reft-pro\/images\/.*|section-property-pro\/images\/.*|google[0-9a-f]+\.html|sitemap\.xsl|fonts\/.*|\.well-known\/.*|payment(?:\/.*)?|api\/payment\/.*)$/i;
  if (STATIC_PASSTHROUGH.test(path)) return context.next();

  // ── Sitemap ───────────────────────────────────────────────────────────────
  if (path === '/sitemap.xml') {
    try {
      const sitemapResp = await env.ASSETS.fetch(new URL('/sitemap.xml', url.origin));
      if (!sitemapResp.ok) return new Response('Not Found', { status: 404 });
      const sitemapXml = await sitemapResp.text();
      return new Response(sitemapXml, {
        status: 200,
        headers: {
          'Content-Type': 'application/xml; charset=utf-8',
          'Cache-Control': 'public, max-age=3600, must-revalidate',
        },
      });
    } catch (e) {
      console.error('[ces:sitemap] ASSETS fetch error:', e.message);
      return new Response('Not Found', { status: 404 });
    }
  }

  // ── /download ─────────────────────────────────────────────────────────────
  if (path === '/download') {
    return new Response(null, {
      status: 302,
      headers: {
        'Location': 'https://drive.google.com/uc?export=download&id=1EQ6UaHvwrchiV0U5vRdXR5YktOZMnfrQ&confirm=t',
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
        'Content-Type': 'text/markdown; charset=utf-8',
        'x-markdown-tokens': tokenEstimate,
        'Vary': 'Accept',
        'Cache-Control': 'public, max-age=3600, must-revalidate',
        'Link': HOMEPAGE_LINK_HEADER,
        ...SHARED_SECURITY_HEADERS,
      },
    });
  }

  // ── Validate key ──────────────────────────────────────────────────────────
  const keyHex = (env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64)
    return errResponse(500, 'Config Error', 'CES_DECRYPT_KEY missing or invalid.');

  // ── XOR key ───────────────────────────────────────────────────────────────
  const xorHex = (env.CES_XOR_KEY || '').trim();
  const XOR_KEY = (xorHex.length === 2 && /^[0-9A-Fa-f]{2}$/.test(xorHex)) ? parseInt(xorHex, 16) : 0x5A;

  // ── Per-request nonce ─────────────────────────────────────────────────────
  const cspNonce = generateNonce();

  // ── Read .enc file ────────────────────────────────────────────────────────
  let encData;
  try {
    const encResp = await env.ASSETS.fetch(new URL(`/public/${encFile}`, url.origin));
    if (!encResp.ok) throw new Error(`HTTP ${encResp.status}`);
    encData = (await encResp.text()).trim();
  } catch (e) {
    console.error('[ces:decrypt] File read error:', encFile, e.message);
    return errResponse(500, 'Server Error', 'A configuration error occurred. Please try again later.');
  }

  // ── Decrypt ───────────────────────────────────────────────────────────────
  let html;
  try {
    html = await decryptEnc(encData, keyHex);
  } catch (e) {
    console.error('[ces:decrypt] Decryption failed for', encFile, '—', e.message);
    return errResponse(500, 'Server Error', 'A configuration error occurred. Please try again later.');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // [M2] MOBILE DOWNLOAD PROTECTION: DECRYPTED HTML ORIGIN GUARD (FIXED)
  // 1. PREPENDED: Guaranteed to run before any parsing, even if <head> is missing.
  // 2. BULLETPROOF CATCH: Uses document.documentElement.innerHTML to prevent
  //    silent TypeError crashes that previously allowed the original site to render.
  // ═══════════════════════════════════════════════════════════════════════════
  const _crPageTitle = html.match(/<title>([^<]*)<\/title>/i)?.[1] || 'Civil Engineering Suite';
  const _crRoutePrefix = route.prefix === '/' ? '' : route.prefix;
  const _crRouteUrl = `https://civilengsuite.pages.dev${_crRoutePrefix}/`;
  const _crRouteLabel = `civilengsuite.pages.dev${_crRoutePrefix}/`;

  const _crPageHtml =
    `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>© Protected — ${escHtml(_crPageTitle)}</title>` +
    `<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0A1A2E;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif;text-align:center;padding:24px}.card{max-width:440px}.icon{font-size:3.5rem;margin-bottom:18px}.title{color:#C17B1A;font-size:1.35rem;font-weight:700;margin-bottom:12px;line-height:1.4}.msg{color:#8AA3C7;font-size:0.9rem;line-height:1.8;margin-bottom:22px}a{color:#C17B1A;font-size:0.88rem;text-decoration:none}a:hover{text-decoration:underline}</style></head><body><div class="card"><div class="icon">&#x1F512;</div><div class="title">&#169; Eng. Aymn Asi &#8212; ${escHtml(_crPageTitle)}</div><div class="msg">Unauthorized copying is prohibited.<br>This page must be accessed from the official website.</div><a href="${_crRouteUrl}">${_crRouteLabel}</a></div></body></html>`;

  const _crB64 = u8ToB64(new TextEncoder().encode(_crPageHtml));

  const decryptedOriginGuard =
    `<script>(function(){'use strict';` +
    `var _o=(typeof window!=='undefined')?window.location.origin:'';` +
    `var _p=(typeof window!=='undefined')?window.location.protocol:'';` +
    `if(_o==='null'||_p==='file:'||_p==='blob:'||_p==='about:'){` +
      `try{` +
        `var _b='${_crB64}';` +
        `var _n=atob(_b);var _ba=new Uint8Array(_n.length);` +
        `for(var i=0;i<_n.length;i++)_ba[i]=_n.charCodeAt(i);` +
        `var _cr=new TextDecoder('utf-8').decode(_ba);` +
        `document.open();document.write(_cr);document.close();` +
      `}catch(e){` +
        `try{document.open();document.write('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Protected</title></head><body style="background:#0A1A2E;color:#C17B1A;font-family:sans-serif;text-align:center;padding:40px;"><h2 style="font-size:1.5rem;margin-bottom:12px;">&#169; Protected</h2><p style="color:#8AA3C7;">Unauthorized copying is prohibited.<br>This page must be accessed from the official website.</p></body></html>');document.close();}` +
        `catch(e2){if(document.documentElement){document.documentElement.innerHTML='<div style="background:#0A1A2E;color:#C17B1A;font-family:sans-serif;text-align:center;padding:40px;"><h2 style="font-size:1.5rem;margin-bottom:12px;">&#169; Protected</h2><p style="color:#8AA3C7;">Unauthorized copying is prohibited.<br>This page must be accessed from the official website.</p></div>';}}` +
      `}` +
    `}` +
    `})();<\/script>`;

  // PREPEND to guarantee execution regardless of HTML structure
  html = decryptedOriginGuard + html;

  // ── Inject base href ──────────────────────────────────────────────────────
  html = html.replace(/(<head[^>]*>)/i, `$1<base href="${baseHref}">`);

  // ── [V4-FAV] Inject favicon links ─────────────────────────────────────────
  if (faviconLinks && !/<link[^>]+rel=["'](?:icon|shortcut icon|apple-touch-icon)["']/i.test(html)) {
    html = html.replace(/(<\/head>)/i, `${faviconLinks}$1`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // BOT PATH
  // ═══════════════════════════════════════════════════════════════════════════
  const ua = request.headers.get('User-Agent') || '';
  if (BOT_RE.test(ua)) {
    const host = url.host;
    let botHtml = html;

    botHtml = botHtml.replace(/<meta\s+name="robots"\s+content="noindex[^"]*"/gi, '<meta name="robots" content="index, follow"');
    botHtml = botHtml.replace(/(<meta\s+(?:property|name)="(?:og:image|og:image:secure_url|twitter:image)"\s+content=")https:\/\/[^/]+(\/[^"]*")/gi, `$1https://${host}$2`);
    botHtml = botHtml.replace(/(https?:\/\/[^"']+)\/footing-pro\/og-image\.png/gi, '$1/footing-pro/images/og-image.png');

    botHtml = botHtml.replace(/(content="https?:\/\/[^"]+\/)og-image\.png"/gi, (match, prefix) => {
      if (/\/images\//.test(prefix)) return match;
      return `${prefix}images/og-image.png"`;
    });

    if (!/<meta[^>]+property="og:image:secure_url"/i.test(botHtml)) {
      botHtml = botHtml.replace(/(<meta[^>]+property="og:image"[^>]*\/?>)/i, (m) => {
        const urlMatch = m.match(/content="([^"]+)"/i);
        if (!urlMatch) return m;
        const imgUrl = urlMatch[1];
        return m + `<meta property="og:image:secure_url" content="${imgUrl}">`
                 + `<meta property="og:image:type" content="image/png">`
                 + `<meta property="og:image:width" content="1200">`
                 + `<meta property="og:image:height" content="630">`;
      });
    }

    botHtml = botHtml.replace(/(<noscript>)\s*<style>[^<]*?body\s*\{[^}]*?display\s*:\s*none[^}]*?\}[^<]*?<\/style>/gi, '$1');
    botHtml = stripProtectionScripts(botHtml);
    botHtml = minifyBotCSS(botHtml);
    botHtml = injectNonces(botHtml, cspNonce);
    botHtml = botHtml.replace(/<\/body>/i, injectNonces(buildWebMCPScript(), cspNonce) + '</body>');

    return new Response(botHtml, { status: 200, headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'private, max-age=3600, must-revalidate',
      'Vary': route.prefix === '/' ? 'User-Agent, Accept' : 'User-Agent',
      'X-Robots-Tag': 'index, follow',
      'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}' 'sha256-707X5+NAXR96e1UzENjwpPf416b6sJGW3mMwS4KSCqw=' 'sha256-9Z5YUtj2GDOBykVWUu8jxOyhx6HrrXGwO4FEHHSUtqQ=' 'unsafe-hashes' 'sha256-nAiI7XK5Mt/SgNQUZPqTuikvwxIVHV3se6mHGQue+88=' 'sha256-Jag+ZHPii6iUmMQWlnwms/mnjM8gRPTOJA2KIyTQQRk=' 'sha256-uLUdJIdD3+8SpL4nHNFN9YmyHRRmrseSQKwzj3ECn2I=' 'sha256-akyHNuxwVvvLQ11iHoDrpca0qH3TU3LfGbtdQ8kNdwI=' 'sha256-UOhLo4NRrWG89b3vpgtU0dc/C8aWLS+MQ2Lf9vW/4Fk=' 'sha256-jHF5hTIlMDyGZRAsNK0HO/WFYrwPvI2I1q0o1xKKB6I=' 'sha256-wflfhEeJWTAjAK0hnm9/OICxAQ8fVnj3168JrJ/m91k=' 'sha256-oTzV9+pQ7IAxC4NoAc7dH4+0Is4KloZ9u7cMJC7UDrE=' 'sha256-bTpi/7w0Cd8ihAWpwcZJIdz49sMq0d73fWWDzp5Ju2Q='`,
      'Link': HOMEPAGE_LINK_HEADER,
      ...SHARED_SECURITY_HEADERS,
    }});
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HUMAN PATH
  // ═══════════════════════════════════════════════════════════════════════════
  const bundle = `<script nonce="${cspNonce}">${buildProtectionBundle(pageFilename)}</script>`;
  html = html.replace(/<\/body>/i, bundle + '</body>');

  html = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/>\s+</g, '><')
    .replace(/\s{2,}/g, ' ')
    .trim();

  html = injectNonces(html, cspNonce);
  html = minifyBotCSS(html);

  const raw = new TextEncoder().encode(html);
  const xored = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) xored[i] = raw[i] ^ XOR_KEY;
  const payload = u8ToB64(xored);

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

  const webMCPBootstrap = `<script nonce="${cspNonce}">(function(){if(!navigator.modelContext||typeof navigator.modelContext.provideContext!=='function')return;try{navigator.modelContext.provideContext({name:'civil-engineering-suite',description:'Civil Engineering Suite — Free ACI 318-19 structural engineering tools by Eng. Aymn Asi.',tools:[{name:'open_footing_pro',description:'Footing Pro v.2026 — ACI 318-19 combined footing design, 17 modules.',inputSchema:{type:'object',properties:{},required:[]},execute:function(){window.location.href='/footing-pro/';return{success:true,url:'/footing-pro/'};}},{name:'open_section_property_pro',description:'Section Property Pro — area, centroid, Ix/Iy, section modulus, radius of gyration.',inputSchema:{type:'object',properties:{},required:[]},execute:function(){window.location.href='/section-property-pro/';return{success:true,url:'/section-property-pro/'};}},{name:'get_suite_info',description:'Returns metadata about all Civil Engineering Suite tools and agent discovery endpoints.',inputSchema:{type:'object',properties:{},required:[]},execute:function(){return{suite:'Civil Engineering Suite',author:'Eng. Aymn Asi',standard:'ACI 318-19',tools:[{name:'Footing Pro v.2026',url:'/footing-pro/',status:'live',modules:17},{name:'Section Property Pro',url:'/section-property-pro/',status:'live'},{name:'Beam Pro',url:'/beam-pro/',status:'coming-2026'},{name:'Column Pro',url:'/column-pro/',status:'coming-2026'},{name:'Deflection Pro',url:'/deflection-pro/',status:'coming-2026'},{name:'Earthquake Pro',url:'/earthquake-pro/',status:'coming-2026'},{name:'Mur Pro',url:'/mur-pro/',status:'coming-2026'},{name:'Add Reft Pro',url:'/add-reft-pro/',status:'coming-2026'}],agentDiscovery:{apiCatalog:'/.well-known/api-catalog',mcpServerCard:'/.well-known/mcp/server-card.json',agentSkills:'/.well-known/agent-skills/index.json',oauthServer:'/.well-known/oauth-authorization-server',oauthResource:'/.well-known/oauth-protected-resource'}};}}]});}catch(e){}})();</script>`;

  const lcpPreload = route.prefix === '/footing-pro'
    ? '<link rel="preload" as="image" href="/footing-pro/images/hero-bg.avif" imagesrcset="/footing-pro/images/hero-bg.avif 1x,/footing-pro/images/hero-bg.webp 1x" imagesizes="100vw" fetchpriority="high">'
    : '';

  // [M1a] Bootstrap origin guard
  const bootstrapOriginGuard =
    `<script nonce="${cspNonce}">(function(){'use strict';` +
    `var _ao='https://civilengsuite.pages.dev';` +
    `var _o=(typeof window!=='undefined')?window.location.origin:'';` +
    `var _dev=/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(_o);` +
    `if(_o!==_ao&&!_dev){` +
      `var _b='${_crB64}';` +
      `var _n=atob(_b);var _ba=new Uint8Array(_n.length);` +
      `for(var i=0;i<_n.length;i++)_ba[i]=_n.charCodeAt(i);` +
      `var _cr=new TextDecoder('utf-8').decode(_ba);` +
      `try{document.open();document.write(_cr);document.close();}` +
      `catch(e){` +
        `try{document.open();document.write('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Protected</title></head><body style="background:#0A1A2E;color:#C17B1A;font-family:sans-serif;text-align:center;padding:40px;"><h2 style="font-size:1.5rem;margin-bottom:12px;">&#169; Protected</h2><p style="color:#8AA3C7;">Unauthorized copying is prohibited.<br>This page must be accessed from the official website.</p></body></html>');document.close();}` +
        `catch(e2){window.location.replace(_ao+'${_crRoutePrefix}/');}` +
      `}` +
    `}` +
    `})();<\/script>`;

  // [M1b] Bootstrap copyright body
  const bootstrapCopyrightBody =
    `<style>#_ces_cr_body{display:none;margin:0;background:#0A1A2E;color:#C17B1A;font-family:sans-serif;align-items:center;justify-content:center;min-height:100vh;text-align:center;position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483647}</style>` +
    `<noscript><style>#_ces_cr_body{display:flex!important}</style></noscript>` +
    `<div id="_ces_cr_body"><div style="padding:40px;max-width:440px"><div style="font-size:3.5rem;margin-bottom:18px">&#x1F512;</div>` +
    `<h2 style="font-size:1.35rem;font-weight:700;margin-bottom:12px;line-height:1.4">&#169; Eng. Aymn Asi &#8212; ${escHtml(_crPageTitle)}</h2>` +
    `<p style="color:#8AA3C7;font-size:0.9rem;line-height:1.8;margin-bottom:22px">Unauthorized copying is prohibited.<br>This page must be accessed from the official website.</p>` +
    `<a href="${_crRouteUrl}" style="color:#C17B1A;font-size:0.88rem">${_crRouteLabel}</a></div></div>`;

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
    + `<title>${_crPageTitle}</title>`
    + ogMetaBlock
    + faviconLinks
    + bootstrapOriginGuard
    + `</head><body>`
    + bootstrapCopyrightBody
    + webMCPBootstrap
    + `<script nonce="${cspNonce}">(function(){try{var p="${payload}";var b=atob(p);var u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i)^${XOR_KEY};var h=new TextDecoder("utf-8").decode(u);document.open();document.write(h);document.close();}catch(e){var _f=document.createElement('p');_f.style.padding='40px';_f.style.color='#C17B1A';_f.style.fontFamily='sans-serif';_f.textContent='Page could not be loaded. Please refresh or contact support.';document.body.appendChild(_f);}})();<\/script>`
    + `</body></html>`;

  return new Response(bootstrap, { status: 200, headers: {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}' 'sha256-707X5+NAXR96e1UzENjwpPf416b6sJGW3mMwS4KSCqw=' 'sha256-9Z5YUtj2GDOBykVWUu8jxOyhx6HrrXGwO4FEHHSUtqQ=' 'unsafe-hashes' 'sha256-nAiI7XK5Mt/SgNQUZPqTuikvwxIVHV3se6mHGQue+88=' 'sha256-Jag+ZHPii6iUmMQWlnwms/mnjM8gRPTOJA2KIyTQQRk=' 'sha256-uLUdJIdD3+8SpL4nHNFN9YmyHRRmrseSQKwzj3ECn2I=' 'sha256-akyHNuxwVvvLQ11iHoDrpca0qH3TU3LfGbtdQ8kNdwI=' 'sha256-UOhLo4NRrWG89b3vpgtU0dc/C8aWLS+MQ2Lf9vW/4Fk=' 'sha256-jHF5hTIlMDyGZRAsNK0HO/WFYrwPvI2I1q0o1xKKB6I=' 'sha256-wflfhEeJWTAjAK0hnm9/OICxAQ8fVnj3168JrJ/m91k=' 'sha256-oTzV9+pQ7IAxC4NoAc7dH4+0Is4KloZ9u7cMJC7UDrE=' 'sha256-bTpi/7w0Cd8ihAWpwcZJIdz49sMq0d73fWWDzp5Ju2Q='`,
    ...(route.prefix === '/' ? {
      'Link': HOMEPAGE_LINK_HEADER,
      'Vary': 'Accept',
    } : {}),
    ...SHARED_SECURITY_HEADERS,
  }});
}
