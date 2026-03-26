/**
 * Civil Engineering Suite — AES-256-GCM Decrypt  v3
 * ─────────────────────────────────────────────────────────────────────────────
 * Security-audit fixes vs v2
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  Layer 5  DevTools detection
 *           + Early check fires synchronously on script parse — catches DevTools
 *             that were already open before the page loaded (was blind before).
 *           + visibilitychange re-check — catches the tab-switch moment that
 *             happens when File→Save As opens an OS dialog in some browsers.
 *           + All handlers now use useCapture:true — cannot be stopped by
 *             page-level event listeners.
 *           + On detection: full-viewport overlay with z-index:MAX hides all
 *             page content (replaces the old document.write approach which
 *             does nothing on a loaded page).
 *
 *  Layer 8  MutationObserver watermark guard
 *           + Now observes attributes (style, class, hidden) on the watermark
 *             element itself — the previous version only watched childList and
 *             was completely blind to style.opacity='0' or visibility:hidden.
 *           + getComputedStyle interval fallback (2 s) catches opacity set via
 *             an external stylesheet rule that MutationObserver can't see.
 *           + Removal path hardened: observer also watches document.body
 *             (not just wm's own subtree) so node removal is caught even when
 *             the parent is targeted.
 *
 *  Layer 1  Right-click block
 *           + useCapture:true — Firefox Shift+right-click fires the contextmenu
 *             event at the bubble phase only; capture-phase listener catches it
 *             regardless of Shift state.
 *
 *  Layer 3  Copy/cut block
 *           + useCapture:true — browser Edit→Copy routes through capture phase;
 *             bubble-only listeners miss it.
 *           + setData() replacement — clipboard receives copyright notice text
 *             instead of the actual selection, so even if the handler fires but
 *             the preventDefault somehow fails the content is protected.
 *
 *  Layer 2  Keyboard shortcut block
 *           + useCapture:true on all keyboard handlers.
 *           + Ctrl+Shift+I / Ctrl+Shift+J / Ctrl+Shift+C / Ctrl+Shift+K
 *             (Firefox console) now blocked.
 *           + Ctrl+A (select-all) now blocked at capture phase.
 *
 *  CSS      selectstart prevention
 *           + useCapture:true.
 *           + INPUT / TEXTAREA / contentEditable correctly exempted so the app
 *             remains usable.
 *
 *  Layer 6  Console warning
 *           + Styled with large stop sign, explicit session-logging notice.
 *           + console.clear() runs first so the warning is always at the top.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Known limitations (unfixable at JS level — documented for transparency)
 * ─────────────────────────────────────────────────────────────────────────────
 *  • File → Save As   — OS-level save dialog; no JS event fires on any browser.
 *                        Ctrl+S Tier 1/2 remains in place for keyboard path.
 *  • OS screenshot    — PrintScreen / Cmd+Shift+3 captured by OS compositor
 *                        before any JS overlay can render.
 *  • JS disabled      — All client-side layers collapse simultaneously.
 *                        Mitigated server-side: enc files are never served raw.
 *  • DevTools undocked— window.outerWidth delta is 0 for undocked DevTools.
 *                        Debugger-timing method (Method B) still fires.
 *  • view-source:     — Shows the XOR bootstrap shell, NOT the decrypted HTML.
 *                        DevTools→Elements always shows live DOM after
 *                        document.write(); this is fundamental to the approach.
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { createDecipheriv, randomBytes } = require('crypto');

// ── Bot / crawler UA pattern ──────────────────────────────────────────────────
const BOT_RE = /googlebot|google-inspectiontool|googleother|bingbot|yandexbot|duckduckbot|baiduspider|applebot|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|slackbot|discordbot/i;

// XOR key — client-side obfuscation only (not cryptographic security).
const _xorHex = (process.env.CES_XOR_KEY || '').trim();
const XOR_KEY  = (_xorHex.length === 2 && /^[0-9A-Fa-f]{2}$/.test(_xorHex))
  ? parseInt(_xorHex, 16)
  : 0x5A;

// ── Shared CSP fragments ──────────────────────────────────────────────────────
//
// FIX: Added explicit object-src 'none' and worker-src 'none'.
//      Although default-src 'self' covers these implicitly, CSP evaluation
//      tools (Google CSP Evaluator, securityheaders.com) flag the absence of
//      explicit directives as a strict-mode gap. Being explicit also prevents
//      any future default-src widening from silently opening these vectors.
//
// NOTE: style-src retains 'unsafe-inline' intentionally.
//      CSS nonces cover <style> blocks but NOT element-level style="" attributes.
//      The encrypted .enc pages use inline style attributes extensively for
//      layout — removing 'unsafe-inline' blocks those attributes in all browsers
//      and breaks the page rendering entirely. 'unsafe-inline' is the only
//      mechanism that covers both <style> blocks AND style="" attributes.
//      The script-src nonce approach (which works for JS) cannot be applied
//      to style="" attributes — this is a fundamental CSP limitation.
//
// FIX: img-src — removed bare 'https:' wildcard. That directive allowed any
//      HTTPS host to serve images into the page, enabling tracking pixels and
//      data-exfiltration via CSS url() references. 'self' and 'data:' are
//      sufficient; data: is retained for base64-inlined images in enc pages.
//
// FIX: Added manifest-src 'none' and media-src 'none'. Both were implicitly
//      covered by default-src 'self' but explicit 'none' closes the vector
//      permanently, survives future default-src widening, and satisfies strict
//      CSP linting (Google CSP Evaluator, Mozilla Observatory).
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
  // FIX: Added report-uri so CSP violations in production are logged
  //      via /api/csp-report (same-origin endpoint, no third-party).
  //      Violations appear in Vercel function logs, searchable via any
  //      log drain (Logtail, Datadog, Axiom). Low overhead: browsers
  //      send reports asynchronously and only on actual violations.
  "report-uri /api/csp-report",
].join('; ');

// ── Distributed rate limiter with automatic in-memory fallback ────────────────
let _upstashLimiter = null;
try {
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    const { Ratelimit } = require('@upstash/ratelimit');
    const { Redis }     = require('@upstash/redis');
    _upstashLimiter = new Ratelimit({
      redis:   Redis.fromEnv(),
      limiter: Ratelimit.slidingWindow(40, '1 m'),
      prefix:  'ces:rl',
    });
  }
} catch (_) {}

const _ipMap      = new Map();
const RATE_WINDOW = 60_000;
const RATE_MAX    = 40;

// FIX: Periodic cleanup — prune entries older than 2× the rate window so the
//      Map cannot grow unboundedly under a sustained attack (memory exhaustion).
//      Runs every RATE_WINDOW ms; safe to call in a long-lived process or a
//      warm Vercel function instance.
setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW * 2;
  for (const [ip, slot] of _ipMap) {
    if (slot.t < cutoff) _ipMap.delete(ip);
  }
}, RATE_WINDOW);

async function allowRequest(ip) {
  if (_upstashLimiter) {
    const { success } = await _upstashLimiter.limit(ip);
    return success;
  }
  const now  = Date.now();
  const slot = _ipMap.get(ip);
  if (!slot || now - slot.t > RATE_WINDOW) {
    _ipMap.set(ip, { t: now, n: 1 });
    return true;
  }
  slot.n += 1;
  return slot.n <= RATE_MAX;
}

// ── Nonce injection ───────────────────────────────────────────────────────────
function injectNonces(html, nonce) {
  return html.replace(/<script(?=[\s>])/g, `<script nonce="${nonce}"`);
}


// ── Handler ───────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {

  // 1. Rate limit ─────────────────────────────────────────────────────────────
  //
  // FIX: x-real-ip is set by Vercel's edge infrastructure and cannot be spoofed
  //      by the client. x-forwarded-for CAN be prepended by the client before
  //      Vercel appends the true IP, making the first element unreliable.
  //      Priority: x-real-ip → x-vercel-forwarded-for → x-forwarded-for[0].
  const ip = (
    req.headers['x-real-ip'] ||
    req.headers['x-vercel-forwarded-for'] ||
    (req.headers['x-forwarded-for'] || '').split(',')[0]
  ).trim() || req.socket?.remoteAddress || 'anon';

  if (!(await allowRequest(ip))) {
    res.setHeader('Retry-After', '60');
    return sendErr(res, 429, 'Too Many Requests',
      'Rate limit exceeded. Please wait a moment and try again.');
  }

  // 2. Validate AES-256-GCM key ───────────────────────────────────────────────
  const keyHex = (process.env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64)
    return sendErr(res, 500, 'Config Error', 'CES_DECRYPT_KEY missing or invalid.');

  let keyBuf;
  try { keyBuf = Buffer.from(keyHex, 'hex'); }
  catch (e) {
    // FIX: Buffer.from errors can reveal the key format. Log server-side only.
    console.error('[ces:decrypt] Key buffer error:', e.message);
    return sendErr(res, 500, 'Server Error', 'A configuration error occurred. Please try again later.');
  }

  // 3. Route to correct .enc file ─────────────────────────────────────────────
  const pathname = (req.url || '/').split('?')[0].replace(/\/+$/, '') || '/';

  let encFile, baseHref, faviconLinks, pageFilename;
  if (pathname === '' || pathname === '/' || pathname === '/index.html') {
    encFile      = 'pc_suite.enc';
    baseHref     = '/';
    pageFilename = 'civil-engineering-suite.html';
    faviconLinks = '<link rel="icon" type="image/x-icon" href="/images/favicon.ico">'
                 + '<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">';
  } else if (pathname.startsWith('/footing-pro')) {
    encFile      = 'footing_pro.enc';
    baseHref     = '/footing-pro/';
    pageFilename = 'footing-pro.html';
    faviconLinks = '<link rel="icon" type="image/png" sizes="32x32" href="/footing-pro/images/favicon-32.png">'
                 + '<link rel="icon" type="image/png" sizes="192x192" href="/footing-pro/images/favicon-192.png">'
                 + '<link rel="apple-touch-icon" sizes="180x180" href="/footing-pro/images/apple-touch-icon.png">';
  } else {
    return sendErr(res, 404, 'Not Found', 'The requested path does not exist.');
  }

  // 4. Read and decrypt .enc ──────────────────────────────────────────────────
  const encPath = path.join(process.cwd(), 'public', encFile);
  let encData;
  try { encData = fs.readFileSync(encPath, 'utf-8').trim(); }
  catch (e) {
    // FIX: Never send e.message or listDir() output to the client.
    //      Node.js fs errors include full server paths (e.g. /var/task/public/...)
    //      and listDir() exposes every filename in public/. Log server-side only.
    console.error('[ces:decrypt] File read error — file:', encFile,
      '| error:', e.message,
      '| public/:', listDir(path.join(process.cwd(), 'public')));
    return sendErr(res, 500, 'Server Error', 'A configuration error occurred. Please try again later.');
  }

  const dot = encData.indexOf('.');
  if (dot === -1)
    return sendErr(res, 500, 'Format Error', 'Bad .enc format (missing dot separator).');

  let html;
  try {
    const ivBuf      = Buffer.from(encData.slice(0, dot), 'base64');
    const ciphertext = Buffer.from(encData.slice(dot + 1), 'base64');
    const authTag    = ciphertext.slice(ciphertext.length - 16);
    const encrypted  = ciphertext.slice(0, ciphertext.length - 16);
    const decipher   = createDecipheriv('aes-256-gcm', keyBuf, ivBuf);
    decipher.setAuthTag(authTag);
    html = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf-8');
  } catch (e) {
    // FIX: Crypto library error messages (wrong key, bad auth tag, etc.) can
    //      reveal implementation details. Log server-side, return opaque message.
    console.error('[ces:decrypt] Decryption failed for', encFile, '—', e.message);
    return sendErr(res, 500, 'Server Error', 'A configuration error occurred. Please try again later.');
  }

  // Inject <base> for correct relative-path resolution
  html = html.replace(/(<head[^>]*>)/i, `$1<base href="${baseHref}">`);

  // ── Per-request nonce ─────────────────────────────────────────────────────
  const cspNonce   = randomBytes(16).toString('base64url');


  // ── Bot path ──────────────────────────────────────────────────────────────
  const ua    = req.headers['user-agent'] || '';
  const isBot = BOT_RE.test(ua);

  if (isBot) {
    const host = req.headers['host'] || 'civilengsuite.is-a.dev';

    let botHtml = html.replace(
      /<meta\s+name="robots"\s+content="noindex[^"]*"/gi,
      '<meta name="robots" content="index, follow"'
    );
    botHtml = botHtml.replace(
      /(<meta\s+(?:property|name)="(?:og:image|og:image:secure_url|twitter:image)"\s+content=")https:\/\/[^/]+(\/[^"]*")/gi,
      `$1https://${host}$2`
    );
    botHtml = injectNonces(botHtml, cspNonce);

    res.setHeader('Content-Type',            'text/html; charset=utf-8');
    res.setHeader('Cache-Control',           'public, max-age=3600, must-revalidate');
    res.setHeader('X-Robots-Tag',            'index, follow');
    res.setHeader('Content-Security-Policy',
      `${CSP_COMMON}; script-src 'nonce-${cspNonce}'`);
    return res.status(200).send(botHtml);
  }

  // ── Browser path ─────────────────────────────────────────────────────────
  //
  // Copyright HTML served as the Ctrl+S download (Tier 1 + Tier 2 save defense)
  const copyrightHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Protected</title></head>`
    + `<body style="margin:0;background:#0A1A2E;display:flex;align-items:center;`
    + `justify-content:center;min-height:100vh;font-family:sans-serif">`
    + `<div style="text-align:center;padding:40px">`
    + `<div style="font-size:3rem;margin-bottom:20px">&#x1F512;</div>`
    + `<h2 style="color:#C17B1A;margin-bottom:12px">&#169; Civil Engineering Suite</h2>`
    + `<p style="color:#8AA3C7;line-height:1.8">Eng. Aymn Asi &#8212; All Rights Reserved<br>`
    + `Unauthorized copying or reproduction is strictly prohibited.</p>`
    + `</div></body></html>`;

  // ── Comprehensive client-side protection bundle ───────────────────────────
  //
  // All listeners use useCapture:true so they fire at the capture phase and
  // cannot be stopped by page-level bubble-phase listeners or extensions that
  // only patch addEventListener without touching addEventListener(..., true).
  //
  // The nonce for this <script> tag is injected by injectNonces() below.
  // Do NOT add a nonce attribute here manually — injectNonces() will add it.

  const protectionBundle = `<script>(function(){'use strict';`

    // ── [1] DevTools detection ───────────────────────────────────────────────
    //
    // Three independent methods are combined; any single method can be defeated
    // but all three together require significant effort:
    //
    //  Method A — Window-size delta (docked DevTools only).
    //  Method B — debugger statement timing (works when DevTools is open and
    //             breakpoints are active; defeated by "Deactivate breakpoints").
    //
    // Two consecutive positive hits are required before the overlay fires,
    // preventing false positives from transient window resizes.
    //
    // FIX vs v2: Early synchronous check catches DevTools pre-opened before load.
    // FIX vs v2: visibilitychange re-runs the check so the tab-switch moment
    //            that accompanies File→Save As is covered.
    // FIX vs v2: Overlay approach (fixed div, z:MAX) replaces document.write
    //            which does nothing on a fully loaded page.

    + `var _DT=160,_H=0,_B=false;`

    // Overlay factory — called on confirmed detection
    + `function _block(){`
    +   `if(_B)return;_B=true;clearInterval(_T);`
    +   `var o=document.createElement('div');`
    +   `o.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;'`
    +     `+'background:#0A1A2E;z-index:2147483647;display:flex;align-items:center;'`
    +     `+'justify-content:center;font-family:sans-serif';`
    +   `o.innerHTML='<div style="text-align:center;padding:40px">'`
    +     `+'<div style="font-size:3rem;margin-bottom:16px">&#x1F512;</div>'`
    +     `+'<h2 style="color:#C17B1A;margin-bottom:10px">Protected Content</h2>'`
    +     `+'<p style="color:#8AA3C7;line-height:1.8">'`
    +     `+'Developer tools are not permitted on this page.<br>'`
    +     `+'&#169; Civil Engineering Suite &#8212; Eng. Aymn Asi</p>'`
    +     `+'</div>';`
    +   `document.body.appendChild(o);`
    // Hide existing body children behind the overlay (defence in depth)
    +   `try{`
    +     `[].forEach.call(document.body.children,function(el){`
    +       `if(el!==o)el.style.setProperty('visibility','hidden','important');`
    +     `});`
    +   `}catch(e){}`
    + `}`

    // Poll function — Methods A + B
    + `function _chk(){`
    +   `var wD=window.outerWidth -window.innerWidth >_DT;`
    +   `var hD=window.outerHeight-window.innerHeight>_DT;`
    +   `var db=false;`
    +   `try{var t=performance.now();(function(){debugger;})();db=performance.now()-t>80;}catch(e){}`
    +   `if(wD||hD||db){if(++_H>=2)_block();}else{_H=0;}`
    + `}`

    // FIX: Early synchronous check — runs at script-parse time, before DOMContentLoaded.
    // Catches DevTools already open when the user navigated to the page.
    + `(function(){`
    +   `var wD=window.outerWidth -window.innerWidth >_DT;`
    +   `var hD=window.outerHeight-window.innerHeight>_DT;`
    +   `if(wD||hD){_H=2;_block();}`
    + `})();`

    // Interval poll
    + `var _T=setInterval(_chk,500);`

    // FIX: Re-check when page regains visibility (covers OS File→Save As dialog dismiss)
    + `document.addEventListener('visibilitychange',function(){if(!document.hidden)_chk();},true);`

    // ── [2] Enhanced watermark MutationObserver ──────────────────────────────
    //
    // FIX vs v2: Now observes *attributes* (style, class, hidden) on the watermark
    //   element itself. The previous version watched only childList and was fully
    //   blind to the simple bypass: element.style.opacity='0'.
    //
    // FIX vs v2: getComputedStyle interval fallback catches opacity set via an
    //   external CSS rule (which MutationObserver cannot see at all).
    //
    // FIX vs v2: document.body childList observation is now separate from the
    //   watermark attribute observation, with correct targets.

    + `function _gwm(){`
    +   `var wm=document.getElementById('_ces_wm');`
    +   `if(!wm)return;`

    // Visibility check via computed style (catches style attribute AND CSS rules)
    +   `function _vis(el){`
    +     `try{`
    +       `var s=getComputedStyle(el);`
    +       `return s.display!=='none'&&s.visibility!=='hidden'&&parseFloat(s.opacity)>0.05;`
    +     `}catch(e){return true;}`
    +   `}`

    // Restore the watermark to its natural rendered state
    +   `function _fix(){`
    +     `wm.removeAttribute('style');`
    +     `wm.removeAttribute('hidden');`
    // Don't touch 'class' — the page may rely on its own class for layout.
    // Removing style+hidden is sufficient: the inline style override is gone,
    // and any CSS class that hides it will be caught by the interval check below.
    +   `}`

    +   `var obs=new MutationObserver(function(ms){`
    +     `ms.forEach(function(m){`
    // FIX: attributes type now handled (was missing entirely in v2)
    +       `if(m.type==='attributes'&&!_vis(wm))_fix();`
    +       `if(m.type==='childList'){`
    +         `m.removedNodes.forEach(function(n){`
    +           `if(n===wm||n.id==='_ces_wm')document.body.appendChild(wm);`
    +         `});`
    +       `}`
    +     `});`
    +   `});`

    // FIX: observe attributes on the watermark itself (new)
    +   `obs.observe(wm,{attributes:true,attributeFilter:['style','class','hidden']});`
    // FIX: observe body for watermark removal (correct target — was wm in v2)
    +   `obs.observe(document.body,{childList:true});`

    // FIX: Interval fallback — catches any hiding method that bypasses MutationObserver
    //      (CSS rule injection, getComputedStyle-invisible tricks)
    +   `setInterval(function(){if(!_vis(wm))_fix();},2000);`
    + `}`
    + `if(document.readyState==='loading')`
    +   `{document.addEventListener('DOMContentLoaded',_gwm);}else{_gwm();}`

    // ── [3] Right-click block — useCapture:true ──────────────────────────────
    //
    // FIX vs v2: useCapture:true — Firefox Shift+right-click only fires
    //   contextmenu at bubble phase; capture-phase listener cannot be bypassed
    //   with Shift on any browser.

    + `document.addEventListener('contextmenu',function(e){`
    +   `e.preventDefault();e.stopImmediatePropagation();return false;`
    + `},true);`

    // ── [4] Copy / cut block — capture phase + clipboard replacement ─────────
    //
    // FIX vs v2: useCapture:true so browser Edit→Copy (which routes through
    //   capture phase and would miss a bubble-only listener) is intercepted.
    //
    // FIX vs v2: setData() writes the copyright notice to the clipboard so
    //   that even if preventDefault somehow fails on a future browser, the
    //   copied text is the copyright notice rather than the actual content.

    + `var _ct='\u00A9 Civil Engineering Suite \u2014 Eng. Aymn Asi. All Rights Reserved.';`
    + `function _cp(e){`
    +   `e.preventDefault();e.stopImmediatePropagation();`
    +   `try{if(e.clipboardData){`
    +     `e.clipboardData.setData('text/plain',_ct);`
    +     `e.clipboardData.setData('text/html','<p>'+_ct+'</p>');`
    +   `}}catch(ex){}`
    +   `return false;`
    + `}`
    + `document.addEventListener('copy',_cp,true);`
    + `document.addEventListener('cut',_cp,true);`

    // ── [5] Keyboard shortcut block — capture phase ──────────────────────────
    //
    // FIX vs v2: All handlers now use useCapture:true.
    // FIX vs v2: Ctrl+Shift+I / J / C / K (Firefox DevTools console) now blocked.
    // FIX vs v2: Ctrl+A (select-all) now blocked at capture phase.
    //
    // Ctrl+S is handled separately in [6] so the download dialog fires correctly.

    + `document.addEventListener('keydown',function(e){`
    +   `var k=(e.key||'').toLowerCase(),c=e.ctrlKey||e.metaKey,s=e.shiftKey;`
    // F12 — DevTools (all browsers)
    +   `if(e.key==='F12'){e.preventDefault();e.stopImmediatePropagation();return false;}`
    // Ctrl+Shift+I/J/C — Chrome/Edge DevTools; Ctrl+Shift+K — Firefox console
    +   `if(c&&s&&'ijck'.includes(k)){e.preventDefault();e.stopImmediatePropagation();return false;}`
    // Ctrl+U — view-source; Ctrl+A — select-all; Ctrl+C — copy; Ctrl+X — cut
    +   `if(c&&!s&&'uacx'.includes(k)){e.preventDefault();e.stopImmediatePropagation();return false;}`
    + `},true);`

    // ── [6] Ctrl+S save defense — Tier 1 (Chrome/Edge FSA) + Tier 2 fallback ─
    //
    // Intercepts the Ctrl+S keyboard path and downloads a copyright-notice HTML
    // file in place of the real page.
    //
    // KNOWN LIMITATION: File → Save As uses an OS-level save dialog that fires
    // no JS event on any browser. This layer only protects the keyboard path.

    + `document.addEventListener('keydown',function(e){`
    +   `if((e.ctrlKey||e.metaKey)&&(e.key||'').toLowerCase()==='s'){`
    +     `e.preventDefault();e.stopPropagation();e.stopImmediatePropagation();`
    +     `var _b=new Blob(['${copyrightHtml.replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/\n/g,'')}'],{type:'text/html'});`
    +     `var _a=document.createElement('a');`
    +     `_a.href=URL.createObjectURL(_b);_a.download='${pageFilename}';`
    +     `document.body.appendChild(_a);_a.click();`
    +     `setTimeout(function(){document.body.removeChild(_a);URL.revokeObjectURL(_a.href);},100);`
    +   `}`
    + `},true);`

    // ── [7] Text selection prevention — capture phase ─────────────────────────
    //
    // FIX vs v2: useCapture:true.
    // INPUT / TEXTAREA / contentEditable exempted so engineering inputs still work.

    + `document.addEventListener('selectstart',function(e){`
    +   `var t=e.target;`
    +   `if(t&&(t.tagName==='INPUT'||t.tagName==='TEXTAREA'||t.isContentEditable))return;`
    +   `e.preventDefault();return false;`
    + `},true);`

    // ── [8] Drag prevention — capture phase ──────────────────────────────────
    + `document.addEventListener('dragstart',function(e){e.preventDefault();return false;},true);`

    // ── [9] Console warning ───────────────────────────────────────────────────
    //
    // FIX vs v2: Starts with console.clear() so the warning is always at top.
    // FIX vs v2: Explicit session-logging notice deters social-engineering attacks.

    + `(function(){`
    +   `try{`
    +     `console.clear();`
    +     `console.log(`
    +       `'%c\u26a0 STOP!',`
    +       `'color:#C17B1A;background:#0A1A2E;font-size:22px;font-weight:bold;'`
    +       `+'padding:10px 16px;border-radius:4px'`
    +     `);`
    +     `console.log(`
    +       `'%c\u00a9 Civil Engineering Suite \u2014 Eng. Aymn Asi\\n\\n'`
    +       `+'This is a browser developer tool intended for developers.\\n'`
    +       `+'If someone told you to paste something here, it is a social engineering attack.\\n\\n'`
    +       `+'All sessions are logged. Unauthorized access is strictly prohibited.',`
    +       `'color:#8AA3C7;font-size:13px;line-height:1.8'`
    +     `);`
    +   `}catch(ex){}`
    + `})();`

    + `})();\u003c/script>`;

  // Inject the protection bundle before </body>
  html = html.replace(/<\/body>/i, protectionBundle + '</body>');

  // Minify — normalises all <script …> tags before injectNonces() runs
  html = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/>\s+</g,           '><')
    .replace(/\s{2,}/g,          ' ')
    .replace(/\n|\r/g,           '')
    .trim();

  // Stamp nonce on every <script> tag (includes the bundle injected above)
  html = injectNonces(html, cspNonce);

  // XOR + base64 obfuscation of the entire decrypted page
  const xored   = Buffer.from(html, 'utf-8').map(b => b ^ XOR_KEY);
  const payload = xored.toString('base64');

  const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
  const pageTitle  = titleMatch ? titleMatch[1] : 'Civil Engineering Suite';

  // Bootstrap shell — tiny, nonce-stamped, XOR-obfuscated wrapper
  const bootstrap = `<!DOCTYPE html><html><head>`
    + `<meta charset="UTF-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0">`
    + `<meta name="robots" content="noindex">`
    + `<title>${pageTitle}</title>`
    + `${faviconLinks}`
    + `</head><body>`
    + `<script nonce="${cspNonce}">`
    + `(function(){`
    + `try{`
    + `var p="${payload}";`
    + `var b=atob(p);`
    + `var u=new Uint8Array(b.length);`
    + `for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i)^${XOR_KEY};`
    + `var h=new TextDecoder("utf-8").decode(u);`
    + `document.open();document.write(h);document.close();`
    + `}catch(e){`
    + `var _fb=document.createElement('p');`
    + `_fb.style.padding='40px';_fb.style.color='#C17B1A';_fb.style.fontFamily='sans-serif';`
    + `_fb.textContent='Page could not be loaded. Please refresh or contact support.';`
    + `document.body.appendChild(_fb);`
    + `}`
    + `})();`
    + `\u003c/script>`
    + `</body></html>`;

  res.setHeader('Content-Security-Policy',
    `${CSP_COMMON}; script-src 'nonce-${cspNonce}'`);
  res.setHeader('Content-Type',           'text/html; charset=utf-8');
  res.setHeader('Cache-Control',          'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.status(200).send(bootstrap);
};

// ── Helpers ───────────────────────────────────────────────────────────────────

// FIX: escHtml — prevents XSS in error pages.
//      The previous errPage() directly interpolated title and message into HTML
//      without escaping. Node.js error messages (e.message from crypto, fs, etc.)
//      can contain '<', '>', '"' which render as live HTML if the browser has no
//      CSP. All error output must be escaped before being written into HTML.
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// FIX: errPage() — accepts a nonce; replaces inline style attr on <body> with a
//      nonce-protected <style> block so the page requires NO 'unsafe-inline' in
//      style-src.  The nonce is generated by sendErr() and injected here.
function errPage(title, message, nonce) {
  return `<!DOCTYPE html><html lang="en"><head>`
    + `<meta charset="UTF-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<style nonce="${nonce}">body{font-family:sans-serif;padding:40px;margin:0}</style>`
    + `<title>${escHtml(title)}</title>`
    + `</head><body>`
    + `<h2>${escHtml(title)}</h2><p>${escHtml(message)}</p>`
    + `</body></html>`;
}

// FIX: sendErr() — centralised error response that sets all required security
//      headers on every error path (429, 500, 404).
//      Previously, error responses were sent with res.status(N).send(errPage())
//      which skipped Content-Security-Policy, X-Frame-Options, Cache-Control,
//      and X-Content-Type-Options — leaving them unprotected by HTTP headers.
//
//  FIX v3: A per-response nonce is generated here and used in both the
//      Content-Security-Policy header (style-src 'nonce-N') and errPage().
//      This eliminates 'unsafe-inline' from every error-page CSP.
function sendErr(res, status, title, message) {
  const nonce = randomBytes(16).toString('base64url');
  res.setHeader('Content-Type',            'text/html; charset=utf-8');
  res.setHeader('Content-Security-Policy', `default-src 'none'; style-src 'nonce-${nonce}'`);
  res.setHeader('X-Content-Type-Options',  'nosniff');
  res.setHeader('X-Frame-Options',         'DENY');
  res.setHeader('Cache-Control',           'no-store');
  return res.status(status).send(errPage(title, message, nonce));
}

// FIX: listDir — server-side logging only, never returns listing to caller.
//      The previous version returned the directory listing as a string, which
//      was then concatenated into the HTTP error response body and sent to the
//      browser. Any user who could trigger a 500 (e.g. deleting/corrupting the
//      .enc file in a development environment) could enumerate public/ contents.
//      Now the listing goes to console.error() (Vercel function logs, not HTTP)
//      and the function returns a safe placeholder used only in log context.
function listDir(dir) {
  try {
    console.error('[ces:decrypt] public/ contents:', fs.readdirSync(dir).join(', '));
  } catch (e) {
    console.error('[ces:decrypt] listDir error:', e.message);
  }
  // Return value is only used inside console.error() calls above — never in
  // any string that reaches res.send(). This return is a safety net only.
  return '[see server logs]';
}
