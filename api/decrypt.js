/**
 * Civil Engineering Suite — AES-256-GCM Decrypt
 * ─────────────────────────────────────────────────────────────────────────────
 * A+ Security changes vs previous version:
 *
 *   1. Nonce on BOT path  — bots now also receive script-src 'nonce-{n}' with
 *      no 'unsafe-inline'. All <script> tags (including JSON-LD data blocks)
 *      get the nonce injected before the response leaves the server.
 *      This closes the last unsafe-inline gap across ALL response paths.
 *
 *   2. Distributed rate limiter — uses @upstash/ratelimit + @upstash/redis
 *      when UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN env vars are
 *      present. Falls back to the in-process Map automatically if they are not,
 *      so the handler works immediately in both environments with zero code changes.
 *
 *   3. All paths now go through this handler — vercel.json rewrites are
 *      unconditional. Static HTML files are never served directly to anyone,
 *      eliminating the last surface where unsafe-inline could leak through the
 *      global vercel.json CSP.
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { createDecipheriv, randomBytes } = require('crypto');

// ── Bot / crawler UA pattern ──────────────────────────────────────────────────
const BOT_RE = /googlebot|google-inspectiontool|googleother|bingbot|yandexbot|duckduckbot|baiduspider|applebot|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|slackbot|discordbot/i;

// XOR key — client-side obfuscation layer only (not cryptographic security)
const XOR_KEY = 0x5A;

// ── Shared CSP fragments ──────────────────────────────────────────────────────
// script-src is always set per-request via nonce — never unsafe-inline
const CSP_COMMON = [
  "default-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: https:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "upgrade-insecure-requests",
].join('; ');

// ── Distributed rate limiter with automatic in-memory fallback ────────────────
//
// TO ENABLE DISTRIBUTED (MULTI-INSTANCE) RATE LIMITING:
//   1. npm install @upstash/ratelimit @upstash/redis
//   2. Add to Vercel environment variables:
//        UPSTASH_REDIS_REST_URL   = https://…upstash.io
//        UPSTASH_REDIS_REST_TOKEN = your_token_here
//   The handler detects these vars and switches to Redis automatically.
//   Remove them to revert to in-memory (e.g. in local dev).
//
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
} catch (_) {
  // Packages not installed — in-memory fallback used automatically
}

// In-memory fallback (single warm Lambda instance)
const _ipMap      = new Map();
const RATE_WINDOW = 60_000;
const RATE_MAX    = 40;

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
// Stamps nonce="${nonce}" on every <script …> opening tag.
// Works correctly on:
//   - Inline executable scripts:   <script>
//   - External scripts:            <script src="…">
//   - JSON-LD data blocks:         <script type="application/ld+json">
//     (nonce on JSON-LD is ignored by browsers and harmless for crawlers)
// Does NOT match </script> end-tags (lookahead (?=[\s>]) requires space or >).
function injectNonces(html, nonce) {
  return html.replace(/<script(?=[\s>])/g, `<script nonce="${nonce}"`);
}

// ── Handler ───────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {

  // 1. Rate limit ─────────────────────────────────────────────────────────────
  // x-vercel-forwarded-for is set by Vercel's edge and cannot be spoofed by
  // the client, unlike x-forwarded-for which is user-controlled.
  const ip = req.headers['x-vercel-forwarded-for']
          || (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
          || req.socket?.remoteAddress
          || 'anon';

  if (!(await allowRequest(ip))) {
    res.setHeader('Retry-After', '60');
    return res.status(429).send(errPage('Too Many Requests',
      'Rate limit exceeded. Please wait a moment and try again.'));
  }

  // 2. Validate AES-256-GCM key ───────────────────────────────────────────────
  const keyHex = (process.env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64)
    return res.status(500).send(errPage('Config Error', 'CES_DECRYPT_KEY missing or invalid.'));

  let keyBuf;
  try { keyBuf = Buffer.from(keyHex, 'hex'); }
  catch (e) { return res.status(500).send(errPage('Key Error', e.message)); }

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
    return res.status(404).send('Not found');
  }

  // 4. Read and decrypt .enc ──────────────────────────────────────────────────
  const encPath = path.join(process.cwd(), 'public', encFile);
  let encData;
  try { encData = fs.readFileSync(encPath, 'utf-8').trim(); }
  catch (e) {
    return res.status(500).send(errPage('File Error',
      `Cannot read ${encFile}: ${e.message} | public/: ${listDir(path.join(process.cwd(), 'public'))}`));
  }

  const dot = encData.indexOf('.');
  if (dot === -1)
    return res.status(500).send(errPage('Format Error', 'Bad .enc format (missing dot separator).'));

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
    return res.status(500).send(errPage('Decrypt Error', e.message));
  }

  // Inject <base> for correct relative-path resolution
  html = html.replace(/(<head[^>]*>)/i, `$1<base href="${baseHref}">`);

  // ── Generate per-request nonce — used on BOTH bot and browser paths ─────────
  const cspNonce = randomBytes(16).toString('base64url');

  // ── Bot path ──────────────────────────────────────────────────────────────
  const ua    = req.headers['user-agent'] || '';
  const isBot = BOT_RE.test(ua);

  if (isBot) {
    const host = req.headers['host'] || 'civilengsuite.is-a.dev';

    // Make page indexable
    let botHtml = html.replace(
      /<meta\s+name="robots"\s+content="noindex[^"]*"/gi,
      '<meta name="robots" content="index, follow"'
    );

    // Rewrite og:image / twitter:image to match the serving host
    botHtml = botHtml.replace(
      /(<meta\s+(?:property|name)="(?:og:image|og:image:secure_url|twitter:image)"\s+content=")https:\/\/[^/]+(\/[^"]*")/gi,
      `$1https://${host}$2`
    );

    // Inject nonce on bot path — eliminates 'unsafe-inline' here too
    botHtml = injectNonces(botHtml, cspNonce);

    res.setHeader('Content-Type',            'text/html; charset=utf-8');
    res.setHeader('Cache-Control',           'public, max-age=3600, must-revalidate');
    res.setHeader('X-Robots-Tag',            'index, follow');
    res.setHeader('Content-Security-Policy',
      `${CSP_COMMON}; script-src 'nonce-${cspNonce}'`);
    return res.status(200).send(botHtml);
  }

  // ── Browser path ─────────────────────────────────────────────────────────
  // Protections:
  //   1. Ctrl+S / Cmd+S  → intercept → download copyright notice
  //   2. Print           → handled by each page's own overlay
  //   3. view-source     → XOR + base64 obfuscation (deterrence)
  //   4. CSP nonce       → per-request, no unsafe-inline

  const copyrightHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Protected</title></head>`
    + `<body style="margin:0;background:#0A1A2E;display:flex;align-items:center;`
    + `justify-content:center;min-height:100vh;font-family:sans-serif">`
    + `<div style="text-align:center;padding:40px">`
    + `<div style="font-size:3rem;margin-bottom:20px">&#x1F512;</div>`
    + `<h2 style="color:#C17B1A;margin-bottom:12px">&#169; Civil Engineering Suite</h2>`
    + `<p style="color:#8AA3C7;line-height:1.8">Eng. Aymn Asi &#8212; All Rights Reserved<br>`
    + `Unauthorized copying or reproduction is strictly prohibited.</p>`
    + `</div></body></html>`;

  // Nonce is added to this tag in the bulk injectNonces() pass below
  const protectionScript = `<script>(function(){`
    + `document.addEventListener('keydown',function(e){`
    + `if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){`
    + `e.preventDefault();e.stopPropagation();e.stopImmediatePropagation();`
    + `var _b=new Blob(['${copyrightHtml.replace(/'/g, "\\'").replace(/\n/g, '')}'],{type:'text/html'});`
    + `var _a=document.createElement('a');`
    + `_a.href=URL.createObjectURL(_b);_a.download='${pageFilename}';`
    + `document.body.appendChild(_a);_a.click();`
    + `setTimeout(function(){document.body.removeChild(_a);URL.revokeObjectURL(_a.href);},100);`
    + `}},true);`
    + `})();\u003c/script>`;

  html = html.replace(/<\/body>/i, protectionScript + '</body>');

  // Minify first — normalises all <script …> tags into a consistent form
  // before injectNonces() processes them
  html = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/>\s+</g,           '><')
    .replace(/\s{2,}/g,          ' ')
    .replace(/\n|\r/g,           '')
    .trim();

  // Inject nonce into every <script> tag, then XOR+base64 the whole thing
  html = injectNonces(html, cspNonce);

  const xored   = Buffer.from(html, 'utf-8').map(b => b ^ XOR_KEY);
  const payload = xored.toString('base64');

  const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
  const pageTitle  = titleMatch ? titleMatch[1] : 'Civil Engineering Suite';

  // Bootstrap shell — its own <script> carries the same nonce
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
    + `for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i)^0x5A;`
    + `var h=new TextDecoder("utf-8").decode(u);`
    + `document.open();document.write(h);document.close();`
    + `}catch(e){`
    + `document.body.innerHTML="<p style='padding:40px;color:#C17B1A;font-family:sans-serif'>Error: "+e.message+"</p>";`
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
function errPage(title, message) {
  return `<!DOCTYPE html><html><head><title>${title}</title></head>`
    + `<body style="font-family:sans-serif;padding:40px">`
    + `<h2>${title}</h2><p>${message}</p>`
    + `</body></html>`;
}
function listDir(dir) {
  try { return fs.readdirSync(dir).join(', '); } catch (e) { return e.message; }
}
