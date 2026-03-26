/**
 * Civil Engineering Suite — AES-256-GCM Decrypt
 *
 * Security fixes applied:
 *   1. Nonce-based CSP  — removes 'unsafe-inline' from script-src on the browser path.
 *      A fresh cryptographic nonce is generated per request, injected into every
 *      <script> tag in the decrypted HTML, and set in the Content-Security-Policy
 *      header.  The global vercel.json CSP (which keeps 'unsafe-inline' for the
 *      static files served to bots) is overridden only for this handler's responses.
 *
 *   2. Rate limiting    — simple in-memory token-bucket per IP address.
 *      Works within a single warm Vercel Lambda instance (module-level Map persists
 *      between invocations).  For multi-region or high-traffic production, swap the
 *      allowRequest() function for @upstash/ratelimit + @upstash/redis — the call
 *      site is identical.
 *
 *   3. Bot path CSP     — bots now also receive an explicit strict-ish CSP instead
 *      of relying solely on the global vercel.json header.  Bots don't execute JS
 *      so 'unsafe-inline' on that path is harmless, but tightening it costs nothing.
 */

const fs   = require('fs');
const path = require('path');
const { createDecipheriv, randomBytes } = require('crypto');

const BOT_RE = /googlebot|google-inspectiontool|googleother|bingbot|yandexbot|duckduckbot|baiduspider|applebot|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|slackbot|discordbot/i;

// XOR key used only for client-side view-source obfuscation.
// This is deterrence, not security — the real protection is AES-256-GCM above.
const XOR_KEY = 0x5A;

// ── Rate limiter ──────────────────────────────────────────────────────────────
// Module-level Map persists across warm invocations of the same Lambda instance.
// To upgrade to a production-grade distributed rate limiter:
//
//   npm install @upstash/ratelimit @upstash/redis
//
//   const { Ratelimit } = require('@upstash/ratelimit');
//   const { Redis }     = require('@upstash/redis');
//   const ratelimit = new Ratelimit({
//     redis:    Redis.fromEnv(),
//     limiter:  Ratelimit.slidingWindow(40, '1 m'),
//     prefix:   'ces:rl',
//   });
//   // Then replace allowRequest(ip) with:
//   //   const { success } = await ratelimit.limit(ip);
//   //   return success;

const _ipMap      = new Map();
const RATE_WINDOW = 60_000;   // sliding window: 1 minute
const RATE_MAX    = 40;       // max requests per IP per window

function allowRequest(ip) {
  const now  = Date.now();
  const slot = _ipMap.get(ip);
  if (!slot || now - slot.t > RATE_WINDOW) {
    _ipMap.set(ip, { t: now, n: 1 });
    return true;
  }
  slot.n += 1;
  return slot.n <= RATE_MAX;
}

// ── Shared CSP fragments ──────────────────────────────────────────────────────
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

// ── Handler ───────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {

  // 1. Rate limit ─────────────────────────────────────────────────────────────
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
          || req.socket?.remoteAddress
          || 'anon';

  if (!allowRequest(ip)) {
    res.setHeader('Retry-After', '60');
    return res.status(429).send(errPage('Too Many Requests',
      'Rate limit exceeded. Please wait a moment and try again.'));
  }

  // 2. Validate AES key ───────────────────────────────────────────────────────
  const keyHex = (process.env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64)
    return res.status(500).send(errPage('Config Error', 'CES_DECRYPT_KEY missing or invalid.'));

  let keyBuf;
  try { keyBuf = Buffer.from(keyHex, 'hex'); }
  catch (e) { return res.status(500).send(errPage('Key Error', e.message)); }

  // 3. Route to the right .enc file ───────────────────────────────────────────
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

  // 4. Read + decrypt .enc file ───────────────────────────────────────────────
  const encPath = path.join(process.cwd(), 'public', encFile);
  let encData;
  try { encData = fs.readFileSync(encPath, 'utf-8').trim(); }
  catch (e) {
    return res.status(500).send(errPage('File Error',
      `Cannot read ${encFile}: ${e.message} | public/: ${listDir(path.join(process.cwd(), 'public'))}`));
  }

  const dot = encData.indexOf('.');
  if (dot === -1) return res.status(500).send(errPage('Format Error', 'Bad .enc format (missing dot separator).'));

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

  // Inject <base> so all relative asset paths resolve correctly
  html = html.replace(/(<head[^>]*>)/i, `$1<base href="${baseHref}">`);

  // ── Bot path ─────────────────────────────────────────────────────────────────
  // Bots reach this handler only when they bypass the vercel.json rewrite
  // (e.g. direct /api/decrypt access).  We still serve them the full indexable HTML.
  const ua    = req.headers['user-agent'] || '';
  const isBot = BOT_RE.test(ua);

  if (isBot) {
    const host = req.headers['host'] || 'civilengsuite.is-a.dev';

    // Make sure search engines can index this response
    let botHtml = html.replace(
      /<meta\s+name="robots"\s+content="noindex[^"]*"/gi,
      '<meta name="robots" content="index, follow"'
    );

    // Rewrite og:image / twitter:image so previews work on any domain
    // (Vercel preview URLs, custom domains, etc.)
    botHtml = botHtml.replace(
      /(<meta\s+(?:property|name)="(?:og:image|og:image:secure_url|twitter:image)"\s+content=")https:\/\/[^/]+(\/[^"]*")/gi,
      `$1https://${host}$2`
    );

    res.setHeader('Content-Type',              'text/html; charset=utf-8');
    res.setHeader('Cache-Control',             'public, max-age=3600, must-revalidate');
    res.setHeader('X-Robots-Tag',              'index, follow');
    // Explicit CSP for the bot path (bots don't run JS, but good hygiene)
    res.setHeader('Content-Security-Policy',
      `${CSP_COMMON}; script-src 'self' 'unsafe-inline'`);
    return res.status(200).send(botHtml);
  }

  // ── Browser path ─────────────────────────────────────────────────────────────
  // Protections:
  //   1. Ctrl+S / Cmd+S → intercept → serve copyright notice download
  //   2. Print           → handled by each page's own overlay (not duplicated here)
  //   3. view-source     → XOR + base64 payload (obfuscation / deterrence layer)
  //   4. CSP nonce       → every <script> requires a per-request nonce (NEW)

  const copyrightHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Protected</title></head>`
    + `<body style="margin:0;background:#0A1A2E;display:flex;align-items:center;`
    + `justify-content:center;min-height:100vh;font-family:sans-serif">`
    + `<div style="text-align:center;padding:40px">`
    + `<div style="font-size:3rem;margin-bottom:20px">&#x1F512;</div>`
    + `<h2 style="color:#C17B1A;margin-bottom:12px">&#169; Civil Engineering Suite</h2>`
    + `<p style="color:#8AA3C7;line-height:1.8">Eng. Aymn Asi &#8212; All Rights Reserved<br>`
    + `Unauthorized copying or reproduction is strictly prohibited.</p>`
    + `</div></body></html>`;

  // NOTE: The nonce attribute is NOT added here by hand.
  // After minification, all <script> tags are bulk-replaced with
  // <script nonce="…"> in a single pass below — including this one.
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

  // Inject protection script before </body>
  html = html.replace(/<\/body>/i, protectionScript + '</body>');

  // Minify to a single line (must happen BEFORE nonce injection so all
  // <script …> patterns are normalised into the same form)
  html = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/>\s+</g,           '><')
    .replace(/\s{2,}/g,          ' ')
    .replace(/\n|\r/g,           '')
    .trim();

  // ── Generate per-request CSP nonce ─────────────────────────────────────────
  // base64url avoids + / = characters that would need escaping in HTML attributes.
  const cspNonce = randomBytes(16).toString('base64url');

  // ── Inject nonce into EVERY <script> tag ───────────────────────────────────
  // Lookahead (?=[\s>]) matches <script> and <script …> but NOT </script>.
  // This single pass covers page scripts, external scripts, AND the protection
  // script injected above — no script in the final HTML is nonce-less.
  html = html.replace(/<script(?=[\s>])/g, `<script nonce="${cspNonce}"`);

  // XOR + base64 obfuscation (nonces are now baked into the payload)
  const xored   = Buffer.from(html, 'utf-8').map(b => b ^ XOR_KEY);
  const payload = xored.toString('base64');

  const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
  const pageTitle  = titleMatch ? titleMatch[1] : 'Civil Engineering Suite';

  // The bootstrap <script> itself also carries the nonce so the browser
  // will execute it under the strict nonce-only CSP set below.
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

  // ── Set strict nonce-based CSP ──────────────────────────────────────────────
  // This res.setHeader() call overrides the global 'unsafe-inline' CSP set in
  // vercel.json for this specific response.  The static files served directly to
  // bots still use the vercel.json global (which keeps 'unsafe-inline' for those
  // pages' own inline scripts — we cannot remove it there without refactoring
  // the static HTML files themselves).
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
