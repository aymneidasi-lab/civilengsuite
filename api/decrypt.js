/**
 * Civil Engineering Suite — AES-256-GCM Decrypt
 *
 * Security fixes vs previous version:
 *
 *   FIX 1 — Bot UA spoofing closed.
 *            Bot path now requires BOTH: UA pattern match AND reverse-DNS
 *            verification that the IP resolves to a known crawler hostname.
 *            Spoofing User-Agent: googlebot from a random IP returns the
 *            standard obfuscated browser response — not the plaintext HTML.
 *
 *   FIX 2 — XOR key no longer appears in browser responses.
 *            A per-request effectiveKey is derived server-side:
 *              effectiveKey = (XOR_KEY ^ (nonce[0] ^ nonce[1])) & 0xFF
 *            Only effectiveKey is written to the bootstrap; the static
 *            XOR_KEY value never appears in any response. Each request
 *            produces a different effectiveKey — captured payloads from
 *            different sessions cannot be decoded with the same key.
 *
 *   FIX 3 — document.write() replaced with iframe + Blob URL.
 *            The bootstrap creates a Blob from the decoded HTML and loads
 *            it in a full-viewport iframe. No document.write(), no risk of
 *            Chromium's progressive restrictions, and nonce propagation is
 *            no longer needed across a document.write boundary.
 *            CSP updated with  frame-src blob:  to authorise this pattern.
 *
 *   FIX 4 — Loud warning if CES_XOR_KEY is absent at startup.
 *            The dev fallback (0x5A) is logged as a warning so it is never
 *            silently active in production.
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const dns  = require('dns').promises;
const { createDecipheriv, randomBytes } = require('crypto');

// ── Bot UA pattern ────────────────────────────────────────────────────────────
const BOT_RE = /googlebot|google-inspectiontool|googleother|bingbot|yandexbot|duckduckbot|baiduspider|applebot|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|slackbot|discordbot/i;

// Reverse-DNS hostname suffixes accepted as verified crawlers.
// Source: Google, Bing, Yandex, Baidu, Apple, and social-preview docs.
const VERIFIED_CRAWLER_SUFFIXES = [
  '.googlebot.com',
  '.google.com',
  '.search.msn.com',
  '.yandex.com',
  '.yandex.net',
  '.crawl.yahoo.net',
  '.crawl.baidu.com',
  '.crawl.baidu.jp',
  '.duckduckgo.com',
  '.apple.com',
  '.linkedin.com',
  '.facebook.com',
  '.twitter.com',
  '.slack.com',
  '.discord.com',
];

// ── XOR key ───────────────────────────────────────────────────────────────────
const _xorHex = (process.env.CES_XOR_KEY || '').trim();
if (!_xorHex) {
  // Intentionally loud — a missing key in production is a misconfiguration.
  console.warn('[CES] WARNING: CES_XOR_KEY env var is not set. Using dev fallback (0x5A). Set this in Vercel environment variables before deploying.');
}
const XOR_KEY = (_xorHex.length === 2 && /^[0-9A-Fa-f]{2}$/.test(_xorHex))
  ? parseInt(_xorHex, 16)
  : 0x5A; // dev fallback only — must be overridden in production

// ── Shared CSP fragments ──────────────────────────────────────────────────────
// frame-src blob: is required for the iframe+Blob bootstrap (FIX 3).
// script-src is always set per-request via nonce — never unsafe-inline.
const CSP_COMMON = [
  "default-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: https:",
  "connect-src 'self'",
  "frame-src blob:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "upgrade-insecure-requests",
].join('; ');

// ── Distributed rate limiter with in-memory fallback ─────────────────────────
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

// ── Bot IP verification via reverse DNS (FIX 1) ───────────────────────────────
// Resolves the request IP to its hostname and checks it against the allow-list
// of verified crawler suffixes. Times out after 2 s to bound latency.
// A request that looks like a bot but fails DNS verification gets the standard
// obfuscated browser response — not the plaintext bot response.
async function verifyBotIP(ip) {
  return new Promise(resolve => {
    const timer = setTimeout(() => resolve(false), 2000);
    dns.reverse(ip)
      .then(hostnames => {
        clearTimeout(timer);
        const verified = hostnames.some(h =>
          VERIFIED_CRAWLER_SUFFIXES.some(s => h === s.slice(1) || h.endsWith(s))
        );
        resolve(verified);
      })
      .catch(() => {
        clearTimeout(timer);
        resolve(false);
      });
  });
}

// ── Handler ───────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {

  // 1. Rate limit
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
          || req.socket?.remoteAddress
          || 'anon';

  if (!(await allowRequest(ip))) {
    res.setHeader('Retry-After', '60');
    return res.status(429).send(errPage('Too Many Requests',
      'Rate limit exceeded. Please wait a moment and try again.'));
  }

  // 2. Validate AES-256-GCM key
  const keyHex = (process.env.CES_DECRYPT_KEY || '').trim();
  if (!keyHex || keyHex.length !== 64)
    return res.status(500).send(errPage('Config Error', 'CES_DECRYPT_KEY missing or invalid.'));

  let keyBuf;
  try { keyBuf = Buffer.from(keyHex, 'hex'); }
  catch (e) { return res.status(500).send(errPage('Key Error', e.message)); }

  // 3. Route to correct .enc file
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

  // 4. Read and decrypt .enc
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

  // Inject <base> for relative-path resolution
  html = html.replace(/(<head[^>]*>)/i, `$1<base href="${baseHref}">`);

  // Per-request nonce
  const cspNonce = randomBytes(16).toString('base64url');

  // 5. Bot detection — UA pattern + reverse DNS verification (FIX 1)
  const ua           = req.headers['user-agent'] || '';
  const looksLikeBot = BOT_RE.test(ua);
  const isBot        = looksLikeBot && await verifyBotIP(ip);

  // ── Bot path ──────────────────────────────────────────────────────────────
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
    res.setHeader('Content-Security-Policy', `${CSP_COMMON}; script-src 'nonce-${cspNonce}'`);
    return res.status(200).send(botHtml);
  }

  // ── Browser path ──────────────────────────────────────────────────────────
  const copyrightHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Protected</title></head>`
    + `<body style="margin:0;background:#0A1A2E;display:flex;align-items:center;`
    + `justify-content:center;min-height:100vh;font-family:sans-serif">`
    + `<div style="text-align:center;padding:40px">`
    + `<div style="font-size:3rem;margin-bottom:20px">&#x1F512;</div>`
    + `<h2 style="color:#C17B1A;margin-bottom:12px">&#169; Civil Engineering Suite</h2>`
    + `<p style="color:#8AA3C7;line-height:1.8">Eng. Aymn Asi &#8212; All Rights Reserved<br>`
    + `Unauthorized copying or reproduction is strictly prohibited.</p>`
    + `</div></body></html>`;

  // Ctrl+S / Cmd+S interception — stays in inner HTML so it fires when the
  // user is focused inside the iframe (which is where keyboard focus lives).
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

  // Minify
  html = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/>\s+</g,           '><')
    .replace(/\s{2,}/g,          ' ')
    .replace(/\n|\r/g,           '')
    .trim();

  // Inject nonces into the inner HTML (executed inside the blob iframe)
  html = injectNonces(html, cspNonce);

  // ── Per-request effective XOR key (FIX 2) ────────────────────────────────
  // The static XOR_KEY is combined with two bytes of the per-request nonce.
  // Only the resulting effectiveKey appears in the bootstrap response — the
  // static secret never does. A different effectiveKey per request means
  // payloads from different sessions are not interchangeable.
  const nonceByte    = (cspNonce.charCodeAt(0) ^ cspNonce.charCodeAt(1)) & 0xFF;
  const effectiveKey = (XOR_KEY ^ nonceByte) & 0xFF;

  const xored   = Buffer.from(html, 'utf-8').map(b => b ^ effectiveKey);
  const payload = xored.toString('base64');

  const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
  const pageTitle  = titleMatch ? titleMatch[1] : 'Civil Engineering Suite';

  // ── Bootstrap shell — iframe + Blob URL (FIX 3) ──────────────────────────
  // No document.write(). The decoded HTML is turned into a Blob URL and
  // loaded in a full-viewport iframe. The inner page scrolls inside the
  // iframe exactly as it would in a normal page. The CSP on the bootstrap
  // governs the outer shell; the inner blob page inherits same-origin trust.
  const bootstrap = `<!DOCTYPE html><html><head>`
    + `<meta charset="UTF-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0">`
    + `<meta name="robots" content="noindex">`
    + `<title>${pageTitle}</title>`
    + `${faviconLinks}`
    + `<style>*{margin:0;padding:0;box-sizing:border-box}html,body{height:100%;overflow:hidden}#f{border:none;width:100%;height:100%;display:block}</style>`
    + `</head><body>`
    + `<iframe id="f" title="${pageTitle}"></iframe>`
    + `<script nonce="${cspNonce}">`
    + `(function(){`
    + `try{`
    + `var p="${payload}";`
    + `var b=atob(p);`
    + `var u=new Uint8Array(b.length);`
    + `var k=${effectiveKey};`
    + `for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i)^k;`
    + `var h=new TextDecoder("utf-8").decode(u);`
    + `var blob=new Blob([h],{type:"text/html"});`
    + `var url=URL.createObjectURL(blob);`
    + `var f=document.getElementById("f");`
    + `f.src=url;`
    + `f.onload=function(){URL.revokeObjectURL(url);};`
    + `}catch(e){`
    + `document.body.style.cssText="padding:40px;color:#C17B1A;font-family:sans-serif";`
    + `document.body.innerHTML="<p>Error: "+e.message+"</p>";`
    + `}`
    + `})();`
    + `\u003c/script>`
    + `</body></html>`;

  res.setHeader('Content-Security-Policy',  `${CSP_COMMON}; script-src 'nonce-${cspNonce}'`);
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
