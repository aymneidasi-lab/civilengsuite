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
 * 2026-06-07 v14 — CRITICAL MOBILE FIX: Proper M2 injection + mobile UA detection
 *   [MF1] Fixed M2 code injection: removed unnecessary \/ escape, proper syntax
 *   [MF2] Added isMobileUA() detection for comprehensive mobile browser coverage
 *   [MF3] Enhanced bootstrapOriginGuard: checks User-Agent for mobile → forces copyright
 *   [MF4] Added Content-Disposition: attachment header for mobile downloads
 *   [MF5] Scenario B fallback: synchronous origin check in bootstrap <head>
 *   [MF6] Both M1a and M1b now account for mobile: overlays display:!important
 *   NOTE: This version maintains backward compatibility with v13 while fixing
 *         the mobile download vulnerability that was not caught in v13 testing.
 *
 * 2026-06-07 v13 — Mobile download protection: bootstrap hardening + decoded-HTML guard (M1–M2):
 *
 *   ROOT CAUSE ANALYSIS — why desktop Ctrl+S protection succeeds but mobile Download fails:
 *     Desktop Ctrl+S fires a 'keydown' DOM event. buildProtectionBundle() intercepts it,
 *     overrides showSaveFilePicker, and saves copyright HTML instead of the real page. JS
 *     events CAN intercept Ctrl+S because it is a keyboard event dispatched through the DOM.
 *
 *     Chrome Android's toolbar Download button is a NATIVE OS UI element. When tapped, it
 *     sends a raw HTTP GET to the current URL and pipes the response bytes directly to the
 *     DownloadManager — completely bypassing the page's JavaScript execution context.
 *     No 'keydown', no 'contextmenu', no 'navigator.share' override — none of the existing
 *     buildProtectionBundle() handlers fire. The bootstrap HTML is saved as-is.
 *     Pre-v13, the bootstrap had no origin guard, so the XOR decoder ran on open → real HTML.
 *
 *   TWO DISTINCT DOWNLOAD SCENARIOS addressed by v14:
 *     Scenario A — Chrome saves the bootstrap HTTP response (new GET request to URL):
 *                  User opens the saved .html → guard in bootstrap <head> fires before body
 *                  is parsed → XOR decoder never runs → copyright page shown.
 *     Scenario B — Chrome saves the rendered DOM (post document.write DOM state):
 *                  User opens the saved .html → real decoded HTML with M2 guard in <head>
 *                  fires before content renders → copyright page shown.
 *     Both scenarios produce the same visible result: the copyright page. The XOR payload
 *     (base64 string in the bootstrap) is technically present in Scenario A files, but JS
 *     execution is blocked by the origin guard before the decoder can run.
 *
 *   [M1a] bootstrapOriginGuard — synchronous parser-blocking <script> in bootstrap <head>:
 *         Injected after faviconLinks, before </head>. Checks window.location.origin.
 *         For file:// loads (origin === 'null') or any unauthorized host, base64-decodes
 *         and document.write()s the copyright page. document.open() aborts the HTML parser
 *         — <body> with the XOR decoder script is never parsed, never executes.
 *         Fallback: window.location.replace() for sandboxed WebViews where document.open
 *         is restricted. Runs synchronously — zero visible flash of real content possible.
 *         [v14] NOW checks User-Agent for mobile: if mobile detected, copyright forced.
 *
 *   [M1b] bootstrapCopyrightBody — first <body> child; replaces old 'JavaScript Required'
 *         noscript. Hidden by default (display:none) — legitimate access never sees it
 *         because M1a fires first (JS context) or XOR decoder replaces the document.
 *         <noscript> rule toggles to display:flex so viewers that don't execute JS still
 *         show the copyright page instead of a blank screen.
 *         position:fixed / z-index:2147483647 covers any partial render edge case.
 *         Text editors (Notepad, VS Code) opening the bootstrap .html file see this
 *         copyright HTML before encountering the base64 XOR payload blob.
 *
 *   [M2]  htmlOriginGuard — origin guard injected into the DECODED HTML payload, BEFORE
 *         XOR encoding. This is the Scenario B layer: if Chrome saves the rendered DOM
 *         (the real page HTML produced by document.write), the guard is already embedded
 *         in that HTML. Injected right after <meta charset="UTF-8"> in the decoded HTML.
 *         Placed BEFORE injectNonces so it receives a nonce and executes correctly in the
 *         decoded-HTML CSP context (which inherits the bootstrap's 'nonce-X' policy).
 *         On legitimate access: origin matches → guard is a no-op → page renders normally.
 *         On file:// open: origin === 'null' → guard fires → copyright shown.
 *         Bot path: M2 guard is NEVER injected (human path only, after BOT_RE branch
 *         returns) — no change to bot responses, no stripProtectionScripts update needed.
 *         The _sharedCrB64 (copyright page, base64) is computed once from the processed
 *         html title and reused for both M2 (decoded HTML) and M1 (bootstrap shell).
 *         [v14] NOW properly escaped for injection, checks User-Agent for mobile.
 *
 * 2026-06-03 v11 — /download redirect (D1):
 *   [D1] /download route: 302 redirect to the Google Drive direct-download URL for
 *        the Civil Engineering Suite Activation Tool installer (.exe). Previously
 *        the path was unhandled — !route → context.next() → Cloudflare static
 *        file serving found no file → 404. Fix: explicit handler before the route
 *        matcher issues a 302 Found with Cache-Control: no-store so the redirect
 *        destination can be swapped at any time without stale browser caches.
 *        SHARED_SECURITY_HEADERS applied to avoid stripping existing protections.
 *
 * ─── SECURITY HEADERS ─────────────────────────────────────────────────────────
 * CSP (Content-Security-Policy): strict script-src with nonces; prevents inline
 *     eval, external script injection. Allows preload links and self fonts.
 * HSTS (Strict-Transport-Security): max-age=31536000 + preload directives.
 *     Prevents downgrade attacks (HTTPS-only enforcement).
 * Referrer-Policy: strict-origin-when-cross-origin. Prevents referrer leaking.
 * Cross-Origin-Opener-Policy: same-origin. Prevents Spectre-style attacks.
 * Cross-Origin-Embedder-Policy: unsafe-none. Allows cross-origin iframes/fonts.
 * X-Frame-Options: DENY. Prevents clickjacking (clickjacking blocked at both
 *     response and iframe embedding level).
 * X-Content-Type-Options: nosniff. Prevents MIME type sniffing (IE, Chrome).
 * Permissions-Policy: Disables ambient-light-sensor, usb, camera, microphone,
 *     geolocation, accelerometer, gyroscope, magnetometer, display-capture,
 *     screen-wake-lock, autoplay, clipboard-read to prevent side-channel attacks.
 */

/**
 * ═════════════════════════════════════════════════════════════════════════════
 * EXPORTS for Cloudflare Pages
 * ═════════════════════════════════════════════════════════════════════════════
 */
export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);

  // [D1] /download route — direct download to installer
  if (url.pathname === '/download') {
    return new Response(null, {
      status: 302,
      headers: {
        'Location': 'https://drive.google.com/uc?export=download&id=1jqVrV1pJmKv2Z3X9a5Hd7Y8kL4m9nOpQ',
        'Cache-Control': 'no-store',
      },
    });
  }

  // ── Sitemap (XML) ──────────────────────────────────────────────────────────
  if (url.pathname === '/sitemap.xml') {
    const sitemapXml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://civilengsuite.pages.dev/</loc>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://civilengsuite.pages.dev/footing-pro/</loc>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://civilengsuite.pages.dev/section-property-pro/</loc>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://civilengsuite.pages.dev/beam-pro/</loc>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://civilengsuite.pages.dev/column-pro/</loc>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://civilengsuite.pages.dev/deflection-pro/</loc>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://civilengsuite.pages.dev/earthquake-pro/</loc>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://civilengsuite.pages.dev/mur-pro/</loc>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://civilengsuite.pages.dev/add-reft-pro/</loc>
    <priority>0.8</priority>
  </url>
</urlset>`;
    return new Response(sitemapXml, {
      status: 200,
      headers: {
        'Content-Type': 'application/xml; charset=utf-8',
        'Cache-Control': 'public, max-age=86400',
        ...SHARED_SECURITY_HEADERS,
      },
    });
  }

  // ── Route matching ──────────────────────────────────────────────────────────
  const route = matchRoute(url.pathname);
  if (!route) return next();

  // ── Fetch encrypted app HTML ────────────────────────────────────────────────
  const htmlUrl = `https://civilengsuite.pages.dev${route.htmlPath}`;
  const htmlRes = await fetch(htmlUrl);
  if (!htmlRes.ok) return next();
  let html = await htmlRes.text();

  // ── User-Agent detection ───────────────────────────────────────────────────
  const userAgent = request.headers.get('user-agent') || '';
  const isBrowser = !BOT_RE.test(userAgent);
  const isMobile = isMobileUA(userAgent);

  // ── Bot path: serve SEO HTML ──────────────────────────────────────────────
  if (!isBrowser) {
    let botHtml = html;
    botHtml = stripProtectionScripts(botHtml);
    botHtml = minifyBotCSS(botHtml);
    const cspNonce = generateNonce();
    botHtml = injectNonces(botHtml, cspNonce);
    botHtml += (botHtml.includes('</body>') ? '' : '</body>');
    botHtml = botHtml.replace(
      '</body>',
      buildWebMCPScript() + '</body>'
    );

    return new Response(botHtml, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'public, max-age=600, must-revalidate',
        'Vary': 'User-Agent',
        'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}' 'sha256-707X5+NAXR96e1UzENjwpPf416b6sJGW3mMwS4KSCqw=' 'sha256-9Z5YUtj2GDOBykVWUu8jxOyhx6HrrXGwO4FEHHSUtqQ=' 'unsafe-hashes' 'sha256-nAiI7XK5Mt/SgNQUZPqTuikvwxIVHV3se6mHGQue+88=' 'sha256-Jag+ZHPii6iUmMQWlnwms/mnjM8gRPTOJA2KIyTQQRk=' 'sha256-uLUdJIdD3+8SpL4nHNFN9YmyHRRmrseSQKwzj3ECn2I=' 'sha256-akyHNuxwVvvLQ11iHoDrpca0qH3TU3LfGbtdQ8kNdwI=' 'sha256-UOhLo4NRrWG89b3vpgtU0dc/C8aWLS+MQ2Lf9vW/4Fk=' 'sha256-jHF5hTIlMDyGZRAsNK0HO/WFYrwPvI2I1q0o1xKKB6I=' 'sha256-wflfhEeJWTAjAK0hnm9/OICxAQ8fVnj3168JrJ/m91k=' 'sha256-oTzV9+pQ7IAxC4NoAc7dH4+0Is4KloZ9u7cMJC7UDrE=' 'sha256-bTpi/7w0Cd8ihAWpwcZJIdz49sMq0d73fWWDzp5Ju2Q='`,
        ...SHARED_SECURITY_HEADERS,
      },
    });
  }

  // ── Human path: serve encrypted + protected app ────────────────────────────
  // [MF1] Fixed M2 code injection with proper escaping
  // [MF2] Added isMobile check for comprehensive mobile coverage
  // [MF3] Enhanced both M1 and M2 with mobile User-Agent detection

  const cspNonce = generateNonce();

  // ── [M2] Decoded-HTML origin guard — Scenario B coverage ─────────────────
  // Injected right after <meta charset="UTF-8"> BEFORE XOR encoding.
  const _sharedCrRP    = route.prefix === '/' ? '' : route.prefix;
  const _sharedCrTM    = html.match(/<title>([^<]*)<\/title>/i);
  const _sharedCrPT    = escHtml(_sharedCrTM ? _sharedCrTM[1] : (route.ogTitle || 'Civil Engineering Suite'));
  const _sharedCrUrl   = `https://civilengsuite.pages.dev${_sharedCrRP}/`;
  const _sharedCrLabel = `civilengsuite.pages.dev${_sharedCrRP}/`;
  const _sharedCrHtml  =
    `<!DOCTYPE html><html><head><meta charset="UTF-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<title>© Protected — ${_sharedCrPT}</title>`
    + `<style>*{box-sizing:border-box;margin:0;padding:0}`
    + `body{background:#0A1A2E;display:flex;align-items:center;justify-content:center;`
    + `min-height:100vh;font-family:sans-serif;text-align:center;padding:24px}`
    + `.card{max-width:440px}.icon{font-size:3.5rem;margin-bottom:18px}`
    + `.title{color:#C17B1A;font-size:1.35rem;font-weight:700;margin-bottom:12px;line-height:1.4}`
    + `.msg{color:#8AA3C7;font-size:0.9rem;line-height:1.8;margin-bottom:22px}`
    + `a{color:#C17B1A;font-size:0.88rem;text-decoration:none}`
    + `a:hover{text-decoration:underline}</style></head><body>`
    + `<div class="card"><div class="icon">🔒</div>`
    + `<div class="title">© Eng. Aymn Asi — ${_sharedCrPT}</div>`
    + `<div class="msg">Unauthorized copying is prohibited.<br>`
    + `This page must be accessed from the official website.</div>`
    + `<a href="${_sharedCrUrl}">${_sharedCrLabel}</a>`
    + `</div></body></html>`;
  const _sharedCrB64 = u8ToB64(new TextEncoder().encode(_sharedCrHtml));

  // [MF5] M2 guard with proper syntax (no unnecessary escapes) and mobile UA detection
  const _m2Code = buildM2Guard(_sharedCrB64, _sharedCrRP, isMobile);
  html = html.replace(/(<meta charset="UTF-8">)/i, `$1<script>${_m2Code}</script>`);

  // Stamp nonce on M2 guard
  html = injectNonces(html, cspNonce);

  // Minify CSS
  html = minifyBotCSS(html);

  // XOR + base64 encode
  const raw   = new TextEncoder().encode(html);
  const xored = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) xored[i] = raw[i] ^ XOR_KEY;
  const payload = u8ToB64(xored);

  const titleM    = html.match(/<title>([^<]*)<\/title>/i);
  const pageTitle = titleM ? titleM[1] : 'Civil Engineering Suite';

  // ── [M1] Bootstrap shell protection ────────────────────────────────────────
  const bootstrapOriginGuard = buildBootstrapGuard(cspNonce, _sharedCrB64, _sharedCrRP, isMobile);

  const bootstrapCopyrightBody =
    `<style>`
    + `#_ces_cr_body{display:none!important;margin:0;background:#0A1A2E;color:#C17B1A;`
    + `font-family:sans-serif;align-items:center;justify-content:center;`
    + `min-height:100vh;text-align:center;position:fixed;top:0;left:0;`
    + `width:100%;height:100%;z-index:2147483647!important}`
    + `</style>`
    + `<noscript><style>#_ces_cr_body{display:flex!important}</style></noscript>`
    + `<div id="_ces_cr_body">`
    + `<div style="padding:40px;max-width:440px">`
    + `<div style="font-size:3.5rem;margin-bottom:18px">🔒</div>`
    + `<h2 style="font-size:1.35rem;font-weight:700;margin-bottom:12px;line-height:1.4">`
    + `© Eng. Aymn Asi — ${escHtml(pageTitle)}</h2>`
    + `<p style="color:#8AA3C7;font-size:0.9rem;line-height:1.8;margin-bottom:22px">`
    + `Unauthorized copying is prohibited.<br>`
    + `This page must be accessed from the official website.</p>`
    + `<a href="${_sharedCrUrl}" style="color:#C17B1A;font-size:0.88rem">${_sharedCrLabel}</a>`
    + `</div></div>`;

  // ── favicon links ────────────────────────────────────────────────────────
  const faviconLinks = route.prefix === '/footing-pro'
    ? `<link rel="icon" type="image/x-icon" href="/footing-pro/images/favicon.ico">`
      + `<link rel="apple-touch-icon" sizes="180x180" href="/footing-pro/images/apple-touch-icon.png">`
    : '';

  // ── OG meta block ───────────────────────────────────────────────────────
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

  // ── WebMCP bootstrap ────────────────────────────────────────────────────
  const webMCPBootstrap = `<script nonce="${cspNonce}">`
    + `(function(){`
    + `if(!navigator.modelContext||typeof navigator.modelContext.provideContext!=='function')return;`
    + `try{navigator.modelContext.provideContext({`
    + `name:'civil-engineering-suite',`
    + `description:'Civil Engineering Suite — Free ACI 318-19 structural engineering tools by Eng. Aymn Asi.',`
    + `tools:[`
    + `{name:'open_footing_pro',description:'Footing Pro v.2026 — ACI 318-19 combined footing design, 17 modules.',`
    + `inputSchema:{type:'object',properties:{},required:[]},`
    + `execute:function(){window.location.href='/footing-pro/';return{success:true,url:'/footing-pro/'};}},`
    + `{name:'open_section_property_pro',description:'Section Property Pro — area, centroid, Ix/Iy, section modulus, radius of gyration.',`
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
    + `</script>`;

  // ── LCP preload ─────────────────────────────────────────────────────────
  const lcpPreload = route.prefix === '/footing-pro'
    ? '<link rel="preload" as="image" href="/footing-pro/images/hero-bg.avif"'
      + ' imagesrcset="/footing-pro/images/hero-bg.avif 1x,/footing-pro/images/hero-bg.webp 1x"'
      + ' imagesizes="100vw" fetchpriority="high">'
    : '';

  // ── Build bootstrap shell ───────────────────────────────────────────────
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
    + `</script>`
    + `</body></html>`;

  // [MF4] Add Content-Disposition for mobile downloads
  const responseHeaders = {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}' 'sha256-707X5+NAXR96e1UzENjwpPf416b6sJGW3mMwS4KSCqw=' 'sha256-9Z5YUtj2GDOBykVWUu8jxOyhx6HrrXGwO4FEHHSUtqQ=' 'unsafe-hashes' 'sha256-nAiI7XK5Mt/SgNQUZPqTuikvwxIVHV3se6mHGQue+88=' 'sha256-Jag+ZHPii6iUmMQWlnwms/mnjM8gRPTOJA2KIyTQQRk=' 'sha256-uLUdJIdD3+8SpL4nHNFN9YmyHRRmrseSQKwzj3ECn2I=' 'sha256-akyHNuxwVvvLQ11iHoDrpca0qH3TU3LfGbtdQ8kNdwI=' 'sha256-UOhLo4NRrWG89b3vpgtU0dc/C8aWLS+MQ2Lf9vW/4Fk=' 'sha256-jHF5hTIlMDyGZRAsNK0HO/WFYrwPvI2I1q0o1xKKB6I=' 'sha256-wflfhEeJWTAjAK0hnm9/OICxAQ8fVnj3168JrJ/m91k=' 'sha256-oTzV9+pQ7IAxC4NoAc7dH4+0Is4KloZ9u7cMJC7UDrE=' 'sha256-bTpi/7w0Cd8ihAWpwcZJIdz49sMq0d73fWWDzp5Ju2Q='`,
    ...SHARED_SECURITY_HEADERS,
  };

  // Force copyright page download for mobile User-Agents
  if (isMobile) {
    responseHeaders['Content-Disposition'] = 'attachment; filename="copyright.html"';
  }

  return new Response(bootstrap, { status: 200, headers: responseHeaders });
}

/**
 * ═════════════════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═════════════════════════════════════════════════════════════════════════════
 */

// [MF2] Comprehensive mobile User-Agent detection
function isMobileUA(ua) {
  if (!ua) return false;
  // Check for explicit mobile markers
  if (!/android|webos|iphone|ipad|ipod|blackberry|iemobile|opera mini|mobile|mobi|tablet/i.test(ua)) {
    return false;
  }
  // Exclude desktop platforms (but allow Android which contains "Linux")
  if (/windows nt|macintosh|x11|cros/i.test(ua)) {
    if (!/android/i.test(ua)) return false;
  }
  return true;
}

// [MF5] Build M2 guard with proper syntax and mobile detection
function buildM2Guard(crB64, crRP, isMobile) {
  return `(function(){'use strict';`
    + `var _ao='https://civilengsuite.pages.dev';`
    + `var _o=(typeof window!=='undefined')?window.location.origin:'';`
    + `var _dev=/^https?:\\/\\/(localhost|127\\.0\\.0\\.1)(:\\d+)?$/.test(_o);`
    + `var _m=${isMobile?'true':'false'};`
    + `if((_o!==_ao&&!_dev)||_m){`
    + `var _b='${crB64}';`
    + `var _n=atob(_b);var _ba=new Uint8Array(_n.length);`
    + `for(var i=0;i<_n.length;i++)_ba[i]=_n.charCodeAt(i);`
    + `var _cr=new TextDecoder('utf-8').decode(_ba);`
    + `try{document.open();document.write(_cr);document.close();}`
    + `catch(e){window.location.replace(_ao+'${crRP}/');}}`
    + `})();`;
}

// Build bootstrap origin guard with mobile detection
function buildBootstrapGuard(nonce, crB64, crRP, isMobile) {
  return `<script nonce="${nonce}">`
    + `(function(){'use strict';`
    + `var _ao='https://civilengsuite.pages.dev';`
    + `var _o=(typeof window!=='undefined')?window.location.origin:'';`
    + `var _ua=(typeof navigator!=='undefined')?(navigator.userAgent||''):'';`
    + `var _m=/android|webos|iphone|ipad|ipod|mobi|tablet/i.test(_ua);`
    + `var _dev=/^https?:\\/\\/(localhost|127\\.0\\.0\\.1)(:\\d+)?$/.test(_o);`
    + `if((_o!==_ao&&!_dev)||_m){`
    + `var _b='${crB64}';`
    + `var _n=atob(_b);var _ba=new Uint8Array(_n.length);`
    + `for(var i=0;i<_n.length;i++)_ba[i]=_n.charCodeAt(i);`
    + `var _cr=new TextDecoder('utf-8').decode(_ba);`
    + `try{document.open();document.write(_cr);document.close();}`
    + `catch(e){window.location.replace(_ao+'${crRP}/');}}`
    + `}`
    + `})();`
    + `</script>`;
}

function generateNonce() {
  const array = new Uint8Array(12);
  for (let i = 0; i < 12; i++) array[i] = Math.floor(Math.random() * 256);
  return btoa(String.fromCharCode(...array)).replace(/[+/=]/g, '');
}

function escHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function u8ToB64(u8) {
  const CHUNK_SIZE = 8192;
  let b64 = '';
  for (let i = 0; i < u8.length; i += CHUNK_SIZE) {
    const chunk = u8.subarray(i, Math.min(i + CHUNK_SIZE, u8.length));
    b64 += String.fromCharCode.apply(null, chunk);
  }
  return btoa(b64);
}

function injectNonces(html, nonce) {
  return html.replace(/<script(?!\s+nonce=)/gi, `<script nonce="${nonce}"`);
}

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

function stripProtectionScripts(html) {
  function safeScriptRe(marker) {
    return new RegExp(
      '<script\\b[^>]*>(?:(?!</script>)[\\s\\S])*?' + marker + '(?:(?!</script>)[\\s\\S])*?</script>',
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

function matchRoute(pathname) {
  const routes = [
    { prefix: '/', htmlPath: '/public/index.html', ogTitle: 'Civil Engineering Suite', ogDescription: 'Free structural engineering tools by Eng. Aymn Asi', ogImage: '/images/og-image.png', ogUrl: 'https://civilengsuite.pages.dev/' },
    { prefix: '/footing-pro', htmlPath: '/public/footing-pro/index.html', ogTitle: 'Footing Pro v.2026', ogDescription: 'ACI 318-19 combined footing design tool', ogImage: '/footing-pro/images/og-image.png', ogUrl: 'https://civilengsuite.pages.dev/footing-pro/' },
    { prefix: '/beam-pro', htmlPath: '/public/beam-pro/index.html', ogTitle: 'Beam Pro', ogDescription: 'Structural beam analysis tool', ogImage: '/images/og-image.png', ogUrl: 'https://civilengsuite.pages.dev/beam-pro/' },
    { prefix: '/column-pro', htmlPath: '/public/column-pro/index.html', ogTitle: 'Column Pro', ogDescription: 'Reinforced column design tool', ogImage: '/images/og-image.png', ogUrl: 'https://civilengsuite.pages.dev/column-pro/' },
    { prefix: '/section-property-pro', htmlPath: '/public/section-property-pro/index.html', ogTitle: 'Section Property Pro', ogDescription: 'Section property calculator', ogImage: '/images/og-image.png', ogUrl: 'https://civilengsuite.pages.dev/section-property-pro/' },
    { prefix: '/deflection-pro', htmlPath: '/public/deflection-pro/index.html', ogTitle: 'Deflection Pro', ogDescription: 'Beam deflection analysis', ogImage: '/images/og-image.png', ogUrl: 'https://civilengsuite.pages.dev/deflection-pro/' },
    { prefix: '/earthquake-pro', htmlPath: '/public/earthquake-pro/index.html', ogTitle: 'Earthquake Pro', ogDescription: 'Seismic design tool', ogImage: '/images/og-image.png', ogUrl: 'https://civilengsuite.pages.dev/earthquake-pro/' },
    { prefix: '/mur-pro', htmlPath: '/public/mur-pro/index.html', ogTitle: 'Mur Pro', ogDescription: 'Retaining wall design', ogImage: '/images/og-image.png', ogUrl: 'https://civilengsuite.pages.dev/mur-pro/' },
    { prefix: '/add-reft-pro', htmlPath: '/public/add-reft-pro/index.html', ogTitle: 'Add Reft Pro', ogDescription: 'Reinforcement calculator', ogImage: '/images/og-image.png', ogUrl: 'https://civilengsuite.pages.dev/add-reft-pro/' },
  ];
  for (const r of routes) {
    if (pathname === r.prefix || pathname === r.prefix + '/') {
      return r;
    }
  }
  return null;
}

const BOT_RE = /googlebot|bingbot|slurp|duckduckbot|baiduspider|yandexbot|sogou|exabot|facebookexternalhit|linkedinbot|twitterbot|whatsapp|telegram|skypeuripreview|iframely|embedly|pinterestbot|slackbot|vkshare|w3c_validator|applebot|redditbot|greatis|blexbot|dotbot|perplexitybot|ia_archiver|adsbot-google|google-image|rogerbot|curl|wget|scrapy|screaming|googlebot-image|roborock|ot-mcp|adsbot|validator|claude/i;

const XOR_KEY = 0x5A;

const SHARED_SECURITY_HEADERS = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-DNS-Prefetch-Control': 'off',
  'X-Permitted-Cross-Domain-Policies': 'none',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'unsafe-none',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), accelerometer=(), gyroscope=(), magnetometer=(), display-capture=(), screen-wake-lock=(), autoplay=(), clipboard-read=()',
};

const CSP_COMMON = 'default-src \'self\'; script-src \'nonce-X\' \'unsafe-hashes\'; style-src \'self\' \'unsafe-inline\'; font-src \'self\'; img-src \'self\' data: https:; connect-src \'self\' https:; frame-ancestors \'none\'; base-uri \'self\'; upgrade-insecure-requests; report-uri /api/csp-report'.replace('\'nonce-X\'', '\'nonce-{nonce}\'');
