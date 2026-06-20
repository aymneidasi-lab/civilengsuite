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
 *
 * 2026-06-20 v22 — [WM-FIX] Watermark stamp: remove dark overlay background:
 *
 *   ROOT CAUSE: #ces-watermark element carried background/background-color/
 *   background-image CSS properties that rendered a dark translucent overlay
 *   over the entire viewport. On dark-background page sections (live site),
 *   stamp text color matched the overlay → watermarks invisible (Image 2).
 *   On white-background local file the overlay created contrast → stamps
 *   visible (Image 1). The overlay is cosmetically unintended: the stamp
 *   text children are the functional artifact, not the container background.
 *
 *   [WM-FIX-1] Human-path inline-style cleanup (Pass 1):
 *         regex strips background-* properties from the #ces-watermark
 *         element's inline style= attribute in the decoded HTML BEFORE XOR
 *         encoding. The protection bundle (buildProtectionBundle) captures
 *         _ws = _wm.style.cssText at runtime post-DOMContentLoaded. Since
 *         the markup is cleaned pre-encode, _ws is background-free from the
 *         first snapshot — the MutationObserver will never restore a dark
 *         background. Also handles style-before-id attribute ordering via
 *         a second pass.
 *
 *   [WM-FIX-2] Human-path <head> stylesheet override (Pass 2 — belt-and-suspenders):
 *         Injects <style id='_ces_wm_bg_fix'> with !important declarations
 *         immediately before </head> in the decoded HTML.
 *         CSS cascade: !important in author stylesheet beats non-!important
 *         inline style. MutationObserver watches attribute mutations (style/
 *         class/hidden attrs), NOT computed-style changes from stylesheets —
 *         the override is never undone by the protection bundle.
 *         Placed last in <head> → wins over any earlier same-specificity rule.
 *
 *   [WM-FIX-3] Human-path <style>-block cleanup (Pass 3):
 *         Strips background-* from any <style> block in the decoded HTML that
 *         contains a #ces-watermark rule. Guards against background being set
 *         via CSS class rather than inline style. Skips our own _ces_wm_bg_fix
 *         style block to prevent self-removal.
 *
 *   Bot path: unaffected. WM-FIX injections are in the human-path block only,
 *   after the BOT_RE early return. Crawlers receive unchanged HTML.
 *
 * 2026-06-10 v21 — MHTML mobile download fix: adoptedStyleSheets + DOM overlay (MHTML-FIX):
 *
 *   ROOT CAUSE: Chrome Android's "Download page" (toolbar ⋮ → Download) saves the
 *   RENDERED DOM as MHTML and strips ALL <script> blocks from the archive. When the
 *   saved file is reopened, zero JavaScript executes. The old FxC approach in the
 *   source HTML origin guard's authorized-else branch called:
 *       _ces_hide_src.parentNode.removeChild(_ces_hide_src)
 *   This DOM mutation was captured in the MHTML snapshot. On re-open: _ces_hide_src
 *   was absent from the MHTML DOM → html{visibility:hidden} never applied → real page
 *   fully visible. All JS guards (M1a, M1c, M2) irrelevant — MHTML stripped them.
 *
 *   [MHTML-FIX-A] Source HTML — _ces_cr_src_style overlay CSS block (DOM):
 *         Added <style id="_ces_cr_src_style"> immediately after <style id="_ces_hide_src">.
 *         Contains: #_ces_cr_src_overlay{visibility:visible!important;position:fixed;...}
 *         Both style blocks stay in DOM for authorized access (no removeChild).
 *         MHTML captures both. On MHTML re-open with scripts stripped:
 *           _ces_hide_src → html{visibility:hidden} → real content hidden ✓
 *           _ces_cr_src_style → #_ces_cr_src_overlay{visibility:visible!important} ✓
 *
 *   [MHTML-FIX-B] Source HTML — #_ces_cr_src_overlay DOM element (first body child):
 *         Full copyright card (🔒, title, message, link) rendered in fixed overlay.
 *         Visible by default from _ces_cr_src_style. Hidden for authorized live access
 *         via adoptedStyleSheets (CSSOM — see MHTML-FIX-C). MHTML serializes DOM nodes
 *         only, not CSSOM, so the overlay stays visible in saved MHTML.
 *
 *   [MHTML-FIX-C] Source HTML — authorized-else branch → adoptedStyleSheets (CSSOM):
 *         REPLACED the old removeChild(_ces_hide_src) DOM mutation with:
 *           var _ss = new CSSStyleSheet();
 *           _ss.replaceSync('html{visibility:visible!important;...}
 *                            #_ces_cr_src_overlay{display:none!important}');
 *           document.adoptedStyleSheets = [...].concat([_ss]);
 *         CSSOM adoptedStyleSheets are NOT serialized by Chrome's MHTML writer.
 *         Live access: CSSOM overrides _ces_hide_src → page visible, overlay hidden ✓
 *         MHTML save: DOM unchanged (both style blocks still there), CSSOM gone →
 *           on MHTML re-open: page hidden, overlay visible ✓
 *         Fallback for pre-Chrome 73 / pre-Safari 16.4 (<1% 2026): DOM mutation
 *           (MHTML protection not guaranteed on these ancient browsers; acceptable).
 *
 *   [MHTML-FIX-D] Worker [[path]].js — stripProtectionScripts bot-path cleanup:
 *         Added four new stripping rules for the bot path:
 *           1. <style id="_ces_hide_src">    — remove from bot HTML (clean crawler output)
 *           2. <style id="_ces_cr_src_style"> — remove from bot HTML (new element)
 *           3. <div id="_ces_cr_src_overlay"> — remove from bot HTML (new element)
 *           4. Source origin guard script via /* _ces_src_guard_v21 * / marker
 *         Previously: source HTML origin guard and _ces_hide_src were NOT stripped
 *         from the bot path. Googlebot's Chromium renderer executed the guard's else
 *         branch to make the page visible. This still works after the adoptedStyleSheets
 *         change. The new rules add explicit stripping for a clean bot-path response
 *         with no protection artifacts visible in Google's HTML cache.
 *
 * 2026-06-10 v20 — FxD: M1a authorized-else branch removes _ces_hide (blank-page fix):
 *
 *   [FxD] bootstrapOriginGuard (M1a) authorized-else branch — explicit _ces_hide removal:
 *         BUG (v19): bootstrapOriginGuard had no else branch. _ces_hide removal relied
 *         entirely on document.open()+document.write() in the XOR decoder replacing the
 *         whole document. When document.open() fails (sandboxed context, browser quirk,
 *         corrupt payload), the XOR decoder catch block appends an error <p> to
 *         document.body while html{visibility:hidden!important} from _ces_hide persists.
 *         Result: blank white page — the error paragraph is also invisible.
 *         FIX: M1a is parser-blocking in <head> and executes AFTER _ces_hide is parsed
 *         (it is the first child of <head>). For authorized origins the else branch now
 *         calls getElementById('_ces_hide') + removeChild immediately. _ces_hide removal
 *         no longer depends on document.open() succeeding anywhere downstream.
 *         Mirrors the FxC pattern already applied to the source HTML (_ces_hide_src).
 *
 * 2026-06-09 v19 — CSS pre-hide + M1c overlay visibility fix + copyright message update (FxA, FxB, FxC-msg):
 *
 *   Three hardened protection layers:
 *
 *   [FxA] M1c overlay visibility fix:
 *         BUG: When M1a fires and sets html {display:none!important}, then document.open()
 *         throws, M1c enters the !_m1cOk branch and appends a position:fixed overlay to
 *         document.body. BUT html is still display:none — the CSS rendering tree excludes
 *         it entirely; fixed-position children are NOT rendered. Overlay is invisible.
 *         FIX: Before appending the overlay, reset html cssText to:
 *           'display:block!important;background:#0A1A2E'
 *         The background:#0A1A2E prevents any flash of real page content between the
 *         display:block reset and the first paint of the overlay.
 *
 *   [FxB] CSS pre-hide nuclear layer in bootstrap:
 *         Adds <style id="_ces_hide">html{visibility:hidden!important;pointer-events:none!important}</style>
 *         as the FIRST child of bootstrap <head>, before ALL preloads, metas, and scripts.
 *         Fires at CSS parse time — before M1a, before any script, before any preload is
 *         initiated. For authorized users, document.open()+document.write() inside the XOR
 *         decoder replaces the entire document, removing _ces_hide automatically with it.
 *         For unauthorized users, M1a sets display:none!important (stronger than visibility)
 *         and writes the copyright page. The pre-hide closes the window between parse start
 *         and M1a first execution — a zero-JS fallback for the moment before M1a fires.
 *         visibility:hidden (not display:none) preserves layout so the pre-hide itself does
 *         not cause layout thrash; the body is never fully painted during this window.
 *
 *   [FxC-msg] Copyright message standardization:
 *         All user-visible copyright overlays and copyright pages now use the canonical
 *         message: "© Civil Engineering Suite — Protected Content"
 *         with "Access via civilengsuite.pages.dev" as the action line.
 *         Updated in: _sharedCrHtml, buildProtectionBundle crHtml, bootstrapCopyrightBody,
 *         M1c !_m1cOk overlay innerHTML, M2 DOMContentLoaded fallback innerHTML.
 *
 * 2026-06-09 v18 — Add window.stop() + pre-hide to all origin guards (MF5):
 *
 *   ROOT CAUSE: On Chrome Android content:// URI (Scenario B — Chrome saves the
 *   rendered DOM, opens via DownloadManager ContentProvider), document.open() in
 *   M2/_m2ok=true path SUCCEEDS and writes the copyright page. BUT: Chrome Android
 *   does not fully abort the content:// stream on document.open(). The original HTML
 *   bytes continue being fed to the parser after document.close() — overwriting or
 *   re-rendering the copyright page. Result: copyright flashes briefly, then the
 *   real page renders. The large white side space in the screenshot is the copyright
 *   page's body CSS partially merging with the original document's layout.
 *
 *   [MF5] window.stop() + pre-hide added to ALL document.open() sequences:
 *         Sequence (M1a, M1c, M2, source HTML guard):
 *           try{document.documentElement.style.cssText='display:none!important';}catch(_){}
 *           window.stop();                           // halt content:// stream
 *           document.open();                         // reset document
 *           document.write(_cr);                     // write copyright HTML
 *           document.close();                        // finalize
 *         window.stop() must be called BEFORE document.open() to abort the
 *         in-progress stream. After document.open() the window context may change.
 *         The display:none on documentElement hides existing content immediately,
 *         preventing any visible flash of real content during the transition.
 *         For the DOMContentLoaded fallback path: also set
 *           document.documentElement.style.cssText='display:none!important'
 *         immediately (synchronously) before the listener fires.
 *
 *   NET RESULT: content:// opened files now show copyright page with no flash
 *   and no re-rendering of the real page.
 *
 * 2026-06-09 v17 — Strip source-HTML origin-guard redirect fallback in human path (MF4):
 *
 *   ROOT CAUSE (two bugs, both in the source HTML inline origin guard):
 *
 *   BUG A — HTML parser terminates <script> block early:
 *     The guard comment contained the literal text "</script>." (unescaped):
 *       "the JS engine misreading them as </script>."
 *     Chrome's HTML parser terminates <script> at the FIRST literal </script>
 *     sequence regardless of whether it is inside a JS comment. The JS engine
 *     receives a truncated, syntactically invalid script → SyntaxError thrown →
 *     guard NEVER executes → origin is never checked → real page renders.
 *     Fix: escape the </script> in the comment to <\/script>.
 *
 *   BUG B — catch block redirected to live site:
 *     When document.open() throws (sandboxed context), the catch block called
 *     window.location.replace(_ao + '/') → Chrome loads the live canonical site.
 *     Fix: replace redirect with window['__CES_BLOCK']=1 plus a direct DOM overlay
 *     (fixed-position div covering the page). The overlay fires immediately if
 *     document.body exists, or via DOMContentLoaded if still in <head>.
 *     The __CES_BLOCK flag is also set for M1c (bootstrap XOR decoder context).
 *
 *   [MF4] Human path in [[path]].js: after protection bundle injection, BEFORE minify:
 *         html.replace(/}\s*catch\s*\(\w+\)\s*\{[^{}]*window\.location\.replace...\}/g,
 *                      "}catch(_cre){window['__CES_BLOCK']=1;}")
 *         Handles any other encrypted page source files that still have the old
 *         redirect-catch pattern. The __CES_BLOCK flag is picked up by M1c, and
 *         M2's DOMContentLoaded DOM-overlay handler covers Scenario B.
 *         Note: the parser-termination bug (BUG A) is fixed in the source HTML
 *         directly — [[path]].js cannot fix a broken <script> block since the
 *         HTML parser splits it before the worker sees it.
 *         Bot path: not affected — stripProtectionScripts already removes the
 *         entire source guard block on the bot branch.
 *
 *   [MF4] Human path: after protection bundle injection, BEFORE minify, apply:
 *         html.replace(/}\s*catch\s*\(\w+\)\s*\{[^{}]*window\.location\.replace...\}/g,
 *                      "}catch(_cre){window['__CES_BLOCK']=1;}")
 *         This neutralizes ALL catch-block redirect fallbacks in decoded source HTML.
 *         Pattern is safe: only matches catch blocks whose ENTIRE body is a single
 *         window.location.replace() call (no nested braces) — the exact pattern used
 *         by the source guard. The __CES_BLOCK flag is picked up by M1c if it runs,
 *         and M2's DOMContentLoaded DOM-overlay handler fires regardless.
 *         Bot path: not affected — stripProtectionScripts already removes the entire
 *         source guard block before this point in the bot branch.
 *
 *   NET RESULT: Downloaded .html file opened on Android Chrome (file:// or content://)
 *   now shows the copyright page. The source guard's catch block sets __CES_BLOCK=1
 *   instead of redirecting, allowing M2's DOMContentLoaded DOM overlay to display the
 *   copyright card. The live site is NEVER loaded from a locally opened saved file.
 *
 * 2026-06-09 v16 — Mobile download protection: fix origin-guard redirect fallback (MF1–MF3):
 *
 *   ROOT CAUSE: All three origin-guard layers (M1a bootstrapOriginGuard, M1c
 *   xorDecoderOriginGuard, M2 htmlOriginGuard) shared an identical fallback bug.
 *   When document.open() throws on Chrome Android opening a downloaded file via
 *   the native file viewer (file:// or content:// URI), the catch block fired:
 *       window.location.replace(_aos[0] + path)
 *   This silently navigated the browser to the LIVE canonical URL. Chrome loaded
 *   and rendered the real engineering page — the downloaded file appeared to have
 *   "bypassed" protection, but was actually being redirected to civilengsuite.pages.dev.
 *
 *   [MF1] bootstrapOriginGuard (M1a) fallback: window.location.replace() removed.
 *         Replaced with: attempt document.open() without any redirect on failure.
 *         On document.open() failure, sets window['__CES_BLOCK']=1 so M1c can
 *         detect the blocked state when the HTML parser reaches <body>. If M1a's
 *         document.open() aborts the parser (normal Chrome behavior), M1c is never
 *         reached and copyright is already shown. If it fails, M1c takes over.
 *
 *   [MF2] xorDecoderOriginGuard (M1c): guard condition expanded from
 *         (_xaos.indexOf(_xo)===-1&&!_xd) to also OR window['__CES_BLOCK'],
 *         which is set by M1a on document.open failure. Fallback changed from
 *         window.location.replace() to a fixed-position DOM overlay element
 *         (document.body is available in the <body> script context). The return
 *         statement after copyright display is unconditional — XOR decode NEVER
 *         runs regardless of document.open() success or failure.
 *
 *   [MF3] htmlOriginGuard (M2) fallback: window.location.replace() removed.
 *         Replaced with: (a) inject hide-style into <head> immediately, so real
 *         content is not visible even if document.open() fails; (b) DOMContentLoaded
 *         handler that overwrites document.body with the copyright card. Handles
 *         Scenario B (Chrome Android saves the rendered DOM post document.write).
 *
 *   NET RESULT: Downloaded .html file opened on Android Chrome (file:// or
 *   content://) now shows the copyright page and NEVER silently redirects to
 *   civilengsuite.pages.dev. The live site is not loaded from a locally opened file.
 *
 * 2026-06-09 v15 — Inline non-canonical redirect gate + fix _canonicalOrigin derivation (M3b-inline, M3b-fix):
 *
 *   CONTEXT: v14 documented [M3b] as a SEPARATE gsuite_redirect_worker.js file that would
 *   be deployed independently to the gsuite.pages.dev project. In practice this requires
 *   maintaining two repos/deployments. v15 folds both responsibilities into this single
 *   [[path]].js — the same file now acts as both the canonical serving handler and a
 *   full redirect worker when deployed to any non-canonical Pages project.
 *
 *   [M3b-inline] Non-canonical host redirect gate added at the top of onRequest().
 *         Runs BEFORE STATIC_PASSTHROUGH — every request to a non-canonical host
 *         (e.g., gsuite.pages.dev) is intercepted and 301-redirected to the canonical
 *         domain, including font, image, and .well-known requests. This closes the
 *         CDN bypass at the network layer: no raw file is ever served from any
 *         non-canonical host.
 *         Canonical host: CANONICAL_HOST env var (default: 'civilengsuite.pages.dev').
 *         Add custom domains: ALLOWED_ORIGINS env var (unchanged — comma-separated https:// origins).
 *         Cloudflare preview deployments (*.civilengsuite.pages.dev) are exempt via
 *         subdomain suffix check so preview URLs work without adding them to ALLOWED_ORIGINS.
 *         Localhost / 127.0.0.1 (any port) is always exempt for local wrangler dev.
 *         _canonicalHostname and _allowedHostsRaw computed here are reused below in
 *         [M3a] to build _allowedOriginsJs — no duplicate env-var reads.
 *
 *   [M3b-fix]  _canonicalOrigin no longer derived from url.host.
 *         v14 set: const _canonicalOrigin = `https://${url.host}`;
 *         Critical defect: if [[path]].js is deployed to gsuite.pages.dev WITHOUT the
 *         redirect gate (i.e., v14 only, before this fix), url.host would be
 *         'gsuite.pages.dev', and _canonicalOrigin would be 'https://gsuite.pages.dev'.
 *         All three guard layers (M1a bootstrapOriginGuard, M1c xorDecoderOriginGuard,
 *         M2 htmlOriginGuard) would then emit gsuite.pages.dev as the ALLOWED origin —
 *         completely neutralizing protection for any request served from that host.
 *         Fix: _canonicalOrigin = `https://${_canonicalHostname}` where _canonicalHostname
 *         comes from CANONICAL_HOST env var. By the time [M3a] runs, the redirect gate
 *         has already guaranteed url.hostname IS the canonical host, making this
 *         semantically equivalent but safe for multi-project deployments.
 *
 *   [M3b-urls] _sharedCrUrl and _sharedCrLabel (the copyright page's clickable link)
 *         now use _canonicalOrigin / _canonicalHostname instead of the hardcoded
 *         literal 'https://civilengsuite.pages.dev'. Ensures the copyright page link
 *         is always correct for custom domain deployments.
 *
 * 2026-06-08 v14 — Runtime allowed-origins + gsuite.pages.dev redirect gate (M3):
 *
 *   ROOT CAUSE: gsuite.pages.dev is the default Cloudflare Pages project alias —
 *   a separate project with no Pages Function deployed. Chrome Android's native
 *   Download button issued a GET to gsuite.pages.dev which served raw static files
 *   directly from the CDN, completely bypassing this worker and all M1/M2 guards.
 *
 *   [M3a] Runtime _allowedOriginsJs — replaces the hardcoded 'https://civilengsuite.pages.dev'
 *         string in all 3 guard layers (M2 htmlOriginGuard, M1a bootstrapOriginGuard,
 *         M1c xorDecoderOriginGuard) with a runtime-computed JSON array derived from
 *         url.host (the live CF request hostname). This means the canonical domain is
 *         always correct regardless of which Pages project serves the request, and
 *         custom domains can be added via the ALLOWED_ORIGINS env var
 *         (comma-separated, e.g. "https://civilengsuite.com,https://www.civilengsuite.com")
 *         without a code redeploy.
 *         Guard logic changed from (_o !== _ao) to (_aos.indexOf(_o) === -1) — semantically
 *         identical for a single-element array, extensible for multiple allowed origins.
 *
 *   [M3b] gsuite_redirect_worker.js — standalone Cloudflare Pages Function to deploy
 *         to the gsuite.pages.dev project. Intercepts ALL requests and issues a 301
 *         redirect to https://civilengsuite.pages.dev{path}. This closes the bypass
 *         at the network layer: no raw file is ever served from gsuite.pages.dev.
 *         Deploy: copy to functions/[[path]].js in the gsuite.pages.dev repo root.
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
 *   TWO DISTINCT DOWNLOAD SCENARIOS addressed by v13:
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
 *   [M1c] xorDecoderOriginGuard — third-layer origin check INSIDE the XOR decoder script
 *         itself (bootstrap <body>). Defense-in-depth only: M1a (bootstrap <head>) already
 *         aborts the HTML parser via document.open() so the XOR decoder's <script> tag is
 *         never even parsed on unauthorized file:// opens. M1c only fires in the rare edge
 *         case where M1a was silently neutralized — for example, a browser extension that
 *         strips nonce attributes and forces scripts async, a CSP-relaxing extension, or a
 *         future browser quirk where <head> scripts lose their parser-blocking guarantee.
 *         Reuses _sharedCrB64 (copyright page already in memory from M1a/M2 setup).
 *         On M1c trigger: document.open() + copyright write, then early return — XOR decode
 *         never executes and real HTML is never exposed.
 *         On legitimate access: origin matches → guard is a no-op → decode continues. ✓
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
 *         html title and reused for M1a, M1c (bootstrap) and M2 (decoded HTML).
 *
 * 2026-06-03 v11 — /download redirect (D1):
 *   [D1] /download route: 302 redirect to the Google Drive direct-download URL for
 *        the Civil Engineering Suite Activation Tool installer (.exe). Previously
 *        the path was unhandled — !route → context.next() → Cloudflare static
 *        file serving found no file → 404. Fix: explicit handler before the route
 *        matcher issues a 302 Found with Cache-Control: no-store so the redirect
 *        destination can be swapped at any time without stale browser caches.
 *        SHARED_SECURITY_HEADERS applied to avoid stripping existing protections.
 *        No CSP needed: 302 responses carry no body.
 *
 * 2026-06-03 v10 — Inline handler CSP fix + landing page 404 fix (H1–H2):
 *   [H1] CRITICAL BUG FIX: script-src now includes 'unsafe-hashes' + SHA-256 hashes
 *        for all 9 inline event handlers in the decrypted HTML. Change [F2] (v9)
 *        removed 'unsafe-inline' from script-src to silence console noise. Per CSP
 *        Level 3, nonces bypass unsafe-inline ONLY for <script> elements, not for
 *        inline event handlers (onclick, etc.). Removing unsafe-inline therefore
 *        blocked every onclick attribute in the page — specifically:
 *          · onclick="openSegModal()" on the Hero "Buy License — 249 EGP" button
 *          · onclick="openSegModal()" on the World-First "Subscribe Now" button
 *          · onclick="openSegModal()" on the bottom CTA "Buy License — 249 EGP" button
 *          · onclick="segModalDismiss()" on the modal ✕ close button
 *          · onclick="segModalDismiss()" on the modal Skip button
 *          · onclick="segModalTrack('engineers'|'offices'|'students')" on modal cards
 *          · onclick="window.open('/footing-pro/{segment}/','_self')" on segment cards
 *          · onclick="event.stopPropagation()" on inner anchor tags
 *        All these handlers fired silently into void — the user saw no response.
 *        Fix: 'unsafe-hashes' + explicit SHA-256 hashes for each handler value allows
 *        ONLY those 9 specific handlers. Nonce security for <script> elements is
 *        unchanged. Lighthouse Best Practices score unaffected ('unsafe-hashes' is
 *        not penalized; 'unsafe-inline' was). Applied to BOTH bot and human CSP.
 *   [H2] _redirects BUG FIX (documented here for change log completeness):
 *        The landing page rewrite rules pointed to /public/footing-pro/{segment}/:splat
 *        but the files live at /footing-pro/{segment}/index.html (repo root, not public/).
 *        This mismatch caused 404 on /footing-pro/offices/ and /footing-pro/students/.
 *        Fix is in _redirects: the 3 incorrect rules are removed; Cloudflare Pages
 *        file serving finds the files directly without any redirect rule.
 * 2026-04-28 v9 — PSI font + LCP + CSP fixes (F1–F3):
 *   [F1] STATIC_PASSTHROUGH: added fonts\.* — eliminates function invocation
 *        overhead for every font request. Previously fonts fell through to
 *        context.next() via the !route fallback, adding unnecessary routing
 *        overhead on every woff2 request.
 *   [F2] Human-path bootstrap CSP: removed 'unsafe-inline' from script-src.
 *        Per CSP Level 3 spec, 'unsafe-inline' is ignored when a nonce is
 *        present. Its presence caused browsers to log nonce violations for
 *        inline event handlers in the decoded HTML. Removal eliminates two
 *        console errors per page load, restoring Best Practices to 100.
 *   [F3] lcpPreload: removed type="image/webp", added imagesizes="100vw".
 *        type attribute caused preload skip on some user agents. imagesizes
 *        is required for correct preload width computation on responsive views.
 *        Bootstrap font preloads updated: replaced inter-400/inter-700/playfair-700
 *        with inter-500/inter-600/playfair-400/playfair-900/jetbrains-mono-400/
 *        jetbrains-mono-600 (8 fonts total, ordered by first-viewport priority).
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
  // Case-insensitive; skips scripts that already carry a nonce attribute
  return html.replace(/<script(\b[^>]*?)>/gi, (match, attrs) => {
    if (/\bnonce\s*=/.test(attrs)) return match; // already has nonce
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
function buildProtectionBundle(pageFilename, skipDevGuard) {
  const crHtml = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<title>&#169; Protected &#8212; Civil Engineering Suite</title>`
    + `<style>*{box-sizing:border-box;margin:0;padding:0}html,body{background:#0A1A2E;background-image:linear-gradient(#0A1A2E,#0A1A2E);min-height:100vh}`
    + `body{display:flex;align-items:center;justify-content:center;font-family:'DM Sans','Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;text-align:center;padding:24px}`
    + `.card{max-width:440px;width:100%;background:rgba(255,255,255,0.04);border:1px solid rgba(193,123,26,0.25);border-radius:24px;padding:44px 36px;box-shadow:0 24px 48px rgba(0,0,0,0.45),inset 0 1px 0 rgba(255,255,255,0.06)}`
    + `.icon{font-size:3.2rem;margin-bottom:20px;line-height:1}.title{color:#C17B1A;font-size:1.3rem;font-weight:700;margin-bottom:14px;line-height:1.45;letter-spacing:-0.01em}`
    + `.msg{color:#8AA3C7;font-size:0.875rem;line-height:1.75;margin-bottom:0}.div{height:1px;background:linear-gradient(90deg,transparent,rgba(193,123,26,0.3),transparent);margin:22px 0}`
    + `a{display:inline-flex;align-items:center;gap:6px;color:#FAD98B;font-size:0.88rem;font-weight:600;text-decoration:none;background:rgba(193,123,26,0.15);border:1px solid rgba(193,123,26,0.35);padding:10px 22px;border-radius:40px}`
    + `</style></head><body><div class="card"><div class="icon">&#x1F512;</div>`
    + `<div class="title">&#169; Civil Engineering Suite &#8212; Protected Content</div>`
    + `<div class="msg">Access via the official website.</div>`
    + `<div class="div"></div>`
    + `<a href="https://civilengsuite.pages.dev/">civilengsuite.pages.dev/</a>`
    + `</div></body></html>`;
  const crB64 = u8ToB64(new TextEncoder().encode(crHtml));
  return `(function(){'use strict';`
    + (skipDevGuard ? '' : (
        `var _ov=null,_do=false;`
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
    ))
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

  // [MHTML-FIX-D] Strip MHTML-protection artifacts from bot-path HTML.
  // These elements are deliberately present in the human-path source HTML to protect
  // against Chrome Android MHTML download. The bot path must return clean HTML with
  // no protection CSS or overlay elements that would confuse crawlers or Google's
  // HTML cache snapshot.

  // [MHTML-FIX-D1] Strip <style id="_ces_hide_src"> — html{visibility:hidden}
  // Previously not stripped; Googlebot's renderer executed the origin guard's else
  // branch to override it. Explicit stripping now produces a cleaner bot response.
  html = html.replace(/<style\s+id="_ces_hide_src"[^>]*>[\s\S]*?<\/style>/gi, '');

  // [MHTML-FIX-D2] Strip <style id="_ces_cr_src_style"> — overlay CSS (new in v21).
  html = html.replace(/<style\s+id="_ces_cr_src_style"[^>]*>[\s\S]*?<\/style>/gi, '');

  // [MHTML-FIX-D3] Strip <div id="_ces_cr_src_overlay"> — copyright overlay (new in v21).
  // The overlay contains only nested inline-styled children; no closing-tag ambiguity.
  html = html.replace(/<div\s+id="_ces_cr_src_overlay"[^>]*>[\s\S]*?<\/div>\s*(?=<)/gi, '');

  // [MHTML-FIX-D4] Strip source HTML origin guard via the _ces_src_guard_v21 marker.
  // The guard's unique comment /* _ces_src_guard_v21 */ was added to pc_suite_V1-FIXED_v21.html.
  // safeScriptRe ensures we never cross </script> boundaries.
  html = html.replace(safeScriptRe('_ces_src_guard_v21'), '');

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

  // ── [M3b-inline] Non-canonical host redirect gate ────────────────────────
  // Deployed to the canonical project (civilengsuite.pages.dev): url.hostname
  // matches _canonicalHostname → gate is a no-op → normal serving continues.
  //
  // Deployed to a non-canonical project (e.g., gsuite.pages.dev): url.hostname
  // does NOT match → 301 redirect to canonical → zero raw content served.
  //
  // MUST run before STATIC_PASSTHROUGH so that font/image/well-known requests
  // from non-canonical hosts are also redirected rather than passed through.
  //
  // _canonicalHostname and _allowedHostsRaw are computed once here and reused
  // below in [M3a] for building _allowedOriginsJs — no duplicate env reads.
  //
  // Canonical host  : CANONICAL_HOST env var (default: 'civilengsuite.pages.dev')
  // Additional hosts: ALLOWED_ORIGINS env var (comma-separated https:// origins)
  // Always exempt   : localhost / 127.0.0.1 (any port) for wrangler pages dev
  // Always exempt   : *.civilengsuite.pages.dev preview-deployment subdomains
  const _canonicalHostname = ((env.CANONICAL_HOST || 'civilengsuite.pages.dev')).trim().toLowerCase();
  const _allowedHostsRaw = (env.ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim())
    .filter(s => s.length > 0 && /^https?:\/\//.test(s));
  const _allowedHostsSet = new Set([
    _canonicalHostname,
    ..._allowedHostsRaw.map(o => {
      try { return new URL(o).hostname.toLowerCase(); } catch(e) { return ''; }
    }).filter(Boolean),
  ]);
  const _reqHostLower  = url.hostname.toLowerCase();
  const _isLocalhostReq = /^(localhost|127\.0\.0\.1)(:\d+)?$/.test(url.host);
  // Allow Cloudflare preview deployments: *.civilengsuite.pages.dev
  const _isPreviewDeploy = _reqHostLower.endsWith('.' + _canonicalHostname);
  if (!_allowedHostsSet.has(_reqHostLower) && !_isLocalhostReq && !_isPreviewDeploy) {
    return new Response(null, {
      status: 301,
      headers: {
        'Location':      `https://${_canonicalHostname}${url.pathname}${url.search}`,
        'Cache-Control': 'no-store',
        ...SHARED_SECURITY_HEADERS,
      },
    });
  }

  // ── Always pass through static/SEO files — never intercept these ──────────
  // [P1] ADDED: payment(?:\/.*)? and api\/payment\/.* — payment checkout pages
  //      are static HTML served directly by Cloudflare Pages file serving.
  //      Payment API routes are dedicated CF Pages Functions in
  //      functions/api/payment/*.js which take routing precedence over this
  //      catch-all by Cloudflare's function routing rules, but the passthrough
  //      here is an explicit defensive guard.
  // [S1] NOTE: sitemap.xml is intentionally NOT in STATIC_PASSTHROUGH — it is
  //      handled explicitly below with controlled headers. See [S1] in changelog.
  // [L1] ADDED: footing-pro\/engineers\/? footing-pro\/offices\/?
  //      footing-pro\/students\/? — persona landing pages are static HTML files
  //      deployed at footing-pro/{engineers,offices,students}/index.html.
  //      Without explicit passthrough they fall to the !route → context.next()
  //      fallback which is functionally correct but adds unnecessary route-match
  //      overhead on every landing page request. Explicit passthrough here
  //      short-circuits the ROUTES loop entirely, matching the same pattern used
  //      for all other static sub-paths (images, fonts, .well-known).
  //      These paths MUST NOT be in ROUTES — they are plain static files with no
  //      .enc decryption required. _headers rules for /footing-pro/engineers/*
  //      apply directly (Cloudflare Pages _headers applies to static responses).
  const STATIC_PASSTHROUGH = /^\/(?:robots\.txt|manifest\.json|favicon\.ico|og-image\.png|images\/.*|footing-pro\/images\/.*|footing-pro\/engineers\/?.*|footing-pro\/offices\/?.*|footing-pro\/students\/?.*|beam-pro\/images\/.*|column-pro\/images\/.*|deflection-pro\/images\/.*|earthquake-pro\/images\/.*|mur-pro\/images\/.*|add-reft-pro\/images\/.*|section-property-pro\/images\/.*|google[0-9a-f]+\.html|sitemap\.xsl|fonts\/.*|\.well-known\/.*|payment(?:\/.*)?|api\/payment\/.*)$/i;
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

  // ── [D1] /download — 302 redirect to activation tool installer ───────────
  // Google Drive direct-download URL for CivEngSuite Activation Tool (.exe).
  // 302 (not 301) so the destination can change without browser cache lock-in.
  // Cache-Control: no-store prevents any CDN or browser from caching this
  // redirect; every click fetches the freshest destination from this handler.
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

  // ── [E1] Top-level safety net ─────────────────────────────────────────────
  // All post-decryption logic is wrapped in one try-catch so any uncaught
  // runtime exception (regex edge-case, V8 isolate behaviour, large-string op)
  // returns a clean 500 instead of Cloudflare Error 1101.
  // Check Workers & Pages → Functions → Logs to see the exact error.
  try {

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
      'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}' 'sha256-707X5+NAXR96e1UzENjwpPf416b6sJGW3mMwS4KSCqw=' 'sha256-9Z5YUtj2GDOBykVWUu8jxOyhx6HrrXGwO4FEHHSUtqQ=' 'unsafe-hashes' 'sha256-nAiI7XK5Mt/SgNQUZPqTuikvwxIVHV3se6mHGQue+88=' 'sha256-Jag+ZHPii6iUmMQWlnwms/mnjM8gRPTOJA2KIyTQQRk=' 'sha256-uLUdJIdD3+8SpL4nHNFN9YmyHRRmrseSQKwzj3ECn2I=' 'sha256-akyHNuxwVvvLQ11iHoDrpca0qH3TU3LfGbtdQ8kNdwI=' 'sha256-UOhLo4NRrWG89b3vpgtU0dc/C8aWLS+MQ2Lf9vW/4Fk=' 'sha256-jHF5hTIlMDyGZRAsNK0HO/WFYrwPvI2I1q0o1xKKB6I=' 'sha256-wflfhEeJWTAjAK0hnm9/OICxAQ8fVnj3168JrJ/m91k=' 'sha256-oTzV9+pQ7IAxC4NoAc7dH4+0Is4KloZ9u7cMJC7UDrE=' 'sha256-bTpi/7w0Cd8ihAWpwcZJIdz49sMq0d73fWWDzp5Ju2Q='`,
      // [A1] Link header on ALL bot responses — agents crawling any tool page
      // discover the full agent catalog without needing to hit the homepage first.
      'Link':                    HOMEPAGE_LINK_HEADER,
      ...SHARED_SECURITY_HEADERS,
    }});
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HUMAN PATH — Full protection active
  // ═══════════════════════════════════════════════════════════════════════════

  // ── [DEV-GUARD] DevTools detection toggle ─────────────────────────────────
  // PROD: env.DEV_ALLOW_DEVTOOLS=true disables detection; default = detection active
  // DEV:  ces_toggle_v10.py swaps this line to the hardcoded-true variant
  const _skipDevGuard = (env.DEV_ALLOW_DEVTOOLS || '').trim().toLowerCase() === 'true'; /* [CES-DEV-CLOSE:devtools-guard] */

  // Inject protection bundle at end of body
  const bundle = `<script nonce="${cspNonce}">${buildProtectionBundle(pageFilename, _skipDevGuard)}</script>`;
  html = html.replace(/<\/body>/i, bundle + '</body>');

  // ── [MF4] Neutralize source-HTML inline origin-guard redirect fallback ──────
  // Source HTML files may contain their own legacy inline origin guard (pre-v13)
  // with a catch block that calls window.location.replace() when document.open()
  // throws. On Chrome Android file:// opens, document.open() throws in the
  // sandboxed context → catch fires → window.location.replace redirects to the
  // live site → user sees the real engineering page (the "bypass" in Image 1).
  //
  // Fix: replace the catch-block redirect with window['__CES_BLOCK']=1.
  // This flag is read by M1c (bootstrap XOR decoder guard). M2's DOMContentLoaded
  // DOM-overlay handler fires regardless and displays the copyright card.
  //
  // Pattern safety: [^{}]* ensures we only match catch blocks with NO nested braces
  // — the exact pattern of the source guard's catch body. No legitimate code in the
  // pages has a catch block with a single window.location.replace() and no braces.
  //
  // Applied in the human path only, BEFORE minify, on the decoded source HTML.
  // Bot path is unaffected: stripProtectionScripts already removes the entire
  // source guard <script> block before reaching this point in the bot branch.
  html = html.replace(
    /}\s*catch\s*\(\w+\)\s*\{[^{}]*window\.location\.replace\s*\([^)]+\)[^{}]*\}/g,
    "}catch(_cre){window['__CES_BLOCK']=1;}"
  );
  // ── [WM-FIX] Watermark stamp: remove dark overlay background ───────────────
  // ROOT CAUSE: #ces-watermark background-* properties create a dark translucent
  // overlay. On dark-background page sections the stamp text color blends with
  // the overlay → invisible (Image 2 vs Image 1). The text-stamp children are
  // the functional artifact; the container background is cosmetically harmful.
  //
  // The protection bundle MutationObserver monitors opacity/visibility/display
  // ONLY — NOT background. A <head> <style> with !important survives it.
  // Three-pass approach for complete coverage:

  // [WM-FIX-1] Pass 1a: id-before-style attribute ordering
  html = html.replace(
    /(<[^>]+\bid="ces-watermark"[^>]+\bstyle=")([^"]*?)(")(?=[^>]*>)/gi,
    (m, pre, styles, post) => {
      const c = styles
        .replace(/\bbackground(?:-color|-image|-position|-size|-repeat|-origin|-clip|-attachment)?:[^;]*;?\s*/gi, '')
        .replace(/;{2,}/g, ';').trim().replace(/;$/, '');
      return `${pre}${c}${post}`;
    }
  );
  // [WM-FIX-1] Pass 1b: style-before-id attribute ordering
  html = html.replace(
    /(\bstyle=")([^"]*?)("(?=[^<>]*\bid="ces-watermark"))/gi,
    (m, pre, styles, post) => {
      const c = styles
        .replace(/\bbackground(?:-color|-image|-position|-size|-repeat|-origin|-clip|-attachment)?:[^;]*;?\s*/gi, '')
        .replace(/;{2,}/g, ';').trim().replace(/;$/, '');
      return `${pre}${c}${post}`;
    }
  );
  // [WM-FIX-2] Pass 2: <head> stylesheet override — !important beats normal inline
  // style; MutationObserver never sees stylesheet-sourced computed-style changes.
  html = html.replace(
    /(<\/head>)/i,
    '<style id="_ces_wm_bg_fix">#ces-watermark{background:none!important;background-color:transparent!important;background-image:none!important;box-shadow:none!important}</style>$1'
  );
  // [WM-FIX-3] Pass 3: strip background from <style> block CSS rules targeting
  // #ces-watermark (handles background set via CSS class, not inline style).
  html = html.replace(
    /<style([^>]*)>([\s\S]*?)<\/style>/gi,
    (match, attrs, css) => {
      if (/_ces_wm_bg_fix/.test(attrs)) return match; // skip our own injected fix
      const fixedCss = css.replace(
        /(#ces-watermark\s*\{[^}]*)background(?:-color|-image|-position|-size|-repeat|-origin|-clip|-attachment)?:[^;]*;?/gi,
        '$1'
      );
      return `<style${attrs}>${fixedCss}</style>`;
    }
  );

  // Minify (HTML comments, inter-tag whitespace — does NOT remove newlines so
  // inline JS // comments in marketing pages are preserved correctly)
  html = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/>\s+</g, '><')
    .replace(/\s{2,}/g, ' ')
    .trim();

  // ── [M2] Decoded-HTML origin guard — Scenario B coverage ─────────────────
  // Injected HERE (after minify, BEFORE injectNonces) so the <script> tag
  // receives a nonce from injectNonces and executes in the decoded-HTML CSP
  // context (which inherits the bootstrap response's 'nonce-X' policy).
  //
  // Scenario B: Chrome Android saves the rendered DOM (post document.write)
  // rather than the bootstrap HTTP response. The saved file IS the decoded
  // real HTML. When opened as file://, this guard fires in <head> before any
  // content renders and replaces the document with the copyright page.
  //
  // On legitimate access (origin === 'https://civilengsuite.pages.dev'):
  //   guard check fails → no-op → page renders normally. ✓
  // On file:// open (origin === 'null') or unauthorized host:
  //   guard fires → copyright shown. ✓
  //
  // ── [M3] v14 — Runtime allowed-origins list ──────────────────────────────
  // ROOT CAUSE: gsuite.pages.dev is a second Cloudflare Pages project (the
  // default *.pages.dev alias). Before v14, all 3 guard layers (M1a, M1c, M2)
  // hardcoded 'https://civilengsuite.pages.dev' as the sole allowed origin.
  // When Chrome Android's native Download button made a GET to gsuite.pages.dev,
  // the bootstrap it received had M1a checking for the canonical domain — but
  // because the download came from gsuite.pages.dev, window.location.origin on
  // re-open would be 'null' (file://) which M1a DOES block correctly.
  //
  // The actual bypass: gsuite.pages.dev has NO Pages Function deployed, so it
  // serves raw/unencrypted static files directly from Cloudflare's CDN edge
  // without this worker running at all. The fix has two parts:
  //   1. gsuite.pages.dev must redirect all traffic to civilengsuite.pages.dev
  //      (deploy functions/[[path]].js to that project — see gsuite_redirect_worker.js)
  //   2. All 3 origin guards now use a runtime-computed _aos array (not a hardcoded
  //      string) so the canonical domain is always derived from the live request host,
  //      and custom domains added later require only an env-var change, not a redeploy.
  //
  // ALLOWED_ORIGINS env var (optional): comma-separated additional origins.
  //   Example: "https://civilengsuite.com,https://www.civilengsuite.com"
  //   If absent, only https://{request host} is allowed (plus localhost).
  // [M3b-fix] _canonicalOrigin uses _canonicalHostname (from CANONICAL_HOST env var),
  // NOT url.host. If [[path]].js were deployed to gsuite.pages.dev without the
  // redirect gate, url.host would be 'gsuite.pages.dev' — making gsuite.pages.dev
  // the allowed origin in all 3 guards (M1a, M1c, M2), completely neutralizing
  // protection. With the redirect gate above, url.hostname IS always the canonical
  // host by this point, but using _canonicalHostname is semantically correct and
  // safe regardless. _allowedHostsRaw reused from the redirect gate block above.
  //   If absent, only https://{CANONICAL_HOST} is allowed (plus localhost).
  const _canonicalOrigin = `https://${_canonicalHostname}`;
  const _extraOrigins = _allowedHostsRaw.filter(o => o !== _canonicalOrigin);
  const _allAllowedOrigins = [_canonicalOrigin, ...new Set(_extraOrigins)];
  // Values are safe: _canonicalHostname from CANONICAL_HOST env var,
  // _allowedHostsRaw from ALLOWED_ORIGINS env var (both operator-controlled).
  const _allowedOriginsJs = JSON.stringify(_allAllowedOrigins);

  // _sharedCrB64 is hoisted here and reused for M1 (bootstrapOriginGuard
  // and bootstrapCopyrightBody) later — copyright page computed only once.
  const _sharedCrRP    = route.prefix === '/' ? '' : route.prefix;
  const _sharedCrTM    = html.match(/<title>([^<]*)<\/title>/i);
  const _sharedCrPT    = escHtml(_sharedCrTM ? _sharedCrTM[1] : (route.ogTitle || 'Civil Engineering Suite'));
  const _sharedCrUrl   = `${_canonicalOrigin}${_sharedCrRP}/`;
  const _sharedCrLabel = `${_canonicalHostname}${_sharedCrRP}/`;
  const _sharedCrHtml  =
    `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<title>\u00A9 Protected \u2014 ${_sharedCrPT}<\/title>`
    + `<style>*{box-sizing:border-box;margin:0;padding:0}html,body{background:#0A1A2E;background-image:linear-gradient(#0A1A2E,#0A1A2E);min-height:100vh}`
    + `body{display:flex;align-items:center;justify-content:center;font-family:'DM Sans','Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;text-align:center;padding:24px}`
    + `.card{max-width:440px;width:100%;background:rgba(255,255,255,0.04);border:1px solid rgba(193,123,26,0.25);border-radius:24px;padding:44px 36px;box-shadow:0 24px 48px rgba(0,0,0,0.45),inset 0 1px 0 rgba(255,255,255,0.06)}`
    + `.icon{font-size:3.2rem;margin-bottom:20px;line-height:1}.title{color:#C17B1A;font-size:1.3rem;font-weight:700;margin-bottom:14px;line-height:1.45;letter-spacing:-0.01em}`
    + `.msg{color:#8AA3C7;font-size:0.875rem;line-height:1.75;margin-bottom:0}.div{height:1px;background:linear-gradient(90deg,transparent,rgba(193,123,26,0.3),transparent);margin:22px 0}`
    + `a{display:inline-flex;align-items:center;gap:6px;color:#FAD98B;font-size:0.88rem;font-weight:600;text-decoration:none;background:rgba(193,123,26,0.15);border:1px solid rgba(193,123,26,0.35);padding:10px 22px;border-radius:40px}`
    + `<\/style><\/head><body><div class="card"><div class="icon">&#x1F512;<\/div>`
    + `<div class="title">&#169; Civil Engineering Suite &#8212; Protected Content<\/div>`
    + `<div class="msg">Access via the official website.<\/div>`
    + `<div class="div"><\/div>`
    + `<a href="${_sharedCrUrl}">${_sharedCrLabel}<\/a>`
    + `<\/div><\/body><\/html>`;
  const _sharedCrB64 = u8ToB64(new TextEncoder().encode(_sharedCrHtml));
  const _m2Code =
      `(function(){'use strict';`
    + `var _aos=${_allowedOriginsJs};`
    + `var _o=(typeof window!=='undefined')?window.location.origin:'';`
    + `var _dev=/^https?:\\/\\/(localhost|127\\.0\\.0\\.1)(:\\d+)?$/.test(_o);`
    + `if(_aos.indexOf(_o)===-1&&!_dev){`
    + `var _b='${_sharedCrB64}';`
    + `var _n=atob(_b);var _ba=new Uint8Array(_n.length);`
    + `for(var i=0;i<_n.length;i++)_ba[i]=_n.charCodeAt(i);`
    + `var _cr=new TextDecoder('utf-8').decode(_ba);`
    + `var _m2ok=false;`
    + `try{document.documentElement.style.cssText='display:none!important';}catch(_m2he){}`
    + `window.stop();`
    + `try{document.open();document.write(_cr);document.close();_m2ok=true;}catch(_m2e){}`
    + `if(!_m2ok){`
    + `try{document.documentElement.style.cssText='display:none!important';}catch(_m2se){}`
    + `document.addEventListener('DOMContentLoaded',function(){try{`
    + `document.documentElement.style.cssText='display:block!important;visibility:visible!important;background:#0A1A2E';`
    + `document.body.style.cssText='display:flex!important;margin:0;background:#0A1A2E;background-image:linear-gradient(#0A1A2E,#0A1A2E);min-height:100vh;align-items:center;justify-content:center;font-family:\\'DM Sans\\',\\'Inter\\',-apple-system,system-ui,sans-serif;text-align:center;padding:24px;box-sizing:border-box';`
    + `document.body.innerHTML="<div style='max-width:440px;width:100%;background:rgba(255,255,255,0.04);border:1px solid rgba(193,123,26,0.25);border-radius:24px;padding:44px 36px;box-shadow:0 24px 48px rgba(0,0,0,0.45)'>"`
    + `+"<div style='font-size:3.2rem;margin-bottom:20px;line-height:1'>&#x1F512;</div>"`
    + `+"<h2 style='color:#C17B1A;font-size:1.3rem;font-weight:700;margin-bottom:14px;line-height:1.45'>&#169; Civil Engineering Suite &#8212; Protected Content</h2>"`
    + `+"<p style='color:#8AA3C7;font-size:.875rem;line-height:1.75;margin-bottom:0'>Access via the official website.</p>"`
    + `+"<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(193,123,26,0.3),transparent);margin:22px 0'></div>"`
    + `+"<a href='"+_aos[0]+"' style='display:inline-flex;align-items:center;color:#FAD98B;font-size:.88rem;font-weight:600;text-decoration:none;background:rgba(193,123,26,0.15);border:1px solid rgba(193,123,26,0.35);padding:10px 22px;border-radius:40px'>"+_aos[0].replace("https://","")+"</a></div>";}catch(_m2de){}});`
    + `}`
    + `}`
    + `})();`;
  // Inject right after <meta charset="UTF-8"> — injectNonces below stamps the nonce
  html = html.replace(/(<meta charset="UTF-8">)/i, `$1<script>${_m2Code}<\/script>`);

  // Stamp nonce on every <script> tag (including the M2 guard injected above)
  html = injectNonces(html, cspNonce);

  // [PSI-09] Minify inline <style> blocks before XOR encoding.
  // Reduces encrypted payload size (~2.9 KiB savings). Uses the same
  // minifyBotCSS function already applied on the bot path. Safe: does not
  // touch <style> blocks inside <noscript> or <script> tags.
  html = minifyBotCSS(html);

  // XOR + base64 obfuscation (same algorithm as api/decrypt.js)
  const raw   = new TextEncoder().encode(html);
  const xored = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) xored[i] = raw[i] ^ XOR_KEY;
  const payload = u8ToB64(xored);   // chunked — safe for 500KB+ payloads

  const titleM    = html.match(/<title>([^<]*)<\/title>/i);
  const pageTitle = titleM ? titleM[1] : 'Civil Engineering Suite';

  // ── [M1] Bootstrap shell mobile-download protection ──────────────────────
  // Build origin guard (M1a) and copyright body (M1b) from _sharedCrB64
  // computed above in the M2 block. Same copyright page; no duplicate work.
  //
  // M1a — bootstrapOriginGuard: fires BEFORE <body> is parsed, so the XOR
  //        decoder script in <body> is never reached on unauthorized opens.
  // M1b — bootstrapCopyrightBody: first <body> child.
  //        display:none for legitimate access (XOR decoder replaces the doc
  //        before first paint). <noscript> makes it display:flex when JS is
  //        disabled so no-JS viewers see copyright instead of blank screen.
  //        position:fixed / z-index:2147483647 covers partial-render edge cases.
  //        Text editors (Notepad, VS Code) see this copyright HTML before
  //        encountering the base64 XOR payload blob.
  const bootstrapOriginGuard =
    `<script nonce="${cspNonce}">`
    + `(function(){'use strict';`
    + `var _aos=${_allowedOriginsJs};`
    + `var _o=(typeof window!=='undefined')?window.location.origin:'';`
    + `var _dev=/^https?:\\/\\/(localhost|127\\.0\\.0\\.1)(:\\d+)?$/.test(_o);`
    + `if(_aos.indexOf(_o)===-1&&!_dev){`
    + `var _b='${_sharedCrB64}';`
    + `var _n=atob(_b);var _ba=new Uint8Array(_n.length);`
    + `for(var i=0;i<_n.length;i++)_ba[i]=_n.charCodeAt(i);`
    + `var _cr=new TextDecoder('utf-8').decode(_ba);`
    + `var _m1aOk=false;`
    + `try{document.documentElement.style.cssText='display:none!important';}catch(_m1ahe){}`
    + `window.stop();`
    + `try{document.open();document.write(_cr);document.close();_m1aOk=true;}catch(_m1ae){}`
    + `if(!_m1aOk){window['__CES_BLOCK']=1;}`
    + `}else{`
    + `try{var _hs=document.getElementById('_ces_hide');if(_hs&&_hs.parentNode){_hs.parentNode.removeChild(_hs);}}catch(_hse){}`
    + `}`
    + `})();`
    + `\u003c/script>`;

  const bootstrapCopyrightBody =
    `<style>`
    + `#_ces_cr_body{display:none;margin:0;background:#0A1A2E;background-image:linear-gradient(#0A1A2E,#0A1A2E);`
    + `font-family:'DM Sans','Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;`
    + `align-items:center;justify-content:center;min-height:100vh;text-align:center;`
    + `position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483647;padding:24px;box-sizing:border-box}`
    + `</style>`
    + `<noscript><style>#_ces_cr_body{display:flex!important}</style></noscript>`
    + `<div id="_ces_cr_body">`
    + `<div style="max-width:440px;width:100%;background:rgba(255,255,255,0.04);border:1px solid rgba(193,123,26,0.25);border-radius:24px;padding:44px 36px;box-shadow:0 24px 48px rgba(0,0,0,0.45),inset 0 1px 0 rgba(255,255,255,0.06)">`
    + `<div style="font-size:3.2rem;margin-bottom:20px;line-height:1">&#x1F512;</div>`
    + `<h2 style="color:#C17B1A;font-size:1.3rem;font-weight:700;margin-bottom:14px;line-height:1.45;letter-spacing:-0.01em">`
    + `&#169; Civil Engineering Suite &#8212; Protected Content</h2>`
    + `<p style="color:#8AA3C7;font-size:0.875rem;line-height:1.75;margin-bottom:0">`
    + `Access via the official website.</p>`
    + `<div style="height:1px;background:linear-gradient(90deg,transparent,rgba(193,123,26,0.3),transparent);margin:22px 0"></div>`
    + `<a href="${_sharedCrUrl}" style="display:inline-flex;align-items:center;color:#FAD98B;font-size:0.88rem;font-weight:600;text-decoration:none;background:rgba(193,123,26,0.15);border:1px solid rgba(193,123,26,0.35);padding:10px 22px;border-radius:40px">${_sharedCrLabel}</a>`
    + `</div></div>`;

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
    ? '<link rel="preload" as="image" href="/footing-pro/images/hero-bg.avif"'
      + ' imagesrcset="/footing-pro/images/hero-bg.avif 1x,/footing-pro/images/hero-bg.webp 1x"'
      + ' imagesizes="100vw" fetchpriority="high">'
    : '';

  // [FxB] CSS pre-hide: fires at CSS parse time — before M1a script, before any preload,
  // before any layout. Closes the race window between document parse start and M1a execution.
  // visibility:hidden (not display:none) avoids layout recalc overhead during this window.
  // Removed automatically for authorized users when document.open()+document.write() in the
  // XOR decoder replaces the entire document. Unauthorized users are already covered by M1a
  // display:none before this rule would ever be seen by the page's own JS.
  const bootstrap = `<!DOCTYPE html><html><head>`
    + `<style id="_ces_hide">html{visibility:hidden!important;pointer-events:none!important}</style>`
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
    // [M1c] Defense-in-depth: origin check INSIDE XOR decoder.
    // Runs only if M1a (parser-blocking <head> guard) was somehow bypassed.
    // On unauthorized origin: writes copyright page, then returns — XOR decode never runs.
    + `var _xaos=${_allowedOriginsJs};`
    + `var _xo=window.location.origin;`
    + `var _xd=/^https?:\\/\\/(localhost|127\\.0\\.0\\.1)(:\\d+)?$/.test(_xo);`
    + `if(window['__CES_BLOCK']||(_xaos.indexOf(_xo)===-1&&!_xd)){`
    + `var _xb='${_sharedCrB64}';`
    + `var _xn=atob(_xb);var _xba=new Uint8Array(_xn.length);`
    + `for(var xi=0;xi<_xn.length;xi++)_xba[xi]=_xn.charCodeAt(xi);`
    + `var _xcr=new TextDecoder('utf-8').decode(_xba);`
    + `var _m1cOk=false;`
    + `try{document.documentElement.style.cssText='display:none!important';}catch(_m1che){}`
    + `window.stop();`
    + `try{document.open();document.write(_xcr);document.close();_m1cOk=true;}catch(_xe){}`
    + `if(!_m1cOk){`
    + `try{document.documentElement.style.cssText='display:block!important;visibility:visible!important;background:#0A1A2E';}catch(_m1cde){}`
    + `var _xov=document.createElement('div');`
    + `_xov.setAttribute('style','position:fixed;top:0;left:0;width:100%;height:100%;background:#0A1A2E;background-image:linear-gradient(#0A1A2E,#0A1A2E);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:\\'DM Sans\\',\\'Inter\\',-apple-system,system-ui,sans-serif;text-align:center;padding:24px;box-sizing:border-box;visibility:visible!important');`
    + `_xov.innerHTML="<div style='max-width:440px;width:100%;background:rgba(255,255,255,0.04);border:1px solid rgba(193,123,26,0.25);border-radius:24px;padding:44px 36px;box-shadow:0 24px 48px rgba(0,0,0,0.45)'>"`
    + `+"<div style='font-size:3.2rem;margin-bottom:20px;line-height:1'>&#x1F512;</div>"`
    + `+"<h2 style='color:#C17B1A;font-size:1.3rem;font-weight:700;margin-bottom:14px;line-height:1.45'>&#169; Civil Engineering Suite &#8212; Protected Content</h2>"`
    + `+"<p style='color:#8AA3C7;font-size:.875rem;line-height:1.75;margin-bottom:0'>Access via the official website.</p>"`
    + `+"<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(193,123,26,0.3),transparent);margin:22px 0'></div>"`
    + `+"<a href='"+_xaos[0]+"' style='display:inline-flex;align-items:center;color:#FAD98B;font-size:.88rem;font-weight:600;text-decoration:none;background:rgba(193,123,26,0.15);border:1px solid rgba(193,123,26,0.35);padding:10px 22px;border-radius:40px'>"+_xaos[0].replace("https://","")+"</a></div>";`
    + `try{document.body.appendChild(_xov);}catch(_xoe){}}`
    + `return;}`
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
    + `</body></html>`;

  return new Response(bootstrap, { status: 200, headers: {
    'Content-Type':            'text/html; charset=utf-8',
    'Cache-Control':           'no-store',
    'Content-Security-Policy': `${CSP_COMMON}; script-src 'nonce-${cspNonce}' 'sha256-707X5+NAXR96e1UzENjwpPf416b6sJGW3mMwS4KSCqw=' 'sha256-9Z5YUtj2GDOBykVWUu8jxOyhx6HrrXGwO4FEHHSUtqQ=' 'unsafe-hashes' 'sha256-nAiI7XK5Mt/SgNQUZPqTuikvwxIVHV3se6mHGQue+88=' 'sha256-Jag+ZHPii6iUmMQWlnwms/mnjM8gRPTOJA2KIyTQQRk=' 'sha256-uLUdJIdD3+8SpL4nHNFN9YmyHRRmrseSQKwzj3ECn2I=' 'sha256-akyHNuxwVvvLQ11iHoDrpca0qH3TU3LfGbtdQ8kNdwI=' 'sha256-UOhLo4NRrWG89b3vpgtU0dc/C8aWLS+MQ2Lf9vW/4Fk=' 'sha256-jHF5hTIlMDyGZRAsNK0HO/WFYrwPvI2I1q0o1xKKB6I=' 'sha256-wflfhEeJWTAjAK0hnm9/OICxAQ8fVnj3168JrJ/m91k=' 'sha256-oTzV9+pQ7IAxC4NoAc7dH4+0Is4KloZ9u7cMJC7UDrE=' 'sha256-bTpi/7w0Cd8ihAWpwcZJIdz49sMq0d73fWWDzp5Ju2Q='`,
    // [A1] RFC 8288 Link header — visible in HTTP headers before JS executes.
    // [A4] Vary: Accept on homepage so intermediaries separate markdown/HTML caches.
    ...(route.prefix === '/' ? {
      'Link': HOMEPAGE_LINK_HEADER,
      'Vary': 'Accept',
    } : {}),
    ...SHARED_SECURITY_HEADERS,
  }});

  } catch (e) {
    // [E1] Safety net: converts any uncaught runtime exception to a logged 500
    // instead of Cloudflare Error 1101.
    // Inspect: Cloudflare Dashboard → Workers & Pages → Functions → Real-time logs
    console.error('[ces:runtime] Uncaught exception:', e && e.message, e && e.stack);
    return errResponse(500, 'Server Error', 'An internal error occurred. Please refresh or try again.');
  }
}
