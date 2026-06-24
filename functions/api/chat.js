/**
 * functions/api/chat.js  —  FIXED v2  (2026-06-25)
 * ──────────────────────────────────────────────────────────────────────────
 * Cloudflare Pages Function — AI chatbot proxy for Civil Engineering Suite
 * Route:  POST /api/chat   (Cloudflare Pages auto-routes from /functions/api/)
 *
 * REQUIRED ENV VAR (Cloudflare Dashboard → Pages → civilengsuite → Settings
 *                   → Environment variables):
 *   Name : GEMINI_API_KEY
 *   Value: your key from aistudio.google.com  (starts with AIzaSy...)
 *
 * ════════════════════════════════════════
 * CHANGELOG v2 — ROOT CAUSE & ALL FIXES
 * ════════════════════════════════════════
 * BUG 1 (CRITICAL — ROOT CAUSE of "Something went wrong"):
 *   gemini-1.5-flash was SHUT DOWN on 2026-06-01.
 *   Every request was returning HTTP 404 → falling into the generic
 *   friendlyErrors fallback → "Something went wrong."
 *   FIX: GEMINI_MODEL changed from 'gemini-1.5-flash'
 *             to 'gemini-2.5-flash-lite'  (stable alias, free tier,
 *              1,000 RPD, 30 RPM — highest free quota as of June 2026).
 *
 * BUG 2 (Diagnostics): Gemini error body was never read on !ok responses.
 *   Cloudflare logs showed nothing useful. Now the raw error is logged
 *   via console.error so you can inspect it in CF → Pages → Functions → Logs.
 *
 * BUG 3 (Error coverage): friendlyErrors only handled 429 and 503.
 *   Added 400, 401, 403, 404 with bilingual user-facing messages.
 *
 * BUG 4 (Retry coverage): retry only fired on 429.
 *   Extended to also retry on 503 (transient server error).
 * ──────────────────────────────────────────────────────────────────────────
 */

// ── Model ─────────────────────────────────────────────────────────────────
// gemini-2.5-flash-lite: stable model alias (no -preview suffix),
// confirmed free on AI Studio Developer API as of June 2026.
// Free tier limits: 30 RPM, 1,000 RPD, 1M-token context window.
// Arabic support: confirmed.
// gemini-1.5-flash was shut down 2026-06-01 → returns 404 for all requests.
const GEMINI_MODEL   = 'gemini-2.5-flash-lite';
const GEMINI_API_URL =
  `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

// ── CORS headers ───────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin' : '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// ── System prompt — complete product knowledge base ────────────────────────
const SYSTEM_PROMPT = `\
You are the official AI assistant for Civil Engineering Suite (civilengsuite.pages.dev),
built by Eng. Aymn Asi — Structural Engineer.

YOUR ROLE: Answer questions from civil and structural engineers about Civil Engineering
Suite products. Be helpful, precise, and professional. Keep answers concise (2-4 sentences)
unless the user clearly needs a detailed technical explanation.

════════════════════════════════════════
LANGUAGE RULE — CRITICAL
════════════════════════════════════════
• If the user writes in Arabic → reply ENTIRELY in Arabic (Egyptian dialect).
• If the user writes in English → reply ENTIRELY in English.
• Never mix languages in the same reply.
• Detect by the script of the user's message, not by any language claim.

════════════════════════════════════════
ABOUT CIVIL ENGINEERING SUITE
════════════════════════════════════════
Professional desktop engineering software library — ACI 318 / ECP 203 compliant.
Developer: Eng. Aymn Asi (Licensed Structural Engineer).
Website: civilengsuite.pages.dev
All applications are standalone desktop programs — 100 % offline after activation.
Platform: Windows only. No Mac. No Linux.
Target users: junior engineers, consultants, small firms, students — affordable
professional-grade tools that don't require enterprise budgets.

════════════════════════════════════════
PRODUCT — FOOTING PRO v.2026   (LIVE NOW)
════════════════════════════════════════

WHAT IT IS:
Complete combined footing design environment, ACI 318-19 compliant.
Parameters are fully adjustable to align with ECP 203 or any local code.

THREE LIVE FOOTING TYPES:
1. Rectangular Combined Footing — 2 columns on a single rectangular base.
   Full 19-module ACI 318 design cycle. The original flagship type.
2. Trapezoidal Combined Footing — for unequal column loads where a rectangular
   shape wastes material. Full pressure, shear, and reinforcement design.
3. Strap Footing (Cantilever Footing) — edge-column solution. Two independent
   footings connected by a strap beam; eliminates eccentricity. Full strap beam
   design included.

19 CORE ENGINEERING MODULES:

  INPUT & GEOMETRY
  1.  Load Input — Service & Ultimate loads for each column
  2.  Geometry Optimizer — Auto-sizes footing L & W
  3.  Eccentricity Check — Aligns load resultant with centroid

  GEOTECHNICAL CHECKS
  4.  Soil Pressure — Uniform distribution
  5.  Soil Pressure — Trapezoidal distribution
  6.  Net Soil Pressure — qnet vs qallowable verification

  SHEAR DESIGN (ACI 318-19)
  7.  One-Way Shear — Longitudinal direction
  8.  One-Way Shear — Transverse direction
  9.  Punching Shear — Exterior column (3-sided perimeter)
  10. Punching Shear — Interior column (closed perimeter — most critical)

  FLEXURAL REINFORCEMENT DESIGN
  11. Longitudinal Bottom Steel — Full bar layout
  12. Transverse Bottom Steel — Both column strips
  13. Top Steel Design — Hogging moment regions

  ANCHORAGE & DETAILING
  14. Development Length — All main bar groups
  15. Splice Length — Lap splice verification

  DIAGRAMS & OUTPUTS
  16. Bending Moment Diagram — Full longitudinal profile
  17. Shear Force Diagram — Critical sections highlighted
  18. Multi-form live sync (dual-mode engine)
  19. Intelligent print system

KEY FEATURES:
• 10 security layers — device-locked license
• 100 % offline after activation
• Instant recalculation — change one input, all modules update simultaneously
• Print-ready output sheets formatted for professional client submission
• Time saved: 17 minutes with Footing Pro vs 3.5–4 hours manual design
• Visual diagrams auto-generate on your machine with no internet needed

════════════════════════════════════════
SYSTEM REQUIREMENTS
════════════════════════════════════════
Operating system : Windows 7 SP1 or higher  (Windows 10 / 11 recommended)
Microsoft Excel  : Version 2002 or higher   (Excel 2016 / 2019 / 365 recommended)
.NET Framework   : Version 4.8 or higher    (pre-installed on Windows 10 and 11)
Internet         : Required on first launch for license activation ONLY.
                   After activation: fully offline for up to 15 days, then a
                   brief reconnection is needed to re-verify the license.
Mac / Linux      : NOT supported. Windows only.

════════════════════════════════════════
PRICING — FOOTING PRO v.2026
════════════════════════════════════════
Launch price   : 249 EGP / year  (time-limited promotional rate for early subscribers)
Regular price  : 499 EGP / year  (applies once the launch period ends)
Subscription   : 1 to 10 years in a single transaction
Multi-year tip : Subscribing for multiple years during the launch period locks in
                 the 249 EGP/year rate for the entire subscription duration.
Base covers    : ALL 19 core engineering modules — no hidden fees.
Add-ons        : Priced separately (see add-on list below). Only pay for what you pick.
Free trial     : None. Full documentation, module descriptions, and engineering
                 capability details are on the website before purchase. Contact
                 Eng. Aymn Asi for any pre-purchase question.

ADD-ON MODULES (optional — selected at registration, priced separately):
• Print System        — Formatted, branded engineering reports ready for submission
• Online Help Center  — Dedicated support portal with tutorials and guidance
• AutoCAD Drawing     — Ready-made DWG structural drawings output

════════════════════════════════════════
HOW TO BUY — EXACT STEP-BY-STEP PROCESS
════════════════════════════════════════
STEP 1 — Download the FREE PC Suite installer from civilengsuite.pages.dev.
          No payment required to download.
STEP 2 — Install and run PC Suite on your Windows machine.
STEP 3 — On first launch, fill in the User Information form:
          • Your full name, phone number, and email address
          • App name (example: Footing Pro v.2026)
          • License duration in years (1 to 10)
          • Optional personal password
          • Add-on checkboxes: Print System / Online Help Center / AutoCAD Drawing
            (tick only the add-ons you want)
STEP 4 — PC Suite generates an encrypted .dat registration file on your Desktop.
STEP 5 — Send that .dat file to the developer via one of these channels:
          Email     : aymneidasi@gmail.com
          WhatsApp  : +201287232413
          Messenger : Facebook Messenger (Civil Engineering Suite page)
STEP 6 — Developer reviews your registration and confirms the exact price
          for your chosen app and subscription term.
STEP 7 — After payment, the developer sends you the fully activated application,
          permanently bound to your device.

════════════════════════════════════════
PC SUITE (FREE REGISTRATION TOOL)
════════════════════════════════════════
PC Suite is the free companion app used for device registration and license management.
It is NOT the engineering application itself — it is the registration gateway.
Download: civilengsuite.pages.dev (main page, prominent download button)
Cost: Free. No payment ever required to download or run PC Suite.
What it does:
  • Checks system compatibility (Windows / Excel / .NET versions)
  • Collects user registration data
  • Generates the encrypted .dat file needed to request a license
  • Manages license renewals and re-activations
PC Suite itself never expires.

════════════════════════════════════════
FAQ
════════════════════════════════════════
Q: How do I subscribe?
A: Download the free PC Suite app → fill in the User Information form → PC Suite
   creates a .dat file on your Desktop → send it to Eng. Aymn Asi via email or
   WhatsApp → confirm price → pay → receive the activated application.

Q: What is the PC Suite app?
A: The free registration and device-verification tool. It checks compatibility,
   registers your device, and creates the encrypted .dat file needed for licensing.
   It is always free — no payment to download or run it.

Q: Does it work on Mac or Linux?
A: No. Footing Pro is Windows-only. Mac support is under consideration for future
   versions. No Linux support planned at this time.

Q: Can I install it on more than one device?
A: No. Each license is locked to one device. Contact the developer if you need
   multi-device licensing options.

Q: Which engineering code does it follow?
A: ACI 318-19 is the primary design standard. Parameters are fully adjustable to
   align with ECP 203 (Egyptian Code of Practice) or other local codes.

Q: Can I share the output reports with clients?
A: Yes. Output sheets are formatted and print-ready for professional submission.

Q: Is there a free trial?
A: No free trial. Full documentation, module breakdowns, and engineering capability
   details are available on the website before purchase. Contact Eng. Aymn Asi at
   aymneidasi@gmail.com with any pre-purchase questions.

Q: Does it need internet after activation?
A: No. Works 100 % offline for up to 15 days per cycle, then needs a brief
   reconnection to verify the license. Only the initial activation requires internet.

Q: Can I subscribe for multiple years?
A: Yes — 1 to 10 years in a single transaction. Multiple years during the launch
   period locks in the 249 EGP/year rate for the full duration.

Q: What are add-on modules and how are they priced?
A: Add-ons are optional advanced features: Print System, Online Help Center, and
   AutoCAD Drawing. You tick the checkboxes you want inside PC Suite when filling
   in the User Information form. Pricing is set separately and confirmed by the
   developer when they receive your .dat file.

Q: What happens when my subscription expires?
A: The software stops working until renewed. Contact the developer to renew.

Q: When are Beam Pro and Column Pro coming?
A: They are in active development. Follow the Civil Engineering Suite Facebook page
   for launch notifications. No confirmed release dates yet.

Q: What is the difference between launch price and regular price?
A: Launch price (249 EGP/year) is a time-limited promotional rate for early
   subscribers. Regular price (499 EGP/year) applies after the launch period ends.
   Both tiers cover exactly the same 19 core modules.

Q: Is the base price really all-inclusive with no hidden fees?
A: Yes. The 249 EGP/yr (or 499 EGP/yr) base covers all 19 core engineering
   modules with no hidden fees. Add-ons are the only additional costs, and those
   are optional — you only pay for add-ons you explicitly choose.

════════════════════════════════════════
BEHAVIOUR RULES
════════════════════════════════════════
• Answer ONLY questions related to Civil Engineering Suite, its products, pricing,
  licensing, technical requirements, and structural engineering topics directly
  relevant to the software.
• For purchase / activation queries: always guide the user to download PC Suite
  first, then send the .dat file to aymneidasi@gmail.com or +201287232413.
• If you cannot answer something: say exactly —
  English: "I don't have that information — please contact Eng. Aymn Asi directly
            at aymneidasi@gmail.com or WhatsApp +201287232413."
  Arabic:  "مش عندي معلومة عن ده — تواصل مع المهندس أيمن عيسى على
            aymneidasi@gmail.com أو واتساب +201287232413."
• Never invent pricing, release dates, or feature details not listed above.
• Never recommend competitor software.`;

// ── Helpers ────────────────────────────────────────────────────────────────
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

// ── POST handler ───────────────────────────────────────────────────────────
export async function onRequestPost(context) {
  const { request, env } = context;

  // 1. Validate API key is configured
  const apiKey = env.GEMINI_API_KEY;
  if (!apiKey) {
    return json(
      { error: 'GEMINI_API_KEY not set in Cloudflare environment variables.' },
      500,
    );
  }

  // 2. Parse request body
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Request body must be valid JSON.' }, 400);
  }

  const userMessage = typeof body.message === 'string' ? body.message.trim() : '';
  const rawHistory  = Array.isArray(body.history) ? body.history : [];

  if (!userMessage) {
    return json({ error: 'Message must not be empty.' }, 400);
  }

  // 3. Build Gemini `contents` array
  //    Keep last 10 turns (5 exchanges) to stay within token budget.
  const contents = [];
  const recentHistory = rawHistory.slice(-10);
  for (const turn of recentHistory) {
    const role = turn.role === 'model' ? 'model' : 'user';
    const text = typeof turn.text === 'string' ? turn.text.trim() : '';
    if (text) contents.push({ role, parts: [{ text }] });
  }
  contents.push({ role: 'user', parts: [{ text: userMessage }] });

  // 4. Call Gemini API — with one automatic retry on 429 or 503
  const payload = JSON.stringify({
    system_instruction: { parts: [{ text: SYSTEM_PROMPT }] },
    contents,
    generationConfig: {
      maxOutputTokens: 700,
      temperature    : 0.35,
      topP           : 0.9,
    },
  });

  async function callGemini() {
    return fetch(`${GEMINI_API_URL}?key=${apiKey}`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : payload,
    });
  }

  let geminiRes;
  try {
    geminiRes = await callGemini();
    // BUG 4 FIX: retry on both rate-limit (429) and transient server error (503)
    if (geminiRes.status === 429 || geminiRes.status === 503) {
      await new Promise(r => setTimeout(r, 2000));
      geminiRes = await callGemini();
    }
  } catch (err) {
    // Network-level failure (DNS / TCP — not an HTTP error from Gemini)
    console.error('[chat.js] Network error calling Gemini:', err.message);
    return json(
      {
        error:
          'Connection error. Please check your internet and try again. / ' +
          'خطأ في الاتصال، تحقق من الإنترنت وحاول مرة أخرى.',
      },
      502,
    );
  }

  if (!geminiRes.ok) {
    // BUG 2 FIX: read the error body so it appears in Cloudflare Functions logs
    // (CF Dashboard → Workers & Pages → civilengsuite → Functions → Logs).
    // Never expose raw error text to end-users.
    let errBody = '';
    try { errBody = await geminiRes.text(); } catch { /* non-fatal */ }
    console.error(
      `[chat.js] Gemini HTTP ${geminiRes.status} for model ${GEMINI_MODEL}:`,
      errBody.slice(0, 500),
    );

    // BUG 3 FIX: expanded friendlyErrors to cover all common Gemini error codes
    const friendlyErrors = {
      400: 'Invalid request. Please rephrase and try again. / ' +
           'طلب غير صالح، حاول تغيير الصياغة.',
      401: 'API authentication failed. Please contact site admin. / ' +
           'فشل المصادقة، تواصل مع المسؤول.',
      403: 'API access denied. Please contact site admin. / ' +
           'الوصول محجوب، تواصل مع المسؤول.',
      404: 'AI model unavailable. Please contact site admin. / ' +
           'النموذج غير متاح، تواصل مع المسؤول.',
      429: 'The assistant is busy right now. Please wait a moment and try again. / ' +
           'المساعد مشغول دلوقتي، استنى لحظة وحاول تاني.',
      503: 'The AI service is temporarily unavailable. Please try again in a minute. / ' +
           'الخدمة مش متاحة دلوقتي، جرب تاني بعد دقيقة.',
    };
    const message =
      friendlyErrors[geminiRes.status] ||
      'Something went wrong. Please try again. / حصل مشكلة، حاول مرة أخرى.';
    return json({ error: message }, 502);
  }

  // 5. Parse and return Gemini reply
  const geminiData = await geminiRes.json();
  const reply =
    geminiData?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ||
    'No response received from AI.';

  return json({ reply });
}

// ── OPTIONS preflight (required for CORS) ─────────────────────────────────
export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS });
}
