// factGuard.test.mjs — run with `node factGuard.test.mjs` before `wrangler
// deploy`. No dependencies, no network. Exits non-zero on any failure so it
// can be wired into a pre-deploy CI step.

import { assertFactsRegistrySynced, scanForFactDrift, logFactDrift } from './factGuard.mjs';

// Keep this in sync with the real CRITICAL_FACTS constant in chat.js — this
// copy exists so the test has no dependency on chat.js's other imports
// (kb-data.js, rotation.mjs) which this test does not need.
const CRITICAL_FACTS_TEXT = `
CANONICAL FACTS — exact numbers, use verbatim.
- Code-signing certificate: SHA-256 Authenticode, publisher "Engineering Apps Team".
- Pricing: 249 EGP/yr launch price (499 EGP/yr regular, after launch). 2 yrs = 10%, 3 yrs = 15%.
- License: device-locked. Offline schedule: days 1-15 fully offline; days 16-29 warning;
  days 30-32 final grace (must connect within 3 days); day 33+ blocked.
- Contact: aymneidasi@gmail.com or WhatsApp +201287232413.
`;

const cases = [
  { name: 'clean EN reply', text: "The launch price is 249 EGP/yr (499 EGP/yr regular). The license cannot be transferred to another device.", expectClean: true },
  { name: 'clean AR reply', text: "السعر 249 جنيه في السنة وقت الإطلاق، وبعدين بيرجع 499. الترخيص مربوط بالجهاز ومش ممكن تنقله.", expectClean: true },
  { name: 'drifted price', text: "The current price is 350 EGP/yr for the full package.", expectClean: false },
  { name: 'legit multi-year total not flagged', text: "3 years total comes to 747 EGP total at the launch price.", expectClean: true },
  { name: 'cert date leak', text: "Yes, the certificate is currently signed and valid until 19/05/2028.", expectClean: false },
  { name: 'transfer claim unnegated', text: "Sure, you can transfer the license to a new device.", expectClean: false },
  { name: 'transfer claim correctly negated', text: "No, you cannot transfer the license to a new device.", expectClean: true },
];

let pass = 0, fail = 0;
function check(name, cond) { console.log(`${cond ? 'PASS' : 'FAIL'} — ${name}`); cond ? pass++ : fail++; }

try {
  assertFactsRegistrySynced(CRITICAL_FACTS_TEXT);
  check('registry stays in sync with CRITICAL_FACTS numbers', true);
} catch (e) {
  check(`registry sync: ${e.message}`, false);
}

for (const c of cases) {
  check(c.name, scanForFactDrift(c.text).clean === c.expectClean);
}

try {
  logFactDrift({ clean: true, violations: [] }, { provider: 'gemini' });
  logFactDrift({ clean: false, violations: [{ type: 'price' }] }, { provider: 'groq' });
  check('logFactDrift does not throw', true);
} catch (e) {
  check(`logFactDrift threw: ${e.message}`, false);
}

console.log(`\n${pass}/${pass + fail} passed`);
process.exit(fail ? 1 : 0);
