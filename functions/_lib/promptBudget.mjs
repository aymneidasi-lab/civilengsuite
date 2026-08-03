// Guards against silent prompt bloat (see patch notes: buildSystemPrompt/
// buildGeminiFollowupPrompt/buildWorkersAiSystemPrompt have all drifted
// 1.8x-2.9x past their own documented token budgets through incremental
// edits, with nothing catching the regression). CHARS_PER_TOKEN_FLOOR=3 is
// deliberately conservative (measured ratio for this codebase's actual
// Arabic/English/code-mixed prompts is ~3.75-3.85 chars/token against the
// Anthropic tokenizer proxy -- see verification notes) so this guard trips
// EARLY rather than missing a real regression.
const CHARS_PER_TOKEN_FLOOR = 3;

export function estimateTokens(text) {
  return Math.ceil((text || '').length / CHARS_PER_TOKEN_FLOOR);
}

// name       - label for logs, e.g. "SYSTEM_PROMPT(dev=false)"
// text       - the fully-rendered prompt string
// maxTokens  - designed ceiling for this tier
// env        - the Worker's env object; set PROMPT_BUDGET_STRICT="1" in a
//              staging/CI environment to turn this into a hard failure.
//              Left unset in production so a future prompt edit that nudges
//              a tier a little over budget degrades cost/latency, not
//              uptime -- console.error still surfaces it in Cloudflare's
//              logs immediately either way.
export function assertPromptBudget(name, text, maxTokens, env) {
  const est = estimateTokens(text);
  if (est > maxTokens) {
    const msg = `[promptBudget] ${name} is ~${est} tokens (chars: ${text.length}) against a ` +
      `${maxTokens}-token budget -- ${(est - maxTokens)} over. This prompt has regressed past ` +
      `its designed ceiling; see chat.js changelog for the original budget rationale.`;
    console.error(msg);
    if (env && env.PROMPT_BUDGET_STRICT === '1') throw new Error(msg);
  }
  return est;
}
