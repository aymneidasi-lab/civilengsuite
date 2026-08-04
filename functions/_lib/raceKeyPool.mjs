// Replaces a strict sequential `for (const item of pool) { await attempt(item) }`
// scan with a sliding-window concurrent race: up to `concurrency` attempts
// in flight at once, next item starts the instant a slot frees up, first
// success wins and cancels the rest. Same total attempt count as the
// sequential version (same subrequest-budget cost) -- only wall-clock time
// changes. If every attempt fails, ALL items are still tried (none skipped)
// and the LAST failure (by pool order, not finish order) is returned, to
// match the existing sequential loop's lastProviderResult semantics exactly.
//
// attemptFn signature: async (item, signal, cancelOthers) => result
//   result must be a plain object with an `ok` boolean field.
//   attemptFn should pass `signal` into fetchWithTimeout/fetch so a losing
//   in-flight request is actually cancelled, not just ignored.
//
// [PATCH] cancelOthers() -- BUG 1 FIX (token streaming desync):
//   The original design only cancelled the rest of the pool AFTER an
//   attempt's Promise fully resolved (`res.ok` seen by Promise.race below).
//   For a STREAMING attemptFn that calls a shared onDelta callback many
//   times over several seconds, that left a window -- from "first byte
//   received" to "whole reply finished" -- during which every other
//   in-flight attempt in the same concurrency window could ALSO be
//   mid-stream, each calling the SAME onDelta, interleaving text from two
//   unrelated generations before anyone was ever declared a winner.
//   cancelOthers() lets attemptFn assert "I am the one" the instant it
//   receives its first byte (inside its own onDelta callback), not after
//   its whole reply is in. Call it as early as the caller's own commitment
//   rule requires; it is idempotent and cheap to call more than once.
//
//   Once cancelOthers() fires for index i, this module LOCKS the eventual
//   `winner` to i -- even though the aborted losers' own attemptFn calls
//   may still resolve `{ok:true}` afterward (a provider that had already
//   started streaming before its AbortSignal fired can legitimately report
//   "ok:true, interrupted:true" -- see streamingProviders.mjs's commitment
//   semantics). Without this lock, Promise.race below could see a faster-
//   settling LOSER's ok:true before the actual committed attempt's own
//   Promise resolves, and hand that loser's (irrelevant) result back to the
//   caller as `winner` -- wrong source tag, wrong finishReason, and (worse)
//   abortAllExcept() would then cancel the ACTUAL committed attempt still
//   mid-stream to the client.
export async function raceKeyPool(pool, attemptFn, opts = {}) {
  const concurrency = Math.max(1, opts.concurrency ?? 3);
  const shouldStop = typeof opts.shouldStop === 'function' ? opts.shouldStop : () => false;
  const onAttemptSettled = typeof opts.onAttemptSettled === 'function' ? opts.onAttemptSettled : () => {};

  if (pool.length === 0) return { winner: null, lastResult: null, attempted: 0 };

  const controllers = new Array(pool.length).fill(null);
  const results = new Array(pool.length).fill(undefined);
  let nextIndex = 0;
  let winner = null;
  let lockedIndex = null; // [PATCH] set by cancelOthers() -- see header note
  let attempted = 0;
  let stoppedEarly = false;

  function abortAllExcept(keepIdx) {
    for (let i = 0; i < controllers.length; i++) {
      if (i !== keepIdx && controllers[i] && !controllers[i].signal.aborted) {
        controllers[i].abort();
      }
    }
  }

  function launch(i) {
    const controller = new AbortController();
    controllers[i] = controller;
    attempted++;
    let calledCancel = false;
    function cancelOthers() {
      if (calledCancel) return; // idempotent -- attemptFn may call this once per delta before its own gate learns to stop
      calledCancel = true;
      if (lockedIndex === null) lockedIndex = i;
      abortAllExcept(lockedIndex);
    }
    return attemptFn(pool[i], controller.signal, cancelOthers)
      .catch((err) => ({ ok: false, httpStatus: 0, errStatus: 'RACE_ATTEMPT_THREW', errBody: String(err && err.message || err) }))
      .then((res) => {
        results[i] = res;
        onAttemptSettled(pool[i], res);
        return { i, res };
      });
  }

  const inFlight = new Map(); // index -> promise

  while (true) {
    while (inFlight.size < concurrency && nextIndex < pool.length && !winner && lockedIndex === null && !stoppedEarly) {
      if (shouldStop()) { stoppedEarly = true; break; }
      const i = nextIndex++;
      inFlight.set(i, launch(i));
    }

    if (inFlight.size === 0) break; // nothing left to launch and nothing pending

    const { i, res } = await Promise.race(inFlight.values());
    inFlight.delete(i);

    if (lockedIndex !== null) {
      // [PATCH] A commitment already happened (cancelOthers() fired from
      // inside some attempt's onDelta). Only THAT index's own settlement
      // may become `winner` -- an aborted loser resolving ok:true first
      // (see header note) is drained and ignored, not promoted.
      if (i === lockedIndex) {
        if (res && res.ok) winner = { index: i, result: res };
        break; // terminal either way once the locked attempt itself settles
      }
      continue;
    }

    if (res && res.ok) {
      winner = { index: i, result: res };
      abortAllExcept(i);
      // Let already-settled-but-unawaited losers unwind without becoming
      // unhandled rejections; their eventual results are discarded.
      break;
    }
  }

  if (winner) {
    return { winner: winner.result, lastResult: winner.result, attempted };
  }

  // No winner: last failure BY POOL ORDER (highest index that actually ran),
  // matching the sequential loop's behaviour of lastProviderResult being
  // whichever attempt ran last in pool order, not finish order.
  let lastResult = null;
  for (let i = pool.length - 1; i >= 0; i--) {
    if (results[i] !== undefined) { lastResult = results[i]; break; }
  }
  return { winner: null, lastResult, attempted };
}
