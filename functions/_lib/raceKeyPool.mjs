// Replaces a strict sequential `for (const item of pool) { await attempt(item) }`
// scan with a sliding-window concurrent race: up to `concurrency` attempts
// in flight at once, next item starts the instant a slot frees up, first
// success wins and cancels the rest. Same total attempt count as the
// sequential version (same subrequest-budget cost) -- only wall-clock time
// changes. If every attempt fails, ALL items are still tried (none skipped)
// and the LAST failure (by pool order, not finish order) is returned, to
// match the existing sequential loop's lastProviderResult semantics exactly.
//
// attemptFn signature: async (item, signal) => result
//   result must be a plain object with an `ok` boolean field.
//   attemptFn should pass `signal` into fetchWithTimeout/fetch so a losing
//   in-flight request is actually cancelled, not just ignored.
export async function raceKeyPool(pool, attemptFn, opts = {}) {
  const concurrency = Math.max(1, opts.concurrency ?? 3);
  const shouldStop = typeof opts.shouldStop === 'function' ? opts.shouldStop : () => false;
  const onAttemptSettled = typeof opts.onAttemptSettled === 'function' ? opts.onAttemptSettled : () => {};

  if (pool.length === 0) return { winner: null, lastResult: null, attempted: 0 };

  const controllers = new Array(pool.length).fill(null);
  const results = new Array(pool.length).fill(undefined);
  let nextIndex = 0;
  let winner = null;
  let attempted = 0;
  let stoppedEarly = false;

  function launch(i) {
    const controller = new AbortController();
    controllers[i] = controller;
    attempted++;
    return attemptFn(pool[i], controller.signal)
      .catch((err) => ({ ok: false, httpStatus: 0, errStatus: 'RACE_ATTEMPT_THREW', errBody: String(err && err.message || err) }))
      .then((res) => {
        results[i] = res;
        onAttemptSettled(pool[i], res);
        return { i, res };
      });
  }

  function abortAllExcept(winnerIdx) {
    for (let i = 0; i < controllers.length; i++) {
      if (i !== winnerIdx && controllers[i] && !controllers[i].signal.aborted) {
        controllers[i].abort();
      }
    }
  }

  const inFlight = new Map(); // index -> promise

  while (true) {
    while (inFlight.size < concurrency && nextIndex < pool.length && !winner && !stoppedEarly) {
      if (shouldStop()) { stoppedEarly = true; break; }
      const i = nextIndex++;
      inFlight.set(i, launch(i));
    }

    if (inFlight.size === 0) break; // nothing left to launch and nothing pending

    const { i, res } = await Promise.race(inFlight.values());
    inFlight.delete(i);

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
