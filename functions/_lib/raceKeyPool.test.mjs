import { raceKeyPool } from './raceKeyPool.mjs';
import assert from 'node:assert';

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ── Test 1: caller-level gate + lockedIndex must survive a faster-settling
//    aborted loser that independently resolves ok:true (the exact bug from
//    the diagnosis: B started streaming before A's gate closed, gets
//    aborted, but had already "committed" internally so it still resolves
//    ok:true -- and does so BEFORE A's own longer stream finishes).
async function testLockedIndexBeatsRacyLoser() {
  const pool = [{ id: 'A' }, { id: 'B' }, { id: 'C' }];
  let committedCanceller = null;
  const relayLog = [];
  let aAborted = false;

  // Mirrors chat.js's real attemptFn shape: `{ ...res, originalIndex }` is
  // what actually gets returned to raceKeyPool per attempt.
  const { winner } = await raceKeyPool(pool, async (item, signal, cancelOthers) => {
    if (item.id === 'A') {
      // A commits on its "first delta" at t=20ms, then keeps "streaming"
      // (relayLog keeps growing) until t=150ms -- much slower to fully
      // settle than B.
      await sleep(20);
      if (committedCanceller === null) { committedCanceller = cancelOthers; cancelOthers(); }
      if (committedCanceller === cancelOthers) relayLog.push('A:delta1');
      signal.addEventListener('abort', () => { aAborted = true; });
      await sleep(130);
      if (signal.aborted) throw new Error('A must never be aborted -- it is the committed attempt');
      if (committedCanceller === cancelOthers) relayLog.push('A:delta2');
      return { ok: true, reply: 'full A reply', finishReason: 'STOP', originalIndex: 'A' };
    }
    if (item.id === 'B') {
      // B gets its OWN first byte slightly later than A (t=25ms) so it
      // LOSES the caller-level gate -- but per streamingProviders.mjs's
      // real commitment semantics, B's underlying runStream() has already
      // set committed=true before the gate check runs, so once aborted it
      // still resolves ok:true, and it does so fast (t=30ms) -- BEFORE A.
      await sleep(25);
      if (committedCanceller === null) { committedCanceller = cancelOthers; cancelOthers(); }
      if (committedCanceller === cancelOthers) relayLog.push('B:delta1'); // must NOT run -- A already won
      await sleep(5);
      return { ok: true, reply: 'partial B reply', interrupted: true, finishReason: null, originalIndex: 'B' };
    }
    // C never gets a chance to emit anything (aborted before its first byte).
    await sleep(500);
    return { ok: true, reply: 'C should never get here', originalIndex: 'C' };
  }, { concurrency: 3 });

  assert.ok(winner, 'raceKeyPool must return a non-null winner');
  assert.strictEqual(winner.originalIndex, 'A', `winner must be A, got ${winner.originalIndex}`);
  assert.strictEqual(winner.reply, 'full A reply', 'winner must be A\'s own result object, not B\'s');
  assert.deepStrictEqual(relayLog, ['A:delta1', 'A:delta2'], 'only A\'s deltas may reach the relay -- B\'s must be gated out');
  assert.strictEqual(aAborted, false, 'A must never be aborted once it holds the lock');
  console.log('PASS: testLockedIndexBeatsRacyLoser');
}

// ── Test 2: ordinary (non-streaming) path is unchanged -- first ok:true
//    settlement wins exactly as before, when nobody calls cancelOthers().
async function testOrdinaryWinnerUnchanged() {
  const pool = [{ id: 'A' }, { id: 'B' }, { id: 'C' }];
  const { winner, attempted } = await raceKeyPool(pool, async (item, signal) => {
    if (item.id === 'A') { await sleep(30); return { ok: false, httpStatus: 500, errStatus: 'ERR' }; }
    if (item.id === 'B') { await sleep(10); return { ok: true, reply: 'B wins' }; }
    await sleep(50);
    return { ok: true, reply: 'C too slow' };
  }, { concurrency: 3 });
  assert.strictEqual(winner.reply, 'B wins', 'B (fastest ok:true) must win when no cancelOthers() is used');
  assert.strictEqual(attempted, 3, 'all 3 must have been attempted (concurrency=3 launches all at once)');
  console.log('PASS: testOrdinaryWinnerUnchanged');
}

// ── Test 3: all-failure path still returns the last-by-pool-order failure.
async function testAllFailureLastByPoolOrder() {
  const pool = [{ id: 'A' }, { id: 'B' }, { id: 'C' }];
  const { winner, lastResult, attempted } = await raceKeyPool(pool, async (item) => {
    await sleep(item.id === 'C' ? 5 : 20); // C settles first despite being last in pool order
    return { ok: false, httpStatus: 500, errStatus: `ERR_${item.id}` };
  }, { concurrency: 3 });
  assert.strictEqual(winner, null);
  assert.strictEqual(lastResult.errStatus, 'ERR_C', 'must be pool-order-last (C), not settlement-order-last');
  assert.strictEqual(attempted, 3);
  console.log('PASS: testAllFailureLastByPoolOrder');
}

// ── Test 4: concurrency window -- with pool>concurrency, a 4th item only
//    launches once a slot frees, and locking stops it from ever launching
//    if commitment happens first.
async function testConcurrencyWindowStopsOnLock() {
  const pool = [{ id: 'A' }, { id: 'B' }, { id: 'C' }, { id: 'D' }];
  const launched = [];
  let committedCanceller = null;
  await raceKeyPool(pool, async (item, signal, cancelOthers) => {
    launched.push(item.id);
    if (item.id === 'A') {
      await sleep(10);
      if (committedCanceller === null) { committedCanceller = cancelOthers; cancelOthers(); }
      await sleep(20);
      return { ok: true, reply: 'A' };
    }
    // B, C occupy the other 2 concurrency=3 slots and get aborted quickly.
    await sleep(200);
    return { ok: true, reply: item.id };
  }, { concurrency: 3 });
  assert.ok(!launched.includes('D'), `D must never launch once locked -- launched: ${launched.join(',')}`);
  console.log('PASS: testConcurrencyWindowStopsOnLock (launched: ' + launched.join(',') + ')');
}

await testLockedIndexBeatsRacyLoser();
await testOrdinaryWinnerUnchanged();
await testAllFailureLastByPoolOrder();
await testConcurrencyWindowStopsOnLock();
console.log('ALL PASS');
