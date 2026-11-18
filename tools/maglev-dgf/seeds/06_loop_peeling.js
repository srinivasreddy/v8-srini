// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev

// Target: MaglevLoopPeeler (src/maglev/maglev-loop-peeler.*), enabled by
// --maglev-loop-peeling and driven by the graph builder when a loop has a
// small, statically known trip count ("Block bN peeled" in the printed graph).
//
// Peeling duplicates the loop body, so it stresses phi/value remapping,
// side-effect tracking (LoopEffects, which is also what escape analysis
// relies on) and the optimistic-peeling fallback
// (--maglev-optimistic-peeled-loops). The seed mixes trip counts, early
// exits and nested control flow so several peeling decisions are taken.

function check(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
}

// Constant trip count, branch in the body: classic peeling candidate.
function peelBranchy(a) {
  let s = 0;
  for (let i = 0; i < 8; i++) {
    if (a[i] & 1) {
      s += a[i] * 2;
    } else {
      s -= a[i];
    }
  }
  return s;
}

// Early exit in the first iterations (peeled exits).
function peelEarlyExit(a, limit) {
  let s = 0;
  for (let i = 0; i < 4; i++) {
    if (a[i] > limit) return -1;
    s += a[i];
  }
  return s;
}

// Loop-carried double, peeled + phi untagging interaction.
function peelCarriedDouble(n) {
  let x = 0.5;
  for (let i = 0; i < 3; i++) {
    x = x * 2 + i;
  }
  return x;
}

// Nested loops: inner loop is peeled inside the peeled outer body.
function peelNested(a) {
  let s = 0;
  for (let i = 0; i < 3; i++) {
    for (let j = 0; j < 3; j++) {
      s += a[i][j];
    }
  }
  return s;
}

(function main() {
  const a = [1, 2, 3, 4, 5, 6, 7, 8];
  // 1*2 - 2 + 3*2 - 4 + 5*2 - 6 + 7*2 - 8 = 12.
  %PrepareFunctionForOptimization(peelBranchy);
  check(peelBranchy(a) === 12, 'branchy, interpreter 1');
  check(peelBranchy(a) === 12, 'branchy, interpreter 2');
  %OptimizeMaglevOnNextCall(peelBranchy);
  check(peelBranchy(a) === 12, 'branchy, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(peelBranchy), 'peelBranchy in Maglev');
  }

  %PrepareFunctionForOptimization(peelEarlyExit);
  check(peelEarlyExit([1, 2, 3, 4], 10) === 10, 'early exit, interpreter 1');
  check(peelEarlyExit([1, 2, 3, 4], 2) === -1, 'early exit, interpreter 2');
  %OptimizeMaglevOnNextCall(peelEarlyExit);
  check(peelEarlyExit([1, 2, 3, 4], 10) === 10, 'early exit, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(peelEarlyExit), 'peelEarlyExit in Maglev');
  }

  %PrepareFunctionForOptimization(peelCarriedDouble);
  check(peelCarriedDouble(3) === 8, 'carried, interpreter 1');
  check(peelCarriedDouble(3) === 8, 'carried, interpreter 2');
  %OptimizeMaglevOnNextCall(peelCarriedDouble);
  check(peelCarriedDouble(3) === 8, 'carried, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(peelCarriedDouble),
          'peelCarriedDouble in Maglev');
  }

  %PrepareFunctionForOptimization(peelNested);
  const m = [[1, 2, 3], [4, 5, 6], [7, 8, 9]];
  check(peelNested(m) === 45, 'nested, interpreter 1');
  check(peelNested(m) === 45, 'nested, interpreter 2');
  %OptimizeMaglevOnNextCall(peelNested);
  check(peelNested(m) === 45, 'nested, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(peelNested), 'peelNested in Maglev');
  }

  print('loop-peeling: ok');
})();
