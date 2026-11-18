// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev

// Target: MaglevInliner / MaglevGraphBuilder::TryBuildInlinedCall
// (src/maglev/maglev-inlining.*, maglev-graph-builder.cc), plus the
// polymorphic-call path guarded by --maglev-poly-calls.
//
// Small callees are inlined ("Small function, skipping max-depth"). A
// monomorphic callee is inlined directly; a callee with 2-4 call targets
// produces a polymorphic inlining tree with per-target checks.

function check(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
}

function add1(x) {
  return x + 1;
}

function add2(x) {
  return x + 2;
}

// Monomorphic chain: both calls are inlined into `mono`.
function mono(x) {
  return add1(add1(x)) * 2;
}

// Polymorphic call site: `poly` sees two different targets and inlines a
// dispatch tree (requires --maglev-poly-calls, on by default).
function poly(fn, x) {
  return fn(x) + fn(x);
}

(function main() {
  %PrepareFunctionForOptimization(add1);
  %PrepareFunctionForOptimization(add2);

  %PrepareFunctionForOptimization(mono);
  check(mono(1) === 6, 'mono, interpreter 1');
  check(mono(1) === 6, 'mono, interpreter 2');
  %OptimizeMaglevOnNextCall(mono);
  check(mono(1) === 6, 'mono, maglev');
  if (%IsMaglevEnabled()) check(%ActiveTierIsMaglev(mono), 'mono in Maglev');

  %PrepareFunctionForOptimization(poly);
  check(poly(add1, 1) === 4, 'poly, interpreter 1');
  check(poly(add2, 1) === 6, 'poly, interpreter 2');
  check(poly(add1, 2) === 6, 'poly, interpreter 3');
  check(poly(add2, 2) === 8, 'poly, interpreter 4');
  %OptimizeMaglevOnNextCall(poly);
  check(poly(add1, 3) === 8, 'poly, maglev');
  if (%IsMaglevEnabled()) check(%ActiveTierIsMaglev(poly), 'poly in Maglev');

  print('inlining: ok');
})();
