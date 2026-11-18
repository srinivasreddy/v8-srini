// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev

// Target: MaglevPhiRepresentationSelector
// (src/maglev/maglev-phi-representation-selector.cc), run as the
// kPhiUntagging phase when --maglev-untagged-phis is on.
//
// A loop phi that alternates between a Smi and a heap number forces the
// representation selector to either untag the phi (kFloat64) or insert
// conversions. Both the branchy version below and the "unreliable maps"
// variant exercise the fixpoint / bisection logic.

function check(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
}

function alternating(n, d) {
  let x = 0;
  for (let i = 0; i < n; i++) {
    x = (i & 1) ? 1.5 : 2;
    x = x + d;
  }
  return x;
}

function growing(n) {
  let x = 1;
  for (let i = 0; i < n; i++) {
    x = x * 1.5;
    if (x > 1e6) x = 1;
  }
  return x;
}

function taggedThenSmi(n, o) {
  let x = o.v;
  for (let i = 0; i < n; i++) {
    x = (x === 0) ? i : x;
  }
  return x;
}

(function main() {
  %PrepareFunctionForOptimization(alternating);
  alternating(10, 1);
  alternating(10, 1);
  %OptimizeMaglevOnNextCall(alternating);
  check(alternating(10, 1) === 2.5, 'alternating');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(alternating), 'alternating in Maglev');
  }

  %PrepareFunctionForOptimization(growing);
  growing(4);
  growing(4);
  %OptimizeMaglevOnNextCall(growing);
  check(growing(4) === 5.0625, 'growing');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(growing), 'growing in Maglev');
  }

  const o = {v: 3};
  %PrepareFunctionForOptimization(taggedThenSmi);
  taggedThenSmi(5, o);
  taggedThenSmi(5, o);
  %OptimizeMaglevOnNextCall(taggedThenSmi);
  check(taggedThenSmi(5, o) === 3, 'tagged then smi');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(taggedThenSmi), 'taggedThenSmi in Maglev');
  }

  print('phi-untagging: ok');
})();
