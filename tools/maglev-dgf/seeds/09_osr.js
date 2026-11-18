// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan

// Target: Maglev OSR entry and interpreter frame state reconstruction
// (src/maglev/maglev-interpreter-frame-state.*, MaglevCompiler::Compile with
// osr_offset, "Non-standard entrypoint ... by OSR from ..." in the graph
// builder trace).
//
// OSR replaces a running interpreted frame with a Maglev frame. Everything
// live at the loop header has to be materialized from the interpreter frame
// (registers, accumulator, context, loop phis), which makes OSR a distinct
// and bug-prone entry path compared to a normal call. This seed triggers OSR
// from inside a hot loop, with Smi, double and tagged loop-carried values,
// and a nested loop.
//
// OSR reachability is *not* observable through %ActiveTierIsMaglev: the OSR
// code object is entered on the next loop back edge and does not become the
// function's installed code, so the intrinsic reports false even when OSR
// succeeded. The driver therefore verifies this seed with the
// "--trace-maglev-graph-building" marker "by OSR from"; the harness itself
// only checks that the OSR'd computation is still correct.

function check(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
}

function osrSum(n) {
  let s = 0;
  for (let i = 0; i < n; i++) {
    if (i === 1000 && !%ActiveTierIsMaglev(osrSum)) %OptimizeOsr();
    s = s + i;
  }
  return s;
}

function osrMixed(n, o) {
  let d = 0.5;
  let tag = o;
  let smi = 0;
  for (let i = 0; i < n; i++) {
    if (i === 500 && !%ActiveTierIsMaglev(osrMixed)) %OptimizeOsr();
    d = d + 1.5;
    tag = (i & 1) ? tag : o;
    smi = (smi + i) | 0;
  }
  return d + smi + (tag === o ? 1 : 0);
}

function osrNested(n) {
  let s = 0;
  for (let i = 0; i < n; i++) {
    if (i === 10 && !%ActiveTierIsMaglev(osrNested)) %OptimizeOsr();
    for (let j = 0; j < 4; j++) {
      s = (s + i * j) | 0;
    }
  }
  return s;
}

(function main() {
  // Sum(0..99999) = 99999 * 100000 / 2.
  %PrepareFunctionForOptimization(osrSum);
  check(osrSum(100000) === 4999950000, 'osrSum');

  // d = 0.5 + 1.5 * 5000, smi = Sum(0..4999) with int32 wraparound, tag
  // stays the same object.
  const o = {tag: 1};
  %PrepareFunctionForOptimization(osrMixed);
  check(osrMixed(5000, o) === 12505001.5, 'osrMixed');

  // Inner loop adds Sum(0..3) * i = 6 * i per outer iteration.
  %PrepareFunctionForOptimization(osrNested);
  check(osrNested(1000) === 2997000, 'osrNested');

  print('osr: ok');
})();
