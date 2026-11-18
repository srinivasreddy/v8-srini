// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev

// Target: Maglev register allocation (src/maglev/maglev-regalloc.cc),
// gap moves and spill slot reuse (--maglev-reuse-stack-slots).
//
// Register allocation is where "correct graph, wrong code" bugs concentrate:
// gap moves at branches/calls, spill slot reuse across calls, and the
// handling of values live across a call. This seed maximizes the number of
// simultaneously live values, keeps them live across calls, and uses both
// int32 and tagged/double values so that different register classes are
// exercised.

function check(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
}

function pressure(a, b, c, d, e, f, g) {
  let x1 = a + 1;
  let x2 = b * 2;
  let x3 = c - 3;
  let x4 = d / 4;
  let x5 = e | 5;
  let x6 = f & 6;
  let x7 = g ^ 7;
  let r = x1 * x2 + x3 * x4 + x5 * x6 + x7;
  let y1 = r + 1;
  let y2 = r + 2;
  let y3 = r + 3;
  let y4 = r + 4;
  let y5 = r + 5;
  let y6 = r + 6;
  let y7 = r + 7;
  let y8 = r + 8;
  return y1 + y2 + y3 + y4 + y5 + y6 + y7 + y8;
}

// Values live across a call cannot stay in caller-saved registers.
function liveAcrossCall(a, b, c, d) {
  let t1 = a + 1;
  let t2 = b + 2;
  let t3 = c + 3;
  let t4 = d + 4;
  let s = helper(t1, t2);
  return t1 + t2 + t3 + t4 + s;
}

function helper(x, y) {
  return x * y - 1;
}

// Branchy control flow with many live values: gap moves at merges.
function branchPressure(a, b, c, d, n) {
  let s = 0;
  for (let i = 0; i < n; i++) {
    let v1 = a + i;
    let v2 = b - i;
    let v3 = c * 1.5;
    let v4 = d & 0xff;
    if (i & 1) {
      s += v1 + v2;
    } else {
      s += v3 + v4;
    }
  }
  return s;
}

(function main() {
  %PrepareFunctionForOptimization(helper);
  %PrepareFunctionForOptimization(pressure);
  const p1 = pressure(1, 2, 3, 4, 5, 6, 7);
  check(pressure(1, 2, 3, 4, 5, 6, 7) === p1, 'pressure, interpreter');
  %OptimizeMaglevOnNextCall(pressure);
  check(pressure(1, 2, 3, 4, 5, 6, 7) === p1, 'pressure, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(pressure), 'pressure in Maglev');
  }

  %PrepareFunctionForOptimization(liveAcrossCall);
  const p2 = liveAcrossCall(1, 2, 3, 4);
  check(liveAcrossCall(1, 2, 3, 4) === p2, 'live across call, interpreter');
  %OptimizeMaglevOnNextCall(liveAcrossCall);
  check(liveAcrossCall(1, 2, 3, 4) === p2, 'live across call, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(liveAcrossCall), 'liveAcrossCall in Maglev');
  }

  %PrepareFunctionForOptimization(branchPressure);
  const p3 = branchPressure(1, 2, 3, 4, 16);
  check(branchPressure(1, 2, 3, 4, 16) === p3, 'branch, interpreter');
  %OptimizeMaglevOnNextCall(branchPressure);
  check(branchPressure(1, 2, 3, 4, 16) === p3, 'branch, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(branchPressure), 'branchPressure in Maglev');
  }

  print('regalloc: ok');
})();
