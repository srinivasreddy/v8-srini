// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev

// Target: Maglev truncation (src/maglev/maglev-truncation.{h,cc}), enabled by
// --maglev-truncation.
//
// Truncation rewrites nodes that are only used in 32-bit contexts from
// Int32AddWithOverflow/Int32SubWithOverflow/etc to their non-overflowing
// variants and elides `Int32BitwiseOr`/`Int32Shift` identity nodes. The
// pass is representation-sensitive, so a fuzzer that flips a use from tagged
// to int32 (e.g. by adding a `| 0` or by moving a value into a bitwise op)
// changes the truncation decisions without changing the bytecode much.

function check(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
}

function truncateAdd(a, b) {
  let x = (a + b) | 0;
  let y = (a * 3) & 0x7fffffff;
  return (x + y) | 0;
}

function identityChain(a, b) {
  let x = (a + b) | 0;
  // The `| 0` wrappers are identity nodes after truncation.
  let y = ((x | 0) + (a | 0)) | 0;
  let z = ((y | 0) * 2) | 0;
  return z | 0;
}

function shiftAndCompare(a, b) {
  let x = a << 2;
  let y = b >>> 1;
  if (((x + y) | 0) > 100) return (x - y) | 0;
  return (x + y) | 0;
}

function loopAccumulate(a, n) {
  let acc = 0;
  for (let i = 0; i < n; i++) {
    acc = (acc + (a[i] | 0)) | 0;
    acc = (acc ^ (i + 1)) | 0;
  }
  return acc;
}

(function main() {
  %PrepareFunctionForOptimization(truncateAdd);
  check(truncateAdd(1, 2) === 6, 'add, interpreter 1');
  check(truncateAdd(3, 4) === 16, 'add, interpreter 2');
  %OptimizeMaglevOnNextCall(truncateAdd);
  check(truncateAdd(5, 6) === 26, 'add, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(truncateAdd), 'truncateAdd in Maglev');
  }

  %PrepareFunctionForOptimization(identityChain);
  check(identityChain(1, 2) === 8, 'identity, interpreter 1');
  check(identityChain(3, 4) === 20, 'identity, interpreter 2');
  %OptimizeMaglevOnNextCall(identityChain);
  check(identityChain(5, 6) === 32, 'identity, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(identityChain), 'identityChain in Maglev');
  }

  %PrepareFunctionForOptimization(shiftAndCompare);
  check(shiftAndCompare(1, 2) === 5, 'shift, interpreter 1');
  check(shiftAndCompare(100, 200) === 300, 'shift, interpreter 2');
  %OptimizeMaglevOnNextCall(shiftAndCompare);
  check(shiftAndCompare(100, 200) === 300, 'shift, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(shiftAndCompare), 'shiftAndCompare in Maglev');
  }

  %PrepareFunctionForOptimization(loopAccumulate);
  const a = [1, 2, 3, 4];
  const expected = loopAccumulate(a, 4);
  check(expected === loopAccumulate(a, 4), 'loop, interpreter');
  %OptimizeMaglevOnNextCall(loopAccumulate);
  check(loopAccumulate(a, 4) === expected, 'loop, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(loopAccumulate), 'loopAccumulate in Maglev');
  }

  print('truncation: ok');
})();
