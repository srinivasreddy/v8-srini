// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev

// Target: MaglevGraphBuilder::VisitForInEnumerate / VisitForInPrepare /
// VisitForInNext / VisitForInStep (src/maglev/maglev-graph-builder.cc).
//
// The lowering of `for-in` depends on the ForInFeedback hint stored in the
// feedback vector:
//   * ForInHint::kEnumCacheKeys / kEnumCacheKeysAndIndices
//       -> explicit enum-cache lowering: CheckDynamicValue,
//          LoadEnumCacheLength, CheckCacheIndicesNotCleared.
//   * ForInHint::kAny
//       -> generic `ForInPrepare` + `ForInNext` nodes with lazy deopt.
// Both are reachable from plain JS; this harness reaches both in one process.

function check(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
}

// Fast path: a plain object receiver settles the feedback on the enum cache.
function enumCacheSum(o) {
  let sum = 0;
  for (let key in o) sum += o[key];
  return sum;
}

// Slow path: a Proxy receiver makes the for-in hint kAny, so the graph
// builder emits the generic ForInPrepare/ForInNext nodes.
function proxyKeyLength(o) {
  let n = 0;
  for (let key in o) n += key.length;
  return n;
}

(function main() {
  const o = {a: 1, b: 2, c: 3};
  %PrepareFunctionForOptimization(enumCacheSum);
  check(enumCacheSum(o) === 6, 'enum cache, interpreter 1');
  check(enumCacheSum(o) === 6, 'enum cache, interpreter 2');
  %OptimizeMaglevOnNextCall(enumCacheSum);
  check(enumCacheSum(o) === 6, 'enum cache, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(enumCacheSum), 'enum cache path in Maglev');
  }

  const target = {x: 1, y: 2, z: 3};
  const proxy = new Proxy(target, {
    ownKeys(t) { return Reflect.ownKeys(t); },
    getOwnPropertyDescriptor(t, k) {
      return Reflect.getOwnPropertyDescriptor(t, k);
    },
  });
  %PrepareFunctionForOptimization(proxyKeyLength);
  check(proxyKeyLength(proxy) === 3, 'kAny, interpreter 1');
  check(proxyKeyLength(proxy) === 3, 'kAny, interpreter 2');
  %OptimizeMaglevOnNextCall(proxyKeyLength);
  check(proxyKeyLength(proxy) === 3, 'kAny, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(proxyKeyLength), 'kAny path in Maglev');
  }

  print('forin-hints: ok');
})();
