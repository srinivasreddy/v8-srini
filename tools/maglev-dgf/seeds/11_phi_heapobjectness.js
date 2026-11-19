// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev
// Flags: --maglev-non-eager-inlining

// Target: MaglevPhiRepresentationSelector's tagging conversions
// (src/maglev/maglev-phi-representation-selector.cc:ConvertTaggedPhiTo,
// UpdateNodePhiInput(CheckHeapObject*), EnsurePhiTagged).
//
// The loop phi merges a HeapNumber field (o.d) with the result of a
// Smi-representation field load (o.v), so the selector untags the phi to
// Float64 and the Smi operand is consumed by a check-free UnsafeSmiUntag,
// while the tagged consumer at the bottom needs the value retagged.
//
// Both operands are *loads*, not literals: a constant Smi is materialised
// as a Float64Constant by the untagging and the graph then has no
// UnsafeSmiUntag at all, which is what the target's required_patterns ask
// for.

function phiConsumer(o, n) {
  let x = 0;
  for (let i = 0; i < n; i++) {
    x = (i & 1) ? o.d : (x + o.v);
  }
  // x is a HeapNumber at this point; the consumer below expects a HeapObject
  return x.length + x[0];
}
%PrepareFunctionForOptimization(phiConsumer);
phiConsumer({v: 3, d: 1.5}, 8);
phiConsumer({v: 3, d: 1.5}, 8);
%OptimizeMaglevOnNextCall(phiConsumer);
phiConsumer({v: 3, d: 1.5}, 8);   // warm with HeapNumber
phiConsumer({v: 3, d: 1.5}, 8);   // should not crash on clean build
if (%IsMaglevEnabled()) {
  if (!%ActiveTierIsMaglev(phiConsumer)) throw "not maglev";
}
