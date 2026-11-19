// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev
// Flags: --maglev-non-eager-inlining

// Target: the loop-header Phi keeps the representation inferred from the
// header and the Smi-representation field load is untagged without a check
// (UnsafeSmiUntag), so a back edge that delivers a HeapNumber is only
// handled by the conversions the selector inserts
// (src/maglev/maglev-interpreter-frame-state.cc:MergeLoopValue,
// src/maglev/maglev-ir.h:promote_post_loop_type,
// src/maglev/maglev-phi-representation-selector.cc:ConvertTaggedPhiTo).
//
// The seed pins the Int32 baseline: 100.0 is an integer literal, which
// Maglev materialises as Int32Constant(100), so both adds stay Int32Add and
// the graph contains no Float64Add. `dgf.py direct` swaps the back edge
// value for a real HeapNumber, which is where that Int32Add turns into a
// Float64Add without the header type being re-validated.
//
// o.v is a *load*: a constant Smi is folded and the graph then has no
// UnsafeSmiUntag at all, which is what the target's required_patterns ask.

function backedge(o, n) {
  let x = 0;
  for (let i = 0; i < n; i++) {
    // A rep change on the last iteration; the literal is integral, so
    // Maglev keeps the loop in Int32 (Int32Add, no Float64Add).
    x = (i === n - 1) ? 100.0 : (x + o.v);
  }
  return (x + o.v) | 0;
}
%PrepareFunctionForOptimization(backedge);
backedge({v: 1}, 20); backedge({v: 1}, 20);
%OptimizeMaglevOnNextCall(backedge);
backedge({v: 1}, 20);
backedge({v: 1}, 20);
if (%IsMaglevEnabled()) {
  if (!%ActiveTierIsMaglev(backedge)) throw "not maglev";
}
