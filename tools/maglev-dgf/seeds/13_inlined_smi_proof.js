// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev
// Flags: --maglev-non-eager-inlining

// Target: the inliner splices the callee in with the caller's argument node
// as the callee's parameter, by identity
// (src/maglev/maglev-inlining.cc:BuildInlineFunction,
// src/maglev/maglev-inlining.cc:ReturnedValueRepresentationSelector), and the
// callee's Smi proof is re-derived from the *call feedback*
// (src/maglev/maglev-reducer-inl.h:BuildCheckSmi / BuildSmiUntag), not from
// the type of the node the check ends up on. `inner`'s `x + 1` has
// SignedSmall feedback, so the inlined body gets a CheckedSmiUntag whose
// input is the caller's own parameter (InitialValue(a0)); that check is the
// only thing validating the Smi assumption, so a HeapNumber argument has to
// fail it rather than be untagged as a Smi.
//
// %PrepareFunctionForOptimization(inner) is what makes the non-eager path
// usable at all: without a feedback vector for the callee, TryBuildInlineCall
// gives up with "it has not been compiled/run with feedback yet"
// (src/maglev/maglev-graph-builder.cc) and no INLINE is traced.
// %DisableEagerInlining keeps the call off the eager path, which is the one
// that captures the caller's KnownNodeAspects snapshot.

function check(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
}

function inner(x) { return (x + 1) | 0; }
function outer(a) { return inner(a); }

%PrepareFunctionForOptimization(inner);
%DisableEagerInlining(inner);
%PrepareFunctionForOptimization(outer);

// Warm up with Smis only, so the call feedback is SignedSmall and the Smi
// proof in the callee is built from it.
check(outer(1) === 2, 'interpreter, smi 1');
check(outer(2) === 3, 'interpreter, smi 2');

%OptimizeMaglevOnNextCall(outer);
check(outer(3) === 4, 'maglev, smi');

// The inlined callee now untags the caller's parameter with a
// CheckedSmiUntag. (1.5 + 1) | 0 === 2, so a HeapNumber has to deopt and
// still produce the same value; untagging it as a Smi would not.
check(outer(1.5) === 2, 'maglev, heap number');
check(outer(1.5) === 2, 'maglev, heap number again');

if (%IsMaglevEnabled()) {
  check(%ActiveTierIsMaglev(outer), 'outer in Maglev');
}
