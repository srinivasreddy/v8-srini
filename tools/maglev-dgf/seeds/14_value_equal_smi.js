// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev
// Flags: --expose-gc

// Target: a store into a Smi-typed field needs the value's *Smi
// representation*, and that proof is what suppresses the write barrier
// (src/maglev/maglev-graph-builder.cc:BuildStoreField ->
// StoreTaggedFieldNoWriteBarrier). BuildCheckSmi is what establishes the
// proof for a tagged value (src/maglev/maglev-reducer-inl.h:BuildCheckSmi /
// BuildSmiUntag); when it decides from the node's *value* instead of its
// representation, a HeapNumber that is value-equal to a Smi passes for one
// and the field is written with the tag and without a barrier.
//
// `store`'s value is an untyped parameter, so the checked path is what the
// graph shows: CheckMaps on the receiver, CheckSmi on the value, then
// StoreTaggedFieldNoWriteBarrier. 5.0 and -0.0 are the numbers whose value
// equals a Smi; the bytecode holds 5.0 as the Smi 5, so -0.0 is the one
// that reaches the HeapNumber path. Every store after the warmup is followed
// by a GC while `o` is still live, so a field holding the wrong
// representation is observed.

function check(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
}

function store(o, v) { o.x = v; return o.x; }

%PrepareFunctionForOptimization(store);

// Warm up with Smis only: the field is Smi-typed and the store feedback is
// SignedSmall.
check(store({x: 1}, 5) === 5, 'interpreter, smi 5, fresh object');
check(store({x: 1}, 6) === 6, 'interpreter, smi 6, fresh object');

%OptimizeMaglevOnNextCall(store);

let o = {x: 1};
check(store(o, 7) === 7, 'maglev, smi 7');

if (%IsMaglevEnabled()) {
  check(%ActiveTierIsMaglev(store), 'store in Maglev');
}

// A value that equals the Smi 5: the check has to keep the representation
// Smi, so this stores a Smi or deopts; it must not store a HeapNumber.
check(store(o, 5.0) === 5, 'maglev, smi 5.0');
gc();

// -0.0 is a HeapNumber whose value equals the Smi 0. Storing it with the
// Smi tag and no write barrier is the bug, and the sign is what makes it
// visible: -0 must stay -0.
check(1 / store(o, -0.0) === -Infinity, 'maglev, heap number -0.0');
gc();

check(store(o, 0) === 0, 'maglev, smi 0');
check(1 / store(o, 0) === Infinity, 'maglev, smi 0 is +0');
