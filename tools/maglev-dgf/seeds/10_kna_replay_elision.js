// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev
// Flags: --maglev-non-eager-inlining

// Target: MaglevInliner's KNA replay
// (src/maglev/maglev-inlining.cc:MaglevInliner::BuildInlineFunction), and the
// elisions it feeds: MaglevReducer::BuildCheckSmi / BuildSmiUntag
// (src/maglev/maglev-reducer-inl.h).
//
// Non-eager inlining captures the caller's KnownNodeAspects when the call node
// is built (maglev-graph-builder.cc, "KnownNodeAspects::Ptr call_aspects =
// known_node_aspects().Clone()") and replays that snapshot when the callee is
// spliced in, re-arming only *map* invalidation ("MarkSideEffectsRequire
// Invalidation"). Node *types* have no invalidation rule at all, so a type the
// caller recorded before the call is still there when the callee's body is
// built after the mutation body was spliced in.
//
// The shape below is the smallest one that puts that snapshot between a
// recorded type and a use:
//   n = o.x          -> Smi-representation field load
//   n + 1            -> a check records n : kSmi
//   store(o, v)      -> call site 1, non-eager, mutates o.x
//   bump(o.x), load(o) -> call sites 2 and 3, non-eager, replay the snapshot
// `bump`'s parameter *is* the caller's `o.x` node (arguments are shared by
// identity), so any proof recorded for it travels into the callee.
//
// %DisableEagerInlining is what makes the replay deterministic:
// TryBuildInlineCall prefers the eager path for callees under
// --max-maglev-eager-inlined-bytecode-size, even when non-eager inlining is on.

function check(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
}

// Mutator. Inlined non-eagerly at call site 1.
function store(o, v) {
  o.x = v;
  o.w = 1;
  return o;
}

// Consumer of the same field. Inlined non-eagerly at call site 2.
function load(o) {
  return (o.x + 1) | 0;
}

// Consumer of the value by identity. Inlined non-eagerly at call site 3.
function bump(x) {
  return (x + 1) | 0;
}

%PrepareFunctionForOptimization(store);
%PrepareFunctionForOptimization(load);
%PrepareFunctionForOptimization(bump);
%DisableEagerInlining(store);
%DisableEagerInlining(load);
%DisableEagerInlining(bump);

function driver(o, v) {
  let n = o.x;              // Smi-representation field load
  let m = n + 1;            // records n : kSmi after the check
  store(o, v);              // call site 1: mutation, snapshot captured here
  let a = bump(o.x);        // call site 2: replays the snapshot
  let b = load(o);          // call site 3: replays the snapshot
  return (a + b + m + n * 1.5) | 0;
}

// Warm up with Smis only, so the additions get SignedSmall feedback and the
// field stays Smi-represented.
function warmup(limit) {
  for (let i = 0; i < limit; i++) {
    check(driver({x: 3}, 3) === 16, 'interpreter, smi ' + i);
  }
}

%PrepareFunctionForOptimization(driver);
warmup(4);

%OptimizeMaglevOnNextCall(driver);
check(driver({x: 3}, 3) === 16, 'maglev, smi');
if (%IsMaglevEnabled()) check(%ActiveTierIsMaglev(driver), 'driver in Maglev');

// Now exercise the elided proof with the value that contradicts it: the store
// transitions o.x from a Smi field to a Double field, so the second and third
// call sites read a heap number through a check that was elided from a
// snapshot taken before the mutation existed.
//
// (2.5 + 1) | 0 === 3 and (3 + 1) === 4, so the expected value is
// 3 + 3 + 4 + 3 * 1.5 === 14.5 -> 14.
check(driver({x: 3}, 2.5) === 14, 'maglev, heap number');

// Same shape, but the mutated value is a loop-carried phi, which is the
// promote_post_loop_type path (src/maglev/maglev-ir.h,
// MergePointInterpreterFrameState::MergeLoopValue).
function driverLoop(o, v, limit) {
  let s = 0;
  for (let i = 0; i < limit; i++) {
    let n = s + o.x;
    store(o, v);
    s = (n + bump(o.x) + load(o)) | 0;
  }
  return s;
}

%PrepareFunctionForOptimization(driverLoop);
for (let i = 0; i < 4; i++) {
  check(driverLoop({x: 1}, 1, 2) === 10, 'interpreter, loop ' + i);
}

%OptimizeMaglevOnNextCall(driverLoop);
check(driverLoop({x: 1}, 1, 2) === 10, 'maglev, loop');
if (%IsMaglevEnabled()) {
  check(%ActiveTierIsMaglev(driverLoop), 'driverLoop in Maglev');
}
check(driverLoop({x: 1}, 2.5, 2) === 15, 'maglev, loop heap number');

print('kna replay elision: ok');
