// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev

// Target: virtual-object materialization + the escape-analysis fixpoint over
// InlinedAllocation nodes (src/maglev/maglev-post-hoc-optimizations-
// processors.h, AnyUseMarkingProcessor::RunEscapeAnalysis, and the
// AllocationBlock/InlinedAllocation nodes in maglev-ir.h).
//
// The graph builder turns an object literal into AllocationBlock +
// InlinedAllocation + StoreMap + StoreTaggedField. Escape analysis then
// classifies every InlinedAllocation as escaping or elided. This seed builds
// allocations that do not escape (field values are forwarded), one that does
// (stored into a global), and a context allocation that is only used on an
// unreachable path, which the escape analysis removes from the graph.

function check(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
}

let sink;

// Non-escaping: the object is built, its fields are read, and it is dropped.
function localObject(a, b) {
  let o = {x: a, y: b};
  let p = {u: o.x, v: o.y};
  return p.u * p.v;
}

// Nested non-escaping allocations.
function nestedObject(a) {
  let inner = {v: a};
  let outer = {inner: inner, extra: a + 1};
  return outer.inner.v + outer.extra;
}

// Escaping: the allocation is stored somewhere visible.
function escapingObject(a) {
  let o = {x: a};
  sink = o;
  return o.x;
}

// Double array literal: JSArray + FixedDoubleArray virtual objects.
function doubleArray(a) {
  let arr = [a + 0.5, a + 1.5, a + 2.5];
  return arr[0] + arr[1] + arr[2];
}

// Cold call site: it is never executed before Maglev compiles the caller, so
// the graph builder has no feedback for the global load and emits an
// unconditional deopt here.
function coldCallee() {}

// Elided: the context allocation is created because `captured` is captured by
// the closure, but the live path (`return 0`) never reads or writes it. The
// tail after `coldCallee()` is unreachable in the built graph (cold call site
// -> Deopt), so the escape analysis sees no escaping use of the context and
// elides the allocation, which the trace reports as
// "* Removing allocation node". Note `var captured;` must not be initialised:
// a store to the context on the live path would be an escaping use.
function elidedContext(flag) {
  var captured;
  if (!flag) return 0;
  coldCallee();
  let set = function() { captured = 1; };
  set();
  return captured;
}

(function main() {
  %PrepareFunctionForOptimization(localObject);
  check(localObject(3, 4) === 12, 'local, interpreter 1');
  check(localObject(3, 4) === 12, 'local, interpreter 2');
  %OptimizeMaglevOnNextCall(localObject);
  check(localObject(3, 4) === 12, 'local, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(localObject), 'localObject in Maglev');
  }

  %PrepareFunctionForOptimization(nestedObject);
  check(nestedObject(1) === 3, 'nested, interpreter 1');
  check(nestedObject(1) === 3, 'nested, interpreter 2');
  %OptimizeMaglevOnNextCall(nestedObject);
  check(nestedObject(1) === 3, 'nested, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(nestedObject), 'nestedObject in Maglev');
  }

  %PrepareFunctionForOptimization(escapingObject);
  check(escapingObject(7) === 7, 'escaping, interpreter 1');
  check(escapingObject(7) === 7, 'escaping, interpreter 2');
  %OptimizeMaglevOnNextCall(escapingObject);
  check(escapingObject(7) === 7, 'escaping, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(escapingObject), 'escapingObject in Maglev');
  }
  check(sink.x === 7, 'sink');

  %PrepareFunctionForOptimization(doubleArray);
  check(doubleArray(1) === 7.5, 'double array, interpreter 1');
  check(doubleArray(1) === 7.5, 'double array, interpreter 2');
  %OptimizeMaglevOnNextCall(doubleArray);
  check(doubleArray(1) === 7.5, 'double array, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(doubleArray), 'doubleArray in Maglev');
  }

  // Warm up only the early-return path so that coldCallee() is still cold
  // when Maglev compiles elidedContext.
  %PrepareFunctionForOptimization(elidedContext);
  check(elidedContext(false) === 0, 'elided context, interpreter 1');
  check(elidedContext(false) === 0, 'elided context, interpreter 2');
  %OptimizeMaglevOnNextCall(elidedContext);
  check(elidedContext(false) === 0, 'elided context, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(elidedContext), 'elidedContext in Maglev');
  }
  // The tail deopts (cold call site), so the interpreter finishes the call.
  // Both tiers must agree.
  check(elidedContext(true) === 1, 'elided context, deopt path');

  print('inlined-allocation: ok');
})();
