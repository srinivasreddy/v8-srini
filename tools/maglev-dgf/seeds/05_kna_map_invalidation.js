// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --allow-natives-syntax --maglev --no-turbofan
// Flags: --optimize-on-next-call-optimizes-to-maglev

// Target: KnownNodeAspects (src/maglev/maglev-known-node-aspects.*) and the
// map-tracking / invalidation logic in the graph builder and graph optimizer.
//
// The interesting part for a fuzzer is the invalidation trigger: a load whose
// maps are cached in KnownNodeAspects is only safe as long as nothing can
// change the map. A call that stores a value of a different representation
// into the same field must invalidate the cached map, otherwise the second
// load is miscompiled. This seed pins a map, then perturbs it in several ways
// (representation change, transition, dictionary-mode conversion, deletion).

function check(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
}

// Word in the feedback vector for the load is Smi; the store changes the
// field to a double.
function overwriteWithDouble(o) {
  let a = o.x;
  changeToDouble(o);
  let b = o.x;
  return a + b;
}

function changeToDouble(o) {
  o.x = 1.5;
}

// Field transition: adding a property forces a new map.
function transitionReceiver(o) {
  let a = o.x;
  addProperty(o);
  let b = o.x;
  return a + b;
}

function addProperty(o) {
  o.y = 2;
}

// Dictionary-mode conversion invalidates all field-slot assumptions.
function dictionaryMode(o) {
  let a = o.x;
  delete o.y;
  for (let i = 0; i < 40; i++) o['k' + i] = i;
  let b = o.x;
  return a + b;
}

// Element-kind change (PACKED_SMI -> HOLEY_DOUBLE).
function elementKind(o) {
  let a = o[0];
  o[1] = 1.5;
  o[2] = 2.5;
  let b = o[0];
  return a + b;
}

(function main() {
  %PrepareFunctionForOptimization(changeToDouble);
  %PrepareFunctionForOptimization(overwriteWithDouble);
  let o1 = {x: 1};
  check(overwriteWithDouble(o1) === 2.5, 'double, interpreter 1');
  o1 = {x: 2};
  check(overwriteWithDouble(o1) === 3.5, 'double, interpreter 2');
  %OptimizeMaglevOnNextCall(overwriteWithDouble);
  check(overwriteWithDouble({x: 3}) === 4.5, 'double, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(overwriteWithDouble), 'overwrite in Maglev');
  }

  %PrepareFunctionForOptimization(addProperty);
  %PrepareFunctionForOptimization(transitionReceiver);
  check(transitionReceiver({x: 1}) === 2, 'transition, interpreter 1');
  check(transitionReceiver({x: 2}) === 4, 'transition, interpreter 2');
  %OptimizeMaglevOnNextCall(transitionReceiver);
  check(transitionReceiver({x: 3}) === 6, 'transition, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(transitionReceiver), 'transition in Maglev');
  }

  %PrepareFunctionForOptimization(dictionaryMode);
  check(dictionaryMode({x: 1, y: 2}) === 2, 'dict, interpreter 1');
  check(dictionaryMode({x: 3, y: 4}) === 6, 'dict, interpreter 2');
  %OptimizeMaglevOnNextCall(dictionaryMode);
  check(dictionaryMode({x: 5, y: 6}) === 10, 'dict, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(dictionaryMode), 'dictionaryMode in Maglev');
  }

  %PrepareFunctionForOptimization(elementKind);
  check(elementKind([1, 2, 3]) === 2, 'elements, interpreter 1');
  check(elementKind([4, 5, 6]) === 8, 'elements, interpreter 2');
  %OptimizeMaglevOnNextCall(elementKind);
  check(elementKind([7, 8, 9]) === 14, 'elements, maglev');
  if (%IsMaglevEnabled()) {
    check(%ActiveTierIsMaglev(elementKind), 'elementKind in Maglev');
  }

  print('kna: ok');
})();
