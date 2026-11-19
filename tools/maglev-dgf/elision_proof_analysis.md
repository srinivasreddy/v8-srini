# Elisions and the proofs they trust (Maglev)

Scope: which Maglev optimizations *remove* or *downgrade* a check, which fact
each one relies on, where that fact lives, and which of those facts can be
stale or wrong by the time the elision is made. Line numbers refer to this
tree (`src/maglev/*`, `src/flags/flag-definitions.h`).

The motivating question is the one a differential fuzzer asks: *which
optimization can be talked into believing something that is no longer true?*
An elision is only as good as its proof, and the three subsystems below draw
their proofs from four different stores with four different invalidation
rules.

## 1. Where the code is

| Subsystem | Files / entry points |
| --- | --- |
| **Representation selector** (phi untagging) | `maglev-phi-representation-selector.{h,cc}`. `IsUntagging()` (h:26), `ProcessPhi` (cc:134), `ConvertTaggedPhiTo` (cc:984), `GetRetaggingKindForPhi` (cc:1552), `EnsurePhiTagged` (cc:1563), `UpdateNodePhiInput(...)` overloads (cc:1243-1531). Runs as phase `kPhiUntagging` (`maglev-compiler.cc:196`), after truncation, before dead-code marking. |
| **Inliner** | `maglev-inlining.{h,cc}`: `InlineCallSites` (cc:71), `RunOptimizer` (cc:140), `Run` (cc:160), `ChooseNextCallSite` (cc:191), `IsMatchingTarget` (cc:199), `BuildInlineFunction` (cc:223), `TruncateGraphAt` (cc:418), `ReturnedValueRepresentationSelector` (cc:467). Driven from `maglev-compiler.cc:172-180`, and only when `--maglev-non-eager-inlining` is set (`v8_flags.maglev_non_eager_inlining`, default **false** in `flag-definitions.h:763`). The eager counterpart lives in the graph builder: `BuildEagerInlineCall` (`maglev-graph-builder.cc:7707`) and `MaglevGraphBuilder::BuildInlineFunction` (:7407). |
| **`BuildCheckSmi`** | No longer in the graph builder: it is `MaglevReducer<BaseT>::BuildCheckSmi`, `maglev-reducer-inl.h:3154`, declared at `maglev-reducer.h:928` and forwarded from `maglev-graph-builder.cc:3626`. `BuildSmiUntag` (`maglev-reducer-inl.h:3207`) is its partner. |

Because the builder lives in the *reducer*, the same `BuildCheckSmi` is used
by the graph builder, by the inliner's post-inline optimizer, and by
Turbolev's `GraphOptimizer` — i.e. also in passes where the known-node-aspects
(KNA) set has been *reconstructed* rather than maintained.

## 2. The proof stores

| Proof | Stored in | Invalidated by |
| --- | --- | --- |
| **KNA node type** | `KnownNodeAspects::NodeInfo::type_`, read through `GetTypeUnchecked` (`maglev-known-node-aspects.h:973-990`) | Nothing on a side effect: `KnownNodeAspects::OnSideEffect` (`:431-442`) only forwards to `NodeInfo::OnSideEffect` (`:281-283`), which does `if (any_map_is_unstable_) maps_are_stale_ = true;`. The comment at `:587-589` still says types "require invalidation", but the only consumer of the flag is the map-staleness path. |
| **Static type** | the node itself: `ValueNode::StaticTypeIs` / `GetStaticType`, e.g. `ReturnedValue::type()` forwards to `input_node(0)->GetStaticType()` (`maglev-ir.h:10851-10853`), `Phi::type()` is a field (`maglev-ir.h:10212-10224`) | never — but it is *derived* (from feedback, field representation, or a phi merge) |
| **Maps, constants, alternatives** | `possible_maps_`, `NodeInfo::alternative_`, `SetKnownValue` | maps: `OnSideEffect` / `MarkSingleMapAsStale` / `ClearUnstableNodeAspects*`; alternatives: dropped on merge; constants: only justified by a dominating check |
| **Phi type** | `Phi::type_` (`maglev-ir.h:10212-10224`) | mutated by `promote_post_loop_type` (`:10220`, called from `maglev-interpreter-frame-state.cc:891` and `:922`) and rewritten by `RecomputeKnownNodeAspectsProcessor::RecomputePhiTypes` (`maglev-kna-processor.h:144-169`). No epoch discipline. |

Two structural facts follow, and they frame everything below.

* There *is* an effect epoch, but it guards CSE, not types:
  `effect_epoch_` (`maglev-known-node-aspects.h:1029`), `increment_effect_epoch`
  (`:676`), `kEffectEpochForPureInstructions` (`:958`), consumed by the
  `available_expressions_` map (`maglev-known-node-aspects.cc:327-340`,
  `:734-736`) and by `IsCompatibleWithLoopHeader`
  (`maglev-interpreter-frame-state.h:641-647`). `NodeInfo::type_` is not
  epoch-stamped.
* KNA facts are keyed by **canonical node**: `FindInfo` calls `GetCanonical`
  (`maglev-known-node-aspects.h:1082-1101`), which unwraps identities and
  `ReturnedValue`s (`UnwrapIdentitiesAndReturnedValues`, `:1083`) and walks
  non-tagged conversion chains, stopping at the first tagged node (`:1084-1090`).
  So one conversion/return chain shares a single `NodeInfo`, and any pass that
  re-points such a chain silently reinterprets the recorded type.

`GetCanonical`'s comment (`:1066-1081`) is the clearest statement of the
underlying hazard:

> `n3: CheckedSmiTagInt32(n2)` … Here, `n3` has `NodeType::kSmi`, but
> propagating to `n1` would be wrong, since `n1` could be a smi-ranged
> HeapNumber.

And `GetOrCreateInfoFor` (`:496-505`) seeds a fresh `NodeInfo` by
intersecting with `node->GetStaticType(broker)`, while `GetTypeUnchecked`
(`:983-990`) intersects `info->type()` with the static type and, for
`ReturnedValue`, with the *input's* type. Intersection can only narrow, so a
too-narrow entry is never repaired by reading it. `EnsureTypeHelper`
(`:930-948`) is the whole story of "we know this is a Smi":
`new_type = IntersectType(current_type, type)`; `kAlreadyHadType` when
`NodeTypeIs(current_type, type)`, and a contradiction is repaired by
`set_type(NodeType::kNone)` — i.e. by deopting, never by widening.

## 3. The replay: a callee inherits a snapshot, not the caller's state

Non-eager inlining is the only path where the callee's entry facts are
*reconstructed*. In order:

1. **Capture.** At graph-building time, each non-eager call site clones the
   current KNA and parks it on the call-site record
   (`maglev-graph-builder.cc:7667-7697`):

   ```cpp
   // Creating the CallKnownJSFUnction node will conservatively clear the
   // unstable maps from the KNA. So, we save them before doing this, since this
   // could clear maps that don't need to be cleared.
   KnownNodeAspects::Ptr call_aspects = known_node_aspects().Clone();
   ```

   The clone is taken *before* `BuildCallKnownJSFunction`, so it is
   deliberately **less** conservative than the graph state at the call.
2. **Transport.** `MaglevCallerDetails` carries it to the inliner; the inner
   builder adopts it by move (`maglev-graph-builder.cc:702-705`:
   `is_inline() ? std::move(caller_details->known_node_aspects) : ...`).
3. **Replay.** `MaglevInliner::BuildInlineFunction` hands the same record to
   the inner builder (`maglev-inlining.cc:300-301`) and re-arms side-effect
   invalidation before the body is built (`:291-296`):

   ```cpp
   // This can be invalidated by a previous inlining and it was not propagated to
   // this node.
   // TODO(victorgomes): Check if we should maintain this. We could also clear
   // unstable maps here.
   call_site->caller_details.known_node_aspects
       ->MarkSideEffectsRequireInvalidation();
   ```

   Note what this does and does not do: it sets
   `side_effects_require_invalidation_` (`maglev-known-node-aspects.h:589-591`),
   which only makes `OnSideEffect` *stale the maps*
   (`:431-442` → `NodeInfo::OnSideEffect`, `:281-283`, which is
   `if (any_map_is_unstable_) maps_are_stale_ = true;`). Types, alternatives
   and static types are untouched by the whole mechanism.
4. **Arguments are shared by identity.** `BuildInlineFunction` sets the formal
   parameters to the *caller's* nodes
   (`maglev-graph-builder.cc:7461-7478`, `SetArgument(i + 1, arg_value)` with
   `arg_value = caller_details_->arguments[i + 1]`), after
   `node = node->Unwrap()` (`maglev-inlining.cc:305-307`). So a fact recorded
   about the caller's `x` *is* a fact about the callee's `x`.
5. **The batch, not the call, is the unit.** `Run()` alternates
   `InlineCallSites()` (which inlines every queued call site, best score first)
   with `RunOptimizer()` (`maglev-inlining.cc:167-176`), and `RunOptimizer`
   re-derives the KNA from the spliced graph
   (`RecomputeKnownNodeAspectsProcessor`, `:140-158`). Two call sites in the
   same function are therefore inlined *before* any recompute happens.
6. **Eager inlining differs in one important way**: the fact set flows *back*
   into the caller (`maglev-graph-builder.cc:7762-7764`,
   `current_interpreter_frame_.set_known_node_aspects(
   inner_graph_builder.current_interpreter_frame_.TakeKnownNodeAspects())`).
   On the non-eager path the snapshot is a moved-and-discarded value:
   `ClearCallSiteKnaScope` resets it (`maglev-inlining.cc:59-64`).

The consequence is a precise statement of the exposure: *the entry state of an
inlined callee is the KNA of the caller as it was when the call node was
built, replayed at a program point where the graph may since have changed.*

## 4. Where a stale proof can be adopted

Six asymmetries, each with the reason it survives review.

**(a) The snapshot is frozen.** Between capture (step 1) and replay (step 3)
the graph gains the bodies of every previously inlined call site, but the
snapshot does not. `MarkSideEffectsRequireInvalidation` patches exactly one
of the three invalidation classes (maps) and says so.

**(b) Types are the class without an invalidation rule.** The one comment that
claims otherwise is stale: `maglev-known-node-aspects.h:587-588` ("if unstable
maps **or node types** … have been recorded") describes an intent that
`OnSideEffect` does not implement. The loop-header clone is explicit about
relying on it (`:409-414`):

> Loop headers can safely clone the node types, since those won't be
> invalidated in the loop body, and similarly stable maps will have
> dependencies installed.

**(c) Canonical keys are combined by intersection.** `FindInfo` canonicalises
through `GetCanonical` (`:1082-1101`), and when a second key canonicalises
onto an existing one, `CombineSameValueFrom` (`:272-279`) does
`IntersectType(other.type_)` + `alternative_.FillMissingFrom(...)`. A narrow
fact attached to one spelling of a value can therefore be re-attached to
another spelling of it — the mechanism is *narrowing on collision*, so the
narrower (possibly stale) side wins.

**(d) `Phi::type_` is rewritten outside the KNA.** `MergeLoopValue` reads the
*KNA* type of the backedge value and feeds it into the phi
(`maglev-interpreter-frame-state.cc:880-891`), then
`promote_post_loop_type()` (`maglev-ir.h:10220-10225`) overwrites `type_`
with that union; `ReducePhiPredecessorCount` does the same when a backedge
dies (`maglev-interpreter-frame-state.cc:920-923`). No epoch, no map evidence,
and no re-validation. This is the transport that carries a KNA type out of a
loop and into `StaticTypeIs`.

**(e) `ReturnedValue` reinterprets recorded types for free.** A call node is
rewritten in place at the end of inlining
(`call_node->OverwriteWithReturnValue(returned_value)`,
`maglev-inlining.cc:414`); `ReturnedValue::type()` forwards to
`input_node(0)->GetStaticType()` (`maglev-ir.h:10851-10853`) and `GetCanonical`
unwraps `ReturnedValue`/`Identity` (`maglev-known-node-aspects.h:1083`). So one
`NodeInfo` spans the call node, the returned value, and the callee's `return`
operand; whichever of them recorded a type first speaks for all of them.

**(f) Unsafe conversions are re-established without proof.** The KNA reprocessor
records alternatives for `UnsafeSmiUntag`/`UnsafeSmiTagInt32` but cannot check
the type that justified them, in the compiler's own words
(`maglev-kna-processor.h:384-398`):

> TODO(victorgomes): Ideally we would like to check we already know the type,
> but currently we cannot. The issue is that if the GraphBuilder emits a node A
> and then Ensure(A, kSmi), we are not able to recover that A is an Smi.

The replayer is honest about this (it records the alternative and skips the
`CHECK`), which means the *graph builder's* proof for the unsafe node is gone
by the time the inliner's `RunOptimizer` looks at it.

## 5. The elision under test: `BuildCheckSmi`

`MaglevReducer<BaseT>::BuildCheckSmi` (`maglev-reducer-inl.h:3154-3204`) has
exactly three exits, in this order:

```cpp
if (object->StaticTypeIs(broker(), NodeType::kSmi)) return object;      // 3155
RETURN_IF_DONE(EnsureType(object, NodeType::kSmi, DeoptimizeReason::kSmi)); // 3156
// ...untagged constants in Smi range...                                  // 3158-3176
AddNewNodeNoInputConversion<CheckSmi>({object});                          // 3194
```

* **3155 — the static-type exit.** Proof: `ValueNode::GetStaticType(broker)`.
  This is where a Smi-representation `LoadTaggedField`, an `Int32Constant`, a
  `CheckedSmiTagInt32`, or a **`Phi` with `type_ == kSmi`** is trusted. The
  proof is a *derivation*, not an observation, and it is the exit that
  §4(d) and §4(e) feed.
* **3156 — the KNA exit.** Proof: `NodeInfo::type_` for the canonical node.
  `EnsureType` returns `kAlreadyHadType` when `NodeTypeIs(current_type, kSmi)`
  and the reducer returns the node unchanged (`maglev-reducer.h:1700-1712`),
  i.e. the check node is never emitted. This is the exit §4(a)–(c) feed.
* **3194 — the check.** `CheckSmi` is emitted, and being a `Check*` node it
  *records* the same fact for later uses — which is why a function with one
  real check and N uses compiles N-1 elisions.

Both proofs are "proofs by absence": nothing re-tests them later. What makes
them interesting for a fuzzer is the downstream consequence —
`BuildSmiUntag` (`:3207-3220`) turns a *known* kSmi into `UnsafeSmiUntag`:

```cpp
} else if (ensure_res == EnsureTypeResult::kAlreadyHadType) {
  return AddNewNodeNoInputConversion<UnsafeSmiUntag>({node});   // 3215-3216
} else {
  return AddNewNodeNoInputConversion<CheckedSmiUntag>({node});  // 3218
}
```

`UnsafeSmiUntag` is a raw untag with no runtime check, and `EnsureInt32` takes
the same branch for tagged inputs (`:1575-1583`: `CheckType(value, kSmi)` →
`BuildSmiUntag`). So a wrong kSmi fact does not produce a deopt, it produces an
integer computed from a HeapNumber pointer — the differential oracle's
favourite shape.

**Which oracle can see which exit.** `--maglev-assert-types`
(`flag-definitions.h:781`) instruments `MaglevReducer::GetType`
(`maglev-reducer.h:1752-1768`), which emits a `CheckMaglevType` node whose
builtin prints `CheckMaglevType failed` and hits `Unreachable()`
(`builtins-internal-gen.cc:1766-1812`). Neither `BuildCheckSmi` exit calls
`GetType` — 3155 uses `StaticTypeIs`, 3156 goes
`EnsureType` → `EnsureTypeHelper` → `GetTypeUnchecked` — so **the assertion
builtin does not observe the elision itself**. It observes the *consumers* that
do call `GetType`: `GetFloat64`/`GetHoleyFloat64` (`:1919`, `:2019`),
`GetSmiValue` (`:5868`), `BuildSameValue` (`:3118-3119`), and
`maglev-graph-builder.cc:4666`. That is why the seed in §6 keeps the property
accesses (which do call `GetType`) *after* the elided check: they are what the
assertion build can observe (§6.3, §7).

`BuildCheckMaps` has the same silhouette one level up: the proof is
`NodeInfo::possible_maps_` plus `maps_are_stale_`, the elision is
`MapInference::InsertMapChecks` (or `DependOnStableMap` supplying a
dependency instead of a check). The difference is that maps *do* have an
invalidation rule, which is exactly why §4(b) is the load-bearing asymmetry.

One cache is exempt from that invalidation rule and is worth naming separately,
because it is the only *load* cache that survives a call by design
(`maglev-known-node-aspects.h:1006-1009`):

```cpp
// Valid across side-effecting calls, as long as we install a dependency.
LoadedPropertyMap loaded_constant_properties_;
// Flushed after side-effecting calls.
LoadedPropertyMap loaded_properties_;
```

`ClearUnstableNodeAspects` flushes the second and keeps the first
(`maglev-known-node-aspects.cc:637-641`), and `ClearLoadedPropertiesForKey`
(`maglev-known-node-aspects.h:640-649`) only ever erases from the mutable map.
So a `kConst`-constness load is a node that a *later* inline can reuse across
an inlined store, with the compiler's correctness resting entirely on a
`DependentCode` dependency installed in the caller's compilation.

## 6. Reaching the elision: the trigger recipe

### 6.1 Mechanical prerequisites

| Requirement | Why | Source |
| --- | --- | --- |
| `--maglev-non-eager-inlining` | the replay in §3 does not exist otherwise; default **false** | `flag-definitions.h:763`, wired at `maglev-compilation-info.h:98`/`:110` |
| callee *not* eagerly inlinable | `TryBuildInlineCall` prefers `ShouldEagerInlineCall` **even when non-eager inlining is on** | `maglev-graph-builder.cc:7622-7626`, `:7559-7564` (eager iff `bytecode.length() < max_eager_inlined_bytecode`) |
| `%DisableEagerInlining(callee)` | the deterministic lever: `Runtime_DisableEagerInlining` marks the SFI, `is_eager_inlining_disabled` reads it | `runtime-test.cc:876-887`, `pending-optimization-table.cc:62`, `heap-refs.cc:1964-1970`, checked at `maglev-graph-builder.cc:7527` |
| callee has a feedback vector | otherwise `TRACE_CANNOT_INLINE("it has not been compiled/run with feedback yet")` | `maglev-graph-builder.cc:7591-7597` |
| callee size ≤ 27 bytecode | `max_maglev_inlined_bytecode_size_small` (unlimited small budget); 100 for the regular budget | `flag-definitions.h:723`, `:716` |
| target is a constant closure | `IsMatchingTarget` accepts `FastCreateClosure`, `CreateClosure`, `HeapConstant` SFI match, and otherwise returns `true` | `maglev-inlining.cc:199-219` |
| `--no-turbofan`, `--optimize-on-next-call-optimizes-to-maglev` | keep the tier deterministic, as the other seeds do | `tools/maglev-dgf/README.md:43-52` |

Precedent for the marking idiom is in-tree:
`test/mjsunit/disable-eager-inlining.js:42` and
`test/mjsunit/regress/regress-577474117.js:17`, the latter being a
three-deep chain of non-eager inlines with the comment style
`// 1) Eagerly inline … 2) Non-eagerly inline …`.

### 6.2 The shape

Two callees and one driver, with the value that carries the type flowing
through both call sites:

```js
function store(o, v) { o.x = v; o.w = 1; return o; }      // mutation
function load(o)      { return (o.x + 1) | 0; }           // BuildCheckSmi + UnsafeSmiUntag
%DisableEagerInlining(store);
%DisableEagerInlining(load);

function driver(o, v) {
  let n = o.x;          // (1) tagged load of a Smi-representation field
  let m = n + 1;        // (2) CheckSmi(n) emitted; KNA records n : kSmi
  store(o, v);          // (3) call site A -> snapshot captured here
  let p = load(o);      // (4) call site B -> replays (3)'s snapshot
  return (p + m) | 0;   // (5) GetType consumer
}
```

Points (1)–(2) install the proof, (3) is where the frozen snapshot is taken,
(4) is where it is replayed *after* the graph has grown a mutating body, and
(5) is the `GetType` consumer that `--maglev-assert-types` can observe. Call
`driver` with a HeapNumber `v` after `%OptimizeMaglevOnNextCall(driver)` so
that the elided check is exercised against the value that contradicts it.

Three variants, in increasing order of how much of §4 they exercise:

1. **Straight line** (above). Exercises §4(a) and (e): the snapshot, and the
   call node that becomes `ReturnedValue(o)`.
2. **Loop-carried** — make the value a loop phi so that
   `promote_post_loop_type` transports a KNA type out of the loop (§4(d)):

   ```js
   function driver2(o, v, n) {
     let s = 0;
     for (let i = 0; i < n; i++) {
       s = (s + o.x) | 0;   // o.x load feeds a phi; type merges each iteration
       store(o, i);         // call site inside the loop body
       s = (s + load(o)) | 0;
     }
     return s;
   }
   ```
3. **Const-field** — declare the field `const` so the load lands in
   `loaded_constant_properties_` and survives the call by dependency
   (§5, last paragraph), then have the inlined callee write the *same* key.
   This is the variant that tests the "valid across side-effecting calls"
   claim directly.

### 6.3 Three observables, cheapest first

| Observable | Command | What it proves |
| --- | --- | --- |
| **both callees inlined** | `--trace-maglev-inlining`, patterns `INLINE` / `Inlined call` (same as the `inlining` target) | the replay happened at all; `Run()`'s batch loop is the only path that produces it for marked callees |
| **the check is gone** | `--print-maglev-graph` (this is `PrintAndVerify(..., MaglevPhase::kInlining)`, `maglev-compiler.cc:178-179`) and search the block spliced from `load` for `CheckSmi` | the elision under test fired on the replayed facts |
| **it is wrong** | `--maglev-assert-types`, expect `CheckMaglevType failed`; or `dgf.py check`'s differential/foozzie | the elided proof was stale |

Two caveats on the third row. `CheckMaglevType` is emitted by
`MaglevReducer::GetType` only (`maglev-reducer.h:1752-1768`), so the seed needs
a `GetType` consumer *after* the elided check. In this seed those consumers are
the **property accesses**, not the arithmetic: `GetNamedProperty` /
`SetNamedProperty` ask for the receiver's type
(`maglev-reducer-inl.h:2440`, `maglev-graph-builder.cc:4666`) and the store asks
for the stored value's type, which is why the assertion build of §7 shows
`CheckMaglevType(OtherJSReceiver)` before every field access and
`CheckMaglevType(Smi)` right after the store's `CheckSmi`. Arithmetic on an
already-`int32` value goes through `ChangeInt32ToFloat64`, which does not
consult the KNA at all. And `--maglev-assert-types` adds nodes, which can
perturb the very elision it is supposed to observe; run the assertion build and
the graph-print build separately and compare.

A note on catalog wiring: `dgf.py` passes `trace_flags` verbatim to d8 and
strips them for the `maglev_clean` run (`README.md:41-47`). A flag that changes
*which graph is built* therefore belongs in `config_flags`, which are passed to
the traced run, to the untraced differential run and to `verify` alike:
`--maglev-non-eager-inlining` is one of them. It was originally listed in
`trace_flags`, so `maglev_clean` silently ran the *eager* path and the
differential was really an eager-vs-non-eager comparison — §10.2 shows how that
hid a canary that had fired by hand. The seed's `// Flags:` line must carry the
flag as well so that mjsunit and foozzie run the configuration the target
checks.

### 6.4 Catalog entry

No existing entry fits: `inlining` (`targets.json`) proves that *an* inline
happened but uses the default configuration (eager first, non-eager off) and
has no elision assertion. A new entry:

```json
{
  "id": "kna-replay-elision",
  "subsystem": "known-node-aspects",
  "phase": "Inlining",
  "sources": [
    "src/maglev/maglev-inlining.cc:MaglevInliner::BuildInlineFunction",
    "src/maglev/maglev-inlining.cc:MaglevInliner::RunOptimizer",
    "src/maglev/maglev-reducer-inl.h:MaglevReducer::BuildCheckSmi",
    "src/maglev/maglev-reducer-inl.h:MaglevReducer::BuildSmiUntag"
  ],
  "config_flags": ["--maglev-non-eager-inlining"],
  "trace_flags": ["--trace-maglev-inlining", "--print-maglev-graph"],
  "required_patterns": ["INLINE", "UnsafeSmiUntag"],
  "seed": "seeds/10_kna_replay_elision.js",
  "trigger": [
    "two %DisableEagerInlining-marked callees called from one driver; the",
    "first mutates the field whose Smi-representation load the second",
    "re-reads, so the second callee's entry KNA is a snapshot taken before",
    "the mutation body was spliced in"
  ],
  "bug_classes": [
    "stale NodeInfo::type_ eliding CheckSmi and producing an UnsafeSmiUntag",
    "stale static type after promote_post_loop_type",
    "loaded_constant_properties_ reuse across an inlined store"
  ],
  "oracle": ["differential", "crash", "verifier"]
}
```

## 7. What the seed produces

The seed is `seeds/10_kna_replay_elision.js`. Two drivers, three callees, all
three marked `%DisableEagerInlining` so that every call site goes through the
non-eager queue:

```
$ d8 --allow-natives-syntax --optimize-on-next-call-optimizes-to-maglev \
     --maglev --no-turbofan --maglev-non-eager-inlining \
     --trace-maglev-inlining tools/maglev-dgf/seeds/10_kna_replay_elision.js
[ML:2069] ➕ PUSH   store    Score: 0.07, Node: n15
[ML:2069] ➕ PUSH   bump     Score: 0.11, Node: n19
[ML:2069] ➕ PUSH   load     Score: 0.09, Node: n24
[ML:2069] ✅ INLINE bump     Generated 2 nodes. small_budget += 9 ~~> 9
[ML:2069] ✅ INLINE load     Generated 4 nodes. small_budget += 11 ~~> 20
[ML:2069] ✅ INLINE store    Generated 7 nodes. small_budget += 15 ~~> 35
```

(The second compilation, for `driverLoop`, produces the same six lines, with the
loop's call sites in a different score order.) Both the index-tier run and the
Maglev run print `kna replay elision: ok`, and
`%ActiveTierIsMaglev(driver)` holds after the optimising call.

With `--print-maglev-graph`, the straight-line `driver` comes out as
(excerpt, node ids as printed):

```
 Block b1
  15/9:  CheckMaps(Map[16](HOLEY_ELEMENTS), Map[16](HOLEY_ELEMENTS), check heapobj) [v11/n2]
  16/10: LoadTaggedField(0xc: #x, compressed, Smi) [v11/n2] → [rax|R|t]
  17/11: UnsafeSmiUntag [v16/n10] → [rax|R|w32]
  18/12: Int32IncrementWithOverflow [v17/n11] → [rax|R|w32]
 Block b4                              <- inlined `store`
  20/47: CheckMaps(Map[16](HOLEY_ELEMENTS), no heapobj check) [v11/n2]
  21/48: CheckSmi [v12/n3]
  22/49: StoreTaggedFieldNoWriteBarrier(0xc: #x, mutable) [v11/n2, v12/n3]
  26/54: StoreMap(Map[16](HOLEY_ELEMENTS), Transitioning) [v11/n2]
 Block b3
  27/18: LoadTaggedField(0xc: #x, compressed, Smi) [v11/n2] → [rsi|R|t]
  28/38: Jump b2                        <- inlined `bump`
  29/39: UnsafeSmiUntag [v27/n18] → [rsi|R|w32]
  30/40: Int32IncrementWithOverflow [v29/n39] → [rsi|R|w32]
  37/25: CheckedSmiUntag [v31/n19] → [r8|R|w32]
  38/26: CheckedSmiUntag [v36/n24] → [r11|R|w32]
```

Four things to read out of it:

* `17/11` and `29/39` are `UnsafeSmiUntag`, which `BuildSmiUntag` only
  produces on the `kAlreadyHadType` path (`maglev-reducer-inl.h:3215-3216`).
  The `CheckSmi` for the caller's `n + 1` and for `bump`'s `x + 1` was
  elided — the seed reaches the elision.
* `21/48` is the one `CheckSmi` that *is* emitted, on `store`'s parameter `v`,
  whose type is unknown. Both behaviours appear in the same graph.
* `27/18` has **no `CheckMaps` of its own**: it inherits `15/9`, which was
  emitted before the inlined `store` ran `26/54: StoreMap(…, Transitioning)`.
  The load's Smi-representation proof is therefore a *derivation* taken across
  a map transition.
* `37/25` and `38/26` are `CheckedSmiUntag`, not `UnsafeSmiUntag`, because
  those operands are `Int32ToNumber` results whose KNA type the graph builder
  cannot recover — the §4(f) pessimisation, visible side by side with the
  elision.

With `--maglev-assert-types` the same seed emits 47 `CheckMaglevType` nodes,
including `CheckMaglevType(OtherJSReceiver)` before every field access and
`CheckMaglevType(Smi)` immediately after `CheckSmi` on the stored value, which
is the assertion oracle of §6.3 working on the values this seed produces.

What the seed does *not* claim is that the proof is already stale. The visible
consequence of the heap-number call is a deopt at `21/48` — the store's own
value check — before the elided untags are ever reached with the wrong value.
Making the mutation invisible to that check is the mutation-hunting step, and
the three channels to aim at are the three `bug_classes` in §6.4.

The catalog entry works as written:

```
$ python3 tools/maglev-dgf/dgf.py check kna-replay-elision -v
[HIT ] kna-replay-elision (10_kna_replay_elision.js)
        maglev=rc=0 (0.2s) maglev_clean=rc=0 baseline=rc=0
        hits: INLINEx9, UnsafeSmiUntagx2 (need 0)

1/1 targets reached without divergence
```

`INLINE` is the replay, `UnsafeSmiUntag` is the elision, and the three exit
codes say the index tier, the eager path and the replayed path all agree on the
seed's values.

## 8. Seed-generation prompt

The prompt below reproduces this seed from the analysis alone. It is written to
be handed to a coding model as-is.

```text
Write one self-checking Maglev seed, tools/maglev-dgf/seeds/<nn>_<name>.js,
plus its entry in tools/maglev-dgf/targets.json. This is a *seed*, not a test:
it must (a) be plain mjsunit-runnable JavaScript, (b) assert only that Maglev
was used and that its values are correct, and (c) demonstrably reach one
specific compiler path. Correctness of the compiler is decided later by
tools/clusterfuzz/foozzie; do not encode any compiler bug in the seed.

Target: the Maglev non-eager inliner's KnownNodeAspects replay, and the
BuildCheckSmi / BuildSmiUntag elisions it drives.

Facts to build on (verified in-tree):
- Non-eager inlining captures the caller's KnownNodeAspects when the call node
  is built and replays that snapshot when the callee is spliced in
  (maglev-graph-builder.cc, "known_node_aspects().Clone()"; maglev-inlining.cc,
  MaglevInliner::BuildInlineFunction). The only invalidation re-armed for the
  replayed snapshot is *map* staleness (MarkSideEffectsRequireInvalidation ->
  OnSideEffect -> maps_are_stale_). Node *types* are never invalidated.
- BuildCheckSmi (maglev-reducer-inl.h:3154) has two eliding exits: the static
  type test on line 3155 and the KNA test on 3156 (EnsureType returning
  kAlreadyHadType). BuildSmiUntag (3207) turns a known kSmi into an unchecked
  UnsafeSmiUntag.
- %DisableEagerInlining(callee) is required: TryBuildInlineCall takes the eager
  path for any callee shorter than --max-maglev-eager-inlined-bytecode-size
  (30) even when --maglev-non-eager-inlining is on.

Required structure:
1. A mutator callee that stores into the same field the other callees read, e.g.
   function store(o, v) { o.x = v; o.w = 1; return o; }
2. One or two consumer callees whose arithmetic forces a Smi check, e.g.
   function load(o) { return (o.x + 1) | 0; } and function bump(x) { return
   (x + 1) | 0; } so that one consumer receives the field load *by identity*
   (arguments are shared with the caller) and one re-reads the field.
3. A driver that, in order: loads the field, does an integer operation on the
   load so that its kSmi type is recorded, calls the mutator, then calls the
   consumers, then uses the results in an int32 and a float context.
4. A second driver of the same shape with the call sites inside a for loop, so
   the loop phi type and promote_post_loop_type participate.
5. Mark all callees with %DisableEagerInlining and %PrepareFunctionForOptimization;
   warm up with Smi values only (so feedback is SignedSmall), call
   %OptimizeMaglevOnNextCall on the drivers, assert %ActiveTierIsMaglev on the
   first optimised call, then call once more with a HeapNumber value. Assert the
   tier *before* that last call: the mismatched value may legitimately deopt.

// Flags: line and catalog:
- seed: --allow-natives-syntax --maglev --no-turbofan
        --optimize-on-next-call-optimizes-to-maglev --maglev-non-eager-inlining
- catalog trace_flags: --maglev-non-eager-inlining --trace-maglev-inlining
        --print-maglev-graph
- catalog required_patterns: ["INLINE", "UnsafeSmiUntag"] (the replay and the
        elided untag)

Verify, and paste the evidence into the analysis doc:
1. d8 ... --maglev-non-eager-inlining --trace-maglev-inlining <seed>
   -> one "PUSH" + "✅ INLINE" pair per callee, none of them eager.
2. d8 ... --print-maglev-graph <seed>
   -> the consumers' bodies contain UnsafeSmiUntag with no preceding CheckSmi,
      and the mutator's own parameter still gets a CheckSmi.
3. d8 ... --maglev-assert-types --print-maglev-graph <seed>
   -> CheckMaglevType nodes appear on the property-access and store paths;
      record how many.
4. python3 tools/maglev-dgf/dgf.py check <id> -v
   -> [HIT ], all three exit codes 0, no divergence.

Style: match tools/maglev-dgf/seeds/03_inlining.js (header comment naming the
target files, check(cond, msg) helper, final print('<name>: ok')). Keep every
value computable by hand so the index-tier run agrees.
```

## 9. Limits

* The analysis above is a mechanism map, not a proof of a live miscompile. §7
  shows the elision firing; the staleness it exposes is a hypothesis ranked by
  the three channels in §4/§6.4, to be confirmed by the oracle.
* `BuildCheckMaps` is treated only by analogy (§5, last paragraph). The map
  path has a real invalidation rule, so a stale map fact needs a stale
  *dependency*, which is a different search.
* Turbolev runs a different pipeline (`maglev-compiler.cc:196` onward hands the
  graph to `GraphOptimizer`, which reconstructs the KNA). Every claim here is
  about the Maglev pipeline unless stated otherwise; the `--turbolev` variants
  of these programs are a separate target.
* Reachability is textual: `UnsafeSmiUntag` also appears in graphs whose proof
  is a dominating `CheckMaps`, so the pattern proves the *elision*, not its
  staleness.
* The canary of §10.2 validates the *verifier*, not the mechanism map: it
  shows the two detectors fire when a proof is taken on faith, and says
  nothing about whether the shipping compiler has such a bug.

## 10. Phases 3 and 4: directed mutation and deterministic verification

§6 built one input by hand. §10 is the automated version of the same
reasoning: `dgf.py direct` spends the mutation budget on the values §4 names,
and `dgf.py verify` decides whether a result means anything, using
`dgf.py canary` as the control that keeps the verifier honest.

The difference from a template-based Maglev type-confusion fuzzer is where the
shape comes from. A template fuzzer compiles a fixed shape and hopes that the
interesting instantiation appears. Here the shape is §6's, chosen because
§3–§5 make it the smallest ordering that puts a snapshot between a recorded
type and a use; what the search varies is only the three values that decide
whether the elision at the end of that shape is *observable*, and the graph
signature is what tells it whether a unit of budget changed the compilation at
all.

### 10.1 Directed mutation

A template (`templates/kna_replay_elision.tmpl.js`) is §6's shape with three
slots and nothing else:

| Slot | What it controls | Candidates |
| ---- | ---------------- | ---------- |
| `SMI_CONST` | the constant at the `BuildCheckSmi` site, i.e. the input the check derives from | `1`, `-1`, `0`, `1073741823`, `1073741824`, `2147483647` |
| `BACKEDGE` | the loop-carried value whose merged type `promote_post_loop_type` may rewrite | six shapes, from `n` to `(n + bump(o.x) + load(o)) * 1.5` |
| `ARG_VALUE` | the representation of the argument at the inlined call, which is what a replayed snapshot sees through the shared node | `2.5`, `-0`, `1073741824`, `-1073741824`, `2147483647`, `0.1` |

The catalog carries the candidates (`targets.json`:
`kna-replay-elision.directed`), so widening the campaign is a catalog edit,
not a code change. 6 × 6 × 6 = 216 points, enumerated exhaustively. Two
properties make every point a legal input:

* candidates `print()` instead of asserting, so no expectation has to move and
  the baseline run of the differential *is* the expectation;
* the shape is untouched, so reachability is still decided by the target's
  trace patterns rather than by the slot values.

Coverage feedback is the graph dump. `coverage_signature()` reduces a
`--print-maglev-graph` run to the sorted multiset of node opcodes plus the
count of non-eager inlining events; an unseen signature is a new optimization
path and is stored in `corpus/<target>.json` with the slots that produced it.
The seed's own graph is inserted first, so a candidate that reproduces the
seed is not a new path.

Measured (`out/x64.asan-fuzz`, 216 points, `--random-seed 1`):

```
candidates=216 hit=216 miss=0 new_paths=38 divergences=0 corpus=39
```

Every point still reached `INLINE` + `UnsafeSmiUntag`: changing these values
does not cost the target. The 216 points map onto 38 distinct signatures
beyond the seed's own graph, which is the useful part of the result. What a
point changes is the arithmetic around the elision, and the signature says so
before any output does. One
sample point (`SMI_CONST` = `1073741824`, `BACKEDGE` =
`(n + bump(o.x) + load(o)) * 1.5`, `ARG_VALUE` = `2.5`) diffs against the
seed as `+Int32Add -Int32AddWithOverflow -Int32IncrementWithOverflow`: without
the `| 0`, the loop body is built with a different arithmetic family, while
`UnsafeSmiUntag` stays in the node set on both sides.

### 10.2 Deterministic verification

`verify` runs the differential and the `--maglev-assert-types` build, repeats
both against the canary, and classifies:

| clean | canary | verdict |
| ----- | ------ | ------- |
| fires | fires | `candidate` |
| fires | — | `candidate` |
| does not fire | fires | `canary-only`, discarded |
| does not fire | does not fire | `clean` (or `unreached`) |

The canary is a build in which one proof is taken on faith
(`canary/elide-check-smi.patch`: `BuildCheckSmi` records `kSmi` and then
elides the check that would justify it). Measured on the seed of §7:

```
[CANARY-ONLY] seeds/10_kna_replay_elision.js
        differential=- assert-types=- canary=FIRES
        canary divergence: crash mismatch: maglev=CRASH(rc=-6) baseline=rc=0
```

and, on the canary, the Maglev frame aborts with `abort: Operand is not a
smi` on `<HeapNumber 2.5>` inside `driver` — the `UnsafeSmiUntag` of §5
reading a heap number. On the clean build both detectors stay silent, which is
§9's restated point: the elision is sound today because the store's own
`CheckSmi` deopts first.

Verifying the 39 new-path candidates of §10.1 through the same pipeline:

```
39 candidate(s): canary-only=20, clean=19
clean: differential 0, assert-types 0
canary: differential 20, assert-types 20
```

The canary's firing set is *input-dependent*: 20 of the 39 candidates reach
the point where the elided check matters, the other 19 hit a different check
(an argument conversion) first. A control that fired for every candidate would
be a constant, not a control.

Two harness bugs were found this way, and both had hidden the canary:

1. `--maglev-non-eager-inlining` sat in `trace_flags`, so the untraced
   differential ran the *eager* path (the note in §6.3). The canary fired by
   hand but not under `verify`. Flags that change which graph is built are now
   `config_flags` and reach every run.
2. The first version of the fault elided the check *before* `EnsureType` had
   recorded the type. That trips a DCHECK in a dcheck build —
   `CanElideWriteBarrier(object, value)` (`maglev-reducer-inl.h:630-656`)
   reads the type that `BuildCheckSmi` just recorded — so the graph never
   built. Recording the fact and skipping the check is both buildable and the
   faithful emulation of a stale proof.

### 10.3 What this does not do

* The canary is a detector control. It removes the check the shipping
  compiler emits; it does not reproduce the *ordering* that would make a real
  proof stale (§4), so a `candidate` from this pipeline still needs §7-style
  graph evidence that the proof it trusted was the wrong one.
* The signature is textual and coarse: the same opcode multiset can hide
  different control flow. It is a filter for "did this mutation change the
  compilation", not coverage instrumentation, and the corpus is never
  minimized.
* Mutation is still one-dimensional: three slots, one template, one target.
  `fuzz` covers shapes, `direct` covers values; neither explores a different
  *number* of call sites.
