# Maglev directed greybox fuzzing (prototype)

`tools/maglev-dgf` is a small, target-aware fuzzing driver for Maglev. It sits
on top of the existing differential oracle (`tools/clusterfuzz/foozzie`) and
adds the missing piece: a way to say *"this input compiled through the Maglev
subsystem I care about"*, instead of hoping that random mutation happens to
build the right nodes.

It consists of these parts:

| Path           | Role |
| -------------- | ---- |
| `targets.json` | Catalog: subsystem, C++ entry points, the d8 trace configuration that proves reachability, the seed that reaches it, and (optionally) the directed-mutation slots of that seed. |
| `seeds/*.js`   | Hand-written, self-checking inputs. They assert only that Maglev was used (guarded `%ActiveTierIsMaglev`) and that their expected values are right. |
| `dgf.py`       | Driver: `targets` (list), `check` (reachability + differential), `fuzz` (target-aware mutation), `direct` (value-directed mutation), `bench` (directed vs random-mutation baseline), `minimize` (shrink a divergent candidate), `verify` (deterministic verification), `canary` (injected-fault build). |
| `templates/*.tmpl.js` | Slot templates for `direct`: the same shape as a seed, with the facts that control a representation proof left as `{{SLOT}}` markers. |
| `canary/*.patch` | Injected faults for `verify`'s positive control: one proof taken on faith, applied to the source and built into a separate d8. |

## Why not intrinsics

The reachability oracle is the compiler's own trace output, supplied by the
catalog (`trace_flags` + `hit_patterns` / `required_patterns`), not by the
seed. Consequences:

* A seed stays a plain mjsunit-style test: it can be run by `mjsunit` and by
  foozzie without modification.
* The same seed can be checked against several phases (graph building, phi
  untagging, escape analysis, codegen) by adding catalog entries, which is what
  `generic-differential` does for the whole seed directory.
* Mutants never need to be instrumented, so the mutation stays value-preserving.

## Reachability

`hit_patterns` are regexes matched against the combined stdout/stderr of the
traced Maglev run; `min_hits` (default 1) is the number of matches required.
`required_patterns` must *each* match at least once, for targets where one
signature is not enough — for example `inlined-allocation` needs both an
`InlinedAllocation` node in the printed graph *and* the escape analysis to
report that it removed one.

## Differential mode

Every run compares three d8 invocations:

1. `maglev` – the catalog's `config_flags` and `trace_flags` plus the
   `ignition_maglev` config (`--maglev --turbo-filter=~ --no-turbofan`);
2. `maglev_clean` – the same config *without* the trace flags, so its output is
   comparable to the baseline;
3. `baseline` – `ignition` (`--no-maglev --no-turbofan`).

`config_flags` are part of the configuration and reach all three runs (the
baseline run ignores the Maglev ones); `trace_flags` only make the Maglev run
observable and are dropped for the comparison. A flag that changes which graph
is built, such as `--maglev-non-eager-inlining`, must be a `config_flag` —
otherwise the traced run and the differential run compile different programs
and the differential stops measuring the configuration the target claims.

Both configurations also get `--allow-natives-syntax
--optimize-on-next-call-optimizes-to-maglev` (the seeds call
`%OptimizeMaglevOnNextCall`), and the common flags are copied from
`tools/clusterfuzz/foozzie/v8_commands.py` so that a divergence found here
reproduces under `v8_foozzie.py`. Outputs are compared after normalizing heap
addresses, timings and ANSI colours. A mutant whose *baseline* run fails the
seed's own `FAIL:` self-check is reported as `seed_broken`, not as a
divergence: the expected value moved, not the compiler.

## Usage

```bash
# List the catalog.
python3 tools/maglev-dgf/dgf.py targets

# Assert that every seed reaches its target, with no divergence.
python3 tools/maglev-dgf/dgf.py check

# One target, verbose, showing the matching trace lines.
python3 tools/maglev-dgf/dgf.py check truncation -v

# Check without the differential runs (much faster, reachability only).
python3 tools/maglev-dgf/dgf.py check --no-differential

# Mutate the seed of a target and diff the mutants.
python3 tools/maglev-dgf/dgf.py fuzz --target osr-entry --iterations 50 \
    --random-seed 1 --log /tmp/dgf.jsonl

# Mutate only the values that control a representation proof (needs a
# "directed" section in the catalog entry).
python3 tools/maglev-dgf/dgf.py direct --target kna-replay-elision \
    --iterations 20 --random-seed 1 -v

# Measure that against random mutation on the same budget.
python3 tools/maglev-dgf/dgf.py bench --target phi-heapobjectness \
    --iterations 20 --random-seed 1

# Shrink a saved candidate while the differential still fires.
python3 tools/maglev-dgf/dgf.py minimize \
    mutants/kna-replay-elision/kna-replay-elision-d002-0003.js \
    --target kna-replay-elision

# Deterministic verification, optionally against an injected-fault build.
python3 tools/maglev-dgf/dgf.py canary --fault elide-check-smi
python3 tools/maglev-dgf/dgf.py verify kna-replay-elision \
    --d8 out/x64.asan-fuzz/d8.dgf-clean \
    --canary-d8 out/x64.asan-fuzz/d8.dgf-canary -v
```

`--d8` selects the binary; by default the script picks the first existing
build of `out/{x64.asan-fuzz,x64.fuzzilli,x64.debug,x64.release}/d8`, i.e. the
ASan fuzzing build used for triage. Diverging mutants are written to `--out`
(default `tools/maglev-dgf/mutants/`) and, with `--log`, appended to a JSONL
file with the hit counts, the matched evidence lines and the result of all
three runs.

`fuzz` exits non-zero when it saved a diverging mutant, so it can drive a
smoke-test loop over the whole catalog:

```bash
for target in $(python3 tools/maglev-dgf/dgf.py targets --json | \
    python3 -c 'import json,sys; print(" ".join(t["id"] for t in json.load(sys.stdin)))'); do
  python3 tools/maglev-dgf/dgf.py fuzz --target "$target" \
      --iterations 5 --random-seed 7 || break
done
```

## Mutators

The mutators are structure and representation mutations that keep the seed's
arithmetic intact, so the seed's self-check still holds and any output
difference is a compiler bug:

| Mutator | Mutation | What it perturbs |
| ------- | -------- | ---------------- |
| `extra-arg` | `f(a)` -> `f(a, 0)` | arity feedback, inlined frame layout |
| `identity-call` | `f(a)` -> `f(__dgf_identity(a))` | an extra (inlined) call, new feedback slot |
| `call-duplicate` | `f(a);` -> `f(a); void f(a);` | a second call site: polymorphic feedback, call frequency |
| `inline-arg-rep-change` | `f(5)` -> `f(5.0)`, `f(x)` -> `f((x + 0.5) \| 0)` | the representation of the value handed to an inlined callee: the caller passes a HeapNumber where the callee's `CheckedSmiUntag` still assumes a Smi (targets `inlined-smi-proof`) |
| `redundant-truncation` | `x \| 0` -> `x \| 0 \| 0` | the truncation pass, value unchanged |
| `smi-dot-zero` | `1000` -> `1000.0` | literal kind / representation hint |
| `smi-to-heapnumber` | `7` -> `7.0` | a value's representation: the same number as a HeapNumber, not a Smi (targets `value-equal-smi`; strings, comments and `a[0]` indices are skipped) |
| `loop-bound-or` | `i < n` -> `i < (n \| 0)` | range analysis of the loop bound |
| `backedge-rep-change` | `x = x + o.v;` -> `x = (i === n - 1) ? 1.5 : (x + o.v);` | the representation a loop back edge carries: the header keeps its Smi while the merged value is a HeapNumber on the last (or every other) iteration, so the Phi has two representations to merge (targets `backedge-type`) |
| `void-dead` | adds `void x;` | liveness, an extra node with no side effect |
| `extra-property` | `{a: 1}` -> `{a: 1, __dgf: 0}` | map/field layout (skipped for `for-in` seeds) |

`__dgf_identity` is injected at the first function declaration, and only when a
mutant uses it. Up to `--max-mutations` (default 2) distinct mutators are
applied per mutant.

## Directed mutation (`direct`)

`fuzz` mutates structure and hopes the shape survives; `direct` reasons about
which values the shape needs. It renders a template whose slots are exactly the
facts that can make a representation proof stale — the loop backedge value, the
constant at a `BuildCheckSmi` site, and the representation of the argument of
an inlined call — and changes nothing else:

```bash
python3 tools/maglev-dgf/dgf.py direct --target kna-replay-elision \
    --iterations 20 --random-seed 1 -v
```

Candidates are *mutants, not seeds*: they `print()` their results instead of
asserting them, so every slot combination is a valid input and the baseline run
of the differential supplies the expected values (§8 of
`elision_proof_analysis.md` explains why this keeps the seed's oracle intact).

Coverage feedback is the graph dump, not a sanitizer hook. Every candidate is
compiled with the target's `trace_flags`, and its node-opcode multiset plus
its non-eager inlining count becomes a signature
(`coverage_signature`). A signature that was not seen before is a new
optimization path, is saved under `mutants/<target>/`, and is recorded in
`corpus/<target>.json` together with the slot values that produced it, so a
re-run with a wider `--iterations` starts where the previous one stopped.
`-v` prints the opcode delta against the seed, which is how a mutation that
switches `CheckSmi` for `UnsafeSmiUntag` (or `Int32Add` for `Float64Add`) is
visible at a glance.

A new signature only says that a candidate is *different*, so the search also
scores how close each graph is to the elision itself: the catalog's
`directed.distance` lists the opcodes that must be gone (`want_absent` — a
surviving check is exactly what the fault deletes) and the opcodes the elided
graph still has (`want_present`). The score prefixes the saved file name
(`phi-heapobjectness-d002-0003.js`), so a sorted listing of
`mutants/<target>/` is the search's best-first order, and the summary prints
the distance histogram next to the seed's own distance.

## Baseline comparison (`bench`)

`direct`'s claim is comparative: the slot combinations reach paths that
mutating the seed's structure would not. `bench` measures it, spending the
same number of candidates on both arms of the same catalog entry:

```bash
python3 tools/maglev-dgf/dgf.py bench --target phi-heapobjectness \
    --iterations 20 --random-seed 1
```

The baseline is `generic-differential`: the same seed, mutated by the
mutators `fuzz` uses (up to `--max-mutations`, default 2), with no slots and
no reachability requirement. Both arms are compiled and scored by the same
function (`bench_arm`) — the graph-dump signature, the catalog's
`directed.distance`, and the differential — so the four numbers mean the
same thing on each side:

| Metric | Meaning |
| ------ | ------- |
| `new signatures` | candidates whose signature is neither the seed's nor an earlier candidate's *of the same arm* |
| `distance < seed` | candidates closer to the elision than the seed's own graph |
| `divergences` | candidates where the Maglev and baseline runs disagree |
| `seed_broken` | candidates whose baseline run failed the seed's own self-check, so the expected value moved (lower is better) |

Each arm draws from its own RNG stream, so neither arm's candidates depend on
how many draws the other made, and `--random-seed` repeats a whole
comparison. Nothing is written to disk: `bench` is a measurement, not a
search, so `--out`, the corpus and `minimize` take no part in it. `--json`
prints the same numbers as one object for a campaign log. When the catalog has
fewer slot combinations than `--iterations`, `direct` runs out of them before
the baseline runs out of mutants; the header reports both candidate counts.

On `phi-heapobjectness` the distance metric is where the directed slots pay
off — the graph shape barely moves between value combinations, but random
structural mutation leaves the seed's `CheckSmi` in place:

```
bench: target=phi-heapobjectness iterations=20 seed=11_phi_heapobjectness.js seed_distance=12 random_seed=1
       baseline=generic-differential candidates: direct=20 generic-differential=20

  metric                 direct generic-differential    better
  new signatures              2                    1    direct
  distance < seed            20                    0    direct
  divergences                 0                    0         -
  seed_broken                 0                    0         -

outcome: direct  (better on new_paths, improved)
        distance: 20 vs 0 improving candidates
```

The exit code is the verdict: 1 when the baseline wins (`direct` better on no
metric, worse on some), 0 when `direct` wins, and 0 with a warning when the
arms tie. A tie means the budget did not separate them — not that the slots
are inert — so raise `--iterations`; a `direct` win that did not come from
the distance metric is warned about as well.

## Minimization (`minimize`)

A divergence is only actionable once the input that produces it is small: a
full template render carries every fact the catalog knows about, and the bug
usually needs one of them. Every candidate `direct` saves therefore starts
with one extra line, which is what a reduction is allowed to move:

```js
// dgf-candidate: {"slots": {"FIELD_REPR": "smi", "GC_POSITION": "after", "TRIGGER_VAL": "-0.0", "WARMUP_VAL": "2"}, "target": "value-equal-smi"}
```

`minimize` re-renders the target's template with those slot values, then
greedily removes facts and keeps a step only when the *same* detector — the
differential — still fires on the result:

1. every slot goes back to the seed's default (the catalog lists it first);
2. a numeric value, e.g. an iteration count, goes down to `1`;
3. a list literal goes down to one element;
4. the comments that only explain the template are dropped, so the report is
   the program. The candidate header and the seed's `// Flags:` lines stay.

```bash
python3 tools/maglev-dgf/dgf.py minimize \
    mutants/value-equal-smi/value-equal-smi-d000-0002.js \
    --target value-equal-smi
# [MIN ] mutants/value-equal-smi/value-equal-smi-d000-0002.min.js
#         76 -> 24 lines; WARMUP_VAL: 2 -> 1 (seed)
```

`minimize` writes `<FILE>.min.js` and exits 0 while the reduced file still
diverges, 1 when the reduction took the divergence away — then the candidate
has to be kept as it was. `fuzz` and `direct` call it themselves: a
divergence also writes `<target>-<iteration>-min.js`, so the first report of
a real bug is already the small one.

A `fuzz` mutant is not a template render and records no slot values, so only
step 4 applies to it, and the differential is re-checked on the compacted
text. The reduction is greedy and conservative: it never keeps a step it did
not observe diverging, and a rejected step is not revisited.

The acceptance run for the whole path uses the injected-fault build, because
the clean build does not diverge on `value-equal-smi`:

```bash
python3 tools/maglev-dgf/dgf.py canary --fault value-equal-check   # once
python3 tools/maglev-dgf/dgf.py direct --target value-equal-smi \
    --iterations 20 --random-seed 0 --d8 out/x64.asan-fuzz/d8.dgf-canary
python3 tools/maglev-dgf/dgf.py verify mutants/value-equal-smi/*-min.js \
    --target value-equal-smi --d8 out/x64.asan-fuzz/d8.dgf-canary
```

## Deterministic verification (`verify`, `canary`)

`verify` runs the two detectors that decide whether a candidate is real:

```bash
python3 tools/maglev-dgf/dgf.py verify kna-replay-elision -v
python3 tools/maglev-dgf/dgf.py verify mutants/kna-replay-elision/...js \
    --target kna-replay-elision --canary-d8 out/x64.asan-fuzz/d8.dgf-canary
```

1. `differential` — the Maglev and the baseline configuration, same input,
   normalized output;
2. `assert-types` — `--maglev-assert-types`, which emits a `CheckMaglevType`
   node for every KNA type read and traps when the runtime value disagrees
   with the compile-time fact.

Both are deterministic. To show that they *would* fire if the proof were wrong,
`canary` builds a d8 in which one proof is taken on faith, and installs it
next to the clean build:

```bash
python3 tools/maglev-dgf/dgf.py canary --list
python3 tools/maglev-dgf/dgf.py canary --fault elide-check-smi
# applies canary/elide-check-smi.patch, builds out/x64.asan-fuzz/d8,
# copies it to d8.dgf-canary (+ .json), reverts the patch, rebuilds the clean d8
```

The verdict is then a 2×2:

| clean build | canary build | verdict |
| ----------- | ------------ | ------- |
| fires | fires | `candidate` — a compiler bug candidate |
| fires | does not fire | `candidate` (the canary is not needed) |
| does not fire | fires | `canary-only` — the canary's own footprint, discarded |
| does not fire | does not fire | `clean` — or `unreached`, if the target's trace did not match |

`unreached` is decided in two steps, and both ask *this* target. The trace run
has to print the target's `required_patterns` (all of them) and its
`hit_patterns` (`min_hits` of them); a crash is the second witness, and it only
counts when the report names the target: a basename from the target's
`sources` (`# Fatal error in ../../src/maglev/maglev-truncation.cc`, or a frame
of the stack trace) or a symbol from its `bug_classes` (`ForInNext`,
`promote_post_loop_type`). A DCHECK in the graph builder therefore does not
make an input "reached" truncation, even though both are Maglev — without that
rule every crash anywhere in Maglev turned any mutant into a `candidate`. The
witness is in the JSON as `reached_by`: `trace`, `crash`, or `none`.

`verify` exits non-zero when it produced a `candidate`, so a loop over a mutant
directory stops on the first real finding instead of burying it in a log.

## Adding a target

1. Write a self-checking seed under `seeds/`: warm up, call
   `%OptimizeMaglevOnNextCall`, assert the expected values, and assert the
   Maglev tier with `if (%IsMaglevEnabled()) check(%ActiveTierIsMaglev(f),
   ...)`. Do not assert anything that holds for only one tier.
2. Find the trace configuration that shows the subsystem ran, e.g.
   `--trace-maglev-escape-analysis`, `--print-maglev-graph` or
   `--trace-maglev-inlining`, and confirm the exact wording on the seed:

   ```bash
   out/x64.asan-fuzz/d8 --allow-natives-syntax \
       --optimize-on-next-call-optimizes-to-maglev --maglev --no-turbofan \
       --trace-maglev-inlining tools/maglev-dgf/seeds/03_inlining.js
   ```

3. Add the entry to `targets.json` (`id`, `subsystem`, `phase`, `sources`,
   `trace_flags` / `config_flags`, `hit_patterns` / `required_patterns`,
   `seed`, `trigger`, `bug_classes`, `oracle`). A flag that changes which graph
   is built (for example `--maglev-non-eager-inlining`) belongs in
   `config_flags`: it is passed to every run, including the differential and
   `verify`, while `trace_flags` are only passed to the traced run. `sources`
   is not documentation only: `verify` treats a crash as proof that the target
   was reached when the report names one of those files, so keep the
   `path:Symbol` form. `bug_classes` is read the same way, through the symbol
   tokens in it (`ForInNext`, `promote_post_loop_type`), so name the checks
   and node types a crash of this bug class would print rather than describing
   them only in prose.
4. Run `python3 tools/maglev-dgf/dgf.py check <id> -v` and confirm `[HIT ]`
   plus, for `--trace-maglev-escape-analysis`, that the pattern matches the
   line you expect.

## Running under foozzie

`check`/`fuzz` already mirror foozzie's `ignition_maglev` configuration, so a
saved mutant reproduces with the stock tool:

```bash
python3 tools/clusterfuzz/foozzie/v8_foozzie.py \
    --first-config=ignition --second-config=ignition_maglev \
    --first-d8=out/x64.asan-fuzz/d8 --second-d8=out/x64.asan-fuzz/d8 \
    tools/maglev-dgf/mutants/osr-entry-0007.js
```

## Limitations

* The prototype fuzzes one seed per target; `generic-differential` covers the
  whole `seeds/` directory for plain divergence hunting.
* Trace-based reachability is textual: a pattern must be specific enough not to
  match unrelated output. `required_patterns` exists for that reason.
* Mutation is textual and assumes the seeds keep their small, single-statement
  shape; a mutator that cannot apply returns `None` instead of guessing.
* `direct` needs a `directed` section in the catalog and a template whose
  slots are the values under study; it does not derive either from a seed.
* `bench` compares one seed at one budget: it measures whether the catalog's
  slots beat structural mutation *on that template*, and a tie means the
  budget was too small, not that the directed search is inert. The baseline
  is a structural mutator, so a divergence it finds is a real finding too —
  the four numbers are a comparison, not a filter.
* `minimize` is greedy and value-directed, not a reducer: it moves the
  template's slots and drops comment-only lines, it does not delete
  statements, and a step it rejected is never retried. A candidate that
  records no slot values (a `fuzz` mutant) only loses its comments.
* The coverage signature is a graph-dump fingerprint, not edge coverage: it
  answers "did this value change the compilation", and can be blind to two
  graphs that differ only in control flow.
* `canary` patches the working tree, builds in an existing `out/` directory,
  and rebuilds it afterwards; it needs `autoninja` and a configured build. It
  saves the pre-patch binary as `d8.dgf-clean` (used as `verify --d8`) and the
  patched one as `d8.dgf-canary`. If a build is interrupted, the patch is
  still applied: `dgf.py canary --fault ID --revert`.
* A canary is a detector control, not a bug emulation: `canary-only` means the
  verifier works, `candidate` means the clean build reproduced the finding.
