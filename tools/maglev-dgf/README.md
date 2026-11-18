# Maglev directed greybox fuzzing (prototype)

`tools/maglev-dgf` is a small, target-aware fuzzing driver for Maglev. It sits
on top of the existing differential oracle (`tools/clusterfuzz/foozzie`) and
adds the missing piece: a way to say *"this input compiled through the Maglev
subsystem I care about"*, instead of hoping that random mutation happens to
build the right nodes.

It consists of three parts:

| Path           | Role |
| -------------- | ---- |
| `targets.json` | Catalog: subsystem, C++ entry points, the d8 trace configuration that proves reachability, and the seed that reaches it. |
| `seeds/*.js`   | Hand-written, self-checking inputs. They assert only that Maglev was used (guarded `%ActiveTierIsMaglev`) and that their expected values are right. |
| `dgf.py`       | Driver: `targets` (list), `check` (reachability + differential), `fuzz` (target-aware mutation). |

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

1. `maglev` – the catalog's `trace_flags` plus the `ignition_maglev` config
   (`--maglev --turbo-filter=~ --no-turbofan`);
2. `maglev_clean` – the same config *without* the trace flags, so its output is
   comparable to the baseline;
3. `baseline` – `ignition` (`--no-maglev --no-turbofan`).

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

The mutators are structure mutations that keep the seed's arithmetic intact, so
the seed's self-check still holds and any output difference is a compiler bug:

| Mutator | Mutation | What it perturbs |
| ------- | -------- | ---------------- |
| `extra-arg` | `f(a)` -> `f(a, 0)` | arity feedback, inlined frame layout |
| `identity-call` | `f(a)` -> `f(__dgf_identity(a))` | an extra (inlined) call, new feedback slot |
| `call-duplicate` | `f(a);` -> `f(a); void f(a);` | a second call site: polymorphic feedback, call frequency |
| `redundant-truncation` | `x \| 0` -> `x \| 0 \| 0` | the truncation pass, value unchanged |
| `smi-dot-zero` | `1000` -> `1000.0` | literal kind / representation hint |
| `loop-bound-or` | `i < n` -> `i < (n \| 0)` | range analysis of the loop bound |
| `void-dead` | adds `void x;` | liveness, an extra node with no side effect |
| `extra-property` | `{a: 1}` -> `{a: 1, __dgf: 0}` | map/field layout (skipped for `for-in` seeds) |

`__dgf_identity` is injected at the first function declaration, and only when a
mutant uses it. Up to `--max-mutations` (default 2) distinct mutators are
applied per mutant.

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
   `trace_flags`, `hit_patterns` / `required_patterns`, `seed`, `trigger`,
   `bug_classes`, `oracle`).
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
