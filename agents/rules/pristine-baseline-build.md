---
name: pristine-baseline-build
trigger: model_decision
description: When building an instrumented or traced V8, also build a pristine V8 at the latest dev branch as a differential baseline
---

# Pristine Baseline Build

Whenever you kick off a build of an **instrumented or traced** V8 — for example
a build carrying the `--trace-maglev-type-confusion` instrumentation, custom
oracle / assertion patches, or any local source changes meant for offline or
LLM-assisted analysis — also kick off a **pristine build of the latest dev
branch** (clean `origin/main`) as a differential baseline.

## Why

- The instrumentation is meant to be purely observational. A companion pristine
  binary proves that any behavior divergence (wrong output, crash, a trace that
  implies miscompilation) comes from the bug under study, not from the
  instrumentation itself.
- It catches build breakage introduced by the local changes early: if the
  pristine build succeeds while the instrumented one fails, the change is at
  fault.
- It gives a clean reference binary to diff optimized output against.

## How

- Base the pristine build on a **clean `origin/main`**, never on the
  instrumented branch. Create an isolated worktree so the instrumented tree is
  untouched: `agents/scripts/create_worktree.sh <task_id>` (or `git worktree
  add`), then `gn gen` a separate, clearly named out dir (e.g. `out/pristine`
  vs `out/type_confusion`) and build the same target (e.g. `d8`).
- Launch it in the **background** and rely on completion notifications; do not
  poll. Be mindful that two full V8 builds at once contend for CPU/RAM — on a
  constrained machine, sequence them rather than running both concurrently.
- Keep the two out dirs distinct so the traced and pristine binaries are never
  confused when comparing results.
