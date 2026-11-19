#!/usr/bin/env python3
# Copyright 2026 the V8 project authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Directed greybox fuzzing driver for Maglev.

This is the harness that ties together the three pieces of the Maglev DGF
prototype:

  * seeds/      hand-written, self-checking inputs that drive a specific
                Maglev subsystem,
  * targets.json  catalog mapping a subsystem to the C++ entry points, the
                trace configuration that proves the input reached it, and the
                seed that reaches it,
  * this script   runs a seed, decides from the compiler's own trace output
                whether the target was reached ("hit"), and cross-checks the
                result against a non-Maglev configuration ("differential").

Subcommands:

  targets                 list the catalog
  check [ID ...]          run each seed and assert its target is hit
  fuzz --target ID        mutate a seed, keep mutants that still hit the
                          target, and diff them against the baseline config
  direct --target ID      mutate only the values that control a representation
                          proof, and keep the mutants that reach a new
                          optimization path (coverage from the graph dump)
  verify FILE ...         deterministic verification of a candidate: clean
                          differential, --maglev-assert-types, and (optionally)
                          an injected-fault canary build
  canary --fault ID       build a d8 with one representation proof
                          unconditionally trusted, for the positive control

The reachability oracle is deliberately *not* an intrinsic: seeds only assert
that the Maglev tier was used (guarded `%ActiveTierIsMaglev`) and that their
own results are right, while "did we build the node/pass we care about" is
answered by the compiler's trace flags. Trace flags are supplied by the
catalog, not by the seed, so the same seed can be checked against different
phases.

All d8 invocations use the build from the V8 checkout this script lives in
(`out/<config>/d8`) unless --d8 is given.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import hashlib
import heapq
import itertools
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterable, Sequence

HERE = Path(__file__).resolve().parent
V8_ROOT = HERE.parent.parent
DEFAULT_TARGETS = HERE / "targets.json"
TEMPLATES = HERE / "templates"
CANARY_DIR = HERE / "canary"
DEFAULT_CORPUS = HERE / "corpus"

# Mirrors tools/clusterfuzz/foozzie/v8_commands.py:DEFAULT_FLAGS so that a
# divergence found here reproduces under v8_foozzie.py.
FOOZZIE_COMMON_FLAGS = [
    "--correctness-fuzzer-suppressions",
    "--expose-gc",
    "--fuzzing",
    "--allow-natives-for-differential-fuzzing",
    "--invoke-weak-callbacks",
    "--omit-quit",
    "--harmony",
    "--experimental-fuzzing",
    "--js-staging",
    "--wasm-staging",
    "--wasm-num-compilation-tasks=0",
    "--wasm-max-mem-pages=32767",
    "--suppress-asm-messages",
]

# Mirrors v8_foozzie.py:CONFIG_FLAGS[<config>].
CONFIG_FLAGS = {
    "ignition": ["--no-maglev", "--no-turbofan"],
    # Same as v8_foozzie.py: ignition_maglev.
    "ignition_maglev": ["--maglev", "--turbo-filter=~", "--no-turbofan"],
}

# The seeds need these on top of the foozzie config in both runs.
SEED_FLAGS = [
    "--allow-natives-syntax",
    "--optimize-on-next-call-optimizes-to-maglev",
]

CRASH_PATTERNS = [
    r"^#\s*$",
    r"Check failed:",
    r"DCHECK failed",
    r"FATAL ERROR",
    r"Fatal error",
    r"AddressSanitizer",
    r"Received signal",
    r"Trace/breakpoint trap",
    r"Segmentation fault",
]

SELF_CHECK_FAILURE = "FAIL:"

DEFAULT_TIMEOUT = 60


@dataclasses.dataclass
class D8Result:
    cmd: list[str]
    returncode: int
    timed_out: bool
    stdout: str
    stderr: str
    duration_s: float

    @property
    def output(self) -> str:
        return self.stdout + self.stderr

    @property
    def crashed(self) -> bool:
        if self.timed_out:
            return False
        if self.returncode < 0:
            return True
        return any(re.search(p, self.output, re.M) for p in CRASH_PATTERNS)

    @property
    def self_check_failed(self) -> bool:
        return SELF_CHECK_FAILURE in self.output

    def describe(self) -> str:
        if self.timed_out:
            return "TIMEOUT"
        if self.crashed:
            return f"CRASH(rc={self.returncode})"
        return f"rc={self.returncode}"


def default_d8() -> Path:
    """Picks the fuzzing build, preferring the ASan one used for triage."""
    for name in ("x64.asan-fuzz", "x64.fuzzilli", "x64.debug", "x64.release"):
        candidate = V8_ROOT / "out" / name / "d8"
        if candidate.exists():
            return candidate
    found = shutil.which("d8")
    return Path(found) if found else V8_ROOT / "out" / "x64.release" / "d8"


def run_d8(d8: Path, testcase: Path, flags: Sequence[str],
           timeout: float) -> D8Result:
    cmd = [str(d8)] + list(flags) + [str(testcase)]
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            cwd=str(testcase.parent),
        )
    except subprocess.TimeoutExpired as exc:
        return D8Result(
            cmd=cmd,
            returncode=-1,
            timed_out=True,
            stdout=(exc.stdout or b"").decode("utf-8", "replace"),
            stderr=(exc.stderr or b"").decode("utf-8", "replace"),
            duration_s=time.time() - started,
        )
    return D8Result(
        cmd=cmd,
        returncode=proc.returncode,
        timed_out=False,
        stdout=proc.stdout.decode("utf-8", "replace"),
        stderr=proc.stderr.decode("utf-8", "replace"),
        duration_s=time.time() - started,
    )


def load_targets(path: Path) -> list[dict]:
    with path.open() as f:
        data = json.load(f)
    if data.get("schema_version") != 1:
        raise SystemExit(f"{path}: unsupported schema_version")
    return data["targets"]


def find_target(targets: Iterable[dict], target_id: str) -> dict:
    for target in targets:
        if target["id"] == target_id:
            return target
    known = ", ".join(t["id"] for t in targets)
    raise SystemExit(f"unknown target {target_id!r}; known: {known}")


def seed_path(target: dict) -> Path:
    seed = HERE / target["seed"]
    if seed.is_dir():
        seeds = sorted(seed.glob("*.js"))
        if not seeds:
            raise SystemExit(f"no seeds in {seed}")
        return seeds[0]
    if not seed.exists():
        raise SystemExit(f"missing seed {seed}")
    return seed


def count_hits(target: dict, output: str) -> dict[str, int]:
    counts = {}
    patterns = list(target.get("hit_patterns") or [])
    patterns += list(target.get("required_patterns") or [])
    for pattern in dict.fromkeys(patterns):
        counts[pattern] = len(re.findall(pattern, output, re.M))
    return counts


def required_hits(target: dict) -> int:
    if "min_hits" in target:
        return int(target["min_hits"])
    return 1 if target.get("hit_patterns") else 0


def missing_patterns(target: dict, counts: dict[str, int]) -> list[str]:
    """Patterns in 'required_patterns' that did not appear at all.

    'hit_patterns' are alternatives (any match counts); 'required_patterns'
    are signatures that must all be present, e.g. both the node the seed
    builds and the pass that consumes it.
    """
    return [p for p in target.get("required_patterns") or []
            if counts.get(p, 0) == 0]


def evidence(target: dict, output: str, limit: int = 3) -> list[str]:
    """Returns a few lines that prove the target was reached."""
    found = []
    patterns = target.get("hit_patterns") or []
    for line in strip_ansi(output).splitlines():
        if any(re.search(p, line) for p in patterns):
            found.append(line.strip()[:200])
            if len(found) >= limit:
                break
    return found


def maglev_flags(target: dict, extra: Sequence[str] = (),
                 trace: bool = True) -> list[str]:
    """Flags for the Maglev configuration.

    `config_flags` are part of the configuration, not of the tracing: they
    change which graph is built (e.g. --maglev-non-eager-inlining), so they
    are also passed to the runs that are compared against the baseline.
    `trace_flags` only make the run observable and may be dropped.
    """
    flags = (FOOZZIE_COMMON_FLAGS + CONFIG_FLAGS["ignition_maglev"] +
             SEED_FLAGS + list(target.get("config_flags") or []) +
             list(extra))
    if trace:
        flags += list(target.get("trace_flags") or [])
    return flags


def baseline_flags(extra: Sequence[str] = ()) -> list[str]:
    return (FOOZZIE_COMMON_FLAGS + CONFIG_FLAGS["ignition"] + SEED_FLAGS +
            list(extra))


ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{4,}")
TIME_RE = re.compile(r"\b\d+(\.\d+)?\s*(ms|us|ns|s)\b")
# Graph dumps are printed with ANSI colours even when stdout is a pipe.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def normalize(output: str) -> str:
    """Normalizes output for differential comparison."""
    lines = []
    for line in strip_ansi(output).splitlines():
        line = ADDRESS_RE.sub("0xADDR", line)
        line = TIME_RE.sub("<time>", line)
        lines.append(line.rstrip())
    return "\n".join(lines)


@dataclasses.dataclass
class TargetReport:
    target_id: str
    seed: str
    hit: bool
    hits: dict[str, int]
    required: int
    evidence: list[str]
    maglev: D8Result
    missing: list[str] = dataclasses.field(default_factory=list)
    # Same configuration as `maglev` but without the catalog's trace flags,
    # so its output is comparable with the baseline run.
    maglev_clean: D8Result | None = None
    baseline: D8Result | None = None
    divergence: str | None = None

    @property
    def ok(self) -> bool:
        return (self.hit and self.divergence is None and
                not self.maglev.crashed)

    def to_json(self) -> dict:
        return {
            "target": self.target_id,
            "seed": self.seed,
            "hit": self.hit,
            "hits": self.hits,
            "required_hits": self.required,
            "missing_patterns": self.missing,
            "evidence": self.evidence,
            "maglev": self.maglev.describe(),
            "maglev_rc": self.maglev.returncode,
            "maglev_clean":
                self.maglev_clean.describe() if self.maglev_clean else None,
            "baseline": self.baseline.describe() if self.baseline else None,
            "divergence": self.divergence,
        }


def compare(maglev: D8Result, baseline: D8Result) -> str | None:
    """Returns a human readable divergence description, or None."""
    if maglev.crashed != baseline.crashed:
        return (f"crash mismatch: maglev={maglev.describe()} "
                f"baseline={baseline.describe()}")
    if maglev.timed_out != baseline.timed_out:
        return (f"timeout mismatch: maglev={maglev.describe()} "
                f"baseline={baseline.describe()}")
    if normalize(maglev.output) != normalize(baseline.output):
        return "output mismatch"
    if maglev.returncode != baseline.returncode:
        return (f"exit code mismatch: {maglev.returncode} vs "
                f"{baseline.returncode}")
    return None




def differential_check(d8: Path, target: dict, testcase: Path, timeout: float,
                       extra_flags: Sequence[str] = ()
                       ) -> tuple[D8Result, D8Result, str | None]:
    """Runs the same input in the Maglev and the baseline configuration.

    Trace flags dump the graph, which is not comparable across tiers, so this
    repeats the Maglev config *without* them.
    """
    maglev_clean = run_d8(
        d8, testcase, maglev_flags(target, extra_flags, trace=False), timeout)
    baseline = run_d8(d8, testcase, baseline_flags(extra_flags), timeout)
    return maglev_clean, baseline, compare(maglev_clean, baseline)


def check_target(d8: Path, target: dict, timeout: float,
                 differential: bool = True,
                 extra_flags: Sequence[str] = (),
                 testcase: Path | None = None) -> TargetReport:
    seed = testcase or seed_path(target)
    maglev = run_d8(d8, seed, maglev_flags(target, extra_flags), timeout)
    hits = count_hits(target, maglev.output)
    required = required_hits(target)
    missing = missing_patterns(target, hits)
    report = TargetReport(
        target_id=target["id"],
        seed=str(seed),
        hit=not missing and ((sum(hits.values()) >= required) if required
                             else True),
        hits=hits,
        required=required,
        evidence=evidence(target, maglev.output),
        maglev=maglev,
        missing=missing,
    )
    if differential:
        report.maglev_clean, report.baseline, report.divergence = (
            differential_check(d8, target, seed, timeout, extra_flags))
    return report


def print_report(report: TargetReport, verbose: bool = False) -> None:
    status = "HIT " if report.hit else "MISS"
    if report.divergence:
        status = "DIFF"
    if report.maglev.crashed:
        status = "CRASH"
    print(f"[{status}] {report.target_id} "
          f"({report.seed.rsplit('/', 1)[-1]})")
    print(f"        maglev={report.maglev.describe()} "
          f"({report.maglev.duration_s:.1f}s)"
          + (f" maglev_clean={report.maglev_clean.describe()}"
             if report.maglev_clean else "")
          + (f" baseline={report.baseline.describe()}"
             if report.baseline else ""))
    if report.hits:
        print("        hits: " + ", ".join(
            f"{p}x{c}" for p, c in report.hits.items())
            + f" (need {report.required})")
    if report.missing:
        print("        missing: " + ", ".join(report.missing))
    for line in report.evidence:
        print(f"        | {line}")
    if report.divergence:
        print(f"        divergence: {report.divergence}")
        if verbose:
            print("        --- maglev output (no trace flags) ---")
            print(report.maglev_clean.output[:4000])
            print("        --- baseline output ---")
            print(report.baseline.output[:4000])


# --------------------------------------------------------------------------
# Target-aware mutators
#
# The mutators are deliberately *structure* mutations: they perturb the
# feedback the graph builder sees (call arity, call sites, representation
# hints, loop bounds, liveness) while keeping the seed's arithmetic unchanged,
# so the seed's own self-check still passes for the unmutated build. That
# property is what makes a differential oracle usable: any output difference
# between the Maglev and the baseline run is a real divergence, not a mutated
# expectation.
# --------------------------------------------------------------------------

IDENTITY_HELPER = """\
// Injected by tools/maglev-dgf/dgf.py: an identity call site. It does
// not change the result, but it adds a new feedback slot and a new
// inlining candidate to the graph.
function __dgf_identity(v) { return v; }
"""


@dataclasses.dataclass
class CallSite:
    """A call expression found in the seed source."""
    start: int   # index of the callee identifier
    end: int     # index just past the closing parenthesis
    args: str    # source text between the parentheses


def _find_matching_paren(src: str, open_idx: int) -> int:
    depth = 0
    quote = None
    i = open_idx
    while i < len(src):
        ch = src[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _call_sites(src: str, name: str) -> list[CallSite]:
    """All `name(...)` calls, with nested parentheses handled.

    A plain regex cannot find `check(mono(1) === 6, 'msg')`, because the
    argument list itself contains parentheses.
    """
    sites = []
    pattern = re.compile(r"(?<![\w.$])" + re.escape(name) + r"\s*\(")
    for m in pattern.finditer(src):
        line_start = src.rfind("\n", 0, m.start()) + 1
        prefix = src[line_start:m.start()]
        comment_pos = prefix.find("//")
        if (comment_pos >= 0 and "'" not in prefix[:comment_pos] and
                '"' not in prefix[:comment_pos] and
                "`" not in prefix[:comment_pos]):
            continue
        if src[:m.start()].rstrip().endswith("function"):
            continue
        open_idx = m.end() - 1
        close_idx = _find_matching_paren(src, open_idx)
        if close_idx < 0:
            continue
        sites.append(CallSite(m.start(), close_idx + 1,
                              src[open_idx + 1:close_idx]))
    return sites


def _split_first_arg(args: str) -> tuple[str, str]:
    """Splits `a, b, c` at the first top-level comma.

    Commas inside brackets (e.g. an array literal argument) or inside string
    literals do not separate arguments, so they are skipped.
    """
    depth = 0
    quote = None
    i = 0
    while i < len(args):
        ch = args[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return args[:i], args[i:]
        i += 1
    return args, ""


def _count_args(args: str) -> int:
    """Number of top-level arguments in `args` (empty means none)."""
    if not args.strip():
        return 0
    count = 1
    rest = args
    while True:
        _, rest = _split_first_arg(rest)
        if not rest:
            return count
        rest = rest[1:]
        count += 1


def _pick_call_site(src: str, rng: random.Random, names: list,
                    require_args: bool) -> tuple[str | None, CallSite | None]:
    """Picks a callee that is actually *called* in the source.

    A seed may pass a function as a value without ever calling it (`poly(add1,
    x)` calls `add1` only through the parameter), so a name without call sites
    is skipped instead of failing the mutation.
    """
    names = list(names)
    rng.shuffle(names)
    for name in names:
        sites = [s for s in _call_sites(src, name)
                 if s.args.strip() or not require_args]
        if sites:
            return name, rng.choice(sites)
    return None, None


def op_extra_arg(src: str, rng: random.Random, ctx: dict) -> str | None:
    """f(a) -> f(a, 0): changes arity feedback and the inlined frame.

    Only where the extra argument is ignored: `function f(x, y)` called as
    `f(1)` computes `1 + undefined`, so appending a `0` would move the
    result and the seed's self-check would reject the mutant.
    """
    name, site = _pick_call_site(src, rng, ctx["functions"],
                                 require_args=False)
    if site is None:
        return None
    arity = (ctx.get("arities") or {}).get(name)
    if arity is not None and arity > _count_args(site.args):
        return None
    call = (f"{name}({site.args}, 0)" if site.args.strip()
            else f"{name}(0)")
    return src[:site.start] + call + src[site.end:]


def op_identity_call(src: str, rng: random.Random, ctx: dict) -> str | None:
    """f(a) -> f(__dgf_identity(a)): adds a callee, keeps the value."""
    name, site = _pick_call_site(src, rng, ctx["functions"],
                                 require_args=True)
    if site is None:
        return None
    first, rest = _split_first_arg(site.args)
    call = f"{name}(__dgf_identity({first}){rest})"
    return src[:site.start] + call + src[site.end:]


def op_call_duplicate(src: str, rng: random.Random, ctx: dict) -> str | None:
    """Adds `void f(a);` after a call: a second call site, same values.

    The duplicated result is discarded, so no expectation moves as long as the
    callee has no observable side effects; mutants where it does are rejected
    by the seed's own self-check and counted as `seed_broken`.
    """
    names = list(ctx["functions"]) + list(ctx.get("arrows") or [])
    if not names:
        return None
    candidates = []
    for name in names:
        for site in _call_sites(src, name):
            line_start = src.rfind("\n", 0, site.start) + 1
            line_end = src.find("\n", site.end)
            line_end = len(src) if line_end < 0 else line_end
            line = src[line_start:line_end]
            # Only whole statements on a single line, so that the inserted
            # statement does not split an expression or a block.
            if not line.rstrip().endswith(";"):
                continue
            candidates.append((site, line_start, line_end))
    if not candidates:
        return None
    site, line_start, line_end = rng.choice(candidates)
    indent = src[line_start:site.start]
    indent = indent[:len(indent) - len(indent.lstrip())]
    inserted = f"\n{indent}void {src[site.start:site.end]};"
    return src[:line_end] + inserted + src[line_end:]


def op_redundant_truncation(src: str, rng: random.Random,
                            ctx: dict) -> str | None:
    """`x | 0` -> `x | 0 | 0`: feeds the truncation pass, value unchanged."""
    lines = src.splitlines(True)
    candidates = [
        i for i, line in enumerate(lines)
        if "| 0;" in line and not line.lstrip().startswith("//")
    ]
    if not candidates:
        return None
    i = rng.choice(candidates)
    lines[i] = lines[i].replace("| 0;", "| 0 | 0;", 1)
    return "".join(lines)


def op_smi_dot_zero(src: str, rng: random.Random, ctx: dict) -> str | None:
    """`=== 1000` -> `=== 1000.0`: same value, different literal kind."""
    lines = src.splitlines(True)
    candidates = [
        i for i, line in enumerate(lines)
        if "===" in line and "[" not in line and "%" not in line
    ]
    if not candidates:
        return None
    i = rng.choice(candidates)
    literals = list(re.finditer(r"(?<![\w.])(\d{1,6})(?![\w.])", lines[i]))
    if not literals:
        return None
    m = rng.choice(literals)
    line = lines[i]
    lines[i] = line[:m.end()] + ".0" + line[m.end():]
    return "".join(lines)


def op_loop_bound_or(src: str, rng: random.Random, ctx: dict) -> str | None:
    """`i < n` -> `i < (n | 0)`: keeps the bound, exercises range analysis."""
    pattern = re.compile(r"(for\s*\([^;]*;\s*\w+\s*<\s*)([A-Za-z_]\w*)")
    matches = list(pattern.finditer(src))
    if not matches:
        return None
    m = rng.choice(matches)
    return src[:m.start()] + f"{m.group(1)}({m.group(2)} | 0)" + src[m.end():]


def op_void_dead(src: str, rng: random.Random, ctx: dict) -> str | None:
    """Adds `void x;` after a declaration: keeps liveness, adds a node."""
    lines = src.splitlines(True)
    pattern = re.compile(r"^(\s*)(?:let|const)\s+(\w+)\s*=")
    candidates = []
    for i, line in enumerate(lines):
        if line.lstrip().startswith("//"):
            continue
        m = pattern.match(line)
        # Only single-line declarations: inserting after a line that opens a
        # multi-line statement would split it.
        if m and line.rstrip().endswith(";"):
            candidates.append((i, m.group(1), m.group(2)))
    if not candidates:
        return None
    i, indent, name = rng.choice(candidates)
    lines.insert(i + 1, f"{indent}void {name};\n")
    return "".join(lines)


def op_extra_property(src: str, rng: random.Random, ctx: dict) -> str | None:
    """`{tag: 1}` -> `{tag: 1, __dgf: 0}`: different map, same fields read.

    Skipped for seeds that enumerate keys, where a new property is observable.
    """
    if re.search(r"for\s*\([^)]*\bin\b", src):
        return None
    pattern = re.compile(r"\{(\s*)(\w+)\s*:\s*([^,{}\n]+?)(\s*)\}")
    matches = list(pattern.finditer(src))
    if not matches:
        return None
    m = rng.choice(matches)
    obj = ("{" + m.group(1) + f"{m.group(2)}: {m.group(3)}, __dgf: 0" +
           m.group(4) + "}")
    return src[:m.start()] + obj + src[m.end():]


OPS = [
    ("extra-arg", op_extra_arg),
    ("identity-call", op_identity_call),
    ("call-duplicate", op_call_duplicate),
    ("redundant-truncation", op_redundant_truncation),
    ("smi-dot-zero", op_smi_dot_zero),
    ("loop-bound-or", op_loop_bound_or),
    ("void-dead", op_void_dead),
    ("extra-property", op_extra_property),
]


def mutate_context(src: str) -> dict:
    """Collects the callee names and arities the mutators may rewrite."""
    functions = re.findall(r"^\s*function\s+(\w+)", src, re.M)
    arrows = re.findall(
        r"^\s*(?:const|let|var)\s+(\w+)\s*=\s*"
        r"(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>", src, re.M)
    arities = {}
    for m in re.finditer(r"^\s*function\s+(\w+)\s*\(([^)]*)\)",
                         src, re.M):
        arities[m.group(1)] = _count_args(m.group(2))
    return {"functions": functions, "arrows": arrows, "arities": arities}


def mutate_source(src: str, rng: random.Random,
                  num_ops: int) -> tuple[str, list[str]]:
    """Applies up to num_ops distinct mutators. Returns (source, applied)."""
    ctx = mutate_context(src)
    ops = list(OPS)
    rng.shuffle(ops)
    applied: list[str] = []
    for name, fn in ops:
        if len(applied) >= num_ops:
            break
        try:
            mutated = fn(src, rng, ctx)
        except re.error:
            mutated = None
        if mutated and mutated != src:
            src = mutated
            applied.append(name)
    if "__dgf_identity(" in src and "function __dgf_identity" not in src:
        m = re.search(r"^function\s+\w+", src, re.M)
        idx = m.start() if m else 0
        src = src[:idx] + IDENTITY_HELPER + "\n" + src[idx:]
    return src, applied


# --------------------------------------------------------------------------
# Phase 3: directed mutation
#
# `fuzz` mutates *structure*; `direct` mutates only the values that control a
# representation proof and leaves the shape of the program alone. The
# candidates come from a template whose slots are the facts that §4 of
# elision_proof_analysis.md identifies as able to go stale:
#
#   SMI_CONST  the constant at a BuildCheckSmi site, i.e. the input the
#              check is derived from (in Smi range, at the boundary, outside)
#   BACKEDGE   the loop-carried value the backedge merges, which decides the
#              phi type that promote_post_loop_type may rewrite
#   ARG_VALUE  the representation of the value passed to an inlined call,
#              which is what a replayed snapshot sees through the argument
#              node it shares with the caller
#
# A candidate prints its results instead of asserting them, so every slot
# combination is a valid input and the baseline run supplies the expected
# values. "Did the mutation reach a new optimization path" is answered by the
# graph dump rather than by a sanitizer hook: --print-maglev-graph prints the
# final node list, which is the granularity at which a value mutation changes
# the pipeline (CheckSmi vs UnsafeSmiUntag, Int32Add vs Float64Add).
# --------------------------------------------------------------------------

SLOT_RE = re.compile(r"\{\{([A-Z][A-Z0-9_]*)\}\}")
# Node lines look like "  17/11: UnsafeSmiUntag [v16/n10:[rax|R|t]] -> ...";
# the "id/deopt-id" half is optional depending on the graph printer.
GRAPH_NODE_RE = re.compile(r"^\s*\d+(?:/\d+)?:\s+([A-Za-z][A-Za-z0-9_]*)")


def render_template(source: str, values: dict) -> str:
    """Substitutes {{SLOT}} markers; an unset slot is an error, not a guess."""
    def replace(match: re.Match) -> str:
        name = match.group(1)
        if name not in values:
            raise SystemExit(f"template slot {name} has no value")
        return str(values[name])

    return SLOT_RE.sub(replace, source)


@dataclasses.dataclass
class Signature:
    """Coarse path signature of one Maglev compilation."""
    digest: str
    opcodes: dict[str, int]
    inlines: int

    def delta(self, other: "Signature") -> str:
        """Opcode set difference: `+` new nodes, `-` dropped ones."""
        added = sorted(set(self.opcodes) - set(other.opcodes))
        removed = sorted(set(other.opcodes) - set(self.opcodes))
        parts = [f"+{name}" for name in added[:6]]
        parts += [f"-{name}" for name in removed[:6]]
        return " ".join(parts)


def coverage_signature(output: str) -> Signature:
    """Node-opcode multiset plus the non-eager inlining count.

    Addresses, node ids and immediates are dropped, so the signature is
    stable across runs; opcode *counts* are kept, because "one more CheckSmi"
    is a different path.
    """
    opcodes: dict[str, int] = collections.Counter()
    inlines = 0
    for line in strip_ansi(output).splitlines():
        if "INLINE" in line:
            inlines += 1
            continue
        match = GRAPH_NODE_RE.match(line)
        if match:
            opcodes[match.group(1)] += 1
    key = json.dumps([sorted(opcodes.items()), inlines])
    return Signature(hashlib.sha1(key.encode()).hexdigest()[:16], opcodes,
                     inlines)


def distance(sig: Signature, target: dict) -> int:
    """How far a graph is from the target's elision site; lower is closer.

    A new path signature only says *that* a candidate is different, so the
    directed search has no reason to prefer the candidate that is one node
    away from the elision over the one that is ten nodes away. The catalog
    states the graph shape of the elision from both sides: opcodes that must
    be gone, because a surviving check is the thing the fault removes, and
    opcodes that must be there, because they are what the elision leaves
    behind. A missing "want_present" node weighs little: the site can be
    reached through a different route, and the signature only keeps opcode
    names, not edges.
    """
    spec = target.get("directed", {}).get("distance", {})
    score = 0
    for name in spec.get("want_absent", []):
        if name in sig.opcodes:
            score += spec.get("weight_absent", 10)
    for name in spec.get("want_present", []):
        if name not in sig.opcodes:
            score += spec.get("weight_present", 1)
    return score


def slot_families(spec: dict) -> dict[str, list[str]]:
    """Slot name -> candidate values, in catalog order."""
    families = {name: [str(value) for value in values]
                for name, values in (spec.get("slots") or {}).items()}
    if not families:
        raise SystemExit("target has no 'directed.slots'")
    return families


def slot_key(values: dict, families: dict) -> tuple[str | None, ...]:
    """Identity of one slot combination, independent of insertion order."""
    return tuple(values.get(name) for name in families)


def slot_combinations(spec: dict, rng: random.Random,
                      iterations: int) -> list[dict]:
    """Draws `iterations` distinct slot combinations; all of them if fewer."""
    families = slot_families(spec)
    names = list(families)
    total = 1
    for name in names:
        total *= len(families[name])
    if iterations >= total:
        indices = list(range(total))
    else:
        indices = sorted(rng.sample(range(total), iterations))
    combos = []
    for index in indices:
        combo = {}
        for name in names:
            values = families[name]
            combo[name] = values[index % len(values)]
            index //= len(values)
        combos.append(combo)
    return combos


def single_slot_mutations(values: dict, families: dict) -> list[dict]:
    """The one-slot neighbourhood of a combination, in catalog order.

    Every slot keeps its value except one, which walks its whole family: a
    step that changes exactly one fact of the input, so whatever the graph
    does differently is attributable to that fact. A slot without a value is
    one the seed did not fix, and takes the catalog's first value — the
    catalog lists a slot's seed value first, so the seed itself expands into
    its own neighbourhood.
    """
    base = {name: values.get(name, family[0])
            for name, family in families.items()}
    children = [dict(base)]
    for name, family in families.items():
        for value in family:
            if value != base[name]:
                children.append({**base, name: value})
    return children


def cmd_direct(args, targets: list[dict]) -> int:
    d8 = require_d8(Path(args.d8) if args.d8 else default_d8())
    target = find_target(targets, args.target)
    spec = target.get("directed")
    if not spec:
        raise SystemExit(f"target {target['id']} has no 'directed' section")
    if args.strategy == "best-first" and "distance" not in spec:
        raise SystemExit(f"target {target['id']} has no 'directed.distance'; "
                         "best-first needs it to order the queue")
    template = (HERE / spec["template"]).read_text()
    fixed = dict(spec.get("fixed") or {})
    rng = random.Random(args.random_seed)
    families = slot_families(spec)
    combos = (slot_combinations(spec, rng, args.iterations)
              if args.strategy == "random" else [])

    outdir = Path(args.out) / target["id"]
    outdir.mkdir(parents=True, exist_ok=True)
    corpus_file = Path(args.corpus) / f"{target['id']}.json"
    corpus_file.parent.mkdir(parents=True, exist_ok=True)
    corpus = (json.loads(corpus_file.read_text()) if corpus_file.exists()
              else {})
    seed_trace = run_d8(d8, seed_path(target),
                        maglev_flags(target, args.extra_flag), args.timeout)
    seed_signature = coverage_signature(seed_trace.output)
    seed_distance = distance(seed_signature, target)
    # The seed's own graph is the first path the corpus has seen; without it,
    # the first candidates that reproduce the seed are reported as new.
    corpus.setdefault(seed_signature.digest, {
        "seed": True,
        "slots": {},
        "inlines": seed_signature.inlines,
        "nodes": len(seed_signature.opcodes),
        "hits": count_hits(target, seed_trace.output),
        "distance": seed_distance,
    })

    stats = collections.Counter()
    log = open(args.log, "a") if args.log else None

    def evaluate(combo: dict, index: int) -> int:
        """Renders, runs and reports one candidate; returns its distance."""
        values = {**fixed, **combo}
        source = render_template(template, values)
        label = " ".join(f"{k}={v}" for k, v in sorted(combo.items()))
        with tempfile.TemporaryDirectory(prefix="dgf-direct-") as tmp:
            testcase = Path(tmp) / f"{target['id']}-{index:04d}.js"
            testcase.write_text(source)
            trace = run_d8(d8, testcase,
                           maglev_flags(target, args.extra_flag),
                           args.timeout)
            hits = count_hits(target, trace.output)
            missing = missing_patterns(target, hits)
            signature = coverage_signature(trace.output)
            dist = distance(signature, target)
            stats[f"dist_{dist}"] += 1
            new_path = signature.digest not in corpus
            _, baseline, divergence = differential_check(
                d8, target, testcase, args.timeout, args.extra_flag)
            stats["candidates"] += 1
            stats["hit" if not missing else "miss"] += 1
            # Candidates print instead of asserting, so a baseline that
            # fails its own check means the mutant is malformed, not that
            # the compiler diverged.
            if baseline.self_check_failed or baseline.crashed:
                stats["seed_broken"] += 1
                return dist
            if new_path:
                stats["new_paths"] += 1
                corpus[signature.digest] = {
                    "slots": values,
                    "inlines": signature.inlines,
                    "nodes": len(signature.opcodes),
                    "hits": hits,
                    "distance": dist,
                }
            if divergence:
                stats["divergences"] += 1
            if not (new_path or divergence or args.keep_all):
                if args.verbose:
                    print(f"[---] distance={dist}  {label}")
            else:
                # The distance is part of the name, so a sorted directory
                # listing is the search's best-first order.
                path = outdir / f"{target['id']}-d{dist:03d}-{index:04d}.js"
                path.write_text(source)
                status = ("DIFF" if divergence else
                          "NEW " if new_path else "...")
                print(f"[{status}] {path.name}  {label}"
                      + (f"  distance={dist}" if args.verbose else ""))
                if args.verbose:
                    print(f"        inlines={signature.inlines} "
                          f"nodes={len(signature.opcodes)} "
                          f"delta-vs-seed: "
                          f"{signature.delta(seed_signature) or '-'}"
                          + ("" if not missing
                             else f"  missing: {', '.join(missing)}"))
                if divergence:
                    print(f"        {divergence}")
        if log:
            log.write(json.dumps({
                "target": target["id"],
                "slots": values,
                "signature": signature.digest,
                "distance": dist,
                "new_path": new_path,
                "missing": missing,
                "divergence": divergence,
            }) + "\n")
            log.flush()
        return dist

    try:
        if args.strategy == "best-first":
            # The queue holds evaluated candidates keyed on distance, so the
            # next expansion always continues from the closest graph seen so
            # far instead of from an arbitrary combination. The seed is the
            # first entry: its distance comes from the run above, and it has
            # no slot values until it is expanded.
            order = itertools.count()  # FIFO tie-break between equal scores
            queue = [(seed_distance, next(order), {})]
            seen = {()}  # the seed itself: no slot values, nothing to skip
            index = 0
            while queue and stats["expansions"] < args.iterations:
                dist, _, values = heapq.heappop(queue)
                stats["expansions"] += 1
                where = ("seed" if not values else
                         " ".join(f"{k}={v}"
                                  for k, v in sorted(values.items())))
                print(f"[exp ] #{stats['expansions']:02d} distance={dist}"
                      f"  {where}")
                if dist == 0:
                    break
                for child in single_slot_mutations(values, families):
                    key = slot_key(child, families)
                    if key in seen:
                        continue
                    seen.add(key)
                    index += 1
                    heapq.heappush(queue, (evaluate(child, index),
                                            next(order), child))
        else:
            for index, combo in enumerate(combos):
                evaluate(combo, index)
    finally:
        if log:
            log.close()

    corpus_file.write_text(json.dumps(corpus, indent=1, sort_keys=True) + "\n")
    print(f"\ntarget={target['id']} strategy={args.strategy} "
          f"candidates={stats['candidates']} "
          f"hit={stats['hit']} miss={stats['miss']} "
          f"new_paths={stats['new_paths']} "
          f"divergences={stats['divergences']} "
          f"expansions={stats['expansions']} "
          f"corpus={len(corpus)} ({corpus_file})")
    histogram = sorted((int(key[len("dist_"):]), count)
                       for key, count in stats.items()
                       if key.startswith("dist_"))
    if histogram:
        print(f"distance (seed={seed_distance}): "
              + " ".join(f"{dist}={count}" for dist, count in histogram))
    return 1 if stats["divergences"] else 0


# --------------------------------------------------------------------------
# Phase 4: deterministic verification
#
# Two detectors run on every candidate, in a fixed order:
#
#   differential   maglev vs ignition, same input, normalized output;
#   assert-types   --maglev-assert-types, which turns a KNA type read into a
#                  CheckMaglevType node that traps when the runtime value
#                  disagrees with the compile-time fact (MaglevReducer::
#                  GetType is its only emitter, so this observes the
#                  consumers of the elided proof, not the elision itself).
#
# Both are deterministic: same binary, same input, same answer. The
# injected-fault canary (`dgf.py canary`) exists to prove they *would* fire
# if the proof were wrong. A candidate that only fires against the canary
# build is the canary's own footprint and is discarded; a candidate that
# fires on the clean build is a compiler bug candidate.
# --------------------------------------------------------------------------

ASSERT_TYPE_MARKER = "CheckMaglevType failed"


def assert_types_result(d8: Path, target: dict, testcase: Path, timeout: float,
                        extra_flags: Sequence[str] = ()) -> D8Result:
    flags = maglev_flags(
        target, list(extra_flags) + ["--maglev-assert-types"], trace=False)
    return run_d8(d8, testcase, flags, timeout)


def fires(result: D8Result) -> bool:
    """True when a detector observed a violation, not merely a bad exit."""
    if result.timed_out:
        return False
    return (result.crashed or result.returncode > 0 or
            ASSERT_TYPE_MARKER in result.output)


@dataclasses.dataclass
class Verdict:
    target_id: str
    testcase: str
    reached: bool
    missing: list[str]
    divergence: str | None
    assert_fires: bool
    canary: bool
    canary_divergence: str | None
    canary_assert_fires: bool
    verdict: str

    def to_json(self) -> dict:
        return dataclasses.asdict(self)


def classify(reached: bool, clean_fires: bool, canary_fires: bool) -> str:
    if not reached:
        return "unreached"
    if clean_fires:
        return "candidate"
    if canary_fires:
        return "canary-only"
    return "clean"


MAGLEV_CRASH_RE = re.compile(r"maglev", re.I)


def _crashed_in_maglev(target: dict, result: D8Result) -> bool:
    """True when a crashed run names Maglev itself, not an unrelated fatal.

    A crash is evidence of reachability only if the report points into Maglev:
    `../../src/maglev/...` in the stack, `MaglevGraphBuilder::...`, and so
    on. Without that, a candidate that dies in some other subsystem would be
    counted as having reached the target.
    """
    return result.crashed and bool(MAGLEV_CRASH_RE.search(result.output))


def verify_candidate(target: dict, d8: Path, canary: Path | None,
                     testcase: Path, timeout: float,
                     extra_flags: Sequence[str] = ()) -> Verdict:
    trace = run_d8(d8, testcase, maglev_flags(target, extra_flags), timeout)
    hits = count_hits(target, trace.output)
    missing = missing_patterns(target, hits)
    # A Maglev crash in the trace run already proves the input reached it.
    reached = not missing or _crashed_in_maglev(target, trace)
    _, _, divergence = differential_check(d8, target, testcase, timeout,
                                          extra_flags)
    assert_fires = fires(
        assert_types_result(d8, target, testcase, timeout, extra_flags))
    clean_fires = divergence is not None or assert_fires

    canary_divergence = None
    canary_assert_fires = False
    if canary is not None:
        _, _, canary_divergence = differential_check(canary, target, testcase,
                                                     timeout, extra_flags)
        canary_assert_fires = fires(assert_types_result(
            canary, target, testcase, timeout, extra_flags))
    canary_fires = canary_divergence is not None or canary_assert_fires

    return Verdict(
        target_id=target["id"],
        testcase=str(testcase),
        reached=reached,
        missing=missing,
        divergence=divergence,
        assert_fires=assert_fires,
        canary=canary is not None,
        canary_divergence=canary_divergence,
        canary_assert_fires=canary_assert_fires,
        verdict=classify(reached, clean_fires, canary_fires),
    )


def print_verdict(verdict: Verdict, verbose: bool = False) -> None:
    print(f"[{verdict.verdict.upper()}] {verdict.testcase}")
    detectors = [
        "differential=" + ("FIRES" if verdict.divergence else "-"),
        "assert-types=" + ("FIRES" if verdict.assert_fires else "-"),
    ]
    if verdict.canary:
        canary_fires = bool(verdict.canary_divergence or
                            verdict.canary_assert_fires)
        detectors.append("canary=" + ("FIRES" if canary_fires else "-"))
    print("        " + " ".join(detectors))
    if verdict.missing:
        print("        missing: " + ", ".join(verdict.missing))
    if verdict.divergence:
        print(f"        divergence: {verdict.divergence}")
    if verdict.canary_divergence:
        print(f"        canary divergence: {verdict.canary_divergence}")


def cmd_verify(args, targets: list[dict]) -> int:
    d8 = require_d8(Path(args.d8) if args.d8 else default_d8())
    canary = None
    if args.canary_d8:
        canary = require_d8(Path(args.canary_d8))
        if not Path(str(canary) + ".json").exists():
            print(f"warning: {canary} has no {Path(str(canary)).name}.json; "
                  f"build it with `dgf.py canary --fault ID`", file=sys.stderr)

    known = {target["id"]: target for target in targets}
    jobs: list[tuple[dict, Path]] = []
    for item in args.items:
        if item in known:
            jobs.append((known[item], seed_path(known[item])))
        elif args.target:
            # Resolve: d8 runs with cwd set to the testcase's directory.
            jobs.append((find_target(targets, args.target),
                         Path(item).expanduser().resolve()))
        else:
            raise SystemExit(
                f"{item}: not a target id; pass --target to verify a file")

    verdicts = []
    for target, testcase in jobs:
        if not testcase.exists():
            raise SystemExit(f"missing candidate {testcase}")
        verdict = verify_candidate(target, d8, canary, testcase, args.timeout,
                                   args.extra_flag)
        verdicts.append(verdict)
        if not args.json:
            print_verdict(verdict, verbose=args.verbose)

    if args.json:
        print(json.dumps([v.to_json() for v in verdicts], indent=1))
    counts = collections.Counter(v.verdict for v in verdicts)
    summary = ", ".join(f"{name}={count}" for name, count in
                        sorted(counts.items()))
    # Keep stdout parseable in --json mode: the summary goes to stderr.
    print(f"\n{len(verdicts)} candidate(s): {summary}",
          file=sys.stderr if args.json else sys.stdout)
    return 1 if counts.get("candidate") else 0


def git_apply(patch: Path, reverse: bool) -> None:
    cmd = ["git", "apply", "-p1"] + (["-R"] if reverse else []) + [str(patch)]
    proc = subprocess.run(cmd, cwd=str(V8_ROOT), capture_output=True,
                          text=True)
    if proc.returncode != 0:
        raise SystemExit(f"{' '.join(cmd)}\n{proc.stderr.strip()}")


def cmd_canary(args, targets: list[dict]) -> int:
    faults = json.loads((CANARY_DIR / "faults.json").read_text())["faults"]
    if args.list:
        width = max(len(f["id"]) for f in faults)
        for fault in faults:
            print(f"{fault['id']:<{width}}  {fault['channel']:<38}  "
                  f"{fault['summary']}"
                  + ("" if fault.get("validated") else "  [not built yet]"))
        return 0
    if not args.fault:
        raise SystemExit("pass --fault ID (or --list)")
    fault = next((f for f in faults if f["id"] == args.fault), None)
    if fault is None:
        raise SystemExit(f"unknown fault {args.fault!r}; try --list")

    patch = HERE / fault["patch"]
    config = Path(args.config)
    install = (Path(args.install) if args.install
               else config / "d8.dgf-canary")
    clean_copy = config / "d8.dgf-clean"
    print(f"[canary] {fault['id']}: {fault['summary']}")

    if args.revert:
        git_apply(patch, reverse=True)
        print(f"[canary] reverted {patch.name}; rebuild with "
              f"{args.builder} -C {config} d8")
        return 0

    # Keep a clean reference binary: `verify --d8 <clean> --canary-d8 <canary>`
    # needs both at once, and the build directory holds only one.
    if (config / "d8").exists() and not clean_copy.exists():
        shutil.copy2(config / "d8", clean_copy)
        print(f"[canary] kept the clean reference as {clean_copy}")

    print(f"[canary] applying {patch.name}")
    git_apply(patch, reverse=False)
    if args.apply_only:
        return 0

    print(f"[canary] building d8 in {config} (this is a real build)")
    if subprocess.run([args.builder, "-C", str(config), "d8"],
                      cwd=str(V8_ROOT)).returncode != 0:
        print("[canary] build failed; the patch is still applied "
              f"(revert with: dgf.py canary --fault {fault['id']} --revert)",
              file=sys.stderr)
        return 1

    shutil.copy2(config / "d8", install)
    meta = Path(str(install) + ".json")
    meta.write_text(json.dumps({
        "fault": fault["id"],
        "patch": fault["patch"],
        "config": str(config),
        "validated": fault.get("validated", False),
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }, indent=1) + "\n")
    print(f"[canary] installed {install} (+ {meta.name})")

    if args.keep_source:
        print("[canary] patch left applied (--keep-source)")
        return 0
    print(f"[canary] reverting {patch.name}")
    git_apply(patch, reverse=True)
    print(f"[canary] rebuilding the clean d8")
    if subprocess.run([args.builder, "-C", str(config), "d8"],
                      cwd=str(V8_ROOT)).returncode != 0:
        return 1
    return 0


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def require_d8(path: Path) -> Path:
    # Resolve first: d8 runs with cwd set to the testcase directory.
    path = path.expanduser().resolve()
    if not path.exists():
        raise SystemExit(f"d8 not found: {path} (pass --d8 or build it)")
    return path


def cmd_targets(args, targets: list[dict]) -> int:
    if args.json:
        print(json.dumps(targets, indent=1))
        return 0
    width = max(len(t["id"]) for t in targets)
    for target in targets:
        flags = " ".join(target.get("trace_flags") or []) or "-"
        print(f"{target['id']:<{width}}  {target['subsystem']:<20}  "
              f"{target['seed']:<38}  {flags}")
    return 0


def cmd_check(args, targets: list[dict]) -> int:
    d8 = require_d8(Path(args.d8) if args.d8 else default_d8())
    ids = args.ids or [t["id"] for t in targets]
    reports = []
    for target_id in ids:
        target = find_target(targets, target_id)
        report = check_target(
            d8,
            target,
            args.timeout,
            differential=not args.no_differential,
            extra_flags=args.extra_flag,
        )
        reports.append(report)
        if not args.json:
            print_report(report, verbose=args.verbose)
    if args.json:
        print(json.dumps([r.to_json() for r in reports], indent=1))
    failed = [r for r in reports if not r.ok]
    # Keep stdout parseable in --json mode: the summary goes to stderr.
    summary = (f"\n{len(reports) - len(failed)}/{len(reports)} targets reached "
               f"without divergence")
    print(summary, file=sys.stderr if args.json else sys.stdout)
    return 0 if not failed else 1




def cmd_fuzz(args, targets: list[dict]) -> int:
    d8 = require_d8(Path(args.d8) if args.d8 else default_d8())
    target = find_target(targets, args.target)
    seed = Path(args.seed_file) if args.seed_file else seed_path(target)
    base = seed.read_text()
    rng = random.Random(args.random_seed)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    log = open(args.log, "a") if args.log else None

    stats = {
        "mutants": 0,
        "applied": 0,
        "hit": 0,
        "miss": 0,
        "seed_broken": 0,
        "divergence": 0,
    }
    divergences: list[tuple[Path, TargetReport]] = []
    try:
        for i in range(args.iterations):
            num_ops = rng.randint(1, max(1, args.max_mutations))
            src, applied = mutate_source(base, rng, num_ops)
            if not applied:
                continue
            stats["mutants"] += 1
            stats["applied"] += len(applied)
            with tempfile.TemporaryDirectory(prefix="dgf-") as tmp:
                testcase = Path(tmp) / f"{seed.stem}_{i:04d}.js"
                testcase.write_text(src)
                report = check_target(d8, target, args.timeout,
                                      differential=True, testcase=testcase)
            # A mutant that breaks the seed's own value check invalidates the
            # oracle for this input (the expected value moved, not the
            # compiler), so it is not counted as a divergence.
            if (report.baseline is None or report.baseline.self_check_failed
                    or report.baseline.crashed):
                stats["seed_broken"] += 1
                continue
            if report.hit:
                stats["hit"] += 1
            else:
                stats["miss"] += 1
                if args.require_hit:
                    continue
            if report.divergence:
                stats["divergence"] += 1
                path = outdir / f"{target['id']}-{i:04d}.js"
                path.write_text(src)
                divergences.append((path, report))
                print(f"[DIFF] {path} ({'+'.join(applied)})")
                print(f"       {report.divergence}")
            if log:
                record = report.to_json()
                record.update({"iteration": i, "mutators": applied})
                log.write(json.dumps(record) + "\n")
                log.flush()
    finally:
        if log:
            log.close()

    print(f"\ntarget={target['id']} seed={seed.name} "
          f"mutants={stats['mutants']} hit={stats['hit']} "
          f"miss={stats['miss']} seed_broken={stats['seed_broken']} "
          f"divergences={stats['divergence']}")
    return 1 if divergences else 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--targets", default=str(DEFAULT_TARGETS),
                        help="target catalog (default: %(default)s)")
    common.add_argument("--d8", default=None,
                        help="d8 binary (default: newest fuzzing build)")
    common.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="per-run timeout in seconds")

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("targets", parents=[common],
                       help="list the target catalog")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("check", parents=[common],
                       help="run seeds and assert the target is reached")
    p.add_argument("ids", nargs="*", help="target ids (default: all)")
    p.add_argument("--json", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-differential", action="store_true")
    p.add_argument("--extra-flag", action="append", default=[],
                   help="extra d8 flag, may be repeated")

    p = sub.add_parser("fuzz", parents=[common],
                       help="mutate a seed and diff the mutants")
    p.add_argument("--target", required=True)
    p.add_argument("--iterations", type=int, default=20)
    p.add_argument("--max-mutations", type=int, default=2,
                   help="upper bound on mutators per mutant")
    p.add_argument("--random-seed", type=int, default=None)
    p.add_argument("--seed-file", default=None,
                   help="mutate this file instead of the target's seed")
    p.add_argument("--out", default=str(HERE / "mutants"),
                   help="directory for diverging mutants")
    p.add_argument("--log", default=None, help="append JSONL results here")
    p.add_argument("--allow-miss", dest="require_hit", action="store_false",
                   help="also report divergences that miss the target")

    p = sub.add_parser("direct", parents=[common],
                       help="mutate the values that control a proof")
    p.add_argument("--target", required=True)
    p.add_argument("--iterations", type=int, default=20,
                   help="slot combinations to try (all of them if fewer), or "
                        "expansions under --strategy=best-first")
    p.add_argument("--strategy", choices=("random", "best-first"),
                   default="random",
                   help="candidate order: 'random' samples slot "
                        "combinations, 'best-first' expands the candidate "
                        "closest to the elision (needs directed.distance)")
    p.add_argument("--random-seed", type=int, default=None)
    p.add_argument("--out", default=str(HERE / "mutants"),
                   help="directory for new-path and diverging candidates")
    p.add_argument("--corpus", default=str(DEFAULT_CORPUS),
                   help="path-signature corpus (default: %(default)s)")
    p.add_argument("--log", default=None, help="append JSONL results here")
    p.add_argument("--keep-all", action="store_true",
                   help="save every candidate, not only the interesting ones")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--extra-flag", action="append", default=[],
                   help="extra d8 flag, may be repeated")

    p = sub.add_parser("verify", parents=[common],
                       help="deterministic verification of a candidate")
    p.add_argument("items", nargs="+",
                   help="candidate files, or target ids (their seeds)")
    p.add_argument("--target", default=None,
                   help="target whose trace flags to use for file arguments")
    p.add_argument("--canary-d8", default=None,
                   help="injected-fault build, from `canary --fault ID`")
    p.add_argument("--json", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--extra-flag", action="append", default=[],
                   help="extra d8 flag, may be repeated")

    p = sub.add_parser("canary", parents=[common],
                       help="build a d8 with one proof trusted blindly")
    p.add_argument("--list", action="store_true")
    p.add_argument("--fault", default=None)
    p.add_argument("--config", default="out/x64.asan-fuzz",
                   help="build directory to patch and build "
                        "(default: %(default)s)")
    p.add_argument("--install", default=None,
                   help="where to copy the canary d8 "
                        "(default: <config>/d8.dgf-canary)")
    p.add_argument("--builder", default="autoninja")
    p.add_argument("--apply-only", action="store_true",
                   help="apply the patch and stop")
    p.add_argument("--keep-source", action="store_true",
                   help="apply, build and install, but leave the patch applied")
    p.add_argument("--revert", action="store_true",
                   help="revert the patch of --fault and stop")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    targets = load_targets(Path(args.targets))
    if args.cmd == "targets":
        return cmd_targets(args, targets)
    if args.cmd == "check":
        return cmd_check(args, targets)
    if args.cmd == "fuzz":
        return cmd_fuzz(args, targets)
    if args.cmd == "direct":
        return cmd_direct(args, targets)
    if args.cmd == "verify":
        return cmd_verify(args, targets)
    if args.cmd == "canary":
        return cmd_canary(args, targets)
    raise SystemExit(f"unknown command {args.cmd}")


if __name__ == "__main__":
    sys.exit(main())

