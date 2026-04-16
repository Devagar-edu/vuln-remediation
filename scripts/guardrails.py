"""
guardrails.py — Hard guardrail checks run by the Fix Agent before committing.

All checks are pure functions that accept before/after state and raise
GuardrailError on violation.  The Fix Agent calls run_all() which collects
every failure and raises a single combined error so the agent sees all
violations at once.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


class GuardrailError(RuntimeError):
    """Raised when one or more guardrails are violated."""


@dataclass
class Result:
    name:    str
    passed:  bool
    detail:  str


# ── Individual guardrails ─────────────────────────────────────────────────────

def g1_java_version_unchanged(pom_before: str, pom_after: str) -> Result:
    """G1 — Java compiler source/target/release must not change."""
    tags = ("maven.compiler.source", "maven.compiler.target",
            "maven.compiler.release", "java.version")

    def extract(pom: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for tag in tags:
            m = re.search(rf"<{re.escape(tag)}>([^<]+)</{re.escape(tag)}>", pom)
            if m:
                out[tag] = m.group(1).strip()
        return out

    before = extract(pom_before)
    after  = extract(pom_after)
    for tag in before:
        if tag in after and before[tag] != after[tag]:
            return Result("G1: Java version unchanged", False,
                          f"{tag} changed: {before[tag]} → {after[tag]}")
    return Result("G1: Java version unchanged", True, "OK")


def g2_scope_respected(changed_files: list[str], approved_files: list[str]) -> Result:
    """G2 — No file outside the approved list may be modified."""
    always_ok = {"pom.xml"}
    approved  = set(approved_files) | always_ok
    out_of_scope = [f for f in changed_files if f not in approved]
    if out_of_scope:
        return Result("G2: Scope respected", False,
                      f"Unauthorised files modified: {out_of_scope}")
    return Result("G2: Scope respected", True,
                  f"Only approved files changed: {changed_files}")


def g3_no_new_dependencies(pom_before: str, pom_after: str) -> Result:
    """G3 — The number of <dependency> blocks must not increase."""
    def count(pom: str) -> int:
        return len(re.findall(r"<dependency>", pom))

    before, after = count(pom_before), count(pom_after)
    if after > before:
        return Result("G3: No new dependencies", False,
                      f"<dependency> count increased {before} → {after}")
    return Result("G3: No new dependencies", True, f"Count unchanged ({before})")


def g4_line_delta(original: str, fixed: str, max_ratio: float = 2.5) -> Result:
    """G4 — The line-count delta must not exceed max_ratio × original."""
    orig_n  = max(original.count("\n"), 1)
    fixed_n = fixed.count("\n")
    delta   = abs(fixed_n - orig_n)
    if delta > orig_n * max_ratio:
        return Result("G4: Line delta within tolerance", False,
                      f"Delta {delta} exceeds {max_ratio}× original ({orig_n} lines)")
    return Result("G4: Line delta within tolerance", True,
                  f"Delta {delta} within {max_ratio}× of {orig_n} lines")


def g5_no_method_signature_change(original: str, fixed: str) -> Result:
    """
    G5 — Public/protected method signatures must not change.
    Uses a simple regex to extract method declarations and compares sets.
    """
    sig_re = re.compile(
        r"(?:public|protected)\s+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)"
    )

    def sigs(src: str) -> set[str]:
        return set(sig_re.findall(src))

    before = sigs(original)
    after  = sigs(fixed)
    removed = before - after
    added   = after  - before

    # Removed signatures = renamed or deleted — flag both
    issues = []
    if removed:
        issues.append(f"Removed signatures: {removed}")
    if added:
        issues.append(f"Added signatures (possible renames): {added}")

    if issues:
        return Result("G5: No method signature changes", False, "; ".join(issues))
    return Result("G5: No method signature changes", True, "No signature changes")


# ── Aggregator ────────────────────────────────────────────────────────────────

def run_all(
    pom_before:     str,
    pom_after:      str,
    changed_files:  list[str],
    approved_files: list[str],
    file_diffs: list[tuple[str, str]] = None,  # [(original, fixed), …]
) -> list[Result]:
    """
    Run all guardrails and return the full result list.
    Raises GuardrailError if any guardrail fails.
    """
    results: list[Result] = [
        g1_java_version_unchanged(pom_before, pom_after),
        g2_scope_respected(changed_files, approved_files),
        g3_no_new_dependencies(pom_before, pom_after),
    ]

    if file_diffs:
        for original, fixed in file_diffs:
            results.append(g4_line_delta(original, fixed))
            results.append(g5_no_method_signature_change(original, fixed))

    failures = [r for r in results if not r.passed]
    if failures:
        msgs = "\n".join(f"  ✗ {r.name}: {r.detail}" for r in failures)
        raise GuardrailError(f"Guardrail violation(s):\n{msgs}")

    return results
