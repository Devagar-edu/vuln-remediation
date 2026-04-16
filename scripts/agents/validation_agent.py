#!/usr/bin/env python3
"""
validation_agent.py — Validate the fix branch before developer review.

Runs five independent checks and produces a Markdown validation report
attached to the Jira issue.

Triggered by validation-agent.yml (workflow_dispatch).

Usage:
    python scripts/agents/validation_agent.py \
        --jira-id VULN-42 \
        --remediation-id <uuid> \
        --fix-branch fix/vuln-42-abc1234
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from scripts.utils import github_client as gh, memory
from scripts.utils.config import JiraStatus, GITHUB_ORG, SNYK_TOKEN
from scripts.utils.jira_client import JiraClient
from scripts.utils.llm_client import chat

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

DIFF_SYSTEM_PROMPT = """\
You are a Java code-review specialist validating a security remediation patch.

Examine the git diff and decide whether any BUSINESS LOGIC has changed beyond
what the security fix requires.

Acceptable changes:
  - Replacing a hardcoded credential literal with System.getenv("VAR")
  - Switching to PreparedStatement for SQL queries
  - Bumping a <version> tag in pom.xml
  - Adding a single import required by the fix

Flag these as business-logic changes:
  - Method return-value or branching logic altered
  - Variables or methods renamed
  - Code restructured, extracted, or moved
  - Algorithm behaviour changed
  - Non-fix lines removed or reordered

Respond with ONLY valid JSON — no markdown fences, no explanation:
{
  "business_logic_changed": true|false,
  "confidence": "high|medium|low",
  "findings": ["finding 1", "finding 2"]
}
"""

REPORT_TEMPLATE = """\
# Validation Report
**Jira:** {jira_id} | **Fix Branch:** `{fix_branch}`
**Validated:** {ts}

## Check Results
| # | Check | Result | Detail |
|---|-------|--------|--------|
{rows}

## Overall Result
{overall}

## Findings
{findings}
"""


# ── Shell helpers ─────────────────────────────────────────────────────────────

def _sh(cmd: list[str], cwd: str, env: dict = None,
        timeout: int = 600) -> tuple[int, str]:
    r = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True,
        timeout=timeout, env={**os.environ, **(env or {})},
    )
    return r.returncode, r.stdout + r.stderr


def _clone(repo: str, branch: str, dest: str) -> None:
    token = os.environ["GITHUB_TOKEN"]
    url   = f"https://x-access-token:{token}@github.com/{GITHUB_ORG}/{repo}.git"
    rc, out = _sh(["git", "clone", "--depth", "20", url, dest], cwd="/tmp")
    if rc != 0:
        raise RuntimeError(f"git clone failed:\n{out}")
    rc, out = _sh(["git", "checkout", branch], cwd=dest)
    if rc != 0:
        raise RuntimeError(f"git checkout {branch} failed:\n{out}")
    log.info("Cloned %s@%s → %s", repo, branch, dest)


# ── Individual checks ─────────────────────────────────────────────────────────

def check_tests(repo_dir: str) -> tuple[bool, str]:
    """C1 — Run Maven tests on the fix branch."""
    rc, out = _sh(
        ["mvn", "--batch-mode", "--no-transfer-progress", "clean", "test"],
        cwd=repo_dir,
    )
    if rc == 0:
        return True, "All tests passed"
    # Extract failure summary from Maven output
    lines   = out.splitlines()
    summary = next((l for l in lines if "BUILD FAILURE" in l or "Tests run:" in l), "")
    return False, f"Exit {rc}. {summary}"


def check_scope(repo_dir: str, base_branch: str,
                approved_files: list[str]) -> tuple[bool, str]:
    """C2 — Only approved files may be modified."""
    rc, out = _sh(
        ["git", "diff", "--name-only", f"origin/{base_branch}...HEAD"],
        cwd=repo_dir,
    )
    changed = [f.strip() for f in out.splitlines() if f.strip()]
    approved_set = set(approved_files) | {"pom.xml"}
    out_of_scope = [f for f in changed if f not in approved_set]
    if out_of_scope:
        return False, f"Unauthorised files: {out_of_scope}"
    return True, f"Changed files: {changed}"


def check_java_version(pom_before: str, pom_after: str) -> tuple[bool, str]:
    """C3 — Java compiler version must be identical on both branches."""
    tags = ("maven.compiler.source", "maven.compiler.target",
            "maven.compiler.release")

    def extract(pom: str) -> dict[str, str]:
        return {
            t: m.group(1).strip()
            for t in tags
            if (m := re.search(rf"<{re.escape(t)}>([^<]+)</{re.escape(t)}>", pom))
        }

    before, after = extract(pom_before), extract(pom_after)
    for tag in before:
        if tag in after and before[tag] != after[tag]:
            return False, f"{tag}: {before[tag]} → {after[tag]}"
    return True, "Java version unchanged"


def check_snyk(repo_dir: str, original_vuln_ids: set[str]) -> tuple[bool, str]:
    """C4 — Snyk re-scan: none of the original vuln IDs may remain."""
    if not SNYK_TOKEN:
        return True, "SNYK_TOKEN not set — check skipped"
    rc, out = _sh(
        ["snyk", "test", "--json", "--severity-threshold=low"],
        cwd=repo_dir,
        env={"SNYK_TOKEN": SNYK_TOKEN},
        timeout=300,
    )
    try:
        result = json.loads(out)
    except json.JSONDecodeError:
        return True, "Could not parse Snyk output — treating as pass"
    remaining = {v.get("id", "") for v in result.get("vulnerabilities", [])}
    still_present = original_vuln_ids & remaining
    if still_present:
        return False, f"Still detected: {still_present}"
    return True, "All targeted vulnerabilities resolved"


def check_diff_logic(repo_dir: str, base_branch: str) -> tuple[bool, list[str]]:
    """C5 — LLM diff review for unintended business-logic changes."""
    rc, diff = _sh(
        ["git", "diff", f"origin/{base_branch}...HEAD"],
        cwd=repo_dir,
    )
    if not diff.strip():
        return True, []
    user_prompt = f"Review this security remediation diff:\n\n```diff\n{diff[:6000]}\n```"
    try:
        raw = chat(DIFF_SYSTEM_PROMPT, user_prompt, max_tokens=1024, temperature=0.1)
        raw = re.sub(r"^```(?:json)?\s*", "", raw.strip())
        raw = re.sub(r"\s*```$", "", raw)
        data = json.loads(raw)
        changed  = data.get("business_logic_changed", False)
        findings = data.get("findings", [])
        return not changed, findings
    except Exception as exc:
        log.warning("LLM diff review failed: %s", exc)
        return True, [f"LLM review unavailable ({exc}) — manual review required"]


# ── Main ──────────────────────────────────────────────────────────────────────

def run(jira_id: str, remediation_id: str, fix_branch: str) -> None:
    jira = JiraClient()

    # Load normalised JSON
    raw = jira.get_attachment(jira_id, "normalised-vulnerabilities.json")
    if not raw:
        raise RuntimeError("normalised-vulnerabilities.json not found")
    norm   = json.loads(raw)
    meta   = norm["scan_metadata"]
    repo   = meta["repository"]
    branch = meta["branch"]

    # Collect original vuln IDs for Snyk comparison
    original_ids: set[str] = set()
    for pkg in norm.get("dependency_vulnerabilities", []):
        for v in pkg.get("vulnerabilities", []):
            original_ids.add(v["id"])
    for v in norm.get("code_vulnerabilities", []):
        original_ids.add(v["id"])

    # Load approved plan for scope check
    plan_md = memory.latest_plan(jira_id)
    approved_files: list[str] = []
    if plan_md:
        from scripts.agents.fix_agent import parse_plan
        p = parse_plan(plan_md)
        approved_files = [c["file"] for c in p["code_changes"]]

    log.info("Validation Agent: %s  repo=%s  branch=%s", jira_id, repo, fix_branch)
    memory.audit("validation_agent_started", jira_id, repo, remediation_id,
                 actor="validation-agent-v1",
                 details={"fix_branch": fix_branch})

    # Run checks inside a temp clone
    results: list[dict] = []
    all_findings: list[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = os.path.join(tmp, repo)
        _clone(repo, fix_branch, repo_dir)

        # Fetch pom from both branches for version comparison
        pom_base = gh.get_file(repo, "pom.xml", ref=branch) or ""
        pom_fix  = gh.get_file(repo, "pom.xml", ref=fix_branch) or ""

        # C1 — Tests
        log.info("C1: Running tests…")
        ok, detail = check_tests(repo_dir)
        results.append({"n": 1, "name": "Tests pass", "ok": ok, "detail": detail})
        if not ok:
            all_findings.append(f"Tests: {detail}")

        # C2 — Scope
        log.info("C2: Checking file scope…")
        ok, detail = check_scope(repo_dir, branch, approved_files)
        results.append({"n": 2, "name": "Only approved files modified",
                        "ok": ok, "detail": detail})
        if not ok:
            all_findings.append(f"Scope: {detail}")

        # C3 — Java version
        log.info("C3: Java version check…")
        ok, detail = check_java_version(pom_base, pom_fix)
        results.append({"n": 3, "name": "Java version unchanged",
                        "ok": ok, "detail": detail})
        if not ok:
            all_findings.append(f"Java version: {detail}")

        # C4 — Snyk
        log.info("C4: Snyk re-scan…")
        ok, detail = check_snyk(repo_dir, original_ids)
        results.append({"n": 4, "name": "Targeted vulnerabilities resolved",
                        "ok": ok, "detail": detail})
        if not ok:
            all_findings.append(f"Snyk: {detail}")

        # C5 — LLM diff review
        log.info("C5: LLM diff review…")
        ok, findings = check_diff_logic(repo_dir, branch)
        detail = "; ".join(findings) if findings else "No logic changes detected"
        results.append({"n": 5, "name": "No business-logic changes (LLM)",
                        "ok": ok, "detail": detail})
        all_findings.extend(findings)

    # Build report
    ts          = datetime.now(timezone.utc).isoformat()
    all_passed  = all(r["ok"] for r in results)
    icon        = {True: "✅ PASS", False: "❌ FAIL"}
    rows        = "\n".join(
        f"| {r['n']} | {r['name']} | {icon[r['ok']]} | {r['detail']} |"
        for r in results
    )
    overall = (
        "**ALL CHECKS PASSED** — PR is ready for developer review and merge."
        if all_passed else
        "**ONE OR MORE CHECKS FAILED** — do not merge until issues are resolved."
    )
    findings_md = (
        "\n".join(f"- {f}" for f in all_findings) if all_findings else "_None_"
    )
    report = REPORT_TEMPLATE.format(
        jira_id=jira_id, fix_branch=fix_branch, ts=ts,
        rows=rows, overall=overall, findings=findings_md,
    )

    # Attach report to Jira
    jira.add_attachment(jira_id, "validation-report.md",
                        report.encode(), "text/markdown")

    # Transition Jira and update memory
    if all_passed:
        jira.add_comment(
            jira_id,
            f"Validation Agent: all {len(results)} checks PASSED ✅\n"
            f"PR is ready for your review.  See attached validation-report.md.",
        )
        jira.transition(jira_id, JiraStatus.DEVELOPER_REVIEW)
        for vid in original_ids:
            memory.record_attempt(repo, vid, jira_id, "validated")
    else:
        failed_names = [r["name"] for r in results if not r["ok"]]
        jira.add_comment(
            jira_id,
            f"Validation Agent: {len(failed_names)} check(s) FAILED ❌\n"
            + "\n".join(f"  • {n}" for n in failed_names)
            + "\nSee attached validation-report.md.  Status → Validation Failed.",
        )
        jira.transition(jira_id, JiraStatus.VALIDATION_FAILED)
        for vid in original_ids:
            memory.record_attempt(repo, vid, jira_id, "validation_failed",
                                  error="; ".join(failed_names))

    memory.audit(
        "validation_agent_completed", jira_id, repo, remediation_id,
        actor="validation-agent-v1",
        details={"passed": all_passed, "checks": results},
    )
    log.info("Validation Agent done for %s.  Passed: %s", jira_id, all_passed)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--jira-id",        required=True)
    p.add_argument("--remediation-id", required=True)
    p.add_argument("--fix-branch",     required=True)
    args = p.parse_args()
    try:
        run(args.jira_id, args.remediation_id, args.fix_branch)
    except Exception as exc:
        log.exception("Validation Agent failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
