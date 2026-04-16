#!/usr/bin/env python3
"""
fix_agent.py — Apply an approved remediation plan to pom.xml and source files,
               then raise a Pull Request.

Triggered by fix-agent.yml (workflow_dispatch).  The workflow must have
already checked out the target repository before calling this script.

Usage:
    python scripts/agents/fix_agent.py \
        --jira-id VULN-42 --remediation-id <uuid>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from scripts.guardrails import run_all, GuardrailError
from scripts.utils import github_client as gh, memory
from scripts.utils.config import JiraStatus, GITHUB_ORG
from scripts.utils.jira_client import JiraClient
from scripts.utils.llm_client import chat

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

# ── LLM system prompt for source-code fixes ───────────────────────────────────
FIX_SYSTEM_PROMPT = """\
You are a Java security engineer.  Apply the minimal fix described in the
remediation instructions to the Java source file provided.

STRICT RULES:
1. Modify ONLY the exact lines specified.  Do not touch any other code.
2. Never change method signatures, class names, or package declarations.
3. Never add imports beyond what the fix strictly requires.
4. Never rename variables, methods, or fields.
5. Never add comments except a single  // SECURITY-FIX: <CVE-ID>  on the
   changed line.
6. Hardcoded credentials → replace with  System.getenv("VAR_NAME")
7. SQL injection → use PreparedStatement with parameter placeholders.
8. Output ONLY the complete fixed file.  No markdown fences, no explanation.
"""


# ── Plan parser ───────────────────────────────────────────────────────────────

def parse_plan(md: str) -> dict:
    """
    Parse the approved Markdown plan document.
    Returns:
      dep_changes  : [{group_id, artifact_id, fix_version}]
      code_changes : [{file, line, description}]
      vuln_ids     : [str]
    """
    dep_changes:  list[dict] = []
    code_changes: list[dict] = []
    vuln_ids:     list[str]  = []

    section = None
    for line in md.splitlines():
        stripped = line.strip()
        if "Dependency Changes" in stripped:
            section = "dep"
        elif "Code Changes" in stripped:
            section = "code"
        elif "Vulnerability Summary" in stripped:
            section = "vuln"
        elif stripped.startswith("## "):
            section = None

        if not stripped.startswith("|") or stripped.startswith("|--") or \
                stripped.startswith("| Dep") or stripped.startswith("| File") or \
                stripped.startswith("| ID"):
            continue

        cols = [c.strip() for c in stripped.split("|") if c.strip()]

        if section == "dep" and len(cols) >= 3:
            dep_str  = cols[0]   # "groupId:artifactId"
            fix_ver  = cols[2]   # fix version column
            if ":" in dep_str:
                gid, aid = dep_str.split(":", 1)
                dep_changes.append({
                    "group_id":    gid.strip(),
                    "artifact_id": aid.strip(),
                    "fix_version": fix_ver.strip(),
                })

        elif section == "code" and len(cols) >= 3:
            try:
                code_changes.append({
                    "file":        cols[0],
                    "line":        int(cols[1]) if cols[1].isdigit() else 0,
                    "description": cols[2] if len(cols) > 2 else "",
                })
            except (ValueError, IndexError):
                pass

        elif section == "vuln" and cols:
            vid = cols[0]
            if vid and vid.upper().startswith(("SNYK-", "CVE-")):
                vuln_ids.append(vid)

    return {"dep_changes": dep_changes,
            "code_changes": code_changes,
            "vuln_ids": vuln_ids}


# ── pom.xml updater ───────────────────────────────────────────────────────────

def update_pom(pom: str, dep_changes: list[dict]) -> str:
    """Update <version> tags for specified dependencies.  Returns modified pom."""
    result = pom
    for dep in dep_changes:
        gid, aid, ver = dep["group_id"], dep["artifact_id"], dep["fix_version"]
        pattern = (
            r"(<dependency>.*?<groupId>"
            + re.escape(gid)
            + r"</groupId>.*?<artifactId>"
            + re.escape(aid)
            + r"</artifactId>.*?<version>)[^<]*(</version>)"
        )
        new_pom, n = re.subn(pattern, rf"\g<1>{ver}\g<2>", result, flags=re.DOTALL)
        if n:
            result = new_pom
            log.info("pom.xml: %s:%s  →  %s", gid, aid, ver)
        else:
            log.warning("pom.xml: could not find %s:%s to update", gid, aid)
    return result


# ── Source fixer via LLM ──────────────────────────────────────────────────────

def fix_source_file(repo: str, branch: str, file_path: str,
                    changes: list[dict], plan_context: str) -> tuple[str, str]:
    """
    Call the LLM to fix one source file.
    Returns (original_content, fixed_content).
    """
    original = gh.get_file(repo, file_path, ref=branch)
    if original is None:
        raise FileNotFoundError(f"File not found: {repo}/{file_path}@{branch}")

    change_desc = "\n".join(
        f"Line {c['line']}: {c['description']}" for c in changes
    )
    user_prompt = (
        f"File: {file_path}\n\n"
        f"Required changes:\n{change_desc}\n\n"
        f"Plan context:\n{plan_context[:2000]}\n\n"
        f"Original file:\n{original}"
    )

    fixed = chat(FIX_SYSTEM_PROMPT, user_prompt, max_tokens=8192, temperature=0.05)

    # Strip any accidental markdown fences
    fixed = re.sub(r"^```(?:java|xml)?\s*\n?", "", fixed.strip())
    fixed = re.sub(r"\n?```\s*$", "", fixed)

    return original, fixed


# ── Shell helpers ─────────────────────────────────────────────────────────────

def _sh(cmd: list[str], cwd: str, timeout: int = 600) -> tuple[int, str]:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def _git(args: list[str], cwd: str) -> None:
    rc, out = _sh(["git"] + args, cwd)
    if rc != 0:
        raise RuntimeError(f"git {' '.join(args)} failed:\n{out[-2000:]}")


def _clone(repo: str, branch: str, dest: str) -> None:
    token = os.environ["GITHUB_TOKEN"]
    url   = f"https://x-access-token:{token}@github.com/{GITHUB_ORG}/{repo}.git"
    rc, out = _sh(
        ["git", "clone", "--branch", branch, "--depth", "1", url, dest],
        cwd="/tmp",
    )
    if rc != 0:
        raise RuntimeError(f"git clone failed:\n{out}")
    log.info("Cloned %s@%s → %s", repo, branch, dest)


# ── Main ──────────────────────────────────────────────────────────────────────

def run(jira_id: str, remediation_id: str) -> None:
    jira = JiraClient()

    # 1. Load Jira attachments
    raw_norm = jira.get_attachment(jira_id, "normalised-vulnerabilities.json")
    if not raw_norm:
        raise RuntimeError("normalised-vulnerabilities.json not found on Jira issue")
    norm   = json.loads(raw_norm)
    meta   = norm["scan_metadata"]
    repo   = meta["repository"]
    branch = meta["branch"]

    plan_md = memory.latest_plan(jira_id)
    if not plan_md:
        raise RuntimeError(f"No approved plan found for {jira_id}")
    plan = parse_plan(plan_md)

    log.info("Fix Agent: %s  repo=%s  dep_changes=%d  code_changes=%d",
             jira_id, repo, len(plan["dep_changes"]), len(plan["code_changes"]))
    memory.audit("fix_agent_started", jira_id, repo, remediation_id,
                 actor="fix-agent-v1",
                 details={"dep": len(plan["dep_changes"]),
                          "code": len(plan["code_changes"])})

    # 2. Build fix branch name
    short = hashlib.sha1(remediation_id.encode()).hexdigest()[:7]
    fix_branch = f"fix/{jira_id.lower()}-{short}"

    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = os.path.join(tmp, repo)
        _clone(repo, branch, repo_dir)

        # Configure git identity
        _git(["config", "user.email", "ai-remediation@automation.local"], repo_dir)
        _git(["config", "user.name", "AI Remediation Bot"], repo_dir)
        _git(["checkout", "-b", fix_branch], repo_dir)

        pom_path     = os.path.join(repo_dir, "pom.xml")
        original_pom = Path(pom_path).read_text()
        new_pom      = original_pom

        # 3. Update pom.xml
        if plan["dep_changes"]:
            new_pom = update_pom(original_pom, plan["dep_changes"])
            Path(pom_path).write_text(new_pom)

        # 4. Fix source files via LLM
        file_diffs: list[tuple[str, str]] = []
        approved_source_files: list[str]  = []
        code_by_file: dict[str, list]     = {}

        for chg in plan["code_changes"]:
            code_by_file.setdefault(chg["file"], []).append(chg)

        for file_path, changes in code_by_file.items():
            original, fixed = fix_source_file(repo, branch, file_path,
                                               changes, plan_md)
            file_diffs.append((original, fixed))
            approved_source_files.append(file_path)

            abs_path = os.path.join(repo_dir, file_path.replace("/", os.sep))
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            Path(abs_path).write_text(fixed)
            log.info("Fixed: %s", file_path)

        # 5. Run guardrails BEFORE committing
        changed_files = approved_source_files + (["pom.xml"] if plan["dep_changes"] else [])
        try:
            run_all(
                pom_before     = original_pom,
                pom_after      = new_pom,
                changed_files  = changed_files,
                approved_files = approved_source_files,
                file_diffs     = file_diffs,
            )
            log.info("All guardrails passed ✓")
        except GuardrailError as exc:
            jira.add_comment(jira_id,
                f"Fix Agent ABORTED — guardrail violation:\n{exc}")
            jira.transition(jira_id, JiraStatus.FIX_FAILED)
            raise

        # 6. Verify dependency resolution
        rc, out = _sh(["mvn", "--batch-mode", "--no-transfer-progress",
                        "dependency:resolve", "-q"], repo_dir)
        if rc != 0:
            raise RuntimeError(f"mvn dependency:resolve failed:\n{out[-3000:]}")
        log.info("Dependency resolution OK ✓")

        # 7. Compile
        rc, out = _sh(["mvn", "--batch-mode", "--no-transfer-progress",
                        "compile", "-q"], repo_dir)
        if rc != 0:
            raise RuntimeError(f"mvn compile failed:\n{out[-3000:]}")
        log.info("Compilation OK ✓")

        # 8. Run tests
        rc, test_out = _sh(["mvn", "--batch-mode", "--no-transfer-progress",
                              "test"], repo_dir)
        if rc != 0:
            jira.add_attachment(jira_id, "build-failure.log",
                                test_out.encode(), "text/plain")
            jira.add_comment(jira_id,
                "Fix Agent: tests FAILED after applying fixes. "
                "Attached build-failure.log.  Status → Fix Failed.")
            jira.transition(jira_id, JiraStatus.FIX_FAILED)
            for vid in plan["vuln_ids"]:
                memory.record_attempt(repo, vid, jira_id, "test_failed",
                                      error=test_out[-1000:])
            raise RuntimeError("Tests failed after fix")
        log.info("All tests passed ✓")

        # 9. Commit
        _git(["add", "-A"], repo_dir)
        ids_str = ", ".join(plan["vuln_ids"][:5])
        commit_msg = (
            f"fix(security): remediate {ids_str} per {jira_id}\n\n"
            f"Remediation ID : {remediation_id}\n"
            f"Approved plan  : {jira_id} (attached to Jira)\n"
            f"Files changed  : {', '.join(changed_files)}"
        )
        _git(["commit", "-m", commit_msg], repo_dir)

        # 10. Push
        token = os.environ["GITHUB_TOKEN"]
        remote = f"https://x-access-token:{token}@github.com/{GITHUB_ORG}/{repo}.git"
        _git(["remote", "set-url", "origin", remote], repo_dir)
        _git(["push", "origin", fix_branch], repo_dir)
        log.info("Pushed branch %s", fix_branch)

    # 11. Create Pull Request
    pr_body = (
        f"## Security Remediation — {jira_id}\n\n"
        f"| Field | Value |\n|---|---|\n"
        f"| Jira | {jira_id} |\n"
        f"| Remediation ID | {remediation_id} |\n"
        f"| Branch | `{fix_branch}` |\n\n"
        f"### Vulnerabilities Fixed\n"
        + "".join(f"- `{v}`\n" for v in plan["vuln_ids"])
        + f"\n### Files Changed\n"
        + "".join(f"- `{f}`\n" for f in changed_files)
        + "\n### Guardrails Passed\n"
        "- Java version: NOT changed\n"
        "- Scope: ONLY approved files modified\n"
        "- Tests: ALL PASSING\n\n"
        "### Reviewer Checklist\n"
        "- [ ] pom.xml version changes look correct\n"
        "- [ ] Source changes are minimal and targeted\n"
        "- [ ] No business logic appears altered\n"
    )
    pr_url = gh.create_pr(
        repo_name = repo,
        title     = f"[Security] {jira_id} — vulnerability remediation",
        body      = pr_body,
        head      = fix_branch,
        base      = branch,
    )

    # 12. Update Jira
    jira.add_comment(
        jira_id,
        f"Fix Agent completed.\n"
        f"PR: {pr_url}\n"
        f"Branch: {fix_branch}\n"
        f"Files changed: {', '.join(changed_files)}\n"
        f"All tests passed.  Moving to In Validation.",
    )
    jira.transition(jira_id, JiraStatus.IN_VALIDATION)

    # 13. Record in memory
    for vid in plan["vuln_ids"]:
        memory.record_attempt(repo, vid, jira_id, "pr_raised", pr_url=pr_url)

    # 14. Dispatch Validation Agent
    gh.dispatch_workflow(
        repo, "validation-agent.yml",
        {"jira_id": jira_id,
         "remediation_id": remediation_id,
         "fix_branch": fix_branch},
    )

    memory.audit("fix_agent_completed", jira_id, repo, remediation_id,
                 actor="fix-agent-v1",
                 details={"pr_url": pr_url, "branch": fix_branch,
                          "files": changed_files})
    log.info("Fix Agent done.  PR: %s", pr_url)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--jira-id",        required=True)
    p.add_argument("--remediation-id", required=True)
    args = p.parse_args()
    try:
        run(args.jira_id, args.remediation_id)
    except Exception as exc:
        log.exception("Fix Agent failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
