#!/usr/bin/env python3
"""
fix_agent.py — Apply an approved remediation plan to pom.xml and source files,
               then raise a Pull Request.

Triggered by fix-agent.yml (workflow_dispatch).
                                                                     

Usage:
    python scripts/agents/fix_agent.py \
        --jira-id VULN-42 --remediation-id <uuid>

Build retry logic
-----------------
If mvn compile or mvn test fails the agent does NOT immediately give up.
Instead it:
  1. Feeds the compiler / test error back to the LLM as a correction prompt.
  2. Re-applies the corrected file(s).
  3. Re-runs the build.
This cycle repeats up to MAX_BUILD_RETRIES times before the agent marks the
issue Fix Failed.
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

MAX_BUILD_RETRIES = int(os.environ.get("MAX_BUILD_RETRIES", "3"))

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

# ── LLM system prompt for build-error correction ──────────────────────────────
CORRECTION_SYSTEM_PROMPT = """\
You are a Java security engineer reviewing a fix that caused a build failure.

Your task: correct the Java source file so the build error is resolved while
keeping the original security fix in place.

STRICT RULES:
1. Keep the security fix that was already applied — do not revert it.
2. Fix ONLY what the compiler or test error requires.
3. Do not change method signatures, class names, or package declarations.
4. Do not add or remove any imports beyond what is strictly required.
5. Output ONLY the complete corrected file.  No markdown fences, no explanation.
"""


# ── Plan loader — Jira first, governance repo fallback ────────────────────────

def _load_plan(jira: JiraClient, jira_id: str) -> str:
    """
    Fetch the approved plan.

    Primary:  the plan Markdown attached to the Jira ticket itself.
              The plan agent attaches it as  remediation-plan-vN.md.
              We try v1..v10 newest-first, same as the governance fallback.
    Fallback: governance repo (plans/{jira_id}/plan-vN.md).
              Used if the Jira attachment is missing (e.g. attachment was
              manually deleted or the ticket was recreated).
    """
    # Try Jira attachments newest-first
    for v in range(10, 0, -1):
        raw = jira.get_attachment(jira_id, f"remediation-plan-v{v}.md")
        if raw:
            log.info("Loaded plan v%d from Jira attachment on %s", v, jira_id)
            return raw

    # Fallback: governance repo
    log.warning(
        "Plan not found as Jira attachment on %s — falling back to governance repo",
        jira_id,
    )
    plan = memory.latest_plan(jira_id)
    if plan:
        log.info("Loaded plan from governance repo for %s", jira_id)
        return plan

    raise RuntimeError(
        f"No approved plan found for {jira_id}. "
        "Expected a 'remediation-plan-vN.md' attachment on the Jira ticket."
    )


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
    return original, _strip_fences(fixed)

                                          
                                                                 
                                            

def correct_source_file(file_path: str, current_content: str,
                        build_error: str, plan_context: str) -> str:
    """
    Ask the LLM to correct a file that caused a build failure.
    Returns the corrected file content.
    """
    user_prompt = (
        f"File: {file_path}\n\n"
        f"Build / test error output (last 3000 chars):\n"
        f"{build_error[-3000:]}\n\n"
        f"Current (broken) file content:\n{current_content}\n\n"
        f"Original plan context:\n{plan_context[:2000]}"
    )
    corrected = chat(CORRECTION_SYSTEM_PROMPT, user_prompt,
                     max_tokens=8192, temperature=0.05)
    return _strip_fences(corrected)


def _strip_fences(text: str) -> str:
    text = re.sub(r"^```(?:java|xml)?\s*\n?", "", text.strip())
    return re.sub(r"\n?```\s*$", "", text)


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


# ── Build helpers ─────────────────────────────────────────────────────────────

def _mvn(goal: str, repo_dir: str, timeout: int = 600) -> tuple[int, str]:
    return _sh(
        ["mvn", "--batch-mode", "--no-transfer-progress", goal],
        repo_dir,
        timeout=timeout,
    )


def _apply_corrections(repo_dir: str, repo: str, branch: str,
                       build_error: str, plan_md: str,
                       code_by_file: dict[str, list],
                       attempt: int) -> list[tuple[str, str]]:
    """
    For each source file that was changed, ask the LLM to correct it given
    the build error.  Writes corrected files into repo_dir.
    Returns new file_diffs list.
    """
    log.info("Build retry %d/%d — asking LLM to correct failing files",
             attempt, MAX_BUILD_RETRIES)
    file_diffs = []
    for file_path, _changes in code_by_file.items():
        abs_path = os.path.join(repo_dir, file_path.replace("/", os.sep))
        current = Path(abs_path).read_text()
        corrected = correct_source_file(file_path, current, build_error, plan_md)
        # Only write if the LLM actually changed something
        if corrected != current:
            Path(abs_path).write_text(corrected)
            log.info("Correction applied: %s", file_path)
        file_diffs.append((current, corrected))
    return file_diffs


# ── Main ──────────────────────────────────────────────────────────────────────

def run(jira_id: str, remediation_id: str) -> None:
    jira = JiraClient()

    # 1. Load normalised JSON from Jira attachment
    raw_norm = jira.get_attachment(jira_id, "normalised-vulnerabilities.json")
    if not raw_norm:
        raise RuntimeError("normalised-vulnerabilities.json not found on Jira issue")
    norm   = json.loads(raw_norm)
    meta   = norm["scan_metadata"]
    repo   = meta["repository"]
    branch = meta["branch"]

    # 2. Load plan — from Jira attachment (primary), governance repo (fallback)
                   
    plan_md = _load_plan(jira, jira_id)
    plan    = parse_plan(plan_md)

    log.info("Fix Agent: %s  repo=%s  dep_changes=%d  code_changes=%d",
             jira_id, repo, len(plan["dep_changes"]), len(plan["code_changes"]))
    memory.audit("fix_agent_started", jira_id, repo, remediation_id,
                 actor="fix-agent-v1",
                 details={"dep": len(plan["dep_changes"]),
                          "code": len(plan["code_changes"])})

    # 3. Build fix branch name
    short = hashlib.sha1(remediation_id.encode()).hexdigest()[:7]
    fix_branch = f"fix/{jira_id.lower()}-{short}"

    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = os.path.join(tmp, repo)
        _clone(repo, branch, repo_dir)

                                
        _git(["config", "user.email", "ai-remediation@automation.local"], repo_dir)
        _git(["config", "user.name",  "AI Remediation Bot"], repo_dir)
        _git(["checkout", "-b", fix_branch], repo_dir)

        pom_path     = os.path.join(repo_dir, "pom.xml")
        original_pom = Path(pom_path).read_text()
        new_pom      = original_pom

        # 4. Update pom.xml
        if plan["dep_changes"]:
            new_pom = update_pom(original_pom, plan["dep_changes"])
            Path(pom_path).write_text(new_pom)

        # 5. Fix source files via LLM (initial pass)
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

                                             
        changed_files = approved_source_files + (["pom.xml"] if plan["dep_changes"] else [])

        # 6. Guardrails (run once — these are policy checks, not build checks)
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
                                     
            jira.add_comment(jira_id, f"Fix Agent ABORTED — guardrail violation:\n{exc}")
            jira.transition(jira_id, JiraStatus.FIX_FAILED)
            raise

        # 7. Verify dependency resolution
                                                                       
        rc, out = _mvn("-q dependency:resolve", repo_dir)
        if rc != 0:
            jira.add_comment(jira_id,
                f"Fix Agent: dependency resolution failed. "
                f"Check pom.xml version changes.\n\n{out[-2000:]}")
            jira.transition(jira_id, JiraStatus.FIX_FAILED)
            raise RuntimeError(f"mvn dependency:resolve failed:\n{out[-3000:]}")
        log.info("Dependency resolution OK ✓")

        # 8. Compile + test with LLM-assisted retry loop
        #    Each failed build feeds the error back to the LLM which corrects
        #    the source files; the build is then re-attempted.
        build_error: str = ""
        build_passed = False
                                      

        for attempt in range(1, MAX_BUILD_RETRIES + 1):
            # 8a. Correct source files if this is a retry
            if attempt > 1 and code_by_file:
                file_diffs = _apply_corrections(
                    repo_dir, repo, branch, build_error, plan_md,
                    code_by_file, attempt,
                )
                jira.add_comment(
                    jira_id,
                    f"Fix Agent: build attempt {attempt - 1} failed. "
                    f"LLM correction applied — retrying build (attempt {attempt}/{MAX_BUILD_RETRIES}).\n\n"
                    f"Error summary:\n{build_error[-1000:]}",
                )

            # 8b. Compile
            rc, out = _mvn("compile -q", repo_dir)
            if rc != 0:
                build_error = out
                log.warning("Compile failed (attempt %d/%d)", attempt, MAX_BUILD_RETRIES)
                if attempt == MAX_BUILD_RETRIES:
                    break
                continue

            log.info("Compilation OK ✓ (attempt %d)", attempt)

            # 8c. Test
            rc, test_out = _mvn("test", repo_dir)
            if rc != 0:
                build_error = test_out
                log.warning("Tests failed (attempt %d/%d)", attempt, MAX_BUILD_RETRIES)
                if attempt == MAX_BUILD_RETRIES:
                    break
                continue

            log.info("All tests passed ✓ (attempt %d)", attempt)
            build_passed = True
            break

        if not build_passed:
            # All retries exhausted — attach full log and fail
            jira.add_attachment(jira_id, "build-failure.log",
                                build_error.encode(), "text/plain")
            jira.add_comment(
                jira_id,
                f"Fix Agent: build FAILED after {MAX_BUILD_RETRIES} LLM correction "
                f"attempt(s). Attached build-failure.log. Status → Fix Failed.\n\n"
                f"Last error (truncated):\n{build_error[-1500:]}",
            )
            jira.transition(jira_id, JiraStatus.FIX_FAILED)
            for vid in plan["vuln_ids"]:
                memory.record_attempt(repo, vid, jira_id, "build_failed",
                                      error=build_error[-1000:])
            raise RuntimeError(
                f"Build failed after {MAX_BUILD_RETRIES} retries"
            )

        # 9. Commit
        _git(["add", "-A"], repo_dir)
        ids_str = ", ".join(plan["vuln_ids"][:5])
        build_attempts_note = (
            f"" if build_passed and build_error == ""
            else f"\nBuild passed after LLM correction."
        )
        commit_msg = (
            f"fix(security): remediate {ids_str} per {jira_id}\n\n"
            f"Remediation ID : {remediation_id}\n"
            f"Approved plan  : {jira_id} (attached to Jira)\n"
            f"Files changed  : {', '.join(changed_files)}"
            f"{build_attempts_note}"
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
