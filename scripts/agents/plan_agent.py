#!/usr/bin/env python3
"""
plan_agent.py — Generate a Markdown remediation plan using gpt-4o-mini.

Triggered by plan-agent.yml (workflow_dispatch from orchestrator).

Usage:
    python scripts/agents/plan_agent.py --jira-id VULN-42 --remediation-id <uuid>
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone

from scripts.utils import github_client as gh, memory
from scripts.utils.config import JiraStatus, GovPaths, GOVERNANCE_REPO
from scripts.utils.jira_client import JiraClient
from scripts.utils.llm_client import chat

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

# ── System prompt (also stored versioned in governance repo) ──────────────────
SYSTEM_PROMPT = """\
You are a senior Java application security remediation planner embedded in an
enterprise DevSecOps pipeline.

YOUR SOLE OUTPUT is a structured Markdown remediation plan — you produce NO code.

ABSOLUTE RULES (violations will be rejected by automated guardrails):
1. NEVER suggest changing the Java version (maven.compiler.source/target/release).
2. NEVER suggest adding dependencies that are not a direct replacement for a
   vulnerable dependency.
3. NEVER suggest refactoring, renaming, or reorganising code unrelated to the
   vulnerability.
4. Only address the exact vulnerability IDs supplied in the input.
5. For each dependency upgrade, identify every API or behaviour change that the
   new version introduces and list it in the Impact Analysis section.
6. If a known-fix entry exists for a CVE, you MUST use that exact fix version
   and mark it as "validated".
7. For code vulnerabilities (hardcoded secrets, SQL injection, etc.) describe the
   change at line-level only — no method extractions, no rewrites.

OUTPUT: Respond with ONLY the Markdown document.  No preamble, no explanation,
no markdown fences around the entire document.
"""

# ── Plan document template ────────────────────────────────────────────────────
TEMPLATE = """\
# Remediation Plan
**Jira:** {jira_id} | **Repo:** {repo} | **Branch:** {branch}
**Generated:** {ts} | **Remediation ID:** {remediation_id}
**Plan Version:** {version}

## Vulnerability Summary
| ID | Package / File | Type | Severity | Action |
|----|----------------|------|----------|--------|
{vuln_table_rows}

## Dependency Changes (pom.xml)
| Dependency | Current Version | Fix Version | Validated | Breaking Risk |
|-----------|-----------------|-------------|-----------|---------------|
{dep_table_rows}

## Code Changes Required
| File | Line | Vulnerability | Recommended Change |
|------|------|---------------|--------------------|
{code_table_rows}

## Impact Analysis
{impact_text}

## Guardrails Confirmed
- Java version: NOT changed
- Business logic: NOT modified
- New dependencies: NOT added (only existing dependency version bumped)
- Scope: ONLY files listed in the Code Changes table above

## History
- v{version}: Plan generated ({date})
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_pom(repo: str, branch: str) -> str:
    content = gh.get_file(repo, "pom.xml", ref=branch)
    return content or "(pom.xml not found in repository)"


def _get_snippets(repo: str, branch: str, norm: dict, ctx: int = 25) -> dict[str, str]:
    """Return {file_path: annotated_snippet} for each affected source file."""
    snippets: dict[str, str] = {}
    for v in norm.get("code_vulnerabilities", []):
        for occ in v.get("occurrences", []):
            path = occ["file"]
            if path in snippets:
                continue
            content = gh.get_file(repo, path, ref=branch)
            if not content:
                continue
            lines = content.splitlines()
            start = max(0, occ["line"] - ctx - 1)
            end   = min(len(lines), occ["line"] + ctx)
            snippets[path] = "\n".join(
                f"{i + start + 1:4}: {l}"
                for i, l in enumerate(lines[start:end])
            )
    return snippets


def _build_user_prompt(norm: dict, repo: str, pom: str,
                       snippets: dict, history: list, known_fixes: list) -> str:
    meta = norm["scan_metadata"]
    parts = [
        f"## Target\nRepository: {repo}  Branch: {meta['branch']}\n",
        "## Normalised Vulnerability Data\n```json",
        json.dumps(norm, indent=2)[:10_000],   # safety cap
        "```",
        "\n## Current pom.xml\n```xml",
        pom[:6_000],
        "```",
    ]

    if snippets:
        parts.append("\n## Affected Source Snippets")
        for path, snip in snippets.items():
            parts.append(f"\n### {path}\n```java\n{snip}\n```")

    if history:
        parts.append("\n## Previous Fix History (do not repeat these exact fixes if they failed)")
        parts.append("```json\n" + json.dumps(history, indent=2) + "\n```")

    if known_fixes:
        parts.append("\n## Known Validated Fixes (prefer these exact versions)")
        parts.append("```json\n" + json.dumps(known_fixes, indent=2) + "\n```")

    parts.append(f"\n## Required Output Template\n{TEMPLATE}")
    return "\n".join(parts)


# ── Main ──────────────────────────────────────────────────────────────────────

def run(jira_id: str, remediation_id: str) -> None:
    jira = JiraClient()

    # 1. Load normalised JSON from Jira attachment
    raw = jira.get_attachment(jira_id, "normalised-vulnerabilities.json")
    if not raw:
        raise RuntimeError(f"normalised-vulnerabilities.json not found on {jira_id}")
    norm   = json.loads(raw)
    meta   = norm["scan_metadata"]
    repo   = meta["repository"]
    branch = meta["branch"]

    log.info("Plan Agent: %s  repo=%s  branch=%s", jira_id, repo, branch)
    memory.audit("plan_agent_started", jira_id, repo, remediation_id,
                 actor="plan-agent-v1")

    # 2. Gather context
    pom       = _get_pom(repo, branch)
    snippets  = _get_snippets(repo, branch, norm)

    # 3. Load memory
    history = []
    for pkg in norm.get("dependency_vulnerabilities", []):
        for v in pkg.get("vulnerabilities", []):
            h = memory.get_history(repo, v["id"])
            if h:
                history.append(h)
    known_fixes = memory.all_known_fixes()

    # 4. Determine plan version
    version = memory.next_plan_version(jira_id)

    # 5. Call LLM
    user_prompt = _build_user_prompt(norm, repo, pom, snippets, history, known_fixes)
    log.info("Calling gpt-4o-mini for plan (version %d)…", version)
    plan_content = chat(SYSTEM_PROMPT, user_prompt, max_tokens=4096, temperature=0.1)

    # 6. Inject metadata into any unfilled template placeholders
    now = datetime.now(timezone.utc).isoformat()
    for k, v in {
        "{jira_id}": jira_id, "{repo}": repo, "{branch}": branch,
        "{ts}": now, "{remediation_id}": remediation_id,
        "{version}": str(version), "{date}": now[:10],
    }.items():
        plan_content = plan_content.replace(k, v)

    # 7. Persist to governance repo
    path = memory.save_plan(jira_id, version, plan_content)
    log.info("Plan saved: %s", path)

    # 8. Attach to Jira and transition
    jira.add_attachment(jira_id, f"remediation-plan-v{version}.md",
                        plan_content.encode(), "text/markdown")
    jira.add_comment(
        jira_id,
        f"Plan Agent generated Remediation Plan v{version}.\n\n"
        f"Please review the attached 'remediation-plan-v{version}.md'.\n\n"
        f"  → To proceed with the fix: change status to 'Approved for Fix'\n"
        f"  → To reject: change status to 'Rejected' and add a comment",
    )
    jira.transition(jira_id, JiraStatus.AWAITING_APPROVAL)

    # 9. Audit
    memory.audit("plan_agent_completed", jira_id, repo, remediation_id,
                 actor="plan-agent-v1",
                 details={"plan_version": version, "plan_path": path})

    log.info("Plan Agent complete for %s (plan v%d)", jira_id, version)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--jira-id",         required=True)
    p.add_argument("--remediation-id",  required=True)
    args = p.parse_args()
    try:
        run(args.jira_id, args.remediation_id)
    except Exception as exc:
        log.exception("Plan Agent failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
