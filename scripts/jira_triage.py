#!/usr/bin/env python3
"""
jira_triage.py — Create or update Jira issues from a normalised vulnerability JSON.

One Jira issue is created per unique dependency package group and per unique
code-vulnerability rule.  Existing open issues are detected and only commented
on (not duplicated).

Usage:
    python scripts/jira_triage.py normalised.json \
        [--repo my-app] [--branch main] [--commit abc123]
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Ensure the vuln-remediation root is on sys.path regardless of invocation
# location. GitHub Actions calls this as:
#   python vuln-remediation/scripts/jira_triage.py  (from the app repo root)
# which puts vuln-remediation/scripts/ on sys.path, not vuln-remediation/.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.utils import memory
from scripts.utils.config import JiraStatus, SEVERITY_ORDER
from scripts.utils.jira_client import JiraClient

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _top_severity(vuln_list: list) -> str:
    for sev in SEVERITY_ORDER:
        for v in vuln_list:
            if v.get("severity", "").lower() == sev:
                return sev
    return "low"


def _description_text(norm: dict) -> str:
    m = norm["scan_metadata"]
    lines = [
        f"Repository   : {m['repository']}",
        f"Branch       : {m['branch']}",
        f"Commit       : {m['commit_id']}",
        f"Scan time    : {m['scan_time']}",
        f"Remediation  : {m['remediation_id']}",
        "",
        "═══ DEPENDENCY VULNERABILITIES ═══",
    ]
    for pkg in norm.get("dependency_vulnerabilities", []):
        lines.append(f"\n▸ {pkg['package']}  "
                     f"{pkg['current_version']} → {pkg['recommended_fix_version']}")
        for v in pkg.get("vulnerabilities", []):
            cves = ", ".join(v.get("cve", [])) or "no CVE"
            lines.append(f"  {v['id']}  [{v['severity'].upper()}]  "
                         f"CVSS:{v.get('cvss', 0)}  {cves}")
    lines += ["", "═══ CODE VULNERABILITIES ═══"]
    for v in norm.get("code_vulnerabilities", []):
        files = ", ".join(o["file"] for o in v.get("occurrences", []))
        lines.append(f"\n▸ {v['rule_name']}  [{v['severity'].upper()}]")
        lines.append(f"  {v['description']}")
        lines.append(f"  Files: {files}")
    s = norm["summary"]
    lines += [
        "",
        f"Summary: {s['critical_count']} critical  {s['high_count']} high  "
        f"{s['medium_count']} medium  {s['low_count']} low",
    ]
    return "\n".join(lines)


def _groups_from_norm(norm: dict) -> list[dict]:
    """
    Return a flat list of issue groups.  Each group becomes one Jira issue.
    """
    groups = []
    repo = norm["scan_metadata"]["repository"]

    # One issue per vulnerable package (groups all CVEs on that package together)
    for pkg in norm.get("dependency_vulnerabilities", []):
        vulns = pkg.get("vulnerabilities", [])
        top   = _top_severity(vulns)
        groups.append({
            "type":       "dependency",
            "summary":    f"[{repo}] Dependency vulnerability: {pkg['package']} ({top.upper()})",
            "severity":   top,
            "primary_id": vulns[0]["id"] if vulns else pkg["id"],
            "all_ids":    [v["id"] for v in vulns],
        })

    # One issue per code vulnerability rule
    for v in norm.get("code_vulnerabilities", []):
        groups.append({
            "type":       "code",
            "summary":    f"[{repo}] Code vulnerability: {v['rule_name']} ({v['severity'].upper()})",
            "severity":   v.get("severity", "low"),
            "primary_id": v["id"],
            "all_ids":    [v["id"]],
        })

    return groups


# ── Main triage ───────────────────────────────────────────────────────────────

def triage(norm: dict, jira: JiraClient) -> list[str]:
    """Create/update a single Jira issue per execution. Returns the issue key."""
    meta = norm["scan_metadata"]
    repo = meta["repository"]
    rem_id = meta["remediation_id"]
    desc = _description_text(norm)
    touched: list[str] = []

    # Aggregate all groups into a single description
    aggregated_description = f"Repository: {repo}\nRemediation ID: {rem_id}\n\n"
    for group in _groups_from_norm(norm):
        primary = group["primary_id"]

        # 1. Exception check
        exc, reason = memory.is_excepted(primary)
        if exc:
            log.info("Skipping excepted vulnerability %s: %s", primary, reason)
            continue

        # Add group details to the aggregated description
        aggregated_description += f"- Vulnerability: {primary}\n"

    # 2. Check for an existing Jira issue for this remediation ID
    existing = jira.find_open_issue(rem_id, repo)
    if existing:
        log.info("Issue %s already open for remediation ID %s — updating description", existing, rem_id)
        jira.update_issue(existing, aggregated_description)
        touched.append(existing)
    else:
        # 3. Create a new Jira issue
        new_issue = jira.create_issue(
            summary=f"Remediation for {repo} - {rem_id}",
            description=aggregated_description,
            project=meta["jira_project"],
            issue_type="Task"  # Adjust the issue type as needed
        )
        log.info("Created new Jira issue %s for remediation ID %s", new_issue, rem_id)
        touched.append(new_issue)

    return touched

# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("normalised_json")
    parser.add_argument("--repo",   default=None)
    parser.add_argument("--branch", default=None)
    parser.add_argument("--commit", default=None)
    args = parser.parse_args()

    norm = json.loads(Path(args.normalised_json).read_text())

    # Allow CLI overrides of metadata (GitHub Actions passes these)
    if args.repo:
        norm["scan_metadata"]["repository"] = args.repo
    if args.branch:
        norm["scan_metadata"]["branch"] = args.branch
    if args.commit:
        norm["scan_metadata"]["commit_id"] = args.commit

    keys = triage(norm, JiraClient())
    log.info("Triage complete.  Issues: %s", keys)


if __name__ == "__main__":
    main()
