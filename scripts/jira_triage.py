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
    """Create/update Jira issues.  Returns list of issue keys touched."""
    meta   = norm["scan_metadata"]
    repo   = meta["repository"]
    rem_id = meta["remediation_id"]
    desc   = _description_text(norm)
    touched: list[str] = []

    for group in _groups_from_norm(norm):
        primary = group["primary_id"]

        # 1. Exception check
        exc, reason = memory.is_excepted(primary)
        if exc:
            log.info("Skipping excepted vulnerability %s: %s", primary, reason)
            continue

        # 2. De-duplicate against open Jira issues
        existing = jira.find_open_issue(primary, repo)
        if existing:
            log.info("Issue %s already open for %s — updating comment", existing, primary)
            jira.add_comment(existing,
                f"Re-scan at {meta['scan_time']} still detects this vulnerability.\n"
                f"Commit: {meta['commit_id']}")
            touched.append(existing)
            continue

        # 3. Create new issue
        priority = JiraClient.severity_to_priority(group["severity"])
        labels   = [repo, group["type"], group["severity"],
                    f"rem-{rem_id[:8]}"]   # short tag for searchability

        key = jira.create_issue(
            summary     = group["summary"],
            description = JiraClient.to_adf(desc),
            labels      = labels,
            priority    = priority,
        )

        # 4. Store remediation_id as a label for webhook lookups
        jira.add_label(key, f"remediation-id-{rem_id}")

        # 5. Attach the full normalised JSON
        jira.add_attachment(key, "normalised-vulnerabilities.json",
                            json.dumps(norm, indent=2).encode(), "application/json")

        # 6. Transition to Open
        jira.transition(key, JiraStatus.OPEN)

        # 7. Audit
        memory.audit(
            event          = "jira_issue_created",
            jira_id        = key,
            repo           = repo,
            remediation_id = rem_id,
            actor          = "jira-triage",
            details        = {"vuln_ids": group["all_ids"], "severity": group["severity"]},
        )

        touched.append(key)
        log.info("Created %s for %s", key, primary)

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
