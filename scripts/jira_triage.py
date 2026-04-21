#!/usr/bin/env python3
"""
jira_triage.py — Create or update a single Jira issue per execution from a
                  normalised vulnerability JSON.

One Jira issue is created per scan execution, combining ALL dependency and
code vulnerabilities into a single ticket.  If an open issue already exists
for this remediation_id (e.g. a re-scan), it is commented on rather than
duplicated.

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

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
    
from scripts.utils import memory
from scripts.utils.config import JiraStatus, SEVERITY_ORDER, JIRA_PROJECT_KEY
from scripts.utils.jira_client import JiraClient

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _top_severity(norm: dict) -> str:
    """Return the highest severity across ALL vulnerabilities in the scan."""
    all_severities: list[str] = []

    for pkg in norm.get("dependency_vulnerabilities", []):
        for v in pkg.get("vulnerabilities", []):
            all_severities.append(v.get("severity", "low").lower())

    for v in norm.get("code_vulnerabilities", []):
        all_severities.append(v.get("severity", "low").lower())

    for sev in SEVERITY_ORDER:
        if sev in all_severities:
            return sev
    return "low"


def _all_vuln_ids(norm: dict) -> list[str]:
    """Return every vulnerability ID present in the normalised scan."""
    ids: list[str] = []
    for pkg in norm.get("dependency_vulnerabilities", []):
        for v in pkg.get("vulnerabilities", []):
            ids.append(v["id"])
    for v in norm.get("code_vulnerabilities", []):
        ids.append(v["id"])
    return ids


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
    dep_vulns = norm.get("dependency_vulnerabilities", [])
    if dep_vulns:
        for pkg in dep_vulns:
            lines.append(f"\n▸ {pkg['package']}  "
                         f"{pkg['current_version']} → {pkg['recommended_fix_version']}")
            for v in pkg.get("vulnerabilities", []):
                cves = ", ".join(v.get("cve", [])) or "no CVE"
                lines.append(f"  {v['id']}  [{v['severity'].upper()}]  "
                             f"CVSS:{v.get('cvss', 0)}  {cves}")
    else:
        lines.append("  (none)")

    lines += ["", "═══ CODE VULNERABILITIES ═══"]
    code_vulns = norm.get("code_vulnerabilities", [])
    if code_vulns:
        for v in code_vulns:
            files = ", ".join(o["file"] for o in v.get("occurrences", []))
            lines.append(f"\n▸ {v['rule_name']}  [{v['severity'].upper()}]")
            lines.append(f"  {v['description']}")
            lines.append(f"  Files: {files}")
    else:
        lines.append("  (none)")

    s = norm["summary"]
    lines += [
        "",
        f"Summary: {s['critical_count']} critical  {s['high_count']} high  "
        f"{s['medium_count']} medium  {s['low_count']} low",
    ]
    return "\n".join(lines)


def _issue_summary(norm: dict, top_severity: str) -> str:
    """Build the single Jira issue summary line."""
    m = norm["scan_metadata"]
    repo = m["repository"]
    s = norm["summary"]
    counts = []
    if s.get("critical_count", 0):
        counts.append(f"{s['critical_count']} critical")
    if s.get("high_count", 0):
        counts.append(f"{s['high_count']} high")
    if s.get("medium_count", 0):
        counts.append(f"{s['medium_count']} medium")
    if s.get("low_count", 0):
        counts.append(f"{s['low_count']} low")
    count_str = ", ".join(counts) if counts else "no"
    return f"[{repo}] Vulnerability scan: {count_str} vulnerabilities ({top_severity.upper()})"


def _find_existing_issue(norm: dict, jira: JiraClient) -> str | None:
    """
    Look for an already-open Jira issue created for this remediation_id.

    Strategy (most reliable → least):
    1. Label search on  rem-<first-8-chars-of-remediation-id>  — safe alphanumeric
       label, no special characters that could break JQL.  This is the primary
       dedup mechanism and is always tried first.
    2. Full remediation-id label  remediation-id-<uuid>  — added after creation,
       so may be absent on very fresh tickets; tried as a secondary label search.
    3. Returns None if both searches fail or return nothing.  The caller will
       then create a new issue.  We deliberately do NOT fall back to a
       summary~"<snyk-id>" search because Snyk IDs contain colons and hyphens
       that some Jira configurations reject with 410/400, causing the whole
       pipeline to abort.
    """
    m = norm["scan_metadata"]
    repo = m["repository"]
    rem_id = m["remediation_id"]

    # ── Search 1: short rem- label (set at creation time, always alphanumeric) ──
    short_tag = f"rem-{rem_id[:8]}"
    from scripts.utils.config import JIRA_PROJECT_KEY as _PROJ_KEY
    jql_short = (
        f'project="{_PROJ_KEY}" AND labels="{short_tag}" '
        f'AND labels="{repo}" '
        f'AND status NOT IN ("Closed","Excepted","Rejected")'
    )
    try:
        res = jira._get("/search", params={"jql": jql_short, "maxResults": 1, "fields": "key"})
        issues = res.get("issues", [])
        if issues:
            log.info("Dedup: found existing issue %s via short rem- label", issues[0]["key"])
            return issues[0]["key"]
    except Exception as exc:
        log.warning("Dedup: short rem- label search failed (%s), trying full remediation-id label", exc)

    # ── Search 2: full remediation-id label (set just after creation) ──────────
    full_tag = f"remediation-id-{rem_id}"
    jql_full = (
        f'project="{_PROJ_KEY}" AND labels="{full_tag}" '
        f'AND status NOT IN ("Closed","Excepted","Rejected")'
    )
    try:
        res = jira._get("/search", params={"jql": jql_full, "maxResults": 1, "fields": "key"})
        issues = res.get("issues", [])
        if issues:
            log.info("Dedup: found existing issue %s via full remediation-id label", issues[0]["key"])
            return issues[0]["key"]
    except Exception as exc:
        log.warning("Dedup: full remediation-id label search also failed (%s) — will create new issue", exc)

    return None


# ── Main triage ───────────────────────────────────────────────────────────────

def triage(norm: dict, jira: JiraClient) -> list[str]:
    """
    Create or update a SINGLE Jira issue for all vulnerabilities in this scan.
    Returns a list containing the one issue key touched (or empty if all excepted).
    """
    meta   = norm["scan_metadata"]
    repo   = meta["repository"]
    rem_id = meta["remediation_id"]
    desc   = _description_text(norm)

    all_ids = _all_vuln_ids(norm)

    # ── Check if every vulnerability is excepted ───────────────────────────
    non_excepted_ids: list[str] = []
    for vid in all_ids:
        exc, reason = memory.is_excepted(vid)
        if exc:
            log.info("Vulnerability %s is excepted: %s", vid, reason)
        else:
            non_excepted_ids.append(vid)

    if not non_excepted_ids:
        log.info("All vulnerabilities in this scan are excepted — no Jira issue created.")
        return []

    top_severity = _top_severity(norm)
    summary      = _issue_summary(norm, top_severity)
    priority     = JiraClient.severity_to_priority(top_severity)
    labels       = [repo, "vulnerability-scan", top_severity, f"rem-{rem_id[:8]}"]

    # ── De-duplicate against existing open issues ──────────────────────────
    existing = _find_existing_issue(norm, jira)
    if existing:
        log.info("Open issue %s already exists for remediation %s — adding re-scan comment",
                 existing, rem_id)
        jira.add_comment(
            existing,
            f"Re-scan at {meta['scan_time']} still detects vulnerabilities.\n"
            f"Commit: {meta['commit_id']}\n"
            f"Outstanding IDs: {', '.join(non_excepted_ids)}",
        )
        # Refresh the attachment with the latest normalised JSON
        jira.add_attachment(existing, "normalised-vulnerabilities.json",
                            json.dumps(norm, indent=2).encode(), "application/json")
        return [existing]

    # ── Create a single new issue covering all vulnerabilities ─────────────
    key = jira.create_issue(
        summary     = summary,
        description = JiraClient.to_adf(desc),
        labels      = labels,
        priority    = priority,
    )

    # Store full remediation-id as a label for webhook lookups
    jira.add_label(key, f"remediation-id-{rem_id}")

    # Attach the full normalised JSON (consumed by plan + fix agents)
    jira.add_attachment(key, "normalised-vulnerabilities.json",
                        json.dumps(norm, indent=2).encode(), "application/json")

    # Transition to Open
    jira.transition(key, JiraStatus.OPEN)

    # Audit — record all vuln IDs against the single issue
    memory.audit(
        event          = "jira_issue_created",
        jira_id        = key,
        repo           = repo,
        remediation_id = rem_id,
        actor          = "jira-triage",
        details        = {"vuln_ids": non_excepted_ids, "severity": top_severity,
                          "total_vulns": len(all_ids),
                          "excepted_count": len(all_ids) - len(non_excepted_ids)},
    )

    log.info("Created single issue %s covering %d vulnerability/ies (remediation %s)",
             key, len(non_excepted_ids), rem_id)
    return [key]


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
