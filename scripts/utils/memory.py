"""
memory.py — Reads and writes to the governance repo.

Governance repo structure (all on 'main' branch):
  history/{repo}/{snyk-id}.json     — per-vulnerability fix history
  known-fixes/{snyk-id}.yaml        — validated fix patterns
  known-fixes/index.yaml            — index of all known-fix files
  exceptions/exceptions.yaml        — suppressed vulnerabilities
  plans/{jira-id}/plan-v{n}.md      — versioned plan documents
  audit/audit.jsonl                 — append-only event log
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import yaml

from scripts.utils import github_client as gh
from scripts.utils.config import GOVERNANCE_REPO, GovPaths

log = logging.getLogger(__name__)


# ── Audit log ─────────────────────────────────────────────────────────────────

def audit(event: str, jira_id: str, repo: str,
          remediation_id: str, actor: str, details: dict = None) -> None:
    """Append one JSON-Lines entry to audit/audit.jsonl."""
    entry = {
        "ts":              datetime.now(timezone.utc).isoformat(),
        "event":           event,
        "actor":           actor,
        "jira_id":         jira_id,
        "repo":            repo,
        "remediation_id":  remediation_id,
        "details":         details or {},
    }
    gh.append_line(
        GOVERNANCE_REPO,
        GovPaths.AUDIT,
        json.dumps(entry),
        f"audit: {event} [{jira_id}]",
    )


# ── Remediation history ───────────────────────────────────────────────────────

def _history_path(repo: str, vuln_id: str) -> str:
    safe = vuln_id.replace("/", "-").replace(":", "-")
    return f"{GovPaths.HISTORY}/{repo}/{safe}.json"


def get_history(repo: str, vuln_id: str) -> Optional[dict]:
    raw = gh.get_file(GOVERNANCE_REPO, _history_path(repo, vuln_id))
    return json.loads(raw) if raw else None


def save_history(repo: str, vuln_id: str, data: dict) -> None:
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    gh.upsert_file(
        GOVERNANCE_REPO,
        _history_path(repo, vuln_id),
        json.dumps(data, indent=2),
        f"history: update {vuln_id} [{data.get('jira_id', '')}]",
    )


def record_attempt(repo: str, vuln_id: str, jira_id: str,
                   status: str, pr_url: str = None, error: str = None) -> None:
    existing = get_history(repo, vuln_id) or {
        "vuln_id":  vuln_id,
        "repo":     repo,
        "jira_id":  jira_id,
        "attempts": [],
    }
    existing["attempts"].append({
        "ts":     datetime.now(timezone.utc).isoformat(),
        "status": status,
        "pr_url": pr_url,
        "error":  error,
    })
    existing["status"] = status
    if pr_url:
        existing["pr_url"] = pr_url
    save_history(repo, vuln_id, existing)


def attempt_count(repo: str, vuln_id: str) -> int:
    h = get_history(repo, vuln_id)
    return len(h.get("attempts", [])) if h else 0


# ── Exception list ────────────────────────────────────────────────────────────

def _load_exceptions() -> list:
    raw = gh.get_file(GOVERNANCE_REPO, GovPaths.EXCEPTIONS)
    if not raw:
        return []
    data = yaml.safe_load(raw)
    return (data or {}).get("exceptions", [])


def is_excepted(vuln_id: str) -> tuple[bool, str]:
    for exc in _load_exceptions():
        if exc.get("vuln_id") == vuln_id:
            return True, exc.get("reason", "No reason recorded")
    return False, ""


# ── Known fixes ───────────────────────────────────────────────────────────────

def get_known_fix(snyk_id: str) -> Optional[dict]:
    raw = gh.get_file(GOVERNANCE_REPO, f"{GovPaths.KNOWN_FIXES}/{snyk_id}.yaml")
    return yaml.safe_load(raw) if raw else None


def all_known_fixes() -> list:
    index_raw = gh.get_file(GOVERNANCE_REPO, f"{GovPaths.KNOWN_FIXES}/index.yaml")
    if not index_raw:
        return []
    index = yaml.safe_load(index_raw) or []
    fixes = []
    for entry in index:
        fix = get_known_fix(entry.get("snyk_id", ""))
        if fix:
            fixes.append(fix)
    return fixes


# ── Plans ─────────────────────────────────────────────────────────────────────

def save_plan(jira_id: str, version: int, content: str) -> str:
    path = f"{GovPaths.PLANS}/{jira_id}/plan-v{version}.md"
    gh.upsert_file(GOVERNANCE_REPO, path, content, f"plan: {jira_id} v{version}")
    return path


def latest_plan(jira_id: str) -> Optional[str]:
    """Return the highest-version plan for this issue, or None."""
    for v in range(10, 0, -1):
        content = gh.get_file(
            GOVERNANCE_REPO, f"{GovPaths.PLANS}/{jira_id}/plan-v{v}.md"
        )
        if content:
            return content
    return None


def next_plan_version(jira_id: str) -> int:
    for v in range(1, 11):
        if not gh.get_file(GOVERNANCE_REPO,
                           f"{GovPaths.PLANS}/{jira_id}/plan-v{v}.md"):
            return v
    return 1
