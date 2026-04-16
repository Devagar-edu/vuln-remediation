#!/usr/bin/env python3
"""
orchestrator.py — Webhook listener for Jira issue-updated events.

Runs as a long-lived process on the self-hosted GitHub Actions runner.
Receives Jira webhooks and dispatches the appropriate GitHub Actions
workflow via workflow_dispatch.

Start:
    python scripts/orchestrator.py

Jira webhook setup (Jira Cloud → Settings → System → WebHooks):
    URL    : http://<runner-ip>:8080/webhook/jira
    Events : Issue Updated
    Header : X-Webhook-Secret: <WEBHOOK_SECRET env var>

The orchestrator does NOT execute agent code directly — it only fires
workflow_dispatch events, keeping all agent execution inside GitHub Actions
with full audit trails and job logs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sys

from flask import Flask, request, jsonify

from scripts.utils import github_client as gh
from scripts.utils import memory
from scripts.utils.config import (
    WEBHOOK_SECRET, WEBHOOK_PORT,
    JiraStatus, MAX_FIX_ATTEMPTS,
)
from scripts.utils.jira_client import JiraClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("orchestrator")

app  = Flask(__name__)
jira = JiraClient()


# ── Security ──────────────────────────────────────────────────────────────────

def _authorised(req) -> bool:
    if not WEBHOOK_SECRET:
        log.warning("WEBHOOK_SECRET not set — accepting all requests (not for production)")
        return True
    incoming = req.headers.get("X-Webhook-Secret", "")
    return hmac.compare_digest(incoming, WEBHOOK_SECRET)


# ── Payload helpers ───────────────────────────────────────────────────────────

def _status_change(payload: dict) -> tuple[str, str, str]:
    """Return (issue_key, from_status, to_status).  to_status is '' if no change."""
    key = payload.get("issue", {}).get("key", "")
    for item in payload.get("changelog", {}).get("items", []):
        if item.get("field") == "status":
            return key, item.get("fromString", ""), item.get("toString", "")
    return key, "", ""


def _remediation_id(issue: dict) -> str:
    for label in issue.get("fields", {}).get("labels", []):
        if label.startswith("remediation-id-"):
            return label[len("remediation-id-"):]
    return ""


def _repo_from_issue(issue: dict) -> str:
    """
    Repo name is stored as a label.  It is the first label that is not a
    severity word, type word, or remediation-id tag.
    """
    skip = {"dependency", "code", "critical", "high", "medium",
            "low", "warning", "note", "open"}
    for label in issue.get("fields", {}).get("labels", []):
        if label.startswith("remediation-id-") or label.startswith("rem-"):
            continue
        if label.lower() in skip:
            continue
        return label
    # Fallback: parse from summary  "[repo-name] …"
    summary = issue.get("fields", {}).get("summary", "")
    if summary.startswith("["):
        return summary[1:summary.index("]")]
    return ""


def _all_vuln_ids(jira_key: str) -> list[str]:
    try:
        raw = jira.get_attachment(jira_key, "normalised-vulnerabilities.json")
        if not raw:
            return []
        norm = json.loads(raw)
        ids = []
        for pkg in norm.get("dependency_vulnerabilities", []):
            for v in pkg.get("vulnerabilities", []):
                ids.append(v["id"])
        for v in norm.get("code_vulnerabilities", []):
            ids.append(v["id"])
        return ids
    except Exception as exc:
        log.warning("Could not read vuln IDs from %s: %s", jira_key, exc)
        return []


# ── Dispatch helpers ──────────────────────────────────────────────────────────

def _plan(key: str, repo: str, rem_id: str) -> None:
    log.info("→ Dispatching Plan Agent for %s", key)
    jira.transition(key, JiraStatus.PLANNING)
    jira.add_comment(key, "Plan Agent triggered. Generating remediation plan — please wait.")
    memory.audit("plan_agent_dispatched", key, repo, rem_id, actor="orchestrator")
    gh.dispatch_workflow(repo, "plan-agent.yml",
                         {"jira_id": key, "remediation_id": rem_id})


def _fix(key: str, repo: str, rem_id: str) -> None:
    # Guard: block if attempt limit reached for any vulnerability in this issue
    for vid in _all_vuln_ids(key):
        n = memory.attempt_count(repo, vid)
        if n >= MAX_FIX_ATTEMPTS:
            msg = (
                f"Fix Agent BLOCKED: vulnerability {vid} has {n} failed attempt(s) "
                f"(max {MAX_FIX_ATTEMPTS}).  Escalating to manual review."
            )
            log.warning(msg)
            jira.add_comment(key, msg)
            jira.transition(key, JiraStatus.FIX_FAILED)
            memory.audit("fix_blocked_max_attempts", key, repo, rem_id,
                         actor="orchestrator", details={"vuln_id": vid, "attempts": n})
            return

    log.info("→ Dispatching Fix Agent for %s", key)
    jira.transition(key, JiraStatus.FIXING)
    jira.add_comment(key, "Fix Agent triggered. Applying remediation — please wait.")
    memory.audit("fix_agent_dispatched", key, repo, rem_id, actor="orchestrator")
    gh.dispatch_workflow(repo, "fix-agent.yml",
                         {"jira_id": key, "remediation_id": rem_id})


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/webhook/jira", methods=["POST"])
def webhook():
    if not _authorised(request):
        log.warning("Rejected request with invalid secret from %s", request.remote_addr)
        return jsonify({"error": "Unauthorized"}), 401

    try:
        payload = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"error": "Bad JSON"}), 400

    # We only care about issue-updated events with a status change
    if payload.get("webhookEvent") != "jira:issue_updated":
        return jsonify({"status": "ignored"}), 200

    key, from_status, to_status = _status_change(payload)
    if not to_status:
        return jsonify({"status": "no_status_change"}), 200

    log.info("Status change: %s  '%s' → '%s'", key, from_status, to_status)

    issue  = payload.get("issue", {})
    repo   = _repo_from_issue(issue)
    rem_id = _remediation_id(issue)

    if not repo:
        log.warning("Cannot determine repo for %s — ignoring", key)
        return jsonify({"status": "no_repo"}), 200

    try:
        if to_status == JiraStatus.ASSIGN_TO_AI:
            _plan(key, repo, rem_id)
        elif to_status == JiraStatus.APPROVED_FOR_FIX:
            _fix(key, repo, rem_id)
        else:
            log.info("No action for status '%s'", to_status)
    except Exception as exc:
        log.exception("Error handling %s: %s", key, exc)
        return jsonify({"status": "error", "detail": str(exc)}), 500

    return jsonify({"status": "accepted", "issue": key, "to": to_status}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "vuln-remediation-orchestrator"}), 200


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("Orchestrator listening on 0.0.0.0:%s", WEBHOOK_PORT)
    app.run(host="0.0.0.0", port=WEBHOOK_PORT, debug=False, use_reloader=False)
