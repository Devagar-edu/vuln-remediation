"""
jira_client.py — All Jira REST API v3 operations.
"""
import logging
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

from scripts.utils.config import JIRA_URL, JIRA_USER, JIRA_TOKEN, JIRA_PROJECT_KEY

log = logging.getLogger(__name__)

PRIORITY_MAP = {
    "critical": "Highest", "high": "High",
    "medium": "Medium",    "low": "Low",
    "warning": "Low",      "note": "Low",
}


class JiraClient:
    def __init__(self):
        self._base = f"{JIRA_URL}/rest/api/3"
        self._auth = HTTPBasicAuth(JIRA_USER, JIRA_TOKEN)
        self._h = {"Accept": "application/json", "Content-Type": "application/json"}

    # ── Private HTTP helpers ──────────────────────────────────────────────────

    def _get(self, path: str, params: dict = None) -> dict:
        r = requests.get(f"{self._base}{path}", auth=self._auth,
                         headers=self._h, params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, body: dict) -> dict:
        r = requests.post(f"{self._base}{path}", auth=self._auth,
                          headers=self._h, json=body, timeout=30)
        r.raise_for_status()
        return r.json() if r.text.strip() else {}

    def _put(self, path: str, body: dict) -> None:
        r = requests.put(f"{self._base}{path}", auth=self._auth,
                         headers=self._h, json=body, timeout=30)
        r.raise_for_status()

    # ── Issue CRUD ────────────────────────────────────────────────────────────

    def get_issue(self, key: str) -> dict:
        return self._get(f"/issue/{key}")

    def update_issue(self, issue_key: str, description: str) -> None:
        """Update the description of an existing Jira issue."""
        issue = self.jira.issue(issue_key)
        issue.update(fields={"description": description})

 
    def find_open_issue(self, remediation_id: str, repo: str) -> str | None:
        """Find an open Jira issue for the given remediation ID and repository."""
        jql = f'project = "{self.project}" AND summary ~ "{remediation_id}" AND status != "Done"'
        issues = self.jira.search_issues(jql)
        return issues[0].key if issues else None

    def create_issue(self, summary: str, description: dict,
                     labels: list[str], priority: str) -> str:
        body = {
            "fields": {
                "project":     {"key": JIRA_PROJECT_KEY},
                "summary":     summary,
                "description": description,
                "issuetype":   {"name": "Bug"},
                "priority":    {"name": priority},
                "labels":      labels,
            }
        }
        result = self._post("/issue", body)
        log.info("Created issue %s", result["key"])
        return result["key"]

    def add_label(self, key: str, label: str) -> None:
        self._put(f"/issue/{key}", {"update": {"labels": [{"add": label}]}})

    def add_comment(self, key: str, text: str) -> None:
        """Post a plain-text comment wrapped in Atlassian Document Format."""
        body = {
            "body": {
                "type": "doc", "version": 1,
                "content": [
                    {"type": "paragraph",
                     "content": [{"type": "text", "text": line or " "}]}
                    for line in text.splitlines()
                ]
            }
        }
        self._post(f"/issue/{key}/comment", body)

    def add_attachment(self, key: str, filename: str,
                       data: bytes, mime: str = "text/plain") -> None:
        url = f"{self._base}/issue/{key}/attachments"
        r = requests.post(
            url, auth=self._auth,
            headers={"X-Atlassian-Token": "no-check"},
            files={"file": (filename, data, mime)},
            timeout=60,
        )
        r.raise_for_status()
        log.info("Attached %s to %s", filename, key)

    def get_attachment(self, key: str, filename: str) -> Optional[str]:
        """Return text content of a named attachment, or None."""
        issue = self.get_issue(key)
        for att in issue.get("fields", {}).get("attachment", []):
            if att["filename"] == filename:
                r = requests.get(att["content"], auth=self._auth, timeout=60)
                r.raise_for_status()
                return r.text
        return None

    # ── Transitions ───────────────────────────────────────────────────────────

    def transition(self, key: str, status_name: str) -> bool:
        """Move issue to a named status. Returns True on success."""
        transitions = {
            t["name"]: t["id"]
            for t in self._get(f"/issue/{key}/transitions").get("transitions", [])
        }
        tid = transitions.get(status_name)
        if not tid:
            log.warning("Transition '%s' not available on %s. Available: %s",
                        status_name, key, list(transitions))
            return False
        self._post(f"/issue/{key}/transitions", {"transition": {"id": tid}})
        log.info("Transitioned %s → %s", key, status_name)
        return True

    # ── Static helpers ────────────────────────────────────────────────────────

    @staticmethod
    def to_adf(text: str) -> dict:
        """Convert plain text to a minimal ADF doc."""
        return {
            "type": "doc", "version": 1,
            "content": [
                {"type": "paragraph",
                 "content": [{"type": "text", "text": line or " "}]}
                for line in text.splitlines()
            ]
        }

    @staticmethod
    def severity_to_priority(severity: str) -> str:
        return PRIORITY_MAP.get(severity.lower(), "Medium")
