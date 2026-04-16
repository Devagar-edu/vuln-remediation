"""
config.py — Central configuration loaded from environment.
Every script imports from here; nothing reads os.environ directly elsewhere.
"""
import os
from dotenv import load_dotenv

load_dotenv()


# ── GitHub ────────────────────────────────────────────────────────────────────
GITHUB_TOKEN          = os.environ["GITHUB_TOKEN"]
GITHUB_ORG            = os.environ["GITHUB_ORG"]
GOVERNANCE_REPO       = os.environ.get("GOVERNANCE_REPO", "vuln-governance")
GITHUB_MODELS_ENDPOINT = os.environ.get(
    "GITHUB_MODELS_ENDPOINT", "https://models.inference.ai.azure.com"
)
GITHUB_MODELS_TOKEN   = os.environ["GITHUB_MODELS_TOKEN"]
GITHUB_MODELS_MODEL   = os.environ.get("GITHUB_MODELS_MODEL", "gpt-4o-mini")

# ── Jira ──────────────────────────────────────────────────────────────────────
JIRA_URL              = os.environ["JIRA_URL"].rstrip("/")
JIRA_USER             = os.environ["JIRA_USER"]
JIRA_TOKEN            = os.environ["JIRA_TOKEN"]
JIRA_PROJECT_KEY      = os.environ.get("JIRA_PROJECT_KEY", "VULN")

# ── Orchestrator ──────────────────────────────────────────────────────────────
WEBHOOK_SECRET        = os.environ.get("WEBHOOK_SECRET", "")
WEBHOOK_PORT          = int(os.environ.get("WEBHOOK_PORT", "8080"))

# ── Snyk ──────────────────────────────────────────────────────────────────────
SNYK_TOKEN            = os.environ.get("SNYK_TOKEN", "")
SNYK_ORG              = os.environ.get("SNYK_ORG", "")

# ── Behaviour ─────────────────────────────────────────────────────────────────
MAX_FIX_ATTEMPTS      = int(os.environ.get("MAX_FIX_ATTEMPTS", "3"))
FAIL_ON_SEVERITY      = os.environ.get("FAIL_ON_SEVERITY", "high").lower()

# Ordered from most to least severe
SEVERITY_ORDER = ["critical", "high", "medium", "low", "warning", "note", "info"]


# ── Jira status names (must match your Jira workflow exactly) ─────────────────
class JiraStatus:
    OPEN               = "Open"
    ASSIGN_TO_AI       = "Assign to AI"
    PLANNING           = "Planning"
    AWAITING_APPROVAL  = "Awaiting Approval"
    APPROVED_FOR_FIX   = "Approved for Fix"
    FIXING             = "Fixing"
    FIX_FAILED         = "Fix Failed"
    IN_VALIDATION      = "In Validation"
    VALIDATION_FAILED  = "Validation Failed"
    DEVELOPER_REVIEW   = "Developer Review"
    CLOSED             = "Closed"
    EXCEPTED           = "Excepted"
    REJECTED           = "Rejected"


# ── Governance repo paths ─────────────────────────────────────────────────────
class GovPaths:
    HISTORY      = "history"          # history/{repo}/{snyk-id}.json
    KNOWN_FIXES  = "known-fixes"      # known-fixes/{snyk-id}.yaml + index.yaml
    EXCEPTIONS   = "exceptions/exceptions.yaml"
    PLANS        = "plans"            # plans/{jira-id}/plan-v{n}.md
    AUDIT        = "audit/audit.jsonl"
    PROMPTS      = "config/prompts"   # plan-agent-v1.txt, fix-agent-v1.txt
