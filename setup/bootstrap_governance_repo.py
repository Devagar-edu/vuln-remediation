#!/usr/bin/env python3
"""
setup/bootstrap_governance_repo.py
===================================
One-time bootstrap script that seeds the vuln-governance repository with
the required directory structure, seed files, and empty audit log.

Run this ONCE before your first scan.

Prerequisites:
  - pip install PyGithub PyYAML python-dotenv
  - .env file populated (or env vars exported)
  - GITHUB_TOKEN must have `repo` scope on the governance repo

Usage:
    python setup/bootstrap_governance_repo.py [--dry-run]
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

import json
from datetime import datetime, timezone
from github import Github, GithubException

GITHUB_TOKEN    = os.environ["GITHUB_TOKEN"]
GITHUB_ORG      = os.environ["GITHUB_ORG"]
GOVERNANCE_REPO = os.environ.get("GOVERNANCE_REPO", "vuln-governance")

SEED_DIR = Path(__file__).parent.parent / "config"

DIRECTORY_STRUCTURE = [
    # (path_in_repo, content, commit_message)
    (
        "audit/audit.jsonl",
        json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": "governance_repo_bootstrapped",
            "actor": "bootstrap-script",
            "jira_id": "", "repo": "", "remediation_id": "",
            "details": {"note": "Initial audit log entry — do not delete this file"}
        }) + "\n",
        "chore: initialise audit log",
    ),
    (
        "exceptions/exceptions.yaml",
        (SEED_DIR / "exceptions.yaml").read_text(),
        "chore: seed exception list",
    ),
    (
        "known-fixes/index.yaml",
        (SEED_DIR / "known-fixes-index.yaml").read_text(),
        "chore: seed known-fixes index",
    ),
    (
        "known-fixes/SNYK-JAVA-MYSQL-2386864.yaml",
        (SEED_DIR / "known-fix-mysql-connector.yaml").read_text(),
        "chore: seed mysql-connector known fix",
    ),
    (
        "config/prompts/plan-agent-v1.txt",
        (SEED_DIR / "prompts" / "plan-agent-v1.txt").read_text(),
        "chore: seed plan-agent prompt v1",
    ),
    (
        "config/prompts/fix-agent-v1.txt",
        (SEED_DIR / "prompts" / "fix-agent-v1.txt").read_text(),
        "chore: seed fix-agent prompt v1",
    ),
    (
        "README.md",
        """\
# vuln-governance

This repository is the governance store for the AI-driven vulnerability
remediation framework.  It is maintained exclusively by automation and
the Security Lead.  Do not modify files here directly unless you are
following the governance process documented in the vuln-remediation README.

## Directory structure

| Path | Purpose |
|------|---------|
| `audit/audit.jsonl` | Append-only event log — never modify |
| `exceptions/exceptions.yaml` | Approved vulnerability suppressions |
| `known-fixes/` | Validated fix patterns index + individual fix files |
| `config/prompts/` | Versioned LLM system prompts |
| `history/{repo}/{snyk-id}.json` | Per-repository fix history (created by agents) |
| `plans/{jira-id}/plan-vN.md` | Versioned remediation plans (created by Plan Agent) |
""",
        "chore: add governance repo README",
    ),
]


def bootstrap(dry_run: bool = False) -> None:
    gh   = Github(GITHUB_TOKEN)
    org  = gh.get_organization(GITHUB_ORG)
    repo_full = f"{GITHUB_ORG}/{GOVERNANCE_REPO}"

    # 1. Create repo if it doesn't exist
    try:
        repo = gh.get_repo(repo_full)
        print(f"✓ Repo {repo_full} already exists")
    except GithubException:
        if dry_run:
            print(f"[DRY RUN] Would create repo {repo_full}")
            repo = None
        else:
            print(f"Creating repo {repo_full} ...")
            repo = org.create_repo(
                GOVERNANCE_REPO,
                private=True,
                description="Governance store for AI-driven vulnerability remediation",
                auto_init=True,
            )
            print(f"✓ Created {repo_full}")

    if repo is None:
        print("[DRY RUN] Skipping file creation")
        return

    # 2. Seed all files
    for path, content, message in DIRECTORY_STRUCTURE:
        try:
            existing = repo.get_contents(path, ref="main")
            print(f"  SKIP (exists): {path}")
        except GithubException:
            if dry_run:
                print(f"[DRY RUN] Would create: {path}")
            else:
                repo.create_file(path, message, content.encode(), branch="main")
                print(f"  CREATED: {path}")

    print("\nBootstrap complete.")
    print(f"Governance repo: https://github.com/{repo_full}")
    print("\nNext steps:")
    print("  1. Add repository secrets to vuln-remediation and your app repos")
    print("  2. Configure Jira workflow statuses and automation webhooks")
    print("  3. Copy scan-and-triage.yml to each application repo")
    print("  4. Start the orchestrator: Actions → Orchestrator Service → start")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without making changes")
    args = parser.parse_args()
    bootstrap(dry_run=args.dry_run)
