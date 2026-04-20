"""
github_client.py — All GitHub API operations via PyGithub.
Agents import from here; nothing calls the GitHub API directly.
"""
import logging
import os
from typing import Optional

from github import Github, GithubException, InputGitAuthor

from scripts.utils.config import GITHUB_TOKEN, GITHUB_ORG, GOVERNANCE_REPO

log = logging.getLogger(__name__)
_gh = Github(GITHUB_TOKEN)


# ── Repo helpers ──────────────────────────────────────────────────────────────

def get_repo(repo_name):
    try:
        print(f"Fetching repository: {GITHUB_ORG}/{repo_name}")
        return _gh.get_repo(f"{GITHUB_ORG}/{repo_name}")
    except GithubException.UnknownObjectException:
        print(f"Repository {GITHUB_ORG}/{repo_name} not found.")
        raise
    except GithubException as e:
        print(f"An error occurred: {e}")
        raise


def get_gov_repo():
    return get_repo(GOVERNANCE_REPO)


# ── File read/write ───────────────────────────────────────────────────────────

def get_file(repo_name: str, path: str, ref: str = "main") -> Optional[str]:
    """Return decoded file text or None if not found."""
    try:
        f = get_repo(repo_name).get_contents(path, ref=ref)
        return f.decoded_content.decode("utf-8")
    except GithubException as e:
        if e.status == 404:
            return None
        raise


def upsert_file(repo_name: str, path: str, content: str,
                message: str, branch: str = "main") -> None:
    """Create or overwrite a file on the given branch."""
    repo = get_repo(repo_name)
    data = content.encode("utf-8")
    try:
        existing = repo.get_contents(path, ref=branch)
        repo.update_file(path, message, data, existing.sha, branch=branch)
        log.debug("Updated %s in %s", path, repo_name)
    except GithubException as e:
        if e.status == 404:
            repo.create_file(path, message, data, branch=branch)
            log.debug("Created %s in %s", path, repo_name)
        else:
            raise


def append_line(repo_name: str, path: str, line: str,
                message: str, branch: str = "main") -> None:
    """Append a single line to a file (creates the file if absent)."""
    existing = get_file(repo_name, path, ref=branch) or ""
    upsert_file(repo_name, path, existing + line + "\n", message, branch)


# ── Branch / PR ───────────────────────────────────────────────────────────────

def create_branch(repo_name: str, branch: str, from_ref: str = "main") -> None:
    repo = get_repo(repo_name)
    sha = repo.get_branch(from_ref).commit.sha
    repo.create_git_ref(f"refs/heads/{branch}", sha)
    log.info("Created branch %s in %s", branch, repo_name)


def branch_exists(repo_name: str, branch: str) -> bool:
    try:
        get_repo(repo_name).get_branch(branch)
        return True
    except GithubException:
        return False


def write_file_on_branch(repo_name: str, branch: str, path: str,
                          content: str, message: str) -> None:
    repo = get_repo(repo_name)
    try:
        existing = repo.get_contents(path, ref=branch)
        repo.update_file(path, message, content.encode(), existing.sha, branch=branch)
    except GithubException as e:
        if e.status == 404:
            repo.create_file(path, message, content.encode(), branch=branch)
        else:
            raise


def create_pr(repo_name: str, title: str, body: str,
              head: str, base: str = "main") -> str:
    """Create a PR and return its HTML URL."""
    pr = get_repo(repo_name).create_pull(title=title, body=body, head=head, base=base)
    log.info("Created PR #%s: %s", pr.number, pr.html_url)
    return pr.html_url


def close_branch_prs(repo_name: str, branch: str) -> None:
    for pr in get_repo(repo_name).get_pulls(state="open",
                                             head=f"{GITHUB_ORG}:{branch}"):
        pr.edit(state="closed")
        log.info("Closed PR #%s", pr.number)


def delete_branch(repo_name: str, branch: str) -> None:
    try:
        ref = get_repo(repo_name).get_git_ref(f"heads/{branch}")
        ref.delete()
        log.info("Deleted branch %s", branch)
    except GithubException as e:
        log.warning("Could not delete branch %s: %s", branch, e)


# ── Workflow dispatch ─────────────────────────────────────────────────────────

def dispatch_workflow(repo_name: str, workflow_file: str,
                      inputs: dict, ref: str = "main") -> None:
    """Trigger a workflow_dispatch event on repo_name."""
    repo = get_repo(repo_name)
    wf = repo.get_workflow(workflow_file)
    wf.create_dispatch(ref=ref, inputs={k: str(v) for k, v in inputs.items()})
    log.info("Dispatched %s on %s with inputs %s", workflow_file, repo_name, inputs)
