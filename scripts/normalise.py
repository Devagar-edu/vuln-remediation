#!/usr/bin/env python3
"""
normalise.py — Convert raw Snyk JSON (native or SARIF) to the canonical
               vulnerability schema used by all downstream agents.

Usage:
    # From GitHub Actions (inline):
    python scripts/normalise.py snyk-raw.json \
        --out normalised.json \
        --repo my-app --branch main --commit abc123

    # As a module:
    from scripts.normalise import normalise
    norm = normalise(raw_dict, repo="my-app", branch="main")
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_sarif(raw: dict) -> bool:
    return "runs" in raw and "$schema" in raw


def _is_already_normalised(raw: dict) -> bool:
    return "scan_metadata" in raw and "dependency_vulnerabilities" in raw


def _build_meta(raw: dict, repo: str, branch: str,
                commit_id: str, project: str) -> dict:
    # Try to pull any pre-existing scan_metadata fields
    existing = raw.get("scan_metadata", {})
    return {
        "scanner":         "snyk",
        "scan_time":       existing.get("scan_time",
                               datetime.now(timezone.utc).isoformat()),
        "project":         existing.get("project", project),
        "repository":      existing.get("repository", repo),
        "branch":          existing.get("branch", branch),
        "commit_id":       existing.get("commit_id", commit_id),
        "remediation_id":  existing.get("remediation_id", str(uuid.uuid4())),
    }


# ── Snyk native (snyk test --json) ────────────────────────────────────────────

def _parse_native_sca(raw: dict) -> list:
    """Parse 'snyk test --json' output → dependency_vulnerabilities list."""
    packages: dict[str, dict] = {}

    for v in raw.get("vulnerabilities", []):
        pkg_name = v.get("packageName", "unknown")
        version  = v.get("version", "unknown")
        key = f"{pkg_name}@{version}"

        if key not in packages:
            fixed_in = v.get("fixedIn", [])
            packages[key] = {
                "id":                    str(uuid.uuid4()),
                "package":               pkg_name,
                "current_version":       version,
                "recommended_fix_version": fixed_in[0] if fixed_in else "",
                "vulnerabilities":       [],
                "_meta": {
                    "excepted":         False,
                    "exception_reason": None,
                    "previously_fixed": False,
                    "fix_history_ref":  None,
                },
            }

        packages[key]["vulnerabilities"].append({
            "id":          v.get("id", ""),
            "title":       v.get("title", ""),
            "severity":    v.get("severity", "low"),
            "cvss":        float(v.get("cvssScore", 0)),
            "cve":         v.get("identifiers", {}).get("CVE", []),
            "cwe":         v.get("identifiers", {}).get("CWE", []),
            "exploit":     v.get("exploit", "Not Defined"),
            "description": v.get("description", ""),
        })

    return list(packages.values())


# ── SARIF (snyk code test --json) ─────────────────────────────────────────────

def _parse_sarif_sast(raw: dict) -> list:
    """Parse SARIF output from 'snyk code test --json' → code_vulnerabilities list."""
    results = []

    for run in raw.get("runs", []):
        rules = {
            r["id"]: r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule    = rules.get(rule_id, {})
            props   = rule.get("properties", {})

            occurrences = []
            for loc in result.get("locations", []):
                phy = loc.get("physicalLocation", {})
                reg = phy.get("region", {})
                occurrences.append({
                    "file":         phy.get("artifactLocation", {}).get("uri", ""),
                    "line":         reg.get("startLine", 0),
                    "code_snippet": reg.get("snippet", {}).get("text", ""),
                })

            results.append({
                "id":          str(uuid.uuid4()),
                "rule_id":     rule_id,
                "rule_name":   rule.get("name", rule_id),
                "severity":    result.get("level", "warning"),
                "description": (rule.get("shortDescription", {}).get("text")
                                or result.get("message", {}).get("text", "")),
                "cwe":         [t for t in props.get("tags", []) if "CWE" in t],
                "tags":        props.get("tags", []),
                "occurrences": occurrences,
                "_meta": {"excepted": False, "exception_reason": None},
            })

    return results


# ── Summary ───────────────────────────────────────────────────────────────────

def _summary(dep_vulns: list, code_vulns: list) -> dict:
    counts: dict[str, int] = {}
    for pkg in dep_vulns:
        for v in pkg.get("vulnerabilities", []):
            s = v.get("severity", "low").lower()
            counts[s] = counts.get(s, 0) + 1
    for v in code_vulns:
        s = v.get("severity", "low").lower()
        counts[s] = counts.get(s, 0) + 1
    return {
        "total_dependencies": len(dep_vulns),
        "total_code_issues":  len(code_vulns),
        "critical_count":     counts.get("critical", 0),
        "high_count":         counts.get("high", 0),
        "medium_count":       counts.get("medium", 0) + counts.get("warning", 0),
        "low_count":          counts.get("low", 0) + counts.get("note", 0),
    }


# ── Public API ────────────────────────────────────────────────────────────────

def normalise(raw: dict, repo: str = "unknown", branch: str = "main",
              commit_id: str = "unknown", project: str = "") -> dict:
    """
    Convert any Snyk JSON dict into the canonical schema.
    If the input is already normalised, returns it unchanged.
    """
    if _is_already_normalised(raw):
        log.info("Input already normalised — returning as-is")
        return raw

    project = project or repo

    if _is_sarif(raw):
        dep_vulns  = []
        code_vulns = _parse_sarif_sast(raw)
    else:
        dep_vulns  = _parse_native_sca(raw)
        code_vulns = []

    return {
        "scan_metadata":           _build_meta(raw, repo, branch, commit_id, project),
        "dependency_vulnerabilities": dep_vulns,
        "code_vulnerabilities":    code_vulns,
        "summary":                 _summary(dep_vulns, code_vulns),
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Normalise Snyk JSON to canonical schema")
    parser.add_argument("input",            help="Raw Snyk JSON file")
    parser.add_argument("--out",            help="Output file (default: stdout)")
    parser.add_argument("--repo",           default="unknown")
    parser.add_argument("--branch",         default="main")
    parser.add_argument("--commit",         default="unknown")
    parser.add_argument("--project",        default="")
    parser.add_argument("--threshold",      default=None,
                        help="(Ignored here — used by fail_check.py)")
    args = parser.parse_args()

    raw = json.loads(Path(args.input).read_text())
    result = normalise(raw, repo=args.repo, branch=args.branch,
                       commit_id=args.commit, project=args.project)
    output = json.dumps(result, indent=2)

    if args.out:
        Path(args.out).write_text(output)
        log.info("Written to %s", args.out)
    else:
        print(output)


if __name__ == "__main__":
    main()
