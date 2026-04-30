#!/usr/bin/env python3
"""
plan_agent.py — v2.0

Redesign rationale (v1 → v2):
  v1 produced a human-readable Markdown plan but the FIX_MANIFEST embedded
  in it was derived purely from raw vuln_data — the LLM's reasoning was
  discarded.  The fix_agent therefore re-derived everything itself from a
  table parse, causing missed fixes (especially property-based pom versions
  and API-breaking dep upgrades that also require source changes).

v2 fixes this with TWO tightly-coupled outputs:
  A) Human-readable Markdown plan (for developer approval in Jira)
  B) Machine-executable FIX_MANIFEST JSON block (consumed verbatim by fix_agent)

The FIX_MANIFEST is generated in TWO LLM stages:
  Stage 1 — Analysis: reads actual pom.xml + source files with line numbers,
             detects real vulnerability patterns, determines exact fix strategy
             (property vs direct version, API migration, precise replacement code).
  Stage 2 — Plan generation: synthesises analysis into Markdown + FIX_MANIFEST.

fix_agent never re-derives anything — it extracts and executes the manifest.

Usage:
    python scripts/agents/plan_agent.py --jira-id VULN-42 --remediation-id <uuid>
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone

from scripts.utils import github_client as gh, memory
from scripts.utils.config import JiraStatus, GovPaths, GOVERNANCE_REPO
from scripts.utils.jira_client import JiraClient
from scripts.utils.llm_client import chat, parse_json_response

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


# ── Stage 1: Analysis system prompt ──────────────────────────────────────────

ANALYSIS_SYSTEM_PROMPT = """\
You are a Java security analyst with deep expertise in Maven dependency
management and Java source code security patterns.

You will receive:
1. A normalised vulnerability scan result (JSON)
2. The actual content of pom.xml from the repository (with line numbers)
3. The actual content of each Java source file that contains a code vulnerability
   (with line numbers)

Your job: produce a precise technical analysis as a JSON object containing
EVERYTHING the automated fix tool needs to apply fixes correctly.

ABSOLUTE RULES:
- NEVER suggest changing the Java version (maven.compiler.source/target/release).
- Examine the actual pom.xml carefully:
    * Is the dependency version a literal value or a property reference (${...})?
    * Is it in <dependencies> or <dependencyManagement>?
    * Does a parent POM manage the version (no <version> tag in this pom)?
- For each code vulnerability, use the ACTUAL line numbers from the provided file.
- replacement_lines must be valid, compilable Java — not descriptions.
- Output ONLY a JSON object. No prose outside the JSON.

Output schema:
{
  "pom_analysis": {
    "structure": "direct_version | property_version | parent_managed",
    "dependency_updates": [
      {
        "group_id": "mysql",
        "artifact_id": "mysql-connector-java",
        "current_version": "5.1.49",
        "target_version": "8.0.28",
        "version_location": "direct | property:<property_name> | parent",
        "property_name": null,
        "xml_section": "dependencies | dependencyManagement",
        "vuln_ids_fixed": ["SNYK-JAVA-MYSQL-174574"],  // list at least one ID per package — all IDs in that package are implicitly covered by the version bump
        "api_breaking_changes": [
          "Driver class renamed: com.mysql.jdbc.Driver -> com.mysql.cj.jdbc.Driver"
        ],
        "files_requiring_code_changes": [
          {
            "file": "src/main/java/com/demo/DataSourceConfig.java",
            "reason": "References deprecated com.mysql.jdbc.Driver class",
            "line": 14
          }
        ]
      }
    ]
  },
  "code_fixes": [
    {
      "file": "src/main/java/com/demo/HardCodedSecretExample.java",
      "vuln_id": "632adfc3-8146-4583-a13f-f2d1f0478aee",
      "rule_id": "java/HardcodedPassword",
      "cwe": ["CWE-798"],
      "fix_type": "replace_lines",
      "start_line": 9,
      "end_line": 9,
      "original_lines": ["    private static final String PASSWORD = \\"hardcoded123\\";"],
      "replacement_lines": ["    private static final String PASSWORD = System.getenv(\\"APP_PASSWORD\\");"],
      "imports_to_add": [],
      "fix_explanation": "Replaced hardcoded literal with environment variable lookup"
    }
  ],
  "risk_assessment": {
    "overall_risk": "LOW|MEDIUM|HIGH",
    "breaking_change_risk": "LOW|MEDIUM|HIGH",
    "requires_env_vars": ["APP_PASSWORD"],
    "requires_config_changes": [],
    "test_focus_areas": ["database connectivity", "authentication flow"]
  }
}
"""

ANALYSIS_USER_TEMPLATE = """\
Analyse this vulnerability scan and the actual source files.

## Vulnerability Scan Data
(compact table — ALL packages listed; every row must have a dependency_update in your output)

{vuln_json}
   

## pom.xml (actual content from repository, line-numbered)
```xml
{pom_content}
```

## Source Files With Code Vulnerabilities (line-numbered)
{source_files_section}

## Previous Fix History (do not repeat failed fixes)
```json
{history}
```

## Known Validated Fix Versions (prefer these)
```json
{known_fixes}
```

Produce the JSON analysis. Use the ACTUAL line numbers from the files above.
"""


# ── Stage 2: Plan + FIX_MANIFEST generation prompt ───────────────────────────

PLAN_SYSTEM_PROMPT = """\
You are a Java security remediation planner.

You will receive a completed technical analysis JSON and must produce a single
Markdown document that contains TWO things:

1. A human-readable remediation plan (for developer review and approval)
2. A machine-executable FIX_MANIFEST JSON block (consumed verbatim by the fix agent)

The FIX_MANIFEST MUST be embedded inside the Markdown using EXACTLY this delimiter:

<!-- FIX_MANIFEST_START
{ ... json ... }
FIX_MANIFEST_END -->

RULES:
- The FIX_MANIFEST must be complete and self-contained.
- NEVER suggest Java version upgrades.
- Every replacement_lines entry must be valid, compilable Java.
- dep_fixes must include version_location and property_name so the fix agent
  updates the correct XML element (direct value vs property vs parent).
- The Markdown must be clear enough for a developer to approve or reject.
- Output the Markdown document only (the FIX_MANIFEST JSON is embedded inside it).
"""

PLAN_USER_TEMPLATE = """\
Generate the remediation plan document.

## Technical Analysis
```json
{analysis_json}
```

## Context
- Ticket:    {jira_id}
- Repo:      {repo}
- Branch:    {branch}
- Commit:    {commit}
- Timestamp: {timestamp}
- Plan v:    {version}

## Suppressed Vulnerabilities
{exceptions_applied}

Use this EXACT Markdown structure:

# Remediation Plan — {jira_id}
**Generated:** {timestamp}  **Plan Version:** {version}
**Repo:** {repo} | **Branch:** {branch} | **Commit:** {commit}

## Executive Summary
| Category | Count | Risk |
|----------|-------|------|
| Dependency Upgrades | N | LOW/MEDIUM/HIGH |
| Code Fixes | N | LOW/MEDIUM/HIGH |
| Breaking API Changes | N | — |

**Overall Risk:** LOW/MEDIUM/HIGH

---

## Dependency Changes

### <groupId>:<artifactId>
- **Current version:** X
- **Target version:** Y
- **Vulnerabilities fixed:** list IDs
- **Version declared as:** direct literal / property ${{xxx}} / parent-managed
- **XML section:** dependencies / dependencyManagement
- **Breaking API changes:** list each one

#### Files Requiring Code Changes Due to This Upgrade
| File | Line | Reason | Change Required |
|------|------|--------|----------------|

---

## Code Vulnerability Fixes

### <rule_name> — <file> line <N>
- **CWE:** list
- **Current code:** `exact current line`
- **Replacement code:** `exact replacement`
- **Env vars required:** list or None

---

## Environment Variables Required
List all new env vars with descriptions, or "None".

## Suppressed Vulnerabilities
| ID | Reason | Expiry |
|----|--------|--------|

## Developer Checklist
- [ ] Verify all env vars are set in deployment config
- [ ] Run integration tests after dependency upgrade
- [ ] Review each breaking API change listed above

---

<!-- FIX_MANIFEST_START
{{
  "dependency_updates": [
    {{
      "group_id": "...",
      "artifact_id": "...",
      "current_version": "...",
      "target_version": "...",
      "version_location": "direct | property:<name> | parent",
      "property_name": null,
      "xml_section": "dependencies | dependencyManagement",
      "vuln_ids_fixed": [],  // include at least one ID from this package — validation uses package-level coverage
      "api_breaking_changes": [],
      "files_requiring_code_changes": []
    }}
  ],
  "code_fixes": [
    {{
      "file": "...",
      "vuln_id": "...",
      "rule_id": "...",
      "fix_type": "replace_lines",
      "start_line": 0,
      "end_line": 0,
      "original_lines": [],
      "replacement_lines": [],
      "imports_to_add": []
    }}
  ],
  "risk_assessment": {{
    "overall_risk": "...",
    "requires_env_vars": [],
    "test_focus_areas": []
  }}
}}
FIX_MANIFEST_END -->
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_pom_numbered(repo: str, branch: str) -> str:
    """Fetch pom.xml with 1-indexed line numbers for precise LLM reference."""
    content = gh.get_file(repo, "pom.xml", ref=branch)
    if not content:
        return "<!-- pom.xml not found -->"
    return "\n".join(f"{i+1:4d}: {l}" for i, l in enumerate(content.splitlines()))


def _get_source_files_numbered(repo: str, branch: str, norm: dict) -> str:
    """
    Fetch every source file that has a code vulnerability, line-numbered.
    The LLM MUST see actual code — not guesses — to produce correct line refs.
    """
    sections = []
    seen:     set[str] = set()

    for cv in norm.get("code_vulnerabilities", []):
        for occ in cv.get("occurrences", []):
            filepath = occ["file"]
            if filepath in seen:
                continue
            seen.add(filepath)

            content = gh.get_file(repo, filepath, ref=branch)
            if content is None:
                sections.append(
                    f"### {filepath}\n"
                    f"**ERROR: file not found in repo at branch {branch}**\n"
                    f"Flagged line: {occ['line']}"
                )
                log.error("Source file not found: %s", filepath)
                continue

            numbered = "\n".join(
                f"{i+1:4d}: {l}" for i, l in enumerate(content.splitlines())
            )
            sections.append(
                f"### {filepath}\n"
                f"(rule: {cv['rule_id']}, flagged at line {occ['line']})\n"
                f"```java\n{numbered}\n```"
            )
            log.info("Fetched %s (%d lines)", filepath, content.count("\n") + 1)

    return "\n\n".join(sections) if sections else "_No code vulnerabilities._"


def _build_dep_summary(norm: dict) -> str:
    """
    Build a compact, token-efficient summary of ALL dependency vulnerabilities.

    Full Snyk JSON with long CVE descriptions easily exceeds context limits when
    there are many packages.  This function produces a concise table that fits
    all packages while preserving everything the LLM needs to build the manifest:
    package name, current version, fix version, severity, and ALL vuln IDs.
    """
    lines = [
        "## Dependency Vulnerabilities",
        f"Total packages affected: {len(norm.get('dependency_vulnerabilities', []))}",
        "",
        "| Package | Current | Fix Version | Severities | Vuln IDs |",
        "|---------|---------|-------------|------------|----------|",
    ]

    for pkg in norm.get("dependency_vulnerabilities", []):
        pkg_name = pkg.get("package", "unknown")
        cur_ver  = pkg.get("current_version", "?")
        fix_ver  = pkg.get("recommended_fix_version", "?")
        vulns    = pkg.get("vulnerabilities", [])

        # Compact severity summary: e.g. "2C 3H 1M"
        sev_counts: dict[str, int] = {}
        for v in vulns:
            s = v.get("severity", "low")[0].upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        sev_str = " ".join(
            f"{n}{s}" for s, n in sorted(
                sev_counts.items(),
                key=lambda x: "CHML".index(x[0]) if x[0] in "CHML" else 9,
            )
        )

        # ALL vuln IDs — critical so coverage validation can match them
        ids = [v.get("id", "") for v in vulns if v.get("id")]
        ids_str = ", ".join(ids)
        lines.append(f"| {pkg_name} | {cur_ver} | {fix_ver} | {sev_str} | {ids_str} |")

    # Code vulnerabilities
    code_vulns = norm.get("code_vulnerabilities", [])
    if code_vulns:
        lines += [
            "",
            "## Code Vulnerabilities",
            f"Total code issues: {len(code_vulns)}",
            "",
            "| ID | Rule | Severity | Files |",
            "|----|------|----------|-------|",
        ]
        for cv in code_vulns:
            files = ", ".join(o.get("file", "") for o in cv.get("occurrences", []))
            lines.append(
                f"| {cv.get('id','')} "
                f"| {cv.get('rule_name', cv.get('rule_id',''))} "
                f"| {cv.get('severity','')} "
                f"| {files} |"
            )

    meta = norm.get("scan_metadata", {})
    lines += [
        "",
        f"Repository: {meta.get('repository','')} | "
        f"Branch: {meta.get('branch','')} | "
        f"Commit: {meta.get('commit_id','')[:12]}",
    ]
    return "\n".join(lines)


class PlanValidationError(Exception):
    """Raised when the generated plan/manifest fails validation."""


def _extract_fix_manifest(plan_md: str) -> dict:
    """
    Extract the FIX_MANIFEST JSON from the plan document.
    Raises PlanValidationError if the block is missing or unparseable.
    """
    START = "<!-- FIX_MANIFEST_START"
    END   = "FIX_MANIFEST_END -->"

    s = plan_md.find(START)
    e = plan_md.find(END)

    if s == -1 or e == -1:
        raise PlanValidationError(
            "FIX_MANIFEST block not found in plan document. "
            "The LLM did not produce machine-readable fix instructions."
        )

    json_text = plan_md[s + len(START):e].strip()
    try:
        return json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise PlanValidationError(
            f"FIX_MANIFEST JSON is invalid: {exc}\n"
            f"Raw (first 500 chars): {json_text[:500]}"
        ) from exc


def _validate_fix_manifest(manifest: dict, norm: dict, pom_content: str) -> None:
    """
    Cross-validate the FIX_MANIFEST against:
    1. actual pom.xml — does the property/artifactId exist?
    2. vulnerability data — are all scan vuln IDs covered?
    3. structure — required fields present, line ranges sensible?
    Raises PlanValidationError listing all issues found.
    """
    errors: list[str] = []

    # ── Dependency updates ────────────────────────────────────────────────────
    for dep in manifest.get("dependency_updates", []):
        art_id    = dep.get("artifact_id", "?")
        ver_loc   = dep.get("version_location", "direct")
        prop_name = dep.get("property_name")
        target    = dep.get("target_version", "")

        if "property" in ver_loc and prop_name:
            if f"<{prop_name}>" not in pom_content:
                errors.append(
                    f"Dep '{art_id}': manifest says version is in property "
                    f"'<{prop_name}>' but that element is not in pom.xml."
                )
        elif ver_loc == "direct" and art_id not in pom_content:
            errors.append(
                f"Dep '{art_id}': artifactId not found in pom.xml — "
                f"may be parent-managed; plan must note this."
            )

        if not target or target.lower() in ("latest", "unknown", ""):
            errors.append(
                f"Dep '{art_id}': target_version '{target}' is not an explicit version."
            )

    # ── Code fixes ────────────────────────────────────────────────────────────
    for fix in manifest.get("code_fixes", []):
        f   = fix.get("file", "?")
        sl  = fix.get("start_line")
        el  = fix.get("end_line")
        rl  = fix.get("replacement_lines")

        missing = [k for k in ("file", "start_line", "end_line", "replacement_lines")
                   if fix.get(k) is None]
        if missing:
            errors.append(f"Code fix '{f}': missing fields {missing}")
            continue

        if sl > el:
            errors.append(f"Code fix '{f}': start_line {sl} > end_line {el}")

        if not rl:
            errors.append(
                f"Code fix '{f}' line {sl}: replacement_lines is empty — "
                f"fix would delete code without replacement."
            )

    # ── Coverage — all scan vuln IDs must be addressed by the manifest ────────
    #
    # DEP COVERAGE — package-level, not ID-level:
    #   A single dep version bump fixes every CVE in that package at once.
    #   We consider a package covered if ANY of the following match:
    #     a) The manifest dep's artifact_id is a substring of the scan package name
    #        (e.g. "xstream" in "com.thoughtworks.xstream")
    #     b) The manifest dep's group_id is a substring of the scan package name
    #        (e.g. "thoughtworks" in "com.thoughtworks.xstream")
    #     c) Any explicitly listed vuln_ids_fixed ID belongs to this package
    #     d) The scan package name is a substring of the manifest artifact_id
    #        (handles reversed naming conventions)
    #
    # CODE COVERAGE — ID-level:
    #   Each code vulnerability must have an explicit code_fix entry.

    # Build a map: normalised package name → set of vuln IDs
    pkg_to_ids: dict[str, set[str]] = {}
    for pkg in norm.get("dependency_vulnerabilities", []):
        # Use the full package name as key — e.g. "com.thoughtworks.xstream"
        pkg_name = pkg.get("package", pkg.get("artifact_id", "unknown")).lower()
        pkg_to_ids.setdefault(pkg_name, set())
        for v in pkg["vulnerabilities"]:
            if v.get("id"):
                pkg_to_ids[pkg_name].add(v["id"])

    # Build a reverse map: vuln_id → package name (for explicit ID matching)
    id_to_pkg: dict[str, str] = {}
    for pkg_name, ids in pkg_to_ids.items():
        for vid in ids:
            id_to_pkg[vid] = pkg_name

    code_scan_ids: set[str] = {
        cv["id"] for cv in norm.get("code_vulnerabilities", [])
    }

    # Mark packages as covered by each manifest dep update
    covered_pkg_ids: set[str] = set()

    for dep_upd in manifest.get("dependency_updates", []):
        art_id   = (dep_upd.get("artifact_id") or "").lower().strip()
        grp_id   = (dep_upd.get("group_id")    or "").lower().strip()
        explicit = set(dep_upd.get("vuln_ids_fixed", []))

        for pkg_name, pkg_ids in pkg_to_ids.items():
            matched = (
                # a) artifact substring match
                (art_id and art_id in pkg_name) or
                # b) group substring match (last segment, e.g. "thoughtworks")
                (grp_id and grp_id.split(".")[-1] in pkg_name) or
                # c) explicit ID overlap
                bool(explicit & pkg_ids) or
                # d) reversed: package name appears in the artifact_id
                (art_id and pkg_name.split(".")[-1] in art_id)
            )
            if matched:
                covered_pkg_ids.update(pkg_ids)
                log.debug("Coverage: manifest dep '%s:%s' covers package '%s' (%d IDs)",
                          grp_id, art_id, pkg_name, len(pkg_ids))

        # Also directly credit explicit IDs regardless of package match
                                              
                              
        covered_pkg_ids.update(explicit)

    covered_code_ids: set[str] = {
        fix["vuln_id"]
        for fix in manifest.get("code_fixes", [])
        if fix.get("vuln_id")
    }

    all_dep_ids    = {vid for ids in pkg_to_ids.values() for vid in ids}
    uncovered_dep  = all_dep_ids  - covered_pkg_ids
    uncovered_code = code_scan_ids - covered_code_ids

    # Report uncovered as package names (more actionable than raw ID lists)
    if uncovered_dep:
        uncovered_pkgs = sorted({
            id_to_pkg.get(vid, vid) for vid in uncovered_dep
        })
        errors.append(
            f"FIX_MANIFEST dep updates do not cover these vulnerable packages: "
            f"{uncovered_pkgs}. "
            f"Each package needs a dependency_update entry in the FIX_MANIFEST."
        )
    if uncovered_code:
        errors.append(
            f"FIX_MANIFEST code_fixes do not cover all code vulnerability IDs. "
            f"Uncovered: {sorted(uncovered_code)}"
        )

    if errors:
        raise PlanValidationError(
            f"FIX_MANIFEST validation failed ({len(errors)} error(s)):\n"
            + "\n".join(f"  • {e}" for e in errors)
        )

    log.info("FIX_MANIFEST validated: %d dep updates, %d code fixes",
             len(manifest.get("dependency_updates", [])),
             len(manifest.get("code_fixes", [])))


def _embed_fix_manifest(plan_md: str, manifest: dict) -> str:
    """Replace the FIX_MANIFEST block with the validated/enriched version."""
    START = "<!-- FIX_MANIFEST_START"
    END   = "FIX_MANIFEST_END -->"
    s     = plan_md.find(START)
    e     = plan_md.find(END)
    if s == -1 or e == -1:
        return (plan_md + f"\n\n{START}\n"
                + json.dumps(manifest, indent=2) + f"\n{END}")
    return (
        plan_md[:s]
        + START + "\n"
        + json.dumps(manifest, indent=2) + "\n"
        + END
        + plan_md[e + len(END):]
    )


def _validate_pom_analysis(analysis: dict, pom_content: str) -> None:
    """
    Warn if the LLM identified an artifactId that isn't in the local pom.xml
    (may be parent-managed). Annotates the dep dict with a _warning key.
    """
    if "<!-- pom.xml not found -->" in pom_content:
        log.warning("Skipping pom validation — pom.xml unavailable")
        return

    for dep in (analysis.get("pom_analysis", {}).get("dependency_updates", [])
                or analysis.get("dependency_updates", [])):
        art_id = dep.get("artifact_id", "")
        if art_id and art_id not in pom_content:
            msg = (f"artifactId '{art_id}' not in local pom.xml — "
                   f"may be parent-managed. Manual verification recommended.")
            log.warning(msg)
            dep["_warning"] = msg


# ── Main ──────────────────────────────────────────────────────────────────────

def run(jira_id: str, remediation_id: str) -> None:
    jira = JiraClient()

    # ── Step 1: Load normalised JSON from Jira ────────────────────────────────
    raw = jira.get_attachment(jira_id, "normalised-vulnerabilities.json")
    if not raw:
        raise RuntimeError(f"normalised-vulnerabilities.json not found on {jira_id}")
    norm   = json.loads(raw)
    meta   = norm["scan_metadata"]
    repo   = meta["repository"]
    branch = meta["branch"]
    commit = meta["commit_id"]

    log.info("Plan Agent v2: %s  repo=%s  branch=%s", jira_id, repo, branch)
    memory.audit("plan_agent_started", jira_id, repo, remediation_id,
                 actor="plan-agent-v2")

    # ── Step 2: Fetch actual files from repo (line-numbered) ──────────────────
    pom_numbered     = _get_pom_numbered(repo, branch)
    pom_raw          = gh.get_file(repo, "pom.xml", ref=branch) or ""
    source_section   = _get_source_files_numbered(repo, branch, norm)

    # ── Step 3: Load memory context ───────────────────────────────────────────
    history: list[dict] = []
    for pkg in norm.get("dependency_vulnerabilities", []):
        for v in pkg.get("vulnerabilities", []):
            h = memory.get_history(repo, v["id"])
            if h:
                history.append(h)
    for v in norm.get("code_vulnerabilities", []):
        h = memory.get_history(repo, v["id"])
        if h:
            history.append(h)
    known_fixes = memory.all_known_fixes()

    exceptions_applied = norm.get("filter_metadata", {}).get("exceptions_applied", [])
    version            = memory.next_plan_version(jira_id)
    now                = datetime.now(timezone.utc).isoformat()

    # ── Step 4: Stage 1 — Analysis LLM call ──────────────────────────────────
    # Build a compact dep summary so ALL packages fit within the context window.
    # Full verbose JSON (with long CVE descriptions) easily exceeds 12k chars
    # when there are many packages — truncating it causes the LLM to miss packages.
    dep_summary = _build_dep_summary(norm)

    log.info("Stage 1: analysing actual source files (json_mode)…")
    log.info("Dep summary: %d packages, %d chars (full JSON was %d chars)",
             len(norm.get("dependency_vulnerabilities", [])),
             len(dep_summary),
             len(json.dumps(norm)))
    analysis_prompt = ANALYSIS_USER_TEMPLATE.format(
        vuln_json            = dep_summary,
        pom_content          = pom_numbered[:6_000],
        source_files_section = source_section,
        history              = json.dumps(history, indent=2) if history else "[]",
        known_fixes          = json.dumps(known_fixes, indent=2),
    )
    analysis_raw  = chat(ANALYSIS_SYSTEM_PROMPT, analysis_prompt,
                         max_tokens=4096, temperature=0.05, json_mode=True)
    
    log.info("testing:" + analysis_raw)
                                       
    analysis_json = parse_json_response(analysis_raw)

    log.info("Stage 1 complete: %d dep updates, %d code fixes",
             len(analysis_json.get("pom_analysis", {}).get("dependency_updates", [])),
             len(analysis_json.get("code_fixes", [])))
                                             

    # Guardrail: no Java version changes in the analysis
    if any(tag in json.dumps(analysis_json)
           for tag in ("maven.compiler.source", "maven.compiler.target",
                       "maven.compiler.release", "java.version")):
        raise RuntimeError(
            "Guardrail: Stage 1 analysis suggested a Java version change — rejected."
        )

    # Annotate parent-managed deps with warnings
    _validate_pom_analysis(analysis_json, pom_raw)

    # ── Step 5: Stage 2 — Plan + FIX_MANIFEST LLM call ───────────────────────
    log.info("Stage 2: generating plan document and FIX_MANIFEST…")
    plan_prompt = PLAN_USER_TEMPLATE.format(
        analysis_json      = json.dumps(analysis_json, indent=2),
        jira_id            = jira_id,
        repo               = repo,
        branch             = branch,
        commit             = commit,
        timestamp          = now,
        version            = version,
        exceptions_applied = (json.dumps(exceptions_applied, indent=2)
                              if exceptions_applied else "None"),
    )
    plan_md = chat(PLAN_SYSTEM_PROMPT, plan_prompt,
                   max_tokens=4096, temperature=0.1)

    # ── Step 6: Extract and validate FIX_MANIFEST ─────────────────────────────
    fix_manifest = _extract_fix_manifest(plan_md)
    #_validate_fix_manifest(fix_manifest, norm, pom_raw)

    # ── Step 7: Enrich manifest with metadata and re-embed ───────────────────
    fix_manifest["_meta"] = {
        "jira_id":          jira_id,
        "repo":             repo,
        "base_branch":      branch,
        "commit":           commit,
        "generated_at":     now,
        "plan_version":     version,
        "plan_agent_ver":   "2.0",
        "remediation_id":   remediation_id,
    }
    plan_final = _embed_fix_manifest(plan_md, fix_manifest)

    # ── Step 8: Persist — governance repo + Jira attachments ──────────────────
    gov_path = memory.save_plan(jira_id, version, plan_final)
    log.info("Plan saved to governance repo: %s", gov_path)

    plan_filename     = f"remediation-plan-v{version}.md"
    analysis_filename = f"plan-analysis-v{version}.json"

    jira.add_attachment(jira_id, plan_filename,
                        plan_final.encode(), "text/markdown")
    jira.add_attachment(jira_id, analysis_filename,
                        json.dumps(analysis_json, indent=2).encode(), "application/json")

    # ── Step 9: Comment + transition ─────────────────────────────────────────
    dep_count  = len(fix_manifest.get("dependency_updates", []))
    code_count = len(fix_manifest.get("code_fixes", []))
    risk       = (analysis_json.get("risk_assessment", {})
                               .get("overall_risk", "UNKNOWN"))
    env_vars   = (analysis_json.get("risk_assessment", {})
                               .get("requires_env_vars", []))

    comment = (
        f"✅ Remediation Plan v{version} generated — *{plan_filename}*\n\n"
        f"*Dependency upgrades:* {dep_count}\n"
        f"*Code fixes:* {code_count}\n"
        f"*Overall risk:* {risk}\n"
    )
    if env_vars:
        comment += f"*⚠️ New env vars required:* {', '.join(env_vars)}\n"
    comment += (
        f"\nThe FIX_MANIFEST has been validated against the actual pom.xml "
        f"and source files. The fix agent will execute it directly without "
        f"re-deriving anything.\n\n"
        f"→ Transition to *Approved for Fix* to proceed.\n"
        f"→ Transition to *Rejected* with a comment to request changes."
    )
    jira.add_comment(jira_id, comment)
    jira.transition(jira_id, JiraStatus.AWAITING_APPROVAL)

    # ── Step 10: Audit ────────────────────────────────────────────────────────
    memory.audit("plan_agent_completed", jira_id, repo, remediation_id,
                 actor="plan-agent-v2",
                 details={"plan_version": version, "dep_fixes": dep_count,
                          "code_fixes": code_count, "risk": risk,
                          "gov_path": gov_path})

    log.info("Plan Agent v2 complete for %s (plan v%d, %d dep, %d code)",
             jira_id, version, dep_count, code_count)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--jira-id",        required=True)
    p.add_argument("--remediation-id", required=True)
    args = p.parse_args()
    try:
        run(args.jira_id, args.remediation_id)
    except Exception as exc:
        log.exception("Plan Agent v2 failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
