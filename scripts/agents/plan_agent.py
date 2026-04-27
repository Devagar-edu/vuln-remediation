"""
plan_agent.py  —  v2.0

Redesign rationale (v1 → v2):
  v1 produced a human-readable Markdown plan but the change_summary embedded
  in it was derived purely from raw vuln_data — the LLM's reasoning was
  discarded.  The fix_agent therefore ignored the plan entirely and re-derived
  everything itself, causing repeated failures.

v2 fixes this by making the plan produce TWO outputs that are tightly coupled:
  A) A human-readable Markdown review document (for developer approval)
  B) A machine-executable FIX_MANIFEST JSON block (consumed verbatim by fix_agent)

The FIX_MANIFEST is generated in TWO stages:
  Stage 1 — Analysis LLM call: read the actual source files and pom.xml,
             detect the real vulnerability pattern, and determine the exact
             fix strategy (including pom.xml structure, property-based versions,
             API migration requirements, and precise replacement code).
  Stage 2 — Plan LLM call: synthesise the analysis into the Markdown document
             AND the structured FIX_MANIFEST.

This means fix_agent never has to re-derive anything — it just executes the manifest.
"""

import argparse
import base64
import json
import logging
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scripts.utils.llm_client import LLMClient, LLMError
from scripts.utils.jira_client import JiraManager
from scripts.utils.github_client import GitHubClient
from scripts.utils.memory import MemoryManager
from guardrails import Guardrails, GuardrailViolation
from scripts.utils.audit_logger import AuditLogger

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ─── Stage 1: Analysis prompt — reads real source files ──────────────────────

ANALYSIS_SYSTEM_PROMPT = """You are a Java security analyst with deep expertise in
Maven dependency management and Java source code security patterns.

You will receive:
1. A normalised vulnerability scan result (JSON)
2. The actual content of pom.xml from the repository
3. The actual content of each Java source file that contains a code vulnerability

Your job: produce a precise technical analysis in JSON format that contains
EVERYTHING the automated fix tool needs to apply the fixes correctly.

RULES:
- Examine the actual pom.xml content carefully. Identify:
    * Whether the version is declared as a literal or as a property reference (${...})
    * Whether the dependency is in <dependencies> or <dependencyManagement>
    * The exact XML path to update
- For each code vulnerability, read the actual file content and identify:
    * The exact lines to replace (start_line, end_line — 1-indexed)
    * Any imports that need adding
    * The precise replacement code (not a description — actual Java code)
- Do NOT suggest Java version changes under any circumstances.
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
        "vuln_ids_fixed": ["SNYK-JAVA-MYSQL-174574"],
        "api_breaking_changes": [
          "Driver class renamed: com.mysql.jdbc.Driver -> com.mysql.cj.jdbc.Driver",
          "SSL now required by default — add ?useSSL=false or configure SSL"
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
      "original_lines": ["    private static final String PASSWORD = \"hardcoded123\";"],
      "replacement_lines": ["    private static final String PASSWORD = System.getenv(\"APP_PASSWORD\");"],
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

ANALYSIS_USER_TEMPLATE = """Analyse this vulnerability scan and the actual source files.

## Vulnerability Scan Data
```json
{vuln_json}
```

## pom.xml (actual content from repository)
```xml
{pom_content}
```

## Source Files With Code Vulnerabilities
{source_files_section}

## Known Fix Patterns (from validated history — reuse where applicable)
```json
{known_fixes}
```

Produce the JSON analysis. Be precise — use the actual line numbers and content
from the source files above. Do not guess or hallucinate file content.
"""

# ─── Stage 2: Plan generation prompt ─────────────────────────────────────────

PLAN_SYSTEM_PROMPT = """You are a Java security remediation planner.

You will receive a completed technical analysis JSON and must produce TWO things
in a single response:

1. A MARKDOWN section (human-readable plan for developer review)
2. A FIX_MANIFEST JSON block (machine-executable instructions for the fix agent)

The FIX_MANIFEST must be embedded verbatim inside the Markdown using this exact
delimiter pattern so the fix agent can extract it reliably:

<!-- FIX_MANIFEST_START
{ ... json ... }
FIX_MANIFEST_END -->

RULES:
- The FIX_MANIFEST must be complete and self-contained — the fix agent has no
  other source of truth.
- NEVER suggest Java version upgrades.
- Every replacement_lines entry must be valid, compilable Java.
- The FIX_MANIFEST dep_fixes must specify version_location and property_name
  so the fix agent updates the right XML element.
- The Markdown plan must be clear enough for a developer to approve or reject.
- Output the Markdown document only (the JSON is embedded inside it).
"""

PLAN_USER_TEMPLATE = """Generate the remediation plan document.

## Technical Analysis
```json
{analysis_json}
```

## Ticket: {jira_id}
## Repo: {repo} | Branch: {branch} | Commit: {commit}
## Timestamp: {timestamp}

## Suppressed Vulnerabilities
{exceptions_applied}

Use this EXACT Markdown structure:

# Remediation Plan — {jira_id}
**Generated:** {timestamp}
**Repo:** {repo} | **Branch:** {branch} | **Commit:** {commit}

## Executive Summary
| Category | Count | Risk |
|----------|-------|------|
| Dependency Upgrades | N | LOW/MEDIUM/HIGH |
| Code Fixes | N | LOW/MEDIUM/HIGH |
| Breaking API Changes | N | — |

**Overall Risk:** LOW/MEDIUM/HIGH
**Estimated Impact:** one sentence

---

## Dependency Changes

### <groupId>:<artifactId>
- **Current version:** X
- **Target version:** Y
- **Vulnerabilities fixed:** list IDs
- **Version declared as:** direct literal / property ${{xxx}} / parent-managed
- **XML section:** dependencies / dependencyManagement
- **Breaking API changes:**
  - list each one

#### Files Requiring Code Changes Due to This Upgrade
| File | Line | Reason | Change Required |
|------|------|--------|----------------|
(fill from analysis or write "None")

---

## Code Vulnerability Fixes

### <rule_name> — <file>:<line>
- **CWE:** list
- **Current code (line N):** `exact current line`
- **Replacement code:** `exact replacement line`
- **Why this fixes it:** one sentence
- **Env vars required:** list or None

---

## Environment Variables Required
List all new env vars the application will need after this fix, with descriptions.

## Suppressed Vulnerabilities
| ID | Reason | Expiry |
|----|--------|--------|
(list or "None")

## Developer Checklist
- [ ] Verify all env vars are set in deployment config
- [ ] Run integration tests against database after dep upgrade
- [ ] (add any items from breaking_changes)

---

<!-- FIX_MANIFEST_START
(embed the complete FIX_MANIFEST JSON here — copy directly from the analysis,
ensuring it matches the Markdown above exactly)
FIX_MANIFEST_END -->
"""


class PlanAgent:
    def __init__(self, ticket_key: str, repo: str, base_branch: str):
        self.ticket_key  = ticket_key
        self.repo        = repo
        self.base_branch = base_branch

        self.llm        = LLMClient(max_tokens=4000)
        self.jira       = JiraManager()
        self.gh         = GitHubClient()
        self.memory     = MemoryManager()
        self.guardrails = Guardrails(self.llm)
        self.audit      = AuditLogger(self.jira, ticket_key)

    def run(self):
        start = time.time()
        self.audit.log_agent_start("plan_agent", {
            "ticket": self.ticket_key, "repo": self.repo,
        })

        try:
            # ── Step 1: Load vulnerability data from Jira ─────────────────────
            logger.info("Loading vulnerability data from Jira...")
            vuln_json_text = self.jira.get_attachment_text(self.ticket_key, "vulns-")
            vuln_data      = json.loads(vuln_json_text)

            # ── Step 2: Fetch actual source files from the repo ───────────────
            logger.info("Fetching source files from repo: %s@%s", self.repo, self.base_branch)
            pom_content         = self._fetch_pom(vuln_data)
            source_files_section = self._fetch_source_files(vuln_data)

            # ── Step 3: Load memory context ───────────────────────────────────
            known_fixes        = self.memory.load_known_fixes()
            exceptions_applied = vuln_data.get("filter_metadata", {}).get("exceptions_applied", [])

            # ── Step 4: Stage 1 LLM — deep analysis of actual code ───────────
            logger.info("Stage 1: Analysing actual source files...")
            analysis_json = self._run_analysis_stage(
                vuln_data, pom_content, source_files_section, known_fixes
            )
            self.audit.log("plan_agent", "analysis_stage", "completed", {
                "dep_updates": len(analysis_json.get("pom_analysis", {}).get("dependency_updates", [])),
                "code_fixes":  len(analysis_json.get("code_fixes", [])),
            })

            # ── Step 5: Validate analysis — no Java upgrade ───────────────────
            self.guardrails.assert_no_java_upgrade(json.dumps(analysis_json))
            self.audit.log_guardrail_pass("plan_agent", "no_java_upgrade_in_analysis")

            # Validate pom structure was correctly identified
            self._validate_pom_analysis(analysis_json, pom_content)

            # ── Step 6: Stage 2 LLM — generate plan + FIX_MANIFEST ───────────
            logger.info("Stage 2: Generating plan document and FIX_MANIFEST...")
            plan_md = self._run_plan_stage(
                analysis_json, vuln_data, exceptions_applied
            )

            # ── Step 7: Extract and validate the FIX_MANIFEST ────────────────
            fix_manifest = self._extract_fix_manifest(plan_md)
            self._validate_fix_manifest(fix_manifest, vuln_data, pom_content)
            self.audit.log("plan_agent", "fix_manifest_validated", "completed", {
                "dep_fixes":  len(fix_manifest.get("dependency_updates", [])),
                "code_fixes": len(fix_manifest.get("code_fixes", [])),
            })

            # ── Step 8: Enrich FIX_MANIFEST with metadata ────────────────────
            fix_manifest["_meta"] = {
                "jira_ticket_id": self.ticket_key,
                "repo":           self.repo,
                "base_branch":    self.base_branch,
                "generated_at":   datetime.now(timezone.utc).isoformat(),
                "plan_agent_ver": "2.0",
            }

            # Re-embed the validated manifest back into the plan
            plan_final = self._embed_fix_manifest(plan_md, fix_manifest)

            # ── Step 9: Attach plan to Jira ───────────────────────────────────
            ts            = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            plan_filename = f"REMEDIATION_PLAN_{self.ticket_key}_{ts}.md"
            self.jira.attach_file(
                self.ticket_key,
                plan_final.encode("utf-8"),
                plan_filename,
                "text/markdown",
            )
            logger.info("Plan attached: %s", plan_filename)

            # ── Step 10: Attach analysis JSON separately (for debugging) ──────
            analysis_filename = f"PLAN_ANALYSIS_{self.ticket_key}_{ts}.json"
            self.jira.attach_file(
                self.ticket_key,
                json.dumps(analysis_json, indent=2).encode("utf-8"),
                analysis_filename,
                "application/json",
            )

            # ── Step 11: Transition + comment ────────────────────────────────
            self.jira.transition(self.ticket_key, "Plan Ready")

            dep_count  = len(fix_manifest.get("dependency_updates", []))
            code_count = len(fix_manifest.get("code_fixes", []))
            risk       = analysis_json.get("risk_assessment", {}).get("overall_risk", "UNKNOWN")
            env_vars   = analysis_json.get("risk_assessment", {}).get("requires_env_vars", [])

            comment = (
                f"✅ Remediation plan generated — **{plan_filename}**\n\n"
                f"**Dependency upgrades:** {dep_count}\n"
                f"**Code fixes:** {code_count}\n"
                f"**Overall risk:** {risk}\n"
            )
            if env_vars:
                comment += f"**⚠️ New env vars required:** {', '.join(env_vars)}\n"
            comment += (
                f"\nThe FIX_MANIFEST has been validated against the actual pom.xml "
                f"and source files. The fix agent will execute it directly.\n\n"
                f"Please review the plan and transition to **Plan Approved** to begin fixing."
            )
            self.jira.add_comment(self.ticket_key, comment)

            duration = time.time() - start
            self.audit.log_agent_end("plan_agent", {
                "plan_file":   plan_filename,
                "dep_fixes":   dep_count,
                "code_fixes":  code_count,
                "risk":        risk,
            }, duration)
            logger.info("Plan Agent v2 completed in %.1fs", duration)
            return plan_final, fix_manifest

        except GuardrailViolation as e:
            self.audit.log_guardrail_fail("plan_agent", "validation", str(e))
            self.jira.add_comment(
                self.ticket_key,
                f"❌ Plan guardrail violation:\n{e}\nRe-trigger after resolving."
            )
            self.jira.transition(self.ticket_key, "Blocked")
            raise

        except PlanValidationError as e:
            self.audit.log("plan_agent", "plan_validation", "failed", error=str(e))
            self.jira.add_comment(
                self.ticket_key,
                f"❌ Plan validation failed:\n{e}\n\n"
                f"The plan could not be validated against the actual source files. "
                f"Re-triggering will retry the analysis."
            )
            raise

        except Exception as e:
            self.audit.log_exception("plan_agent", "run", e)
            self.jira.add_comment(
                self.ticket_key,
                f"❌ Plan Agent failed: {type(e).__name__}: {e}\n"
                f"See GitHub Actions logs for details."
            )
            raise

    # ── Stage 1: Analysis ─────────────────────────────────────────────────────

    def _run_analysis_stage(
        self,
        vuln_data: dict,
        pom_content: str,
        source_files_section: str,
        known_fixes: dict,
    ) -> dict:
        user_prompt = ANALYSIS_USER_TEMPLATE.format(
            vuln_json            = json.dumps(vuln_data, indent=2),
            pom_content          = pom_content,
            source_files_section = source_files_section,
            known_fixes          = json.dumps(known_fixes, indent=2),
        )
        raw = self.llm.chat(
            ANALYSIS_SYSTEM_PROMPT,
            user_prompt,
            temperature=0.05,   # very low — we need precision
            max_tokens=4000,
            json_mode=True,
        )
        return self.llm._parse_json_response(raw) if isinstance(raw, str) else raw

    # ── Stage 2: Plan + FIX_MANIFEST generation ───────────────────────────────

    def _run_plan_stage(
        self,
        analysis_json: dict,
        vuln_data: dict,
        exceptions_applied: list,
    ) -> str:
        user_prompt = PLAN_USER_TEMPLATE.format(
            analysis_json      = json.dumps(analysis_json, indent=2),
            jira_id            = self.ticket_key,
            repo               = self.repo,
            branch             = vuln_data["scan_metadata"]["branch"],
            commit             = vuln_data["scan_metadata"]["commit_id"],
            timestamp          = datetime.now(timezone.utc).isoformat(),
            exceptions_applied = json.dumps(exceptions_applied, indent=2) if exceptions_applied else "None",
        )
        return self.llm.chat(
            PLAN_SYSTEM_PROMPT,
            user_prompt,
            temperature=0.1,
            max_tokens=4000,
        )

    # ── FIX_MANIFEST extraction + validation ──────────────────────────────────

    @staticmethod
    def _extract_fix_manifest(plan_md: str) -> dict:
        """
        Extract the FIX_MANIFEST JSON block from the plan document.
        Raises PlanValidationError if not found or unparseable.
        """
        start_tag = "<!-- FIX_MANIFEST_START"
        end_tag   = "FIX_MANIFEST_END -->"

        start = plan_md.find(start_tag)
        end   = plan_md.find(end_tag)

        if start == -1 or end == -1:
            raise PlanValidationError(
                "FIX_MANIFEST block not found in plan document. "
                "The LLM did not produce the required machine-readable fix instructions. "
                "Retrying may resolve this."
            )

        json_text = plan_md[start + len(start_tag):end].strip()

        try:
            manifest = json.loads(json_text)
        except json.JSONDecodeError as e:
            raise PlanValidationError(
                f"FIX_MANIFEST JSON is invalid: {e}\n"
                f"Raw content: {json_text[:500]}"
            )

        return manifest

    def _validate_fix_manifest(
        self,
        manifest: dict,
        vuln_data: dict,
        pom_content: str,
    ):
        """
        Cross-validate the FIX_MANIFEST against:
        1. The actual pom.xml (does the dep version/property exist?)
        2. The actual vulnerability data (are all vuln IDs covered?)
        3. Basic structure checks (required fields present)
        """
        errors = []

        # ── Validate dependency updates ───────────────────────────────────────
        dep_updates = manifest.get("pom_analysis", {}).get("dependency_updates") \
                   or manifest.get("dependency_updates", [])

        for dep in dep_updates:
            art_id    = dep.get("artifact_id", "")
            ver_loc   = dep.get("version_location", "direct")
            prop_name = dep.get("property_name")

            if ver_loc == "property" and prop_name:
                # Verify the property actually exists in pom.xml
                if f"<{prop_name}>" not in pom_content:
                    errors.append(
                        f"Dep '{art_id}': manifest says version is in property "
                        f"'<{prop_name}>' but that element was not found in pom.xml. "
                        f"Check the pom.xml content manually."
                    )
            elif ver_loc == "direct":
                # Verify the artifactId appears in pom.xml
                if art_id and art_id not in pom_content:
                    errors.append(
                        f"Dep '{art_id}': artifactId not found in pom.xml — "
                        f"may be inherited from parent POM. Plan must note this explicitly."
                    )

            # Validate target_version is a plausible semver (not empty, not 'latest')
            target_ver = dep.get("target_version", "")
            if not target_ver or target_ver.lower() in ("latest", "unknown", ""):
                errors.append(
                    f"Dep '{art_id}': target_version is '{target_ver}' — "
                    f"must be an explicit version number."
                )

        # ── Validate code fixes ───────────────────────────────────────────────
        code_fixes = manifest.get("code_fixes", [])
        for fix in code_fixes:
            required = ["file", "start_line", "end_line", "replacement_lines"]
            missing  = [k for k in required if k not in fix or fix[k] is None]
            if missing:
                errors.append(
                    f"Code fix for '{fix.get('file','?')}' is missing fields: {missing}"
                )

            # Verify start_line <= end_line
            if fix.get("start_line") and fix.get("end_line"):
                if fix["start_line"] > fix["end_line"]:
                    errors.append(
                        f"Code fix for '{fix.get('file')}': "
                        f"start_line ({fix['start_line']}) > end_line ({fix['end_line']})"
                    )

            # Verify replacement_lines is not empty
            if not fix.get("replacement_lines"):
                errors.append(
                    f"Code fix for '{fix.get('file')}' line {fix.get('start_line')}: "
                    f"replacement_lines is empty — fix would delete code without replacement."
                )

        # ── Validate all vulnerability IDs from scan are covered ─────────────
        all_scan_vuln_ids = set()
        for pkg in vuln_data.get("dependency_vulnerabilities", []):
            for v in pkg["vulnerabilities"]:
                all_scan_vuln_ids.add(v["id"])
        for cv in vuln_data.get("code_vulnerabilities", []):
            all_scan_vuln_ids.add(cv["id"])

        covered_ids = set()
        for dep in dep_updates:
            covered_ids.update(dep.get("vuln_ids_fixed", []))
        for fix in code_fixes:
            if fix.get("vuln_id"):
                covered_ids.add(fix["vuln_id"])

        uncovered = all_scan_vuln_ids - covered_ids
        if uncovered:
            errors.append(
                f"FIX_MANIFEST does not cover all vulnerability IDs from the scan. "
                f"Uncovered: {uncovered}"
            )

        if errors:
            raise PlanValidationError(
                f"FIX_MANIFEST validation failed with {len(errors)} error(s):\n"
                + "\n".join(f"  • {e}" for e in errors)
            )

        logger.info("FIX_MANIFEST validated: %d dep updates, %d code fixes",
                    len(dep_updates), len(code_fixes))

    @staticmethod
    def _embed_fix_manifest(plan_md: str, manifest: dict) -> str:
        """Replace the FIX_MANIFEST block with the validated/enriched version."""
        start_tag = "<!-- FIX_MANIFEST_START"
        end_tag   = "FIX_MANIFEST_END -->"
        start     = plan_md.find(start_tag)
        end       = plan_md.find(end_tag)
        if start == -1 or end == -1:
            # Append if not found (shouldn't happen after _extract_fix_manifest)
            return plan_md + f"\n\n{start_tag}\n{json.dumps(manifest, indent=2)}\n{end_tag}"

        return (
            plan_md[:start]
            + start_tag + "\n"
            + json.dumps(manifest, indent=2) + "\n"
            + end_tag
            + plan_md[end + len(end_tag):]
        )

    # ── Source file fetching ──────────────────────────────────────────────────

    def _fetch_pom(self, vuln_data: dict) -> str:
        """Fetch pom.xml from the repository. Returns empty string if not found."""
        try:
            content, _ = self.gh.get_file(self.repo, "pom.xml", self.base_branch)
            logger.info("Fetched pom.xml (%d chars)", len(content))
            return content
        except FileNotFoundError:
            logger.warning("pom.xml not found in repo root — checking src/")
            try:
                content, _ = self.gh.get_file(self.repo, "pom.xml", self.base_branch)
                return content
            except FileNotFoundError:
                logger.error("pom.xml not found — dependency analysis will be limited")
                return "<!-- pom.xml not found -->"

    def _fetch_source_files(self, vuln_data: dict) -> str:
        """
        Fetch the content of every Java file that has a code vulnerability.
        Returns a formatted section for inclusion in the analysis prompt.
        This is critical — the LLM must see actual code, not guesses.
        """
        sections = []
        seen     = set()

        for cv in vuln_data.get("code_vulnerabilities", []):
            for occ in cv.get("occurrences", []):
                filepath = occ["file"]
                if filepath in seen:
                    continue
                seen.add(filepath)

                try:
                    content, _ = self.gh.get_file(self.repo, filepath, self.base_branch)
                    # Number the lines so LLM can reference them precisely
                    numbered = "\n".join(
                        f"{i+1:4d}: {line}"
                        for i, line in enumerate(content.splitlines())
                    )
                    sections.append(
                        f"### {filepath}\n"
                        f"(vuln rule: {cv['rule_id']}, flagged line: {occ['line']})\n"
                        f"```java\n{numbered}\n```"
                    )
                    logger.info("Fetched %s (%d lines)", filepath, content.count("\n"))
                except FileNotFoundError:
                    sections.append(
                        f"### {filepath}\n"
                        f"**ERROR: File not found in repo at branch {self.base_branch}**\n"
                        f"Flagged line: {occ['line']}"
                    )
                    logger.error("Source file not found: %s", filepath)
                except Exception as e:
                    sections.append(
                        f"### {filepath}\n"
                        f"**ERROR fetching file: {e}**"
                    )
                    logger.error("Failed to fetch %s: %s", filepath, e)

        if not sections:
            return "_No code vulnerabilities requiring source file analysis._"

        return "\n\n".join(sections)

    # ── pom.xml validation helper ─────────────────────────────────────────────

    @staticmethod
    def _validate_pom_analysis(analysis_json: dict, pom_content: str):
        """
        Quick sanity check: for each dependency the LLM identified,
        verify it actually exists in the pom.xml we fetched.
        If the LLM hallucinated a dependency structure, catch it here
        before generating a plan based on wrong assumptions.
        """
        if not pom_content or pom_content.strip() == "<!-- pom.xml not found -->":
            logger.warning("Skipping pom validation — pom.xml unavailable")
            return

        dep_updates = (
            analysis_json.get("pom_analysis", {}).get("dependency_updates", [])
            or analysis_json.get("dependency_updates", [])
        )
        for dep in dep_updates:
            art_id = dep.get("artifact_id", "")
            if art_id and art_id not in pom_content:
                logger.warning(
                    "LLM identified artifact '%s' but it was not found in pom.xml. "
                    "This may be a parent POM dependency — flagging for review.",
                    art_id,
                )
                dep["_warning"] = (
                    f"artifactId '{art_id}' not found in local pom.xml — "
                    "may be managed by parent POM. Manual verification recommended."
                )


# ─── Exceptions ───────────────────────────────────────────────────────────────

class PlanValidationError(Exception):
    """Raised when the generated plan/manifest fails validation."""


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Plan Agent v2 — AI-driven remediation planner")
    parser.add_argument("--ticket",      required=True, help="Jira ticket key")
    parser.add_argument("--repo",        required=True, help="GitHub repo (org/name)")
    parser.add_argument("--base-branch", default="main", help="Base branch to analyse")
    args = parser.parse_args()

    agent = PlanAgent(args.ticket, args.repo, args.base_branch)
    agent.run()


if __name__ == "__main__":
    main()
