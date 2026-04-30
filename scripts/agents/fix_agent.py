#!/usr/bin/env python3
"""
fix_agent.py — v2.0
                                         

Consumes the FIX_MANIFEST JSON block embedded in the plan document by
plan_agent v2.  Never re-derives fix logic — executes the manifest verbatim.

Key changes from v1:
- extract_fix_manifest() replaces parse_plan() — reads FIX_MANIFEST JSON directly
- update_pom() handles property-based versions, dependencyManagement section,
  and parent-managed deps (with a clear warning rather than silent skip)
- apply_code_fix() uses start_line/end_line/replacement_lines/imports_to_add
  from the manifest — no LLM re-derivation for the initial fix
- api_breaking_changes code fixes (files_requiring_code_changes) are applied
  alongside regular code fixes so dep upgrades don't break compilation
- Build retry correction prompt includes the manifest's original intent so the
  correcting LLM knows exactly what it was trying to achieve

Usage:
    python scripts/agents/fix_agent.py \
        --jira-id VULN-42 --remediation-id <uuid>

                 
                 
                                                                        
           
                                                                            
                                      
                       
                                                                           
                 
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from scripts.guardrails import run_all, GuardrailError
from scripts.utils import github_client as gh, memory
from scripts.utils.config import JiraStatus, GITHUB_ORG
from scripts.utils.jira_client import JiraClient
from scripts.utils.llm_client import chat

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

MAX_BUILD_RETRIES = int(os.environ.get("MAX_BUILD_RETRIES", "3"))

# ── FIX_MANIFEST delimiter (must match plan_agent exactly) ────────────────────
_MANIFEST_START = "<!-- FIX_MANIFEST_START"
_MANIFEST_END   = "FIX_MANIFEST_END -->"
                                                          

             
                                                                       
                                                                        
                                                           
                                              
                                                                        
                
                                                                    
                                                                       
                                                                            
   

class FixManifestError(Exception):
    """Raised when FIX_MANIFEST is missing, invalid, or fails validation."""


# ── LLM prompt for build-error correction ─────────────────────────────────────
CORRECTION_SYSTEM_PROMPT = """\
You are a Java security engineer reviewing a fix that caused a build failure.

Your task: correct the Java source file so the build error is resolved while
keeping the original security fix in place.

STRICT RULES:
1. Keep the security fix that was already applied — do not revert it.
2. Fix ONLY what the compiler or test error requires.
3. Do not change method signatures, class names, or package declarations.
4. Do not add or remove imports beyond what is strictly required.
5. Output ONLY the complete corrected file.  No markdown fences, no explanation.
"""


# ── Plan loader — Jira attachment first, governance repo fallback ──────────────

def _load_plan(jira: JiraClient, jira_id: str) -> str:
    """
    Load the approved plan Markdown.

                                                                   
    Primary:  Jira attachment  remediation-plan-vN.md  (newest version first).
                                                                           
    Fallback: governance repo  plans/{jira_id}/plan-vN.md.
                                                                         
                                                            
    """
                                       
    for v in range(10, 0, -1):
        raw = jira.get_attachment(jira_id, f"remediation-plan-v{v}.md")
        if raw:
            log.info("Loaded plan v%d from Jira attachment on %s", v, jira_id)
            return raw

                               
                
    log.warning("Plan not found as Jira attachment on %s — falling back to governance repo",
                jira_id)
     
    plan = memory.latest_plan(jira_id)
    if plan:
        log.info("Loaded plan from governance repo for %s", jira_id)
        return plan

    raise FixManifestError(
        f"No approved plan found for {jira_id}. "
        "Expected a 'remediation-plan-vN.md' Jira attachment."
    )


# ── FIX_MANIFEST extraction ───────────────────────────────────────────────────

def extract_fix_manifest(plan_md: str) -> dict:
    """
    Extract and parse the FIX_MANIFEST JSON block from the plan document.
    Raises FixManifestError if the block is missing or the JSON is invalid.
                                                           
                                                
                          
    """
    s = plan_md.find(_MANIFEST_START)
    e = plan_md.find(_MANIFEST_END)
                                 

    if s == -1 or e == -1:
        raise FixManifestError(
            "FIX_MANIFEST block not found in plan. "
            "The plan was not generated by plan_agent v2, or the block was "
            "accidentally removed. Re-run the plan agent to regenerate."
        )
                            
                                                 
                            
                                        
                          

    json_text = plan_md[s + len(_MANIFEST_START):e].strip()
    try:
        manifest = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise FixManifestError(
            f"FIX_MANIFEST JSON is invalid: {exc}\n"
            f"First 500 chars: {json_text[:500]}"
        ) from exc

    # Basic structure check
    if "dependency_updates" not in manifest and "code_fixes" not in manifest:
        raise FixManifestError(
            "FIX_MANIFEST is missing both 'dependency_updates' and 'code_fixes' keys. "
            "Manifest may be malformed. Re-run plan agent."
        )

    return manifest
                                                       
                                                     
                              
                                                
                                    
                                               
                                               
                                                   
                  

                                                  
                
                                     
                                           
                                                                            
                                                                    
                  
                                            
                    

def _all_vuln_ids_from_manifest(manifest: dict) -> list[str]:
    ids = []
    for dep in manifest.get("dependency_updates", []):
        ids.extend(dep.get("vuln_ids_fixed", []))
    for fix in manifest.get("code_fixes", []):
        if fix.get("vuln_id"):
            ids.append(fix["vuln_id"])
    return list(dict.fromkeys(ids))  # deduplicate, preserve order

                                       
                                         
                                 

# ── pom.xml updater — handles all three version_location modes ────────────────

def update_pom(pom: str, dependency_updates: list[dict]) -> tuple[str, list[str]]:
    """
    Apply dependency version updates to pom.xml content.

    Handles:
      version_location = "direct"           — update <version> inside <dependency>
      version_location = "property:<name>"  — update <name>X.Y.Z</name> property
      version_location = "parent"           — cannot be auto-patched; logs warning

    Returns:
      (updated_pom_content, list_of_warnings)
    """
    result   = pom
    warnings = []

    for dep in dependency_updates:
        gid      = dep.get("group_id", "")
        aid      = dep.get("artifact_id", "")
        target   = dep.get("target_version", "")
        ver_loc  = dep.get("version_location", "direct")
        prop     = dep.get("property_name")          # e.g. "mysql.version"
        section  = dep.get("xml_section", "dependencies")

        if not target or target.lower() in ("latest", "unknown", ""):
            warnings.append(f"Skipping {aid}: target_version '{target}' is not explicit")
            continue

        # ── Case 1: property-based version ─────────────────────────────────
        if "property" in ver_loc and prop:
            prop_pattern = rf"(<{re.escape(prop)}>)[^<]*(</\s*{re.escape(prop)}>)"
            new_pom, n = re.subn(prop_pattern, rf"\g<1>{target}\g<2>", result)
            if n:
                result = new_pom
                log.info("pom.xml property <%s>: → %s", prop, target)
            else:
                warnings.append(
                    f"Property <{prop}> not found in pom.xml — "
                    f"could not update {aid} to {target}. Check pom manually."
                )
            continue

        # ── Case 2: parent-managed (no <version> in this pom) ──────────────
        if ver_loc == "parent":
            warnings.append(
                f"{aid}: version is parent-managed — cannot auto-patch. "
                f"Manually update the parent POM to include {target}."
            )
            continue

        # ── Case 3: direct <version> inside <dependency> ────────────────────
        # Build a pattern that matches the dep block (group + artifact, any order)
        # and replaces only its <version> tag.
        dep_block_pattern = (
            r"(<dependency>.*?<groupId>"
            + re.escape(gid)
            + r"</groupId>.*?<artifactId>"
            + re.escape(aid)
            + r"</artifactId>.*?<version>)[^<]*(</version>)"
        )
        new_pom, n = re.subn(dep_block_pattern, rf"\g<1>{target}\g<2>",
                             result, flags=re.DOTALL)
        if n:
            result = new_pom
            log.info("pom.xml %s:%s → %s (section: %s)", gid, aid, target, section)
        else:
            # Try reversed order (artifactId before groupId)
            dep_block_alt = (
                r"(<dependency>.*?<artifactId>"
                + re.escape(aid)
                + r"</artifactId>.*?<groupId>"
                + re.escape(gid)
                + r"</groupId>.*?<version>)[^<]*(</version>)"
            )
            new_pom, n = re.subn(dep_block_alt, rf"\g<1>{target}\g<2>",
                                 result, flags=re.DOTALL)
            if n:
                result = new_pom
                log.info("pom.xml %s:%s → %s (reversed element order)", gid, aid, target)
            else:
                warnings.append(
                    f"Could not find {gid}:{aid} with a direct <version> in pom.xml. "
                    f"It may be property-based or parent-managed — check the plan."
                )

    return result, warnings

                                                                                                                                                

# ── Source file patcher — uses manifest line ranges directly ──────────────────

def apply_code_fix(repo_dir: str, fix: dict) -> tuple[str, str]:
    """
    Apply a single code fix from the FIX_MANIFEST to a file on disk.

    Uses:
      fix.start_line / fix.end_line  — 1-indexed, inclusive
      fix.replacement_lines          — list of replacement line strings
      fix.imports_to_add             — list of import statements to inject

    Returns (original_content, patched_content).
    Raises FileNotFoundError if the file doesn't exist in the repo.
    """
    file_path = fix["file"]
    abs_path  = os.path.join(repo_dir, file_path.replace("/", os.sep))
                                                                               

    if not os.path.exists(abs_path):
        raise FileNotFoundError(
            f"File '{file_path}' not found in cloned repo at {abs_path}. "
            "Check that the plan's file path is correct."
        )

    original_content = Path(abs_path).read_text(encoding="utf-8")
    lines            = original_content.splitlines(keepends=True)

    start = fix["start_line"] - 1   # convert to 0-indexed
    end   = fix["end_line"]         # exclusive end for slice (1-indexed end is inclusive)

    if start < 0 or end > len(lines) or start >= end:
        raise ValueError(
            f"Fix for '{file_path}': line range [{fix['start_line']}, {fix['end_line']}] "
            f"is out of bounds (file has {len(lines)} lines)."
        )

    # Preserve the indentation style of the first line being replaced
    # if the replacement lines don't already have leading whitespace
    leading = re.match(r"^(\s*)", lines[start]).group(1) if lines else ""

    replacement = fix.get("replacement_lines", [])
    # Ensure every replacement line ends with a newline
    replacement_with_newlines = [
        (r if r.endswith("\n") else r + "\n")
        for r in replacement
    ]

    patched_lines = lines[:start] + replacement_with_newlines + lines[end:]

    # Inject any required imports (after the last existing import line)
    imports_to_add = fix.get("imports_to_add", [])
    if imports_to_add:
        patched_lines = _inject_imports(patched_lines, imports_to_add)

    patched_content = "".join(patched_lines)
    Path(abs_path).write_text(patched_content, encoding="utf-8")

    log.info("Applied fix: %s lines %d-%d (%d→%d lines)",
             file_path, fix["start_line"], fix["end_line"],
             end - start, len(replacement))

    return original_content, patched_content


def _inject_imports(lines: list[str], imports: list[str]) -> list[str]:
    """
    Insert import statements after the last existing import statement in the file.
    If no import block exists, insert after the package declaration.
    """
    last_import_idx = -1
    package_idx     = -1

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("import "):
            last_import_idx = i
        elif stripped.startswith("package "):
            package_idx = i

    insert_after = last_import_idx if last_import_idx != -1 else package_idx
    if insert_after == -1:
        insert_after = 0   # fallback: top of file

    import_lines = [f"import {imp};\n" if not imp.startswith("import ") else f"{imp}\n"
                    for imp in imports]
    return lines[:insert_after + 1] + import_lines + lines[insert_after + 1:]


# ── API-breaking code changes from dep upgrades ───────────────────────────────

def collect_api_breaking_fixes(dependency_updates: list[dict]) -> list[dict]:
    """
    Extract files_requiring_code_changes from dep upgrades.
    These are files that break compilation after a dep version bump
    (e.g. renamed driver class after MySQL connector upgrade).

    Returns a flat list compatible with the code_fixes format,
    BUT without start_line/replacement_lines — these are flagged for
    LLM-assisted fixing since the plan agent identified the file and reason
    but the exact replacement depends on actual file content.
    """
    fixes = []
    for dep in dependency_updates:
        for fc in dep.get("files_requiring_code_changes", []):
            fixes.append({
                "file":              fc["file"],
                "vuln_id":           None,
                "rule_id":           f"api_breaking_change:{dep['artifact_id']}",
                "fix_type":          "api_breaking",
                "reason":            fc.get("reason", ""),
                "line_hint":         fc.get("line", 0),
                "breaking_changes":  dep.get("api_breaking_changes", []),
                "dep_artifact_id":   dep.get("artifact_id", ""),
                "dep_target_version": dep.get("target_version", ""),
                # These are filled by apply_api_breaking_fix via LLM
                "replacement_lines": [],
                "imports_to_add":    [],
            })
    return fixes


def apply_api_breaking_fix(repo_dir: str, fix: dict,
                           plan_context: str) -> tuple[str, str]:
    """
    For API-breaking changes flagged by a dep upgrade, use the LLM to apply
    the specific change. The LLM is given the actual file + the explicit list
    of breaking changes + the reason so it can make a targeted fix.
    """
    file_path = fix["file"]
    abs_path  = os.path.join(repo_dir, file_path.replace("/", os.sep))

    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"File '{file_path}' not found for API-breaking fix")

    original = Path(abs_path).read_text(encoding="utf-8")
    numbered = "\n".join(f"{i+1:4d}: {l}"
                         for i, l in enumerate(original.splitlines()))

    breaking_list = "\n".join(f"  - {b}" for b in fix.get("breaking_changes", []))
    system_prompt = """\
You are a Java security engineer applying a targeted API migration fix.

The project's dependency has been upgraded to a new version that has breaking
API changes.  You must update this file to be compatible with the new version.

STRICT RULES:
1. Apply ONLY the changes needed to fix the API incompatibility listed below.
2. Do not change business logic, method signatures (unless required), or comments.
3. Do not change the Java/Maven version.
4. Output ONLY the complete corrected file.  No markdown, no explanation.
"""
    user_prompt = (
        f"File: {file_path}\n\n"
        f"Dependency upgraded: {fix['dep_artifact_id']} → {fix['dep_target_version']}\n"
        f"Reason this file needs changing: {fix['reason']}\n"
        f"Line hint: {fix['line_hint']}\n\n"
        f"Breaking API changes in this upgrade:\n{breaking_list}\n\n"
        f"File content (line-numbered):\n{numbered}\n\n"
        f"Plan context:\n{plan_context[:1500]}"
    )

    fixed = chat(system_prompt, user_prompt, max_tokens=8192, temperature=0.05)
    fixed = _strip_fences(fixed)
    Path(abs_path).write_text(fixed, encoding="utf-8")
    log.info("API-breaking fix applied: %s", file_path)
    return original, fixed


# ── Build correction helper ───────────────────────────────────────────────────
                                            

def correct_source_file(file_path: str, current_content: str,
                        build_error: str, original_fix: dict,
                        plan_context: str) -> str:
    """
    Ask the LLM to correct a file that caused a build failure.
    Includes the original manifest intent so the LLM knows what it was trying to do.
    Returns corrected file content.
    """
    intent = (
        f"The security fix being applied was:\n"
        f"  Rule: {original_fix.get('rule_id', 'unknown')}\n"
        f"  Lines {original_fix.get('start_line', '?')}–{original_fix.get('end_line', '?')}\n"
        f"  Replacement was:\n"
        + "\n".join(f"    {r}" for r in original_fix.get("replacement_lines", []))
    ) if original_fix else ""

    user_prompt = (
        f"File: {file_path}\n\n"
        f"Build / test error output (last 3000 chars):\n{build_error[-3000:]}\n\n"
        f"{intent}\n\n"
        f"Current (broken) file:\n{current_content}\n\n"
        f"Plan context:\n{plan_context[:1500]}"
    )
    corrected = chat(CORRECTION_SYSTEM_PROMPT, user_prompt,
                     max_tokens=8192, temperature=0.05)
    return _strip_fences(corrected)


def _strip_fences(text: str) -> str:
    text = re.sub(r"^```(?:java|xml)?\s*\n?", "", text.strip())
    return re.sub(r"\n?```\s*$", "", text)


# ── Shell helpers ─────────────────────────────────────────────────────────────

def _sh(cmd: list[str], cwd: str, timeout: int = 600) -> tuple[int, str]:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def _git(args: list[str], cwd: str) -> None:
    rc, out = _sh(["git"] + args, cwd)
    if rc != 0:
        raise RuntimeError(f"git {' '.join(args)} failed:\n{out[-2000:]}")


def _clone(repo: str, branch: str, dest: str) -> None:
    token = os.environ["GITHUB_TOKEN"]
    url   = f"https://x-access-token:{token}@github.com/{GITHUB_ORG}/{repo}.git"
    rc, out = _sh(
        ["git", "clone", "--branch", branch, "--depth", "1", url, dest],
        cwd="/tmp",
    )
    if rc != 0:
        raise RuntimeError(f"git clone failed:\n{out}")
    log.info("Cloned %s@%s → %s", repo, branch, dest)


                                                                                                                            

def _mvn(goal: str, repo_dir: str, timeout: int = 600) -> tuple[int, str]:
    return _sh(
        ["mvn", "--batch-mode", "--no-transfer-progress"] + goal.split(),
        repo_dir,
        timeout=timeout,
    )


                                                             
                                                      
                                                     
                                                              
       
                                                                          
                                                           
                                
       
                                                                         
                                        
                   
                                                    
                                                                         
                                            
                                                                                 
                                                          
                                
                                                
                                                         
                                               
                     


# ── Main ──────────────────────────────────────────────────────────────────────

def run(jira_id: str, remediation_id: str) -> None:
    jira = JiraClient()

    # 1. Load normalised JSON from Jira
    raw_norm = jira.get_attachment(jira_id, "normalised-vulnerabilities.json")
    if not raw_norm:
        raise RuntimeError("normalised-vulnerabilities.json not found on Jira issue")
    norm   = json.loads(raw_norm)
    meta   = norm["scan_metadata"]
    repo   = meta["repository"]
    branch = meta["branch"]

    # 2. Load plan and extract FIX_MANIFEST
                   
    plan_md  = _load_plan(jira, jira_id)
    manifest = extract_fix_manifest(plan_md)

    dep_updates   = manifest.get("dependency_updates", [])
    code_fixes    = manifest.get("code_fixes", [])
    vuln_ids      = _all_vuln_ids_from_manifest(manifest)
    api_fixes     = collect_api_breaking_fixes(dep_updates)

    log.info("Fix Agent v2: %s  repo=%s  dep_updates=%d  code_fixes=%d  api_fixes=%d",
             jira_id, repo, len(dep_updates), len(code_fixes), len(api_fixes))
    memory.audit("fix_agent_started", jira_id, repo, remediation_id,
                 actor="fix-agent-v2",
                 details={"dep": len(dep_updates), "code": len(code_fixes),
                          "api_breaking": len(api_fixes)})

    # 3. Build fix branch
    short      = hashlib.sha1(remediation_id.encode()).hexdigest()[:7]
    fix_branch = f"fix/{jira_id.lower()}-{short}"

    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = os.path.join(tmp, repo)
        _clone(repo, branch, repo_dir)

                                
        _git(["config", "user.email", "ai-remediation@automation.local"], repo_dir)
        _git(["config", "user.name",  "AI Remediation Bot"], repo_dir)
        _git(["checkout", "-b", fix_branch], repo_dir)

        pom_path     = os.path.join(repo_dir, "pom.xml")
        original_pom = Path(pom_path).read_text(encoding="utf-8")
        new_pom      = original_pom

                           
                               
                                                                   
                                              

        # 4. Update pom.xml using manifest's version_location / property_name
        if dep_updates:
            new_pom, pom_warnings = update_pom(original_pom, dep_updates)
            Path(pom_path).write_text(new_pom, encoding="utf-8")
            for w in pom_warnings:
                log.warning("pom.xml: %s", w)
            if pom_warnings:
                jira.add_comment(jira_id,
                    "Fix Agent pom.xml warnings (manual review may be needed):\n"
                    + "\n".join(f"• {w}" for w in pom_warnings))

        # 5. Apply code fixes directly from manifest (no LLM re-derivation)
        file_diffs: list[tuple[str, str]]             = []
        approved_source_files: list[str]              = []
        fix_by_file:  dict[str, dict]                 = {}   # for correction loop

        for fix in code_fixes:
            fp = fix["file"]
            try:
                original, patched = apply_code_fix(repo_dir, fix)
                                                                
                file_diffs.append((original, patched))
                approved_source_files.append(fp)
                fix_by_file[fp] = fix
            except (FileNotFoundError, ValueError) as exc:
                log.error("Code fix failed for %s: %s", fp, exc)
                jira.add_comment(jira_id,
                    f"Fix Agent: could not apply fix for `{fp}`:\n{exc}")
                raise

        # 6. Apply API-breaking changes from dep upgrades (LLM-assisted)
        for fix in api_fixes:
            fp = fix["file"]
            if fp in approved_source_files:
                log.info("API-breaking fix for %s already covered by code_fixes — skipping", fp)
                continue
            try:
                original, patched = apply_api_breaking_fix(repo_dir, fix, plan_md)
                file_diffs.append((original, patched))
                approved_source_files.append(fp)
                fix_by_file[fp] = fix
            except FileNotFoundError as exc:
                log.warning("API-breaking fix skipped (file not found): %s — %s", fp, exc)

                                             
        changed_files = approved_source_files + (["pom.xml"] if dep_updates else [])

        # 7. Guardrails — policy checks (run once, not per retry)
        try:
            run_all(
                pom_before     = original_pom,
                pom_after      = new_pom,
                changed_files  = changed_files,
                approved_files = approved_source_files,
                file_diffs     = file_diffs,
            )
            log.info("All guardrails passed ✓")
        except GuardrailError as exc:
                                     
            jira.add_comment(jira_id, f"Fix Agent ABORTED — guardrail violation:\n{exc}")
            jira.transition(jira_id, JiraStatus.FIX_FAILED)
            raise

        # 8. Dependency resolution check
                                                                       
        rc, out = _mvn("dependency:resolve -q", repo_dir)
        if rc != 0:
            jira.add_comment(jira_id,
                f"Fix Agent: dependency resolution failed — check pom.xml version changes.\n\n"
                f"{out[-2000:]}")
            jira.transition(jira_id, JiraStatus.FIX_FAILED)
            raise RuntimeError(f"mvn dependency:resolve failed:\n{out[-3000:]}")
        log.info("Dependency resolution OK ✓")

        # 9. Compile + test with LLM-assisted retry loop
                                                                             
                                                              
        build_error  = ""
        build_passed = False
                                      

        for attempt in range(1, MAX_BUILD_RETRIES + 1):

            # On retry: ask LLM to correct each changed source file
            if attempt > 1 and approved_source_files:
                log.info("Build retry %d/%d — requesting LLM corrections", attempt, MAX_BUILD_RETRIES)
                new_diffs = []
                for fp in approved_source_files:
                    abs_path = os.path.join(repo_dir, fp.replace("/", os.sep))
                    current  = Path(abs_path).read_text(encoding="utf-8")
                    corrected = correct_source_file(
                        fp, current, build_error,
                        fix_by_file.get(fp, {}),
                        plan_md,
                    )
                    if corrected != current:
                        Path(abs_path).write_text(corrected, encoding="utf-8")
                        log.info("Correction written: %s", fp)
                    new_diffs.append((current, corrected))
                file_diffs = new_diffs

                jira.add_comment(jira_id,
                            
                    f"Fix Agent: build attempt {attempt - 1} failed. "
                    f"LLM correction applied — retrying "
                    f"(attempt {attempt}/{MAX_BUILD_RETRIES}).\n\n"
                    f"Error (truncated):\n{build_error[-1000:]}")
                 

            # Compile
            rc, out = _mvn("compile -q", repo_dir)
            if rc != 0:
                build_error = out
                log.warning("Compile FAILED (attempt %d/%d)", attempt, MAX_BUILD_RETRIES)
                if attempt < MAX_BUILD_RETRIES:
                    continue
                break

            log.info("Compilation OK ✓ (attempt %d)", attempt)

            # Test
            rc, test_out = _mvn("test", repo_dir)
            if rc != 0:
                build_error = test_out
                log.warning("Tests FAILED (attempt %d/%d)", attempt, MAX_BUILD_RETRIES)
                if attempt < MAX_BUILD_RETRIES:
                         
                    continue
                break

            log.info("All tests passed ✓ (attempt %d)", attempt)
            build_passed = True
            break

        if not build_passed:
                                                                
            jira.add_attachment(jira_id, "build-failure.log",
                                build_error.encode(), "text/plain")
            jira.add_comment(jira_id,
                        
                f"Fix Agent: build FAILED after {MAX_BUILD_RETRIES} LLM correction "
                f"attempt(s). See attached build-failure.log. Status → Fix Failed.\n\n"
                f"Last error (truncated):\n{build_error[-1500:]}")
             
            jira.transition(jira_id, JiraStatus.FIX_FAILED)
            for vid in vuln_ids:
                memory.record_attempt(repo, vid, jira_id, "build_failed",
                                      error=build_error[-1000:])
                                 
            raise RuntimeError(f"Build failed after {MAX_BUILD_RETRIES} retries")
               

        # 10. Commit
        _git(["add", "-A"], repo_dir)
        ids_str    = ", ".join(vuln_ids[:5])
                               
                                                     
                                                        
         
        commit_msg = (
            f"fix(security): remediate {ids_str} per {jira_id}\n\n"
            f"Remediation ID : {remediation_id}\n"
            f"Approved plan  : {jira_id} (remediation-plan-vN.md attachment)\n"
            f"Files changed  : {', '.join(changed_files)}"
                                    
        )
        _git(["commit", "-m", commit_msg], repo_dir)

        # 11. Push
        token  = os.environ["GITHUB_TOKEN"]
        remote = f"https://x-access-token:{token}@github.com/{GITHUB_ORG}/{repo}.git"
        _git(["remote", "set-url", "origin", remote], repo_dir)
        _git(["push", "origin", fix_branch], repo_dir)
        log.info("Pushed branch %s", fix_branch)

    # 12. Create Pull Request
    risk = manifest.get("risk_assessment", {}).get("overall_risk", "UNKNOWN")
    env_vars = manifest.get("risk_assessment", {}).get("requires_env_vars", [])
    env_var_note = (
        f"\n> ⚠️ **New env vars required:** {', '.join(env_vars)}\n"
        if env_vars else ""
    )
    pom_warnings_note = ""
    if dep_updates:
        parent_managed = [d["artifact_id"] for d in dep_updates
                          if d.get("version_location") == "parent"]
        if parent_managed:
            pom_warnings_note = (
                f"\n> ⚠️ **Parent-managed deps (manual update needed):** "
                f"{', '.join(parent_managed)}\n"
            )

    pr_body = (
        f"## Security Remediation — {jira_id}\n\n"
        f"| Field | Value |\n|---|---|\n"
        f"| Jira | {jira_id} |\n"
        f"| Remediation ID | `{remediation_id}` |\n"
        f"| Branch | `{fix_branch}` |\n"
        f"| Overall Risk | {risk} |\n\n"
        f"{env_var_note}{pom_warnings_note}"
        f"### Vulnerabilities Fixed\n"
        + "".join(f"- `{v}`\n" for v in vuln_ids)
        + f"\n### Files Changed\n"
        + "".join(f"- `{f}`\n" for f in changed_files)
        + "\n### Fix Method\n"
        "Fixes applied directly from FIX_MANIFEST (plan_agent v2) — "
        "no LLM re-derivation of fix logic.\n\n"
        "### Guardrails Passed\n"
        "- Java version: NOT changed\n"
        "- Scope: ONLY approved files modified\n"
        "- Tests: ALL PASSING\n\n"
        "### Reviewer Checklist\n"
        "- [ ] pom.xml version changes look correct\n"
        "- [ ] Source changes match the approved plan\n"
        "- [ ] No business logic appears altered\n"
        + ("- [ ] Set required env vars before deploying\n" if env_vars else "")
        + ("- [ ] Update parent POM for parent-managed deps\n" if pom_warnings_note else "")
    )

    pr_url = gh.create_pr(
        repo_name = repo,
        title     = f"[Security] {jira_id} — vulnerability remediation",
        body      = pr_body,
        head      = fix_branch,
        base      = branch,
    )

    # 13. Update Jira
    jira.add_comment(jira_id,
                
        f"Fix Agent v2 completed.\n"
        f"PR: {pr_url}\n"
        f"Branch: `{fix_branch}`\n"
        f"Files changed: {', '.join(changed_files)}\n"
        f"All tests passed. Moving to In Validation.")
     
    jira.transition(jira_id, JiraStatus.IN_VALIDATION)

    # 14. Record attempts in memory
    for vid in vuln_ids:
        memory.record_attempt(repo, vid, jira_id, "pr_raised", pr_url=pr_url)

    # 15. Dispatch Validation Agent
                         
    gh.dispatch_workflow(repo, "validation-agent.yml",
                            
                         {"jira_id": jira_id, "remediation_id": remediation_id,
                          "fix_branch": fix_branch})
     

    memory.audit("fix_agent_completed", jira_id, repo, remediation_id,
                 actor="fix-agent-v2",
                 details={"pr_url": pr_url, "branch": fix_branch,
                          "files": changed_files, "vuln_ids": vuln_ids})
    log.info("Fix Agent v2 done.  PR: %s", pr_url)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--jira-id",        required=True)
    p.add_argument("--remediation-id", required=True)
    args = p.parse_args()
    try:
        run(args.jira_id, args.remediation_id)
    except Exception as exc:
        log.exception("Fix Agent v2 failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
