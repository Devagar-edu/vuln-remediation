"""
tests/test_core.py — Unit tests for pure-logic functions that need no network.

Run:
    pip install pytest
    pytest tests/test_core.py -v
"""
import json
import sys
import os

# Make scripts importable without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Patch environment so config.py doesn't raise on missing vars
_env_defaults = {
    "GITHUB_TOKEN":        "test",
    "GITHUB_ORG":          "test-org",
    "GITHUB_MODELS_TOKEN": "test",
    "JIRA_URL":            "https://test.atlassian.net",
    "JIRA_USER":           "test@test.com",
    "JIRA_TOKEN":          "test",
}
for k, v in _env_defaults.items():
    os.environ.setdefault(k, v)

import pytest
from scripts.normalise import normalise, _is_sarif, _is_already_normalised
from scripts.guardrails import (
    g1_java_version_unchanged,
    g2_scope_respected,
    g3_no_new_dependencies,
    g4_line_delta,
    g5_no_method_signature_change,
    run_all, GuardrailError,
)
from scripts.agents.fix_agent import parse_plan, update_pom
from scripts.fail_check import check


# ── normalise.py ──────────────────────────────────────────────────────────────

SAMPLE_NATIVE = {
    "vulnerabilities": [
        {
            "id": "SNYK-JAVA-MYSQL-451464",
            "packageName": "mysql:mysql-connector-java",
            "version": "5.1.49",
            "fixedIn": ["8.0.13"],
            "title": "Access Control Bypass",
            "severity": "high",
            "cvssScore": 8.8,
            "identifiers": {"CVE": ["CVE-2018-3258"], "CWE": ["CWE-288"]},
            "exploit": "Not Defined",
            "description": "Desc",
        }
    ]
}


def test_normalise_native_produces_schema():
    result = normalise(SAMPLE_NATIVE, repo="test-app", branch="main")
    assert "scan_metadata" in result
    assert result["scan_metadata"]["repository"] == "test-app"
    assert len(result["dependency_vulnerabilities"]) == 1
    pkg = result["dependency_vulnerabilities"][0]
    assert pkg["package"] == "mysql:mysql-connector-java"
    assert pkg["current_version"] == "5.1.49"
    assert pkg["vulnerabilities"][0]["severity"] == "high"


def test_normalise_passthrough():
    already = {
        "scan_metadata": {"scanner": "snyk", "repository": "r",
                          "branch": "main", "scan_time": "t",
                          "project": "p", "commit_id": "c",
                          "remediation_id": "u"},
        "dependency_vulnerabilities": [],
        "code_vulnerabilities": [],
        "summary": {},
    }
    result = normalise(already)
    assert result is already   # should be returned as-is


def test_normalise_summary_counts():
    result = normalise(SAMPLE_NATIVE)
    assert result["summary"]["high_count"] == 1
    assert result["summary"]["critical_count"] == 0


# ── guardrails.py ─────────────────────────────────────────────────────────────

POM_JAVA11 = "<maven.compiler.source>11</maven.compiler.source>"
POM_JAVA17 = "<maven.compiler.source>17</maven.compiler.source>"

def test_g1_passes_when_version_unchanged():
    r = g1_java_version_unchanged(POM_JAVA11, POM_JAVA11)
    assert r.passed

def test_g1_fails_when_version_changed():
    r = g1_java_version_unchanged(POM_JAVA11, POM_JAVA17)
    assert not r.passed
    assert "11" in r.detail and "17" in r.detail


def test_g2_passes_for_approved_files():
    r = g2_scope_respected(["src/Foo.java", "pom.xml"], ["src/Foo.java"])
    assert r.passed

def test_g2_fails_for_unapproved_file():
    r = g2_scope_respected(["src/Foo.java", "src/Bar.java"], ["src/Foo.java"])
    assert not r.passed
    assert "Bar.java" in r.detail


DEP_ONE = "<dependency><groupId>a</groupId></dependency>"
DEP_TWO = DEP_ONE + "<dependency><groupId>b</groupId></dependency>"

def test_g3_passes_same_count():
    assert g3_no_new_dependencies(DEP_ONE, DEP_ONE).passed

def test_g3_fails_when_dep_added():
    r = g3_no_new_dependencies(DEP_ONE, DEP_TWO)
    assert not r.passed


def test_g4_passes_small_delta():
    orig  = "a\n" * 100
    fixed = "a\n" * 105
    assert g4_line_delta(orig, fixed).passed

def test_g4_fails_large_delta():
    orig  = "a\n" * 50
    fixed = "a\n" * 200
    assert not g4_line_delta(orig, fixed).passed


def test_g5_passes_unchanged_sigs():
    code = "public String doThing(int x) { return null; }"
    assert g5_no_method_signature_change(code, code).passed

def test_g5_fails_renamed_method():
    before = "public String doThing(int x) { return null; }"
    after  = "public String renamed(int x) { return null; }"
    r = g5_no_method_signature_change(before, after)
    assert not r.passed


def test_run_all_raises_on_violation():
    with pytest.raises(GuardrailError):
        run_all(
            pom_before    = POM_JAVA11,
            pom_after     = POM_JAVA17,   # G1 violation
            changed_files = ["pom.xml"],
            approved_files= [],
        )


# ── fix_agent.parse_plan ──────────────────────────────────────────────────────

SAMPLE_PLAN = """
# Remediation Plan
**Jira:** VULN-42

## Vulnerability Summary
| ID | Package / File | Type | Severity | Action |
|----|----------------|------|----------|--------|
| SNYK-JAVA-MYSQL-451464 | mysql:mysql-connector-java | dep | high | upgrade |

## Dependency Changes (pom.xml)
| Dependency | Current Version | Fix Version | Validated | Breaking Risk |
|-----------|-----------------|-------------|-----------|---------------|
| mysql:mysql-connector-java | 5.1.49 | 8.0.28 | Yes | Medium |

## Code Changes Required
| File | Line | Vulnerability | Recommended Change |
|------|------|---------------|--------------------|
| src/main/java/com/demo/HardCodedSecretExample.java | 9 | HardcodedPassword | Replace literal with System.getenv |
"""

def test_parse_plan_dep_changes():
    plan = parse_plan(SAMPLE_PLAN)
    assert len(plan["dep_changes"]) == 1
    dep = plan["dep_changes"][0]
    assert dep["group_id"] == "mysql"
    assert dep["artifact_id"] == "mysql-connector-java"
    assert dep["fix_version"] == "8.0.28"

def test_parse_plan_code_changes():
    plan = parse_plan(SAMPLE_PLAN)
    assert len(plan["code_changes"]) == 1
    assert plan["code_changes"][0]["line"] == 9

def test_parse_plan_vuln_ids():
    plan = parse_plan(SAMPLE_PLAN)
    assert "SNYK-JAVA-MYSQL-451464" in plan["vuln_ids"]


# ── fix_agent.update_pom ──────────────────────────────────────────────────────

SAMPLE_POM = """<dependencies>
  <dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <version>5.1.49</version>
  </dependency>
</dependencies>"""

def test_update_pom_changes_version():
    updated = update_pom(SAMPLE_POM, [{
        "group_id": "mysql",
        "artifact_id": "mysql-connector-java",
        "fix_version": "8.0.28",
    }])
    assert "8.0.28" in updated
    assert "5.1.49" not in updated

def test_update_pom_does_not_change_unrelated():
    updated = update_pom(SAMPLE_POM, [{
        "group_id": "org.springframework",
        "artifact_id": "spring-core",
        "fix_version": "6.1.0",
    }])
    assert "5.1.49" in updated   # unchanged


# ── fail_check.check ─────────────────────────────────────────────────────────

NORM_WITH_HIGH = {
    "dependency_vulnerabilities": [{
        "package": "some:lib",
        "vulnerabilities": [{"id": "X", "severity": "high", "cve": []}]
    }],
    "code_vulnerabilities": [],
}

def test_fail_check_triggers_on_high():
    failures = check(NORM_WITH_HIGH, "high")
    assert len(failures) == 1

def test_fail_check_passes_when_below_threshold():
    failures = check(NORM_WITH_HIGH, "critical")
    assert len(failures) == 0

def test_fail_check_medium_threshold():
    norm = {
        "dependency_vulnerabilities": [{
            "package": "a:b",
            "vulnerabilities": [{"id": "Y", "severity": "medium", "cve": []}]
        }],
        "code_vulnerabilities": [],
    }
    assert len(check(norm, "medium")) == 1
    assert len(check(norm, "high"))   == 0
