"""
tests/test_integration.py — Integration tests using mocked GitHub, Jira, and LLM.

These tests exercise the full agent pipelines without making any real network calls.
Every external dependency (GitHub API, Jira API, LLM) is patched with unittest.mock.

Run:
    pytest tests/test_integration.py -v
"""
from __future__ import annotations

import json
import os
import sys
import textwrap
import unittest
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Patch env before config is imported
_ENV = {
    "GITHUB_TOKEN":        "test-gh-token",
    "GITHUB_ORG":          "test-org",
    "GOVERNANCE_REPO":     "vuln-governance",
    "GITHUB_MODELS_TOKEN": "test-gm-token",
    "JIRA_URL":            "https://test.atlassian.net",
    "JIRA_USER":           "bot@test.com",
    "JIRA_TOKEN":          "test-jira-token",
    "JIRA_PROJECT_KEY":    "VULN",
    "SNYK_TOKEN":          "",
}
for k, v in _ENV.items():
    os.environ.setdefault(k, v)


# ── Fixtures ──────────────────────────────────────────────────────────────────

NORMALISED_JSON = {
    "scan_metadata": {
        "scanner": "snyk",
        "scan_time": "2026-03-16T20:48:14Z",
        "project": "demo-project",
        "repository": "demo-repo",
        "branch": "main",
        "commit_id": "abc123",
        "remediation_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    },
    "dependency_vulnerabilities": [
        {
            "id": "dep-uuid-1",
            "package": "mysql:mysql-connector-java",
            "current_version": "5.1.49",
            "recommended_fix_version": "8.0.28",
            "vulnerabilities": [
                {
                    "id": "SNYK-JAVA-MYSQL-451464",
                    "title": "Access Control Bypass",
                    "severity": "high",
                    "cvss": 8.8,
                    "cve": ["CVE-2018-3258"],
                    "cwe": ["CWE-288"],
                    "exploit": "Not Defined",
                    "description": "Vulnerability description.",
                }
            ],
            "_meta": {
                "excepted": False, "exception_reason": None,
                "previously_fixed": False, "fix_history_ref": None,
            },
        }
    ],
    "code_vulnerabilities": [
        {
            "id": "code-uuid-1",
            "rule_id": "java/HardcodedPassword",
            "rule_name": "HardcodedPassword",
            "severity": "warning",
            "description": "Use of Hardcoded Passwords",
            "cwe": ["CWE-798"],
            "tags": ["java", "Security"],
            "occurrences": [
                {
                    "file": "src/main/java/com/demo/HardCodedSecretExample.java",
                    "line": 9,
                    "code_snippet": 'String password = "hardcoded";',
                }
            ],
            "_meta": {"excepted": False, "exception_reason": None},
        }
    ],
    "summary": {
        "total_dependencies": 1,
        "total_code_issues": 1,
        "critical_count": 0,
        "high_count": 1,
        "medium_count": 0,
        "low_count": 0,
    },
}

SAMPLE_PLAN_MD = textwrap.dedent("""\
    # Remediation Plan
    **Jira:** VULN-42 | **Repo:** demo-repo | **Branch:** main
    **Generated:** 2026-03-16T20:48:14Z | **Remediation ID:** aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    **Plan Version:** 1

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
    | src/main/java/com/demo/HardCodedSecretExample.java | 9 | HardcodedPassword | Replace literal with System.getenv("DB_PASSWORD") |

    ## Impact Analysis
    JDBC driver class changed. SSL required by default.

    ## Guardrails Confirmed
    - Java version: NOT changed
    - Business logic: NOT modified
    - New dependencies: NOT added

    ## History
    - v1: Plan generated (2026-03-16)
""")

SAMPLE_POM = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <project>
      <groupId>com.demo</groupId>
      <artifactId>demo-app</artifactId>
      <version>1.0.0</version>
      <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
      </properties>
      <dependencies>
        <dependency>
          <groupId>mysql</groupId>
          <artifactId>mysql-connector-java</artifactId>
          <version>5.1.49</version>
        </dependency>
      </dependencies>
    </project>
""")

SAMPLE_JAVA_FILE = textwrap.dedent("""\
    package com.demo;

    public class HardCodedSecretExample {
        public void connect() {
            String host = "localhost";
            String user = "root";
            String password = "hardcoded_secret_123"; // SECURITY-FIX: CVE-2018-3258
            System.out.println("Connecting as " + user);
        }
    }
""")

FIXED_JAVA_FILE = textwrap.dedent("""\
    package com.demo;

    public class HardCodedSecretExample {
        public void connect() {
            String host = "localhost";
            String user = "root";
            String password = System.getenv("DB_PASSWORD"); // SECURITY-FIX: CWE-798
            System.out.println("Connecting as " + user);
        }
    }
""")


# ── Jira triage integration test ──────────────────────────────────────────────

class TestJiraTriageIntegration(unittest.TestCase):

    @patch("scripts.utils.memory.is_excepted", return_value=(False, ""))
    @patch("scripts.utils.memory.audit")
    @patch("scripts.jira_triage.JiraClient")
    def test_triage_creates_two_issues(self, mock_jira_cls, mock_audit, mock_exc):
        """One dep vuln + one code vuln → two Jira issues created."""
        jira = MagicMock()
        jira.find_open_issue.return_value = None          # no existing issues
        jira.create_issue.side_effect = ["VULN-1", "VULN-2"]
        jira.transition.return_value = True
        mock_jira_cls.return_value = jira

        from scripts.jira_triage import triage
        keys = triage(NORMALISED_JSON, jira)

        self.assertEqual(len(keys), 2)
        self.assertIn("VULN-1", keys)
        self.assertIn("VULN-2", keys)
        self.assertEqual(jira.add_attachment.call_count, 2)
        self.assertEqual(jira.transition.call_count, 2)

    @patch("scripts.utils.memory.is_excepted", return_value=(True, "Risk accepted"))
    @patch("scripts.utils.memory.audit")
    @patch("scripts.jira_triage.JiraClient")
    def test_triage_skips_excepted_vulns(self, mock_jira_cls, mock_audit, mock_exc):
        """Excepted vulnerabilities must not create Jira issues."""
        jira = MagicMock()
        mock_jira_cls.return_value = jira

        from scripts.jira_triage import triage
        keys = triage(NORMALISED_JSON, jira)

        self.assertEqual(keys, [])
        jira.create_issue.assert_not_called()

    @patch("scripts.utils.memory.is_excepted", return_value=(False, ""))
    @patch("scripts.utils.memory.audit")
    @patch("scripts.jira_triage.JiraClient")
    def test_triage_deduplicates_existing_issue(self, mock_jira_cls, mock_audit, mock_exc):
        """If an open issue already exists, only add a comment — do not create."""
        jira = MagicMock()
        jira.find_open_issue.return_value = "VULN-99"   # already exists
        mock_jira_cls.return_value = jira

        from scripts.jira_triage import triage
        keys = triage(NORMALISED_JSON, jira)

        jira.create_issue.assert_not_called()
        jira.add_comment.assert_called()
        self.assertIn("VULN-99", keys)


# ── Plan Agent integration test ───────────────────────────────────────────────

class TestPlanAgentIntegration(unittest.TestCase):

    def _make_jira_mock(self):
        jira = MagicMock()
        jira.get_attachment.return_value = json.dumps(NORMALISED_JSON)
        jira.transition.return_value = True
        return jira

    @patch("scripts.agents.plan_agent.memory.audit")
    @patch("scripts.agents.plan_agent.memory.save_plan", return_value="plans/VULN-42/plan-v1.md")
    @patch("scripts.agents.plan_agent.memory.next_plan_version", return_value=1)
    @patch("scripts.agents.plan_agent.memory.all_known_fixes", return_value=[])
    @patch("scripts.agents.plan_agent.memory.get_history", return_value=None)
    @patch("scripts.agents.plan_agent.gh.get_file")
    @patch("scripts.agents.plan_agent.chat", return_value=SAMPLE_PLAN_MD)
    @patch("scripts.agents.plan_agent.JiraClient")
    def test_plan_agent_attaches_plan_and_transitions(
        self, mock_jira_cls, mock_chat, mock_get_file,
        mock_hist, mock_fixes, mock_version, mock_save, mock_audit
    ):
        jira = self._make_jira_mock()
        mock_jira_cls.return_value = jira
        mock_get_file.return_value = SAMPLE_POM

        from scripts.agents.plan_agent import run
        run("VULN-42", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

        # Plan must be attached as markdown
        attachment_call = jira.add_attachment.call_args
        self.assertIn("remediation-plan-v1.md", attachment_call[0])

        # Must transition to Awaiting Approval
        jira.transition.assert_called_with("VULN-42", "Awaiting Approval")

        # Comment must be posted
        jira.add_comment.assert_called_once()
        comment_text = jira.add_comment.call_args[0][1]
        self.assertIn("Plan Agent", comment_text)
        self.assertIn("Approved for Fix", comment_text)

        # LLM called once
        mock_chat.assert_called_once()

    @patch("scripts.agents.plan_agent.memory.audit")
    @patch("scripts.agents.plan_agent.JiraClient")
    def test_plan_agent_raises_if_no_attachment(self, mock_jira_cls, mock_audit):
        jira = MagicMock()
        jira.get_attachment.return_value = None   # attachment missing
        mock_jira_cls.return_value = jira

        from scripts.agents.plan_agent import run
        with self.assertRaises(RuntimeError):
            run("VULN-42", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


# ── Fix Agent — unit-level integration tests ──────────────────────────────────

class TestFixAgentParsing(unittest.TestCase):
    """Test fix_agent helpers independently of subprocess/git calls."""

    def test_parse_plan_full(self):
        from scripts.agents.fix_agent import parse_plan
        plan = parse_plan(SAMPLE_PLAN_MD)
        self.assertEqual(len(plan["dep_changes"]), 1)
        self.assertEqual(plan["dep_changes"][0]["group_id"], "mysql")
        self.assertEqual(plan["dep_changes"][0]["fix_version"], "8.0.28")
        self.assertEqual(len(plan["code_changes"]), 1)
        self.assertEqual(plan["code_changes"][0]["line"], 9)
        self.assertIn("SNYK-JAVA-MYSQL-451464", plan["vuln_ids"])

    def test_update_pom_full_flow(self):
        from scripts.agents.fix_agent import update_pom
        updated = update_pom(SAMPLE_POM, [
            {"group_id": "mysql", "artifact_id": "mysql-connector-java", "fix_version": "8.0.28"}
        ])
        self.assertIn("<version>8.0.28</version>", updated)
        self.assertNotIn("<version>5.1.49</version>", updated)
        # compiler versions must be untouched
        self.assertIn("<maven.compiler.source>11</maven.compiler.source>", updated)

    def test_update_pom_leaves_unrelated_deps_unchanged(self):
        from scripts.agents.fix_agent import update_pom
        pom = SAMPLE_POM + textwrap.dedent("""\
            <dependency>
              <groupId>org.springframework</groupId>
              <artifactId>spring-core</artifactId>
              <version>5.3.0</version>
            </dependency>
        """)
        updated = update_pom(pom, [
            {"group_id": "mysql", "artifact_id": "mysql-connector-java", "fix_version": "8.0.28"}
        ])
        self.assertIn("<version>5.3.0</version>", updated)
        self.assertIn("<version>8.0.28</version>", updated)


# ── Guardrails integration test ───────────────────────────────────────────────

class TestGuardrailsIntegration(unittest.TestCase):

    def test_all_guardrails_pass_clean_fix(self):
        from scripts.guardrails import run_all
        results = run_all(
            pom_before     = SAMPLE_POM,
            pom_after      = SAMPLE_POM.replace("5.1.49", "8.0.28"),
            changed_files  = [
                "src/main/java/com/demo/HardCodedSecretExample.java",
                "pom.xml",
            ],
            approved_files = ["src/main/java/com/demo/HardCodedSecretExample.java"],
            file_diffs     = [(SAMPLE_JAVA_FILE, FIXED_JAVA_FILE)],
        )
        self.assertTrue(all(r.passed for r in results))

    def test_guardrails_catch_java_version_change(self):
        from scripts.guardrails import run_all, GuardrailError
        bad_pom = SAMPLE_POM.replace(
            "<maven.compiler.source>11</maven.compiler.source>",
            "<maven.compiler.source>17</maven.compiler.source>",
        )
        with self.assertRaises(GuardrailError) as ctx:
            run_all(
                pom_before=SAMPLE_POM, pom_after=bad_pom,
                changed_files=["pom.xml"], approved_files=[],
            )
        self.assertIn("G1", str(ctx.exception))

    def test_guardrails_catch_out_of_scope_file(self):
        from scripts.guardrails import run_all, GuardrailError
        new_pom = SAMPLE_POM.replace("5.1.49", "8.0.28")
        with self.assertRaises(GuardrailError) as ctx:
            run_all(
                pom_before=SAMPLE_POM, pom_after=new_pom,
                changed_files=["src/main/java/com/demo/Unrelated.java"],
                approved_files=["src/main/java/com/demo/HardCodedSecretExample.java"],
            )
        self.assertIn("G2", str(ctx.exception))

    def test_guardrails_catch_new_dependency(self):
        from scripts.guardrails import run_all, GuardrailError
        extra_dep = SAMPLE_POM + "<dependency><groupId>evil</groupId></dependency>"
        with self.assertRaises(GuardrailError) as ctx:
            run_all(
                pom_before=SAMPLE_POM, pom_after=extra_dep,
                changed_files=["pom.xml"], approved_files=[],
            )
        self.assertIn("G3", str(ctx.exception))


# ── Validation Agent — check functions ───────────────────────────────────────

class TestValidationChecks(unittest.TestCase):

    def test_check_java_version_pass(self):
        from scripts.agents.validation_agent import check_java_version
        ok, detail = check_java_version(SAMPLE_POM, SAMPLE_POM.replace("5.1.49", "8.0.28"))
        self.assertTrue(ok)

    def test_check_java_version_fail(self):
        from scripts.agents.validation_agent import check_java_version
        bad = SAMPLE_POM.replace(
            "<maven.compiler.source>11</maven.compiler.source>",
            "<maven.compiler.source>17</maven.compiler.source>",
        )
        ok, detail = check_java_version(SAMPLE_POM, bad)
        self.assertFalse(ok)
        self.assertIn("11", detail)
        self.assertIn("17", detail)

    def test_check_scope_pass(self):
        from scripts.agents.validation_agent import check_scope
        # We mock git diff output via subprocess
        with patch("scripts.agents.validation_agent._sh",
                   return_value=(0, "pom.xml\nsrc/main/java/com/demo/HardCodedSecretExample.java\n")):
            ok, detail = check_scope(
                "/fake/repo", "main",
                ["src/main/java/com/demo/HardCodedSecretExample.java"],
            )
        self.assertTrue(ok)

    def test_check_scope_fail(self):
        from scripts.agents.validation_agent import check_scope
        with patch("scripts.agents.validation_agent._sh",
                   return_value=(0, "pom.xml\nsrc/main/java/com/demo/Unrelated.java\n")):
            ok, detail = check_scope(
                "/fake/repo", "main",
                ["src/main/java/com/demo/HardCodedSecretExample.java"],
            )
        self.assertFalse(ok)
        self.assertIn("Unrelated.java", detail)

    def test_check_snyk_skipped_without_token(self):
        from scripts.agents.validation_agent import check_snyk
        with patch("scripts.agents.validation_agent.SNYK_TOKEN", ""):
            ok, detail = check_snyk("/fake/repo", {"SNYK-X"})
        self.assertTrue(ok)
        self.assertIn("skipped", detail)

    @patch("scripts.agents.validation_agent.chat")
    def test_check_diff_logic_no_changes(self, mock_chat):
        mock_chat.return_value = json.dumps({
            "business_logic_changed": False,
            "confidence": "high",
            "findings": [],
        })
        from scripts.agents.validation_agent import check_diff_logic
        with patch("scripts.agents.validation_agent._sh",
                   return_value=(0, "--- a/pom.xml\n+++ b/pom.xml\n-5.1.49\n+8.0.28")):
            ok, findings = check_diff_logic("/fake/repo", "main")
        self.assertTrue(ok)
        self.assertEqual(findings, [])

    @patch("scripts.agents.validation_agent.chat")
    def test_check_diff_logic_flags_business_change(self, mock_chat):
        mock_chat.return_value = json.dumps({
            "business_logic_changed": True,
            "confidence": "high",
            "findings": ["Method return value altered in processOrder()"],
        })
        from scripts.agents.validation_agent import check_diff_logic
        with patch("scripts.agents.validation_agent._sh",
                   return_value=(0, "some diff")):
            ok, findings = check_diff_logic("/fake/repo", "main")
        self.assertFalse(ok)
        self.assertIn("processOrder", findings[0])


# ── Orchestrator webhook handler ──────────────────────────────────────────────

class TestOrchestratorWebhook(unittest.TestCase):

    def setUp(self):
        # Import app after env is set
        import scripts.orchestrator as orch
        orch.app.config["TESTING"] = True
        self.client = orch.app.test_client()
        self.orch = orch

    def _payload(self, to_status: str, from_status: str = "Open",
                 labels: list = None) -> dict:
        return {
            "webhookEvent": "jira:issue_updated",
            "issue": {
                "key": "VULN-42",
                "fields": {
                    "labels": labels or ["demo-repo", "dependency", "high",
                                         "remediation-id-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
                    "summary": "[demo-repo] Dependency vulnerability: mysql (HIGH)",
                }
            },
            "changelog": {
                "items": [{"field": "status", "fromString": from_status, "toString": to_status}]
            }
        }

    @patch("scripts.orchestrator.WEBHOOK_SECRET", "")  # disable secret check in tests
    @patch("scripts.orchestrator._plan")
    def test_assign_to_ai_dispatches_plan(self, mock_plan):
        resp = self.client.post(
            "/webhook/jira",
            json=self._payload("Assign to AI"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 200)
        mock_plan.assert_called_once_with(
            "VULN-42", "demo-repo", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )

    @patch("scripts.orchestrator.WEBHOOK_SECRET", "")
    @patch("scripts.orchestrator._fix")
    def test_approved_for_fix_dispatches_fix(self, mock_fix):
        resp = self.client.post(
            "/webhook/jira",
            json=self._payload("Approved for Fix"),
        )
        self.assertEqual(resp.status_code, 200)
        mock_fix.assert_called_once()

    @patch("scripts.orchestrator.WEBHOOK_SECRET", "")
    @patch("scripts.orchestrator._plan")
    @patch("scripts.orchestrator._fix")
    def test_unhandled_status_is_ignored(self, mock_fix, mock_plan):
        resp = self.client.post(
            "/webhook/jira",
            json=self._payload("Developer Review"),
        )
        self.assertEqual(resp.status_code, 200)
        mock_plan.assert_not_called()
        mock_fix.assert_not_called()

    def test_wrong_secret_returns_401(self):
        with patch("scripts.orchestrator.WEBHOOK_SECRET", "correct-secret"):
            resp = self.client.post(
                "/webhook/jira",
                json=self._payload("Assign to AI"),
                headers={"X-Webhook-Secret": "wrong-secret"},
            )
        self.assertEqual(resp.status_code, 401)

    def test_health_endpoint(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"ok", resp.data)

    @patch("scripts.orchestrator.WEBHOOK_SECRET", "")
    def test_non_issue_updated_event_ignored(self):
        resp = self.client.post(
            "/webhook/jira",
            json={"webhookEvent": "jira:issue_created", "issue": {"key": "VULN-1"}},
        )
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "ignored")

    @patch("scripts.orchestrator.WEBHOOK_SECRET", "")
    @patch("scripts.orchestrator.memory.audit")
    @patch("scripts.orchestrator.memory.attempt_count", return_value=3)
    @patch("scripts.orchestrator.MAX_FIX_ATTEMPTS", 3)
    @patch("scripts.orchestrator._all_vuln_ids", return_value=["SNYK-JAVA-MYSQL-451464"])
    @patch("scripts.orchestrator.jira")
    def test_fix_blocked_when_max_attempts_reached(
        self, mock_jira, mock_ids, mock_count, mock_audit
    ):
        mock_jira.transition.return_value = True
        resp = self.client.post(
            "/webhook/jira",
            json=self._payload("Approved for Fix"),
        )
        self.assertEqual(resp.status_code, 200)
        mock_jira.transition.assert_called_with("VULN-42", "Fix Failed")


# ── Normalise edge cases ──────────────────────────────────────────────────────

class TestNormaliseEdgeCases(unittest.TestCase):

    def test_empty_snyk_output_produces_valid_schema(self):
        from scripts.normalise import normalise
        result = normalise({}, repo="empty-app")
        self.assertIn("scan_metadata", result)
        self.assertEqual(result["dependency_vulnerabilities"], [])
        self.assertEqual(result["code_vulnerabilities"], [])
        self.assertEqual(result["summary"]["critical_count"], 0)

    def test_sarif_format_detected(self):
        from scripts.normalise import _is_sarif
        sarif = {"$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json", "runs": []}
        self.assertTrue(_is_sarif(sarif))
        self.assertFalse(_is_sarif({"vulnerabilities": []}))

    def test_normalise_sarif_code_vulns(self):
        from scripts.normalise import normalise
        sarif = {
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"rules": [{
                    "id": "java/HardcodedPassword",
                    "name": "HardcodedPassword",
                    "shortDescription": {"text": "Hardcoded password detected"},
                    "properties": {"tags": ["CWE-798"]},
                }]}},
                "results": [{
                    "ruleId": "java/HardcodedPassword",
                    "level": "warning",
                    "message": {"text": "Hardcoded password"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/main/java/Foo.java"},
                            "region": {"startLine": 12, "snippet": {"text": 'pwd = "secret"'}},
                        }
                    }],
                }]
            }]
        }
        result = normalise(sarif, repo="test-app")
        self.assertEqual(len(result["code_vulnerabilities"]), 1)
        v = result["code_vulnerabilities"][0]
        self.assertEqual(v["rule_id"], "java/HardcodedPassword")
        self.assertEqual(v["occurrences"][0]["line"], 12)
        self.assertEqual(len(result["dependency_vulnerabilities"]), 0)

    def test_remediation_id_is_unique_per_call(self):
        from scripts.normalise import normalise
        r1 = normalise({}, repo="app")
        r2 = normalise({}, repo="app")
        self.assertNotEqual(
            r1["scan_metadata"]["remediation_id"],
            r2["scan_metadata"]["remediation_id"],
        )


# ── Fail check edge cases ─────────────────────────────────────────────────────

class TestFailCheckEdgeCases(unittest.TestCase):

    def test_code_vuln_triggers_failure(self):
        from scripts.fail_check import check
        norm = {
            "dependency_vulnerabilities": [],
            "code_vulnerabilities": [{
                "rule_id": "java/SQLInjection",
                "severity": "high",
                "occurrences": [{"file": "Foo.java"}],
            }],
        }
        failures = check(norm, "high")
        self.assertEqual(len(failures), 1)
        self.assertIn("Foo.java", failures[0])

    def test_multiple_vulns_all_reported(self):
        from scripts.fail_check import check
        norm = {
            "dependency_vulnerabilities": [
                {"package": "a:b", "vulnerabilities": [
                    {"id": "X1", "severity": "critical", "cve": []},
                    {"id": "X2", "severity": "high",     "cve": []},
                ]},
            ],
            "code_vulnerabilities": [],
        }
        # threshold "high"   → catches critical(idx0) + high(idx1) → 2
        self.assertEqual(len(check(norm, "high")),     2)
        # threshold "critical" → catches only critical(idx0) → 1
        self.assertEqual(len(check(norm, "critical")), 1)
        # threshold "medium"  → catches critical(idx0) + high(idx1) + medium(idx2) → 2
        self.assertEqual(len(check(norm, "medium")),   2)
        # threshold "low"     → catches all 4 severity levels → 2 (no low vulns here)
        self.assertEqual(len(check(norm, "low")),      2)


if __name__ == "__main__":
    unittest.main()
