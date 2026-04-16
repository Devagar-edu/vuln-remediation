# Jira Workflow Setup Guide

Complete step-by-step configuration for Jira Cloud.
Estimated time: 45 minutes.

---

## 1. Create the Jira project

1. Log in as a Jira admin.
2. Projects → Create project → Scrum (or Kanban).
3. Name: `Vulnerability Remediation`
4. Key: `VULN` (or whatever you set in `JIRA_PROJECT_KEY`).
5. Access: Private.

---

## 2. Create workflow statuses

Go to: **Settings → Issues → Statuses → Add status**

Create each status below (category in brackets):

| Status Name | Category |
|---|---|
| Open | To Do |
| Assign to AI | In Progress |
| Planning | In Progress |
| Awaiting Approval | In Progress |
| Approved for Fix | In Progress |
| Fixing | In Progress |
| Fix Failed | To Do |
| In Validation | In Progress |
| Validation Failed | To Do |
| Developer Review | In Progress |
| Closed | Done |
| Excepted | Done |
| Rejected | Done |

---

## 3. Create the workflow

Go to: **Settings → Issues → Workflows → Add workflow**

Name: `Vulnerability Remediation Workflow`

Add these transitions (From → To):

```
[All statuses]    → Open                 (name: "Reopen")
Open              → Assign to AI         (name: "Assign to AI")
Open              → Excepted             (name: "Mark as Excepted")
Open              → Rejected             (name: "Reject")
Assign to AI      → Planning             (name: "Start Planning")        [automated]
Planning          → Awaiting Approval    (name: "Plan Ready")            [automated]
Awaiting Approval → Approved for Fix     (name: "Approve for Fix")
Awaiting Approval → Rejected             (name: "Reject Plan")
Approved for Fix  → Fixing               (name: "Start Fixing")          [automated]
Fixing            → In Validation        (name: "Submit for Validation") [automated]
Fixing            → Fix Failed           (name: "Fix Failed")            [automated]
Fix Failed        → Assign to AI         (name: "Retry with AI")
Fix Failed        → Rejected             (name: "Reject")
In Validation     → Developer Review     (name: "Validation Passed")     [automated]
In Validation     → Validation Failed    (name: "Validation Failed")     [automated]
Validation Failed → Assign to AI         (name: "Retry with AI")
Validation Failed → Rejected             (name: "Reject")
Developer Review  → Closed               (name: "Close")
Developer Review  → Rejected             (name: "Reject")
[All statuses]    → Excepted             (name: "Mark as Excepted")      [Security Lead only]
```

Transitions marked `[automated]` are triggered by the agents — developers
do not need to trigger them manually.

---

## 4. Associate workflow with project

1. Settings → Issues → Workflow Schemes → Add workflow scheme.
2. Name: `Vulnerability Remediation Scheme`.
3. Associate the workflow above with issue type `Bug`.
4. Go to your `VULN` project → Project Settings → Workflows.
5. Switch to the new scheme.

---

## 5. Create custom fields

Go to: **Settings → Issues → Custom fields → Create custom field**

| Field Name | Type | Description |
|---|---|---|
| Remediation ID | Text Field (single line) | UUID linking to governance repo |
| PR URL | URL Field | Pull request URL from Fix Agent |
| Validation Score | Number Field | Percentage of validation checks passed |
| Exception Reason | Text Field (multi-line) | Required when status = Excepted |
| AI Plan Version | Number Field | Version of the attached plan document |
| Fix Attempts | Number Field | Auto-incremented by agents |

Add all custom fields to the `VULN` project's screens:
- Default Screen
- VULN: Bug Screen

---

## 6. Create automation rules

Go to: **Project Settings → Automation → Create rule**

### Rule 1 — Trigger Plan Agent

```
Trigger  : Issue transitioned
Condition: Status changed TO "Assign to AI"
Action   : Send web request
  URL    : http://YOUR-RUNNER-IP:8080/webhook/jira
  Method : POST
  Headers:
    Content-Type   : application/json
    X-Webhook-Secret: {{YOUR_WEBHOOK_SECRET}}
  Body   : Custom data (JSON)
           {"webhookEvent":"jira:issue_updated",
            "issue":{{issue.toJsonString()}},
            "changelog":{{changelog.toJsonString()}}}
```

### Rule 2 — Trigger Fix Agent

```
Trigger  : Issue transitioned
Condition: Status changed TO "Approved for Fix"
Action   : Send web request
  (same URL, headers, body as Rule 1)
```

> **Why one URL for two rules?**
> The orchestrator reads the `toString` field from the changelog and routes
> internally — `"Assign to AI"` dispatches the Plan Agent,
> `"Approved for Fix"` dispatches the Fix Agent.

### Rule 3 — SLA reminder (optional)

```
Trigger  : Scheduled
Schedule : Every day at 09:00
Condition: Issue matches JQL:
           project = VULN
           AND status = "Awaiting Approval"
           AND statusCategory != Done
           AND updated <= -5d
Action   : Send email to assignee
  Subject: [VULN] Remediation plan awaiting your approval for 5+ days
  Body   : Issue {{issue.key}} has been waiting for your plan approval
           since {{issue.updated}}. Please review the attached plan.
```

### Rule 4 — Auto-close on PR merge (optional)

```
Trigger  : Incoming webhook (GitHub → Jira integration)
Condition: PR merged AND branch name contains issue key
Action   : Transition issue to "Closed"
           Add comment: "PR merged. Vulnerability resolved."
```

---

## 7. Configure issue screen

Go to: **Project Settings → Screens**

Add the following fields to the `VULN Bug` screen (in addition to defaults):

- Remediation ID
- PR URL
- Validation Score
- Exception Reason
- AI Plan Version
- Fix Attempts
- Labels (required — used by orchestrator to identify repo and remediation ID)
- Attachments (required — normalised JSON + plan docs attached here)

---

## 8. Configure permission scheme

Go to: **Project Settings → Permissions**

| Action | Who |
|---|---|
| Transition issue | Project Member (developers can change status) |
| Transition to "Excepted" | Security Lead role only |
| Delete issues | Project Admin only |
| Edit issues | Project Member |

---

## 9. Test the webhook manually

After the orchestrator is running on your self-hosted runner, test it:

```bash
# From any machine that can reach the runner
curl -X POST http://YOUR-RUNNER-IP:8080/webhook/jira \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: YOUR_WEBHOOK_SECRET" \
  -d '{
    "webhookEvent": "jira:issue_updated",
    "issue": {
      "key": "VULN-TEST-1",
      "fields": {
        "labels": ["demo-repo", "dependency", "high",
                   "remediation-id-00000000-0000-0000-0000-000000000000"],
        "summary": "[demo-repo] Test issue"
      }
    },
    "changelog": {
      "items": [
        {"field": "status", "fromString": "Open", "toString": "Assign to AI"}
      ]
    }
  }'

# Expected response:
# {"issue": "VULN-TEST-1", "status": "accepted", "to": "Assign to AI"}
```

The Plan Agent workflow will then be dispatched in GitHub Actions.

---

## 10. Verify end-to-end

1. Push a commit containing a vulnerability (e.g. hardcoded password).
2. Confirm `scan-and-triage.yml` runs and creates a Jira issue.
3. In Jira, change status to `Assign to AI`.
4. Confirm `plan-agent.yml` runs in GitHub Actions.
5. Confirm the plan document appears as an attachment in Jira.
6. Status should automatically move to `Awaiting Approval`.
7. Change status to `Approved for Fix`.
8. Confirm `fix-agent.yml` runs in GitHub Actions.
9. Confirm a PR appears in GitHub.
10. Confirm `validation-agent.yml` runs automatically.
11. Confirm validation report appears in Jira and status → `Developer Review`.
12. Merge the PR and change Jira status to `Closed`.
