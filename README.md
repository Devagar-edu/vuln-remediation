# vuln-remediation

Enterprise AI-driven vulnerability remediation framework for Java/Maven applications.

**Stack:** GitHub Actions (self-hosted runner) · Snyk · Jira Cloud · GitHub Models (gpt-4o-mini) · Python 3.11

---

## Repository layout

```
vuln-remediation/
├── scripts/
│   ├── normalise.py              # Snyk JSON → canonical schema
│   ├── jira_triage.py            # Create/update Jira issues
│   ├── fail_check.py             # Build severity gate
│   ├── guardrails.py             # Hard guardrail checks (pure functions)
│   ├── orchestrator.py           # Flask webhook listener
│   ├── agents/
│   │   ├── plan_agent.py         # LLM plan generation
│   │   ├── fix_agent.py          # LLM-assisted code + pom fix + PR
│   │   └── validation_agent.py   # Re-scan + diff + LLM review
│   └── utils/
│       ├── config.py             # All env vars in one place
│       ├── github_client.py      # PyGithub wrapper
│       ├── jira_client.py        # Jira REST v3 wrapper
│       ├── llm_client.py         # GitHub Models / OpenAI wrapper
│       └── memory.py             # Governance repo read/write
├── .github/workflows/
│   ├── scan-and-triage.yml       # Triggered on push/PR — runs Snyk
│   ├── plan-agent.yml            # workflow_dispatch — Plan Agent
│   ├── fix-agent.yml             # workflow_dispatch — Fix Agent
│   ├── validation-agent.yml      # workflow_dispatch — Validation Agent
│   ├── rollback.yml              # Manual rollback (pre- or post-merge)
│   └── orchestrator-service.yml  # Start/stop/heartbeat for Flask listener
├── config/
│   ├── prompts/
│   │   ├── plan-agent-v1.txt     # Versioned LLM system prompt (plan)
│   │   └── fix-agent-v1.txt      # Versioned LLM system prompt (fix)
│   ├── exceptions.yaml           # Seed — copy to governance repo
│   ├── known-fixes-index.yaml    # Seed — copy to governance repo
│   └── known-fix-mysql-connector.yaml  # Sample validated fix
├── tests/
│   └── test_core.py              # Unit tests (no network required)
├── requirements.txt
└── .env.example
```

---

## Quick start

### 1. Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.11+ |
| Java | Match your application's `.java-version` |
| Maven | 3.8+ |
| Node.js | 18+ (for Snyk CLI) |
| Git | 2.40+ |

### 2. Clone and configure

```bash
git clone https://github.com/YOUR-ORG/vuln-remediation
cd vuln-remediation
cp .env.example .env
# Edit .env with your real values
pip install -r requirements.txt
```

### 3. Create the governance repository

```bash
# Create a new private repo in your org called "vuln-governance"
# Then seed it with the initial directory structure:

gh repo create YOUR-ORG/vuln-governance --private
cd /tmp && git clone https://github.com/YOUR-ORG/vuln-governance && cd vuln-governance

mkdir -p history known-fixes exceptions plans audit config/prompts

# Copy seed files
cp /path/to/vuln-remediation/config/exceptions.yaml       exceptions/
cp /path/to/vuln-remediation/config/known-fixes-index.yaml known-fixes/index.yaml
cp /path/to/vuln-remediation/config/prompts/*.txt          config/prompts/

# Create empty audit log
echo "" > audit/audit.jsonl

git add -A && git commit -m "chore: initialise governance repo structure"
git push
```

### 4. Configure GitHub repository secrets

Add these secrets to **both** the `vuln-remediation` repo **and** each
application repo that will be scanned:

| Secret | Description |
|--------|-------------|
| `GITHUB_TOKEN` | PAT with `repo` and `workflow` scopes |
| `GITHUB_MODELS_TOKEN` | PAT with access to GitHub Models |
| `GITHUB_ORG` | Your GitHub organisation name |
| `GOVERNANCE_REPO` | `vuln-governance` |
| `JIRA_URL` | `https://yourorg.atlassian.net` |
| `JIRA_USER` | Automation account email |
| `JIRA_TOKEN` | Jira API token |
| `JIRA_PROJECT_KEY` | e.g. `VULN` |
| `SNYK_TOKEN` | Snyk API token |
| `WEBHOOK_SECRET` | 32-char random string for Jira webhook auth |
| `WEBHOOK_PORT` | `8080` (or your chosen port) |

### 5. Configure Jira

#### Create a Jira project

Create a new Jira Software project with key `VULN` (or your chosen key).

#### Create custom workflow statuses

In Jira → Project Settings → Workflow, add these statuses in order:

```
Open → Assign to AI → Planning → Awaiting Approval →
Approved for Fix → Fixing → Fix Failed →
In Validation → Validation Failed → Developer Review → Closed

Also add: Excepted, Rejected (from any status)
```

#### Create Jira automation rules (webhook triggers)

Settings → Automation → Create rule:

**Rule 1 — Trigger Plan Agent**
- Trigger: Issue transitioned
- Condition: Status changed TO `Assign to AI`
- Action: Send web request
  - URL: `http://YOUR-RUNNER-IP:8080/webhook/jira`
  - Method: POST
  - Headers: `X-Webhook-Secret: {{WEBHOOK_SECRET}}`
  - Body: `{{issue.toJsonString()}}`

**Rule 2 — Trigger Fix Agent**
- Trigger: Issue transitioned
- Condition: Status changed TO `Approved for Fix`
- Action: Same web request config as Rule 1

> The orchestrator routes based on the `toString` status field in the payload,
> so a single webhook URL handles both rules.

### 6. Add scan workflow to each application repo

Copy `.github/workflows/scan-and-triage.yml` to each Java application repo,
or reference it via a reusable workflow call.

The workflow checks out `vuln-remediation` alongside the application code,
so no code needs to be duplicated into the application repo.

### 7. Start the orchestrator

**Option A — via GitHub Actions (recommended):**
```
Actions → Orchestrator Service → Run workflow → action: start
```

**Option B — systemd service (production):**
```ini
# /etc/systemd/system/vuln-orchestrator.service
[Unit]
Description=Vulnerability Remediation Orchestrator
After=network.target

[Service]
Type=simple
User=github-runner
WorkingDirectory=/home/github-runner/vuln-remediation
EnvironmentFile=/home/github-runner/vuln-remediation/.env
ExecStart=/usr/bin/python3 scripts/orchestrator.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable --now vuln-orchestrator
```

### 8. Run unit tests

```bash
pytest tests/test_core.py -v
```

---

## End-to-end walkthrough

```
Developer pushes code
  └─▶ scan-and-triage.yml runs
        └─▶ Snyk SCA + SAST
        └─▶ normalise.py merges outputs into normalised.json
        └─▶ jira_triage.py creates Jira issue with JSON attached
        └─▶ fail_check.py exits 1 if high/critical found (build fails)

Developer opens Jira, changes status → "Assign to AI"
  └─▶ Jira automation fires webhook → orchestrator receives it
        └─▶ plan-agent.yml dispatched
              └─▶ plan_agent.py calls gpt-4o-mini
              └─▶ Markdown plan attached to Jira
              └─▶ Status → "Awaiting Approval"

Developer reviews plan, changes status → "Approved for Fix"
  └─▶ Jira automation fires webhook → orchestrator receives it
        └─▶ orchestrator checks attempt count (blocks if ≥ MAX_FIX_ATTEMPTS)
        └─▶ fix-agent.yml dispatched
              └─▶ fix_agent.py:
                    Clone repo → update pom.xml → LLM-fix source files
                    → run guardrails → mvn dependency:resolve
                    → mvn compile → mvn test → commit → push
              └─▶ PR created → Jira status → "In Validation"
              └─▶ validation-agent.yml dispatched automatically

Validation Agent runs 5 checks:
  C1 Tests  C2 Scope  C3 Java version  C4 Snyk re-scan  C5 LLM diff
  └─▶ All pass → Jira status → "Developer Review", PR marked ready
  └─▶ Any fail → Jira status → "Validation Failed", PR marked draft

Developer reviews PR, merges → Jira status → "Closed"
```

---

## Onboarding a new application

1. Add the five secrets to the application repo (see §4).
2. Copy `scan-and-triage.yml` to `.github/workflows/` in the application repo.
3. Create `history/APP-REPO-NAME/` folder in the governance repo.
4. Ensure the application has a passing `mvn test` suite.
5. Push a commit — the first scan runs automatically.

---

## Rollback

**Pre-merge (PR not yet merged):**
```
Actions → Rollback Fix → mode: pre-merge
  → closes PR, deletes branch, sets Jira → Rejected
```

**Post-merge:**
```
Actions → Rollback Fix → mode: post-merge
  → creates revert branch + PR, notifies Jira
```

---

## Governance files (maintained in vuln-governance repo)

| File | Purpose | Who updates |
|------|---------|-------------|
| `exceptions/exceptions.yaml` | Suppressed vulnerabilities | Security Lead via PR |
| `known-fixes/index.yaml` + `known-fixes/*.yaml` | Validated fix patterns | Security Lead via PR |
| `audit/audit.jsonl` | Immutable append-only event log | Automated only |
| `plans/VULN-*/plan-vN.md` | Versioned remediation plans | Plan Agent |
| `history/{repo}/{snyk-id}.json` | Per-vulnerability fix history | Agents |

---

## Troubleshooting

**Orchestrator not receiving webhooks**
- Verify the runner IP is reachable from Jira Cloud (allow-list `443` outbound from Atlassian IPs)
- Check `WEBHOOK_SECRET` matches the header sent by Jira automation
- Run `curl http://localhost:8080/health` on the runner

**Plan Agent produces incomplete plan**
- Check `GITHUB_MODELS_TOKEN` has access to `gpt-4o-mini`
- Increase `max_tokens` in `llm_client.chat()` if the plan is truncated
- Large pom.xml files are trimmed to 6000 chars — adjust the cap in `plan_agent.py`

**Fix Agent: tests fail**
- Attach `build-failure.log` from Jira to your IDE and debug
- Set Jira status to `Rejected`, fix manually, then close

**Validation: Snyk re-scan skipped**
- Set `SNYK_TOKEN` in repository secrets — the check silently passes if the token is absent

**Max fix attempts reached**
- The orchestrator blocks further attempts after `MAX_FIX_ATTEMPTS` (default: 3)
- Set Jira status to `Rejected` and resolve manually; or increase the limit in `.env`
