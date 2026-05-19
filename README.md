# 🐕 ChainHound

> **AWS IAM Privilege Escalation Detection** — End-to-end attack path discovery, risk scoring & AI-powered narratives.

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18+-61DAFB?style=flat&logo=react&logoColor=black)
![AWS](https://img.shields.io/badge/AWS-IAM-FF9900?style=flat&logo=amazonaws&logoColor=white)
![Claude](https://img.shields.io/badge/Claude-Opus-8B5CF6?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## What is ChainHound?

AWS IAM misconfigurations are the #1 cause of cloud breaches — but native AWS tooling can't detect **chained** attack paths. A low-privileged user assuming a role, chaining into another role, and landing on a wildcard policy looks harmless at each individual hop. Only graph traversal across the full chain reveals the danger.

**ChainHound** solves this by:

- 📡 Collecting a full IAM snapshot from your AWS account
- 🕸️ Building a directed graph of users, roles, and policies
- 🔍 Running 5 targeted risk detectors across all reachable paths
- 📊 Scoring each finding with a CVSS-inspired weighted model
- 🤖 Generating AI-powered attack narratives via Claude Opus
- 🖥️ Visualising everything in a React dashboard with graph view

---

## Lab Result

ChainHound detected this **3-hop CRITICAL chain** in the test environment:

```
Dummy123 → LabAssumableRole → LabChainedRole → LabS3WidePolicy
```

| Metric | Value |
|--------|-------|
| Risk Score | **100 / 100** |
| Severity | **CRITICAL** |
| Hops | 3 |
| Detectors Triggered | wildcard, passrole, iam_escalation, compute_passrole |
| Impact | Unrestricted `s3:*` access across entire account |

A low-privileged IAM user with no direct admin permissions — completely undetected by AWS IAM Access Analyzer.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     ChainHound Pipeline                      │
├──────────────┬──────────────┬──────────────┬────────────────┤
│   COLLECT    │  NORMALIZE   │    DETECT    │     REPORT     │
│              │              │              │                │
│ boto3 IAM    │ Graph nodes  │ 5 risk       │ Claude Opus    │
│ snapshot     │ & edges      │ detectors    │ AI narratives  │
│              │              │              │                │
│iam_collector │iam_normalizer│risk_detector │narrative_      │
│    .py       │    .py       │    .py       │generator.py    │
└──────┬───────┴──────┬───────┴──────┬───────┴───────┬────────┘
       │              │              │               │
       ▼              ▼              ▼               ▼
  iam_snapshot   graph.json    findings.json   narratives.json
     .json                                         │
                                                   ▼
                                           ┌───────────────┐
                                           │  FastAPI :8000 │
                                           │  React  :5173  │
                                           └───────────────┘
```

---

## Risk Detectors

| Detector | What It Catches | Score Bonus |
|----------|----------------|-------------|
| `wildcard` | Action or Resource set to `*` | +20 |
| `passrole` | `iam:PassRole` on wildcard resource | +8 |
| `iam_escalation` | `CreatePolicyVersion`, `AttachUserPolicy`, `PutUserPolicy` | +10 |
| `assume_role_wildcard` | `sts:AssumeRole` on `*` | +8 |
| `compute_passrole` | Lambda/EC2 actions + `iam:PassRole` | +12 |

**Scoring formula:**
```
Score = base_score + Σ(detector_bonuses) + Σ(service_bonuses)  [max 100]
```

Base scores: `CRITICAL=90`, `HIGH=70`, `MEDIUM=40`, `LOW=20`

---

## Project Structure

```
chainhound/
├── collector/
│   └── iam_collector.py          # boto3 IAM snapshot collection
├── normalizer/
│   └── iam_normalizer.py         # graph node/edge normalisation
├── graph/
│   └── graph_builder.py          # directed graph + path traversal
├── risk/
│   ├── risk_detector.py          # 5 pattern-matching detectors
│   ├── risk_scorer.py            # weighted severity scoring
│   ├── path_ranker.py            # attack path ranking
│   └── findings_merger.py        # merge paths + findings
├── ai/
│   └── narrative_generator.py    # Claude Opus AI narratives
├── api/
│   ├── main.py                   # FastAPI backend (port 8000)
│   └── pdf_exporter.py           # ReportLab PDF export
├── ui-react/
│   └── src/
│       ├── App.jsx               # main dashboard
│       ├── api.js                # API client
│       └── components/
│           ├── SummaryCard.jsx   # KPI summary bar
│           ├── PathsTable.jsx    # attack paths table
│           ├── GraphView.jsx     # ReactFlow graph
│           └── NarrativePanel.jsx# AI narrative renderer
└── data/                         # pipeline JSON outputs (gitignored)
```

---

## Setup & Installation

### Prerequisites

- Python 3.9+
- Node.js 18+
- AWS account with IAM read access
- AWS CLI configured (`aws configure`)
- Anthropic API key

### 1 — Clone the repo

```bash
git clone https://github.com/CoderunED/chainhound.git
cd chainhound
```

### 2 — Backend setup

```bash
python3 -m venv venv
source venv/bin/activate       # macOS / Linux
# venv\Scripts\activate        # Windows

pip install boto3 fastapi uvicorn anthropic reportlab
```

### 3 — AWS credentials

```bash
aws configure
# AWS Access Key ID: YOUR_KEY
# AWS Secret Access Key: YOUR_SECRET
# Default region: us-east-1
# Default output format: json
```

### 4 — Anthropic API key

```bash
export ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxx
# Add to ~/.zshrc or ~/.bashrc to persist
```

### 5 — Frontend setup

```bash
cd ui-react
npm install
cd ..
```

---

## Running ChainHound

### Option A — Full pipeline manually

```bash
source venv/bin/activate

python collector/iam_collector.py       # 1. Collect IAM snapshot
python normalizer/iam_normalizer.py     # 2. Normalise to graph
python graph/graph_builder.py           # 3. Build directed graph
python risk/risk_detector.py            # 4. Detect risk patterns
python risk/risk_scorer.py              # 5. Score findings
python risk/path_ranker.py              # 6. Rank attack paths
python risk/findings_merger.py          # 7. Merge paths + findings
python ai/narrative_generator.py        # 8. Generate AI narratives
```

### Option B — Start the dashboard (runs pipeline via Re-scan button)

```bash
# Terminal 1 — API server
source venv/bin/activate
uvicorn api.main:app --reload --port 8000

# Terminal 2 — React dashboard
cd ui-react
npm run dev
```

Open **http://localhost:5173** → click **Re-scan** to run the full pipeline.

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Health check |
| `GET /scan` | Run full pipeline end-to-end |
| `GET /graph` | Graph JSON (nodes, edges, adjacency, paths) |
| `GET /findings` | Merged findings |
| `GET /paths` | Ranked attack paths |
| `GET /narratives` | AI-generated narratives |
| `GET /summary` | Dashboard KPIs |
| `GET /export/pdf` | Download PDF report |

---

## Dashboard Views

| Tab | Description |
|-----|-------------|
| **Findings** | Attack path table — severity badges, score bars, hop counts |
| **Graph** | ReactFlow force-directed IAM graph — users, roles, policies |
| **Narratives** | AI-generated markdown attack report with inline ARN spans |
| **Summary Bar** | Live KPIs — nodes, edges, paths, CRITICAL/HIGH/MEDIUM counts |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Data collection | Python, boto3 |
| Backend API | FastAPI, Uvicorn |
| Graph traversal | Python (custom DFS) |
| AI narratives | Anthropic Claude Opus |
| Frontend | React 18, Vite, ReactFlow |
| PDF export | ReportLab |
| Styling | CSS variables, DM Sans, DM Mono |

---

## Remediation Guidance

If ChainHound finds a CRITICAL path in your environment:

1. **Restrict trust policies** — scope `Principal` to specific ARNs, never `*`
2. **Remove wildcard resources** — replace `Resource: "*"` with specific ARN patterns
3. **Enforce MFA on AssumeRole** — add `aws:MultiFactorAuthPresent: true` condition
4. **Scope PassRole** — limit `iam:PassRole` to specific role ARNs only
5. **Enable CloudTrail** — alert on unexpected `AssumeRole` calls

---

## Roadmap

- [ ] Real-time CloudTrail event monitoring
- [ ] Multi-account AWS Organizations support
- [ ] Slack / PagerDuty alerting integration
- [ ] Trend analysis across scan history
- [ ] Auto-remediation policy generation

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Made with 🐕 by <a href="https://github.com/CoderunED">CoderunED</a>
</p>
