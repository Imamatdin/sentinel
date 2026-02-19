# SENTINEL — Master Implementation Plan (Phases 5–10)

## Platform Identity

**Sentinel** is an autonomous AI pentesting platform. Red team AI agents attack web applications while blue team AI agents defend in real-time. Powered by multi-LLM inference (Cerebras for speed, Claude for reasoning, OpenAI as fallback).

---

## What Exists (Phases 0–4) — DO NOT REBUILD

### Core Infrastructure

- `src/sentinel/config.py` — Configuration management
- `src/sentinel/logging.py` — Structured logging
- `src/sentinel/exceptions.py` — Custom exception hierarchy
- `docker-compose.juice-shop.yml` — Target environment (OWASP Juice Shop)
- Docker services: Neo4j, Temporal, Postgres

### Knowledge Graph (Neo4j)

- 10 node types: Host, Port, Service, Endpoint, Vulnerability, Credential, Session, Finding, User, Token
- 12 edge types: HAS_PORT, RUNS_SERVICE, HAS_ENDPOINT, HAS_VULNERABILITY, AUTHENTICATED_AS, PIVOT_TO, etc.
- `src/sentinel/graph/` — Graph client, models, queries
- Attack path computation exists but is underutilized

### Workflow Orchestration (Temporal.io)

- 5-phase pipeline: Recon → Vuln Analysis → Exploit → Verify → Report
- Human approval gates defined
- `src/sentinel/workflows/` — Workflow definitions
- `src/sentinel/activities.py` — **PLACEHOLDER** activities (hardcoded sample data, not wired to real tools)
- Currently the direct orchestrator runs agents instead of Temporal — THIS MUST BE FIXED

### Tool-Guarded LLM Execution

- Policy engine: 18 action types, 4 risk levels (LOW, MEDIUM, HIGH, CRITICAL)
- Structured schemas for tool calls
- Hallucination verification layer
- `GuardedBaseAgent` — base class all guarded agents extend
- `src/sentinel/agents/guarded_base.py`

### Recon Tools

- `NmapTool` — port/service scanning
- `DNSTool` — DNS enumeration
- `HTTPReconTool` — HTTP header/response analysis
- `WebCrawlerTool` — spider/crawl
- `GuardedReconAgent` — LLM-guided recon with policy gates
- Located in `src/sentinel/tools/recon/`

### Attack Tools (Exist but NOT wired to guarded agents)

- SQL Injection: 5 types (union, blind boolean, blind time, error-based, stacked)
- XSS: 8 payload variants
- Auth brute-force
- IDOR testing
- API endpoint discovery
- Port scanning, path scanning
- Located in `src/sentinel/tools/attack/`

### Blue Team Tools

- `NetworkMonitor` — attack signature detection (detects SSRF, cmd injection, XXE patterns — but no corresponding red team exploit tools exist yet)
- `WAFEngine` — regex-based WAF rules
- `Responder` — audit log generation
- Located in `src/sentinel/tools/defense/`

### Original Agents (6 agents using CerebrasClient)

- Red: `ReconAgent`, `ExploitAgent`, `ReportAgent`
- Blue: `MonitorAgent`, `DefenderAgent`, `ForensicsAgent`
- Located in `sentinel/agents/` (note: older directory, not `src/sentinel/agents/`)

### Security Genome

- Pipeline: Extract → Dedup → Enrich → Store
- SQLite storage
- Located in `src/sentinel/genome/`

### API Layer

- REST endpoints (FastAPI)
- WebSocket real-time streaming
- Located in `src/sentinel/api/`

### Reporting

- PDF generation via Jinja2 + weasyprint
- Red & blue team report templates
- Located in `src/sentinel/reports/`

### Dependencies (in pyproject.toml but UNUSED)

- `pgvector` — no RAG/embedding code exists
- `playwright` — installed but no browser automation tools
- `nuclei` — `ActionType.NUCLEI_SCAN` enum exists, no tool
- `zap` — `ActionType.ZAP_SCAN` enum exists, Docker service defined, no tool

### Frontend

- `frontend/` directory with Next.js project skeleton — **EMPTY/MINIMAL**

---

## Architecture Principles (Apply to ALL Phases)

### 1. Shannon-Style Hypothesis Engine

Every phase must follow: **Recon → Hypothesis → Targeted Validation → Chain Construction → Re-planning**. Never "scan and dump." Treat the target as a stateful graph.

### 2. Proof-by-Exploitation

"No Exploit, No Report" — only verified vulnerabilities with reproducible PoC make it into findings. Discard false positives.

### 3. Evidence-First

Log every HTTP request, every decision, every tool call. Produce replayable attack chains. Export as Python script, Bash script, or Postman collection.

### 4. Graph-Driven Attack Planning

Use Neo4j knowledge graph as the central brain. Agents query the graph: "If I own X, can I reach Y?" "What chain leads to crown_jewel?"

### 5. Tool-Guarded Execution

LLM suggests → Policy engine validates against state graph → Tool executes → Result feeds back into memory. Never raw LLM execution.

### 6. NodeZero-Style Continuous Verification

Store attack graph snapshots per run. Diff across runs. Show new/closed paths, reduced chain depth. Find → Fix → Verify loop.

### 7. Multi-LLM Strategy

- **Cerebras** (zai-glm-4.7): Speed-critical operations (real-time blue team defense, rapid hypothesis generation). 1000-1700 tok/s.
- **Claude** (claude-sonnet-4-5-20250929): Complex reasoning (exploit chain planning, report generation, code analysis).
- **OpenAI** (gpt-4o): Fallback and embedding generation.

---

## Phase Overview

|Phase|Name|Builds On|Core Deliverable|
|---|---|---|---|
|5|Vulnerability Analysis Agent|Phases 0-4|GuardedVulnAgent + Nuclei + ZAP integration|
|6|Exploitation Agent + Browser Automation|Phase 5|GuardedExploitAgent + Playwright + advanced exploits|
|7|Wire Temporal Activities to Real Tools|Phases 5-6|Replace ALL placeholders, Temporal becomes real backbone|
|8|RAG + Genome Feedback Loop|Phase 7|pgvector embeddings, cross-engagement learning|
|9|Advanced Blue Team + Red vs Blue Loop|Phase 8|Behavioral detection, adversarial loop, MITRE ATT&CK|
|10|Next.js Dashboard + Multi-Engagement|Phase 9|Real-time UI, attack graph visualization, executive reporting|

---

## File Naming Convention

All new files go under `src/sentinel/` following existing patterns. Tests go under `tests/` mirroring the source structure.

## Testing Requirements

Every phase must include:

- Unit tests for each new module
- Integration tests for agent-to-tool pipelines
- At minimum one end-to-end test against Juice Shop

## How to Use These Specs

Each phase is a standalone .md file. Hand it to Claude Code with:

```
Read PHASE_X.md and implement everything specified. Follow file paths exactly. Run tests after each module.
```