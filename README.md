# SENTINEL — Autonomous AI Pentesting Platform

**Current: Base Platform (Phases 0-9) + Tiers 1-4 through Level 21 ✓ Complete**

**Future: Enterprise-Grade Autonomous Security Engine (Levels 22-31 In Progress)**

---

## What It Is Today

SENTINEL is a fully functional autonomous penetration testing platform where AI agents simultaneously attack and defend a target application. The base platform (**Phases 0-9**) plus **Levels 1-21** are **complete and production-ready**:

- **Red Team**: Autonomous reconnaissance, vulnerability discovery, and exploitation
- **Blue Team**: Real-time attack detection, behavioral analysis, and countermeasures  
- **Genome Engine**: Vulnerability pattern extraction, deduplication, and CWE/CAPEC enrichment
- **Orchestration**: Temporal workflows for complex multi-step attacks
- **Dashboard**: Real-time WebSocket-fed UI with attack graphs, findings, and red/blue battle view
- **EPSS Integration**: Risk-based vulnerability prioritization with exploit probability scores
- **Supply Chain Security**: SCA/SBOM generation with reachability analysis
- **Compliance Reporting**: Auto-mapped PCI/SOC2/ISO/NIST control mappings
- **LLM Cost Optimization**: Model router with tiered pricing and prompt caching
- **Container & K8s Scanning**: Trivy/Grype integration with kube-bench misconfig detection
- **Change-Based Testing**: Git webhook diff parsing with selective re-testing
- **WebSocket Fuzzing**: Frame mutation and CSWSH detection
- **Hybrid SAST**: AST/DFG extraction with LLM reasoning over code structure
- **Auto Threat Modeling**: STRIDE threat model generation from repo ingestion
- **Predictive Vuln Scoring**: ML model for bug class prioritization
- **Business Logic Testing**: BOLA/IDOR differential testing and race condition detection
- **gRPC & Protobuf Fuzzer**: Auto-generated requests from .proto files
- **GraphRAG + HyDE**: Neo4j entity traversal with hypothetical document embeddings
- **Auto-Patch Generation**: LLM-generated fixes with exploit re-verification
- **Multi-Agent Debate**: Reviewer agents with Reflexion self-correction
- **Knowledge Graph Analytics**: GDS PageRank and betweenness centrality analysis
- **CTEM Diff Engine**: Snapshot attack graph diffs across runs
- **Behavioral Blue Team**: Transformer-based anomaly detection
- **AI/LLM App Security**: Prompt injection and MCP tool poisoning detection
- **MCP Server Interface**: JSON-RPC exposure for external AI agents
- **Federated Learning**: Cross-deployment pattern sharing with differential privacy

Built for the Cerebras "Need for Speed" hackathon. Cerebras inference speed (1000-1700 tok/s) enables sub-second defensive responses to attacks.

---

## What It Will Become

As **Levels 22-31** are implemented, SENTINEL will complete its evolution into a **comprehensive autonomous security engine**:

| Stage | Transformation |
|-------|---------------|
| **Tier 4 Complete (L20-L21)** | MCP server integration, federated learning across deployments |
| **Tier 4 Remaining (L22-L24)** | Formal verification, RL-trained pentesting agents, Stackelberg game optimization |
| **Tier 5 (L25-L31)** | Research frontier: Game-theoretic optimization, WASM fuzzing, self-play red vs blue training |

**End State**: An AI that doesn't just find vulnerabilities—it understands your entire attack surface, predicts what matters, patches automatically, and learns from every engagement across the fleet.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Frontend (3001)                  │
│         Next.js 14 + WebSocket + Dashboard          │
│  Engagements │ Findings │ Genome │ Red/Blue │ Graph │
└─────────────────────┬───────────────────────────────┘
                      │ REST + WebSocket
┌─────────────────────▼───────────────────────────────┐
│                   API (8000)                        │
│    FastAPI + EngagementManager + Dashboard Routes   │
│              EventBus (in-process)                  │
├──────────┬─────────────────┬────────────────────────┤
│ Red Team │   Orchestrator  │      Blue Team         │
│ ReconAgt │                 │     MonitorAgt         │
│ VulnAgt  │  Phase Control  │     BehavioralDetector │
│ ExploitAg│                 │     ActiveDefense      │
│ ReportAg │                 │     ForensicsAgt       │
├──────────┴─────────────────┴────────────────────────┤
│             Tool Layer                              │
│  Nuclei │ ZAP │ Custom Exploits │ PoC Generator     │
├─────────────────────────────────────────────────────┤
│              Temporal + Neo4j + pgvector            │
│         Workflows │ Knowledge Graph │ RAG           │
├─────────────────────────────────────────────────────┤
│            Security Genome v2                       │
│    Embedding Store │ RAG Pipeline │ Pattern DB      │
├─────────────────────────────────────────────────────┤
│            Federated Learning                       │
│    Anonymizer │ Bayesian Confidence │ Aggregation   │
├─────────────────────────────────────────────────────┤
│            MCP Server Interface                     │
│    JSON-RPC │ Tool Registry │ OAuth2 Auth          │
└─────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
- A Cerebras API key (get one at https://cloud.cerebras.ai)

### Run with Docker

```bash
# Clone and configure
git clone <repo-url> && cd sentinel
cp docker/.env.example docker/.env
# Edit docker/.env with your CEREBRAS_API_KEY

# Launch all services
cd docker
docker compose up --build

# Open http://localhost:80
# Click "Start Engagement" and watch the AI battle
```

### Run Locally (Development)

```bash
# Terminal 1: Juice Shop target
docker run -d -p 3000:3000 bkimminich/juice-shop

# Terminal 2: Backend API
pip install -e . --break-system-packages
python -m uvicorn sentinel.api.app:create_app --factory --port 8000

# Terminal 3: Frontend
cd frontend && npm install && npm run dev

# Open http://localhost:3001
```

---

## How It Works (Current)

1. **Recon Phase**: Red team agents discover the attack surface (endpoints, technologies, potential vulns)
2. **Attack + Defense Phase**: Red team exploits while blue team monitors, detects, and deploys countermeasures
3. **Report Phase**: Both teams generate reports—red team pentest report, blue team incident response
4. **Genome Phase**: Findings processed through Security Genome pipeline, extracting reusable vulnerability patterns
5. **Federated Learning**: Anonymized patterns aggregated across deployments with differential privacy
6. **MCP Interface**: External AI agents can invoke Sentinel tools via JSON-RPC

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| LLM | Cerebras Cloud (Llama 3.3 70B) |
| Backend | FastAPI + WebSocket + asyncio + Temporal |
| Frontend | Next.js 15 + TypeScript + Tailwind |
| Database | Neo4j (knowledge graph) + PostgreSQL + pgvector |
| Workflow | Temporal.io |
| Scanner | Nuclei + OWASP ZAP + Trivy/Grype |
| Genome | SQLite → pgvector (RAG) |
| Federated | Bayesian confidence + Laplace differential privacy |
| MCP | JSON-RPC 2.0 + OAuth2 |
| Deployment | Docker Compose |

---

## Project Structure

```
sentinel/
├── agents/         # AI agents: Recon, Vuln, Exploit, Defense, Verifier
├── api/            # FastAPI routes: engagement, dashboard, genome, federated, mcp
├── core/           # CerebrasClient, models, settings
├── defense/        # Blue team: detection, MITRE mapping, remediation
├── events/         # EventBus, Event types
├── federated/      # Federated learning: anonymizer, confidence, aggregator
├── genome/         # Security Genome v2: RAG, embeddings, patterns
├── graph/          # Neo4j knowledge graph client
├── mcp/            # MCP server: tools, auth, registry
├── orchestration/  # Temporal workflows, activities, worker
├── tools/          # Nuclei, ZAP, exploit tools, PoC generator
frontend/
├── app/            # Next.js pages: engagements, findings, genome, redblue
├── components/     # Dashboard, graph, findings, layout components
├── hooks/          # React hooks: useWebSocket, useEngagement, useAttackGraph
└── lib/            # API client, types, constants
a_plan/             # 31 Level specifications (roadmap)
```

---

## Current Capabilities (Phases 0-9 + Levels 1-21)

### Base Platform (Phases 0-9)

| Feature | Status |
|---------|--------|
| Autonomous reconnaissance | ✅ |
| LLM-powered vulnerability analysis | ✅ |
| Exploit verification (browser-based) | ✅ |
| Temporal workflow orchestration | ✅ |
| Neo4j knowledge graph | ✅ |
| Blue team behavioral detection | ✅ |
| Genome pattern extraction | ✅ |
| RAG-powered vulnerability context | ✅ |
| Real-time dashboard | ✅ |
| Multi-agent system | ✅ |

### Tier 1 — Foundation (L01-L07)

| Level | Feature | Status |
|-------|---------|--------|
| L01 | EPSS risk scoring | ✅ |
| L02 | Supply chain scanner (SCA/SBOM) | ✅ |
| L03 | Compliance report generator | ✅ |
| L04 | LLM cost optimizer | ✅ |
| L05 | Container & K8s scanner | ✅ |
| L06 | Change-based diff testing | ✅ |
| L07 | WebSocket fuzzer | ✅ |

### Tier 2 — Intelligence (L08-L13)

| Level | Feature | Status |
|-------|---------|--------|
| L08 | Hybrid SAST (AST + LLM) | ✅ |
| L09 | Auto threat modeling | ✅ |
| L10 | Predictive vulnerability scoring | ✅ |
| L11 | Business logic tester | ✅ |
| L12 | gRPC & Protobuf fuzzer | ✅ |
| L13 | GraphRAG + HyDE retrieval | ✅ |

### Tier 3 — Advanced (L14-L19)

| Level | Feature | Status |
|-------|---------|--------|
| L14 | Auto-patch generator | ✅ |
| L15 | Multi-agent debate & review | ✅ |
| L16 | Knowledge graph risk analytics | ✅ |
| L17 | CTEM diff engine | ✅ |
| L18 | Behavioral blue team ML | ✅ |
| L19 | AI/LLM app security | ✅ |

### Tier 4 — Competitive Moat (L20-L24)

| Level | Feature | Status |
|-------|---------|--------|
| L20 | MCP server interface | ✅ |
| L21 | Federated learning pipeline | ✅ |
| L22 | Formal verification + fuzzing | 🔄 |
| L23 | RL pentesting agent | 🔄 |
| L24 | Stackelberg game planner | 🔄 |

### Tier 5 — Moonshots (L25-L31)

| Level | Feature | Status |
|-------|---------|--------|
| L25 | FlipIt persistence game | 🔄 |
| L26 | Wasm binary fuzzer | 🔄 |
| L27 | Active inference agent | 🔄 |
| L28 | Colonel Blotto allocator | 🔄 |
| L29 | Self-play red vs blue | 🔄 |
| L30 | Multi-tenant architecture | 🔄 |
| L31 | Benchmark harness | 🔄 |

---

## Roadmap: Levels 22-31

The platform through **Level 21** is **complete**. These remaining levels add cutting-edge research capabilities:

| Tier | Levels | Focus | What Gets Added |
|------|--------|-------|-----------------|
| **Tier 4** | L22-L24 | Moat | Formal verification, RL pentesting agents, game-theoretic optimization |
| **Tier 5** | L25-L31 | Moonshots | WASM fuzzing, self-play training, multi-tenancy, public benchmark |

📁 **Level specs:** [`a_plan/`](a_plan/)  
📄 **Index:** [`a_plan/level-0-index.md`](a_plan/level-0-index.md)

---

## Stats

- **~63k lines** of code (Python + TypeScript)
- **~24k lines** Python (core platform)
- **~1.5k lines** TypeScript/React (dashboard)
- **~24k lines** documentation (levels + specs)

---

## License

This project is licensed under the **Business Source License 1.1 (BSL 1.1)**.

- **Non-production use**: Free (development, testing, research)
- **Production use**: Requires commercial license or compliance with Additional Use Grant
- **Change Date**: 2030-02-19 (becomes GPL v2.0+ on this date)
- **Competing use**: Prohibited without explicit permission

For commercial licensing inquiries, please open an issue or contact the author.

See [LICENSE](./LICENSE) for full terms.
