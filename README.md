# SENTINEL — Autonomous AI Pentesting Platform

**Current: Base Platform (Phases 0-9) ✓ Complete**

**Future: Enterprise-Grade Autonomous Security Engine (31 Levels In Progress)**

---

## What It Is Today

SENTINEL is a fully functional autonomous penetration testing platform where AI agents simultaneously attack and defend a target application. The base platform (**Phases 0-9**) is **complete and production-ready**:

- **Red Team**: Autonomous reconnaissance, vulnerability discovery, and exploitation
- **Blue Team**: Real-time attack detection, behavioral analysis, and countermeasures  
- **Genome Engine**: Vulnerability pattern extraction, deduplication, and CWE/CAPEC enrichment
- **Orchestration**: Temporal workflows for complex multi-step attacks
- **Dashboard**: Real-time WebSocket-fed UI with attack graphs, findings, and red/blue battle view

Built for the Cerebras "Need for Speed" hackathon. Cerebras inference speed (1000-1700 tok/s) enables sub-second defensive responses to attacks.

---

## What It Will Become

As the **31 research-driven levels** are implemented, SENTINEL will evolve from a pentesting platform into a **comprehensive autonomous security engine**:

| Stage | Transformation |
|-------|---------------|
| **Tier 1 (L01-L07)** | Enterprise-ready: EPSS risk scoring, supply chain security, compliance reporting, K8s scanning |
| **Tier 2 (L08-L13)** | Intelligence-driven: Hybrid SAST with AST+LLM, auto threat modeling, predictive vulnerability scoring |
| **Tier 3 (L14-L19)** | Self-healing: Auto-patch generation, multi-agent debate for accuracy, behavioral blue team ML |
| **Tier 4 (L20-L24)** | Competitive moat: MCP server integration, federated learning, RL-trained pentesting agents |
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

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| LLM | Cerebras Cloud (Llama 3.3 70B) |
| Backend | FastAPI + WebSocket + asyncio + Temporal |
| Frontend | Next.js 15 + TypeScript + Tailwind |
| Database | Neo4j (knowledge graph) + PostgreSQL + pgvector |
| Workflow | Temporal.io |
| Scanner | Nuclei + OWASP ZAP |
| Genome | SQLite → pgvector (RAG) |
| Deployment | Docker Compose |

---

## Project Structure

```
sentinel/
├── agents/         # AI agents: Recon, Vuln, Exploit, Defense, Verifier
├── api/            # FastAPI routes: engagement, dashboard, genome
├── core/           # CerebrasClient, models, settings
├── defense/        # Blue team: detection, MITRE mapping, remediation
├── events/         # EventBus, Event types
├── genome/         # Security Genome v2: RAG, embeddings, patterns
├── graph/          # Neo4j knowledge graph client
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

## Current Capabilities (Phases 0-9)

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

---

## Roadmap: 31 Levels (Tiers 1-5)

The base platform is **complete**. These 31 research-driven levels add enterprise and cutting-edge capabilities:

| Tier | Levels | Focus | What Gets Added |
|------|--------|-------|-----------------|
| **Tier 1** | L01-L07 | Foundation | EPSS scoring, SCA/SBOM, compliance reports, LLM cost optimization, K8s scanning, change-based testing |
| **Tier 2** | L08-L13 | Intelligence | Hybrid SAST (AST+LLM), auto threat modeling, predictive scoring, business logic testing, gRPC fuzzing |
| **Tier 3** | L14-L19 | Advanced | Auto-patch generation, multi-agent debate, KG analytics, CTEM diff engine, behavioral ML blue team |
| **Tier 4** | L20-L24 | Moat | MCP server, federated learning, formal verification, RL pentesting agents |
| **Tier 5** | L25-L31 | Moonshots | Game-theoretic optimization, WASM fuzzing, self-play training, multi-tenancy |

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

MIT
