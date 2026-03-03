# SENTINEL

## Autonomous AI Security Platform

SENTINEL is a fully autonomous penetration testing and security operations platform where AI agents simultaneously attack and defend your infrastructure. It does not just find vulnerabilities. It understands them, exploits them, patches them, and learns from every engagement to become smarter over time.

Built for security teams who need continuous, intelligent protection without the overhead of manual pentesting cycles.

---

## What SENTINEL Does

### Autonomous Red Team Operations

SENTINEL's red team agents discover and exploit vulnerabilities without human intervention:

- **Reconnaissance**: Automated discovery of endpoints, technologies, and potential attack surfaces
- **Vulnerability Analysis**: LLM-powered assessment combining traditional scanning with intelligent reasoning
- **Exploit Verification**: Browser-based exploitation with screenshot proof and impact confirmation
- **Business Logic Testing**: BOLA/IDOR differential testing, race condition detection, workflow state machine abuse
- **AI/LLM Security**: Prompt injection testing, RAG poisoning detection, MCP tool poisoning, agent hijacking validation

### Autonomous Blue Team Defense

While the red team attacks, blue team agents defend:

- **Real-time Detection**: Behavioral analysis of incoming traffic with transformer-based anomaly detection
- **MITRE ATT&CK Mapping**: Automatic correlation of observed techniques to standard frameworks
- **Active Defense**: Automated countermeasures including adaptive WAF rule synthesis
- **Session Profiling**: Per-user behavioral baselines with deviation alerting
- **Red/Blue Feedback Loop**: Defensive improvements inform attack strategies and vice versa

### Security Genome Intelligence

Every finding feeds into a living knowledge system:

- **Pattern Extraction**: Vulnerability signatures distilled into reusable patterns
- **CWE/CAPEC Enrichment**: Automatic classification against industry standards
- **RAG-Powered Context**: Vector embeddings enable semantic similarity search across findings
- **GraphRAG + HyDE**: Neo4j entity traversal combined with hypothetical document embeddings
- **Knowledge Graph Analytics**: PageRank for risk prioritization, betweenness centrality for chokepoint identification

### Federated Learning Across Deployments

SENTINEL gets smarter with every customer while preserving privacy:

- **Anonymized Pattern Sharing**: Techniques that work are shared across deployments with differential privacy (Laplace noise, ε=1.0)
- **Bayesian Confidence Scoring**: Beta-Bernoulli tracking of technique effectiveness per tech stack
- **Thompson Sampling**: Optimal exploration/exploitation balance for attack strategy selection
- **Global Model Updates**: Aggregated insights improve every deployment without exposing customer data

### Formal Verification & Hybrid Fuzzing

For the highest-confidence vulnerability discovery:

- **LLM Property Generation**: PropertyGPT-style invariant synthesis from source code
- **Z3 SMT Verification**: Mathematical proof of property satisfaction or violation
- **Driller-Style Fuzzing**: Coverage-guided fuzzing with concolic execution fallback
- **Counterexample Seeding**: Z3-found violations seed the fuzzer for deeper exploration

### Reinforcement Learning Attack Agents

Train agents that discover novel attack paths:

- **Gymnasium Environment**: CyberBattleSim-style network simulation with crown jewel objectives
- **DQN/PPO Training**: Deep reinforcement learning for optimal attack sequencing
- **Curriculum Learning**: Progression from toy networks to complex enterprise topologies
- **Evolving Strategies**: Agents discover non-obvious attack chains humans might miss

### Game-Theoretic Resource Optimization

Mathematically optimal security resource allocation:

- **Stackelberg Security Games**: MILP-based scan allocation minimizing worst-case expected loss
- **Colonel Blotto Portfolio Optimization**: Distribute scan budgets across hundreds of applications
- **FlipIt Persistence Games**: Optimal retest/patch frequency per asset based on value and attack rate
- **Self-Play Co-Training**: Red vs blue agents train against each other, continuously improving both

### Active Inference Scanning

Information-theoretically optimal reconnaissance:

- **Bayesian Belief Models**: Beta distributions track certainty about network state
- **Expected Information Gain**: Scan decisions maximize uncertainty reduction per unit cost
- **Attention-Weighted Exploration**: Focus effort where it matters most
- **Free Energy Minimization**: Provably efficient information gathering

### WebAssembly Security

Cutting-edge Wasm analysis capabilities:

- **Binary Analysis**: Parse and analyze WebAssembly modules for attack surface
- **Type-Aware Fuzzing**: WALTZZ-style stack-invariant mutations
- **Coverage-Guided Exploration**: Instrumented execution with feedback-directed mutation
- **Opcode Mutation Strategies**: Arithmetic swaps, comparison swaps, constant replacement, memory offset manipulation

### Multi-Tenant SaaS Architecture

Enterprise-grade isolation for scaled deployment:

- **Postgres Row-Level Security**: Database-level tenant isolation even against application bugs
- **Neo4j Label Isolation**: Per-tenant graph labels prevent cross-tenant traversal
- **Temporal Queue Separation**: Per-tenant task queues with plan-based worker allocation
- **Contextvar Scoping**: Async-safe tenant context propagation

### Compliance & Reporting

Enterprise reporting without the manual work:

- **Auto-Mapped Controls**: PCI DSS, SOC 2, ISO 27001, NIST CSF mappings generated automatically
- **PDF Report Generation**: Executive summaries with technical appendices
- **EPSS Risk Scoring**: Exploit probability scores for every CVE
- **CTEM Diff Engine**: Snapshot attack graphs across runs, show new/closed paths, verify fixes

### Supply Chain Security

Modern software composition analysis:

- **SCA/SBOM Generation**: Dependency inventory with reachability analysis
- **Container Scanning**: Trivy/Grype integration for image vulnerabilities
- **K8s Misconfiguration**: kube-bench for CIS Kubernetes Benchmark validation
- **Dependency Confusion Detection**: Identifies risky internal package naming

### Hybrid SAST + DAST

Combine static and dynamic analysis:

- **AST/DFG Extraction**: Code structure analysis for reasoning foundations
- **LLM Code Analysis**: Large language models reason over control flow and data flow
- **Auto Threat Modeling**: STRIDE threat generation from repository ingestion
- **Auto-Patch Generation**: LLM-generated fixes with exploit re-verification

### MCP Server Interface

Expose SENTINEL to external AI agents:

- **JSON-RPC 2.0**: Standard protocol for tool invocation
- **Atomic Tools**: Individual scanner access for simple use cases
- **Orchestrator Tools**: Full engagement execution for complex scenarios
- **OAuth2 Authentication**: Secure API access with scoped permissions

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Frontend (Next.js)                          │
│   Real-time Dashboard │ Attack Graph │ Findings │ Red/Blue Battle   │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ REST + WebSocket
┌──────────────────────────────▼──────────────────────────────────────┐
│                        API Gateway (FastAPI)                        │
│   Engagement Management │ Tenant Context │ MCP Endpoint │ Federated  │
├──────────────────────────┬─────────────────┬────────────────────────┤
│      Red Team Agents     │  Orchestration  │     Blue Team          │
│   Recon │ Vuln │ Exploit │   Temporal.io   │   Detect │ Defend      │
├──────────────────────────┴─────────────────┴────────────────────────┤
│                        Tool Layer                                   │
│   Nuclei │ ZAP │ Custom Exploits │ PoC Generator │ Wasm Fuzzer     │
├─────────────────────────────────────────────────────────────────────┤
│                        Intelligence Layer                           │
│   Security Genome │ GraphRAG │ Vector Store │ Pattern Matching     │
├─────────────────────────────────────────────────────────────────────┤
│                        Learning Layer                               │
│   Federated Learning │ RL Agents │ Self-Play │ Bayesian Scoring    │
├─────────────────────────────────────────────────────────────────────┤
│                        Optimization Layer                           │
│   Stackelberg Games │ Colonel Blotto │ FlipIt │ Active Inference   │
├─────────────────────────────────────────────────────────────────────┤
│                        Verification Layer                           │
│   Property Generator │ Z3 SMT │ Hybrid Fuzzer │ Formal Methods      │
├─────────────────────────────────────────────────────────────────────┤
│                        Data Layer                                   │
│   Neo4j (Graph) │ Postgres + pgvector │ Temporal │ S3/MinIO        │
├─────────────────────────────────────────────────────────────────────┤
│                        Isolation Layer                              │
│   Row-Level Security │ Label Isolation │ Tenant Queues             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
- Cerebras API key (or compatible OpenAI-compatible endpoint)

### Docker Deployment

```bash
# Clone and configure
git clone <repo-url> && cd sentinel
cp docker/.env.example docker/.env
# Edit docker/.env with your API keys

# Launch all services
cd docker
docker compose up --build

# Access at http://localhost:80
# Click "Start Engagement" to begin autonomous testing
```

### Development Mode

```bash
# Terminal 1: Target application
docker run -d -p 3000:3000 bkimminich/juice-shop

# Terminal 2: Backend
pip install -e .
python -m uvicorn sentinel.api.app:create_app --factory --port 8000

# Terminal 3: Frontend
cd frontend && npm install && npm run dev

# Access at http://localhost:3001
```

---

## Core Workflows

### Continuous Automated Red Teaming

1. **Discovery**: Agents map your attack surface automatically
2. **Risk Prioritization**: EPSS scores + knowledge graph analytics rank targets
3. **Intelligent Exploitation**: Thompson sampling selects optimal attack techniques
4. **Verification**: Browser-based proof with screenshot evidence
5. **Remediation**: Auto-generated patches with exploit re-verification
6. **Learning**: Successful patterns fed back to federated model

### Autonomous Defense Operations

1. **Baseline**: Behavioral profiling establishes normal activity patterns
2. **Detection**: Transformer-based anomaly detection identifies deviations
3. **Correlation**: MITRE ATT&CK mapping contextualizes alerts
4. **Response**: Automated countermeasures including WAF rule synthesis
5. **Feedback**: Detection gaps inform red team priorities

### Game-Theoretic Security Planning

1. **Asset Valuation**: Crown jewel identification and business impact scoring
2. **Threat Modeling**: STRIDE analysis with automatic threat generation
3. **Optimal Allocation**: Stackelberg/Blotto solvers distribute scan budget
4. **Retest Cadence**: FlipIt optimization determines testing frequency per asset
5. **Continuous Improvement**: Self-play training evolves attack and defense strategies

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| LLM Engine | Cerebras Cloud (Llama 3.3 70B) |
| Backend | FastAPI + Python 3.11 |
| Frontend | Next.js 15 + TypeScript + Tailwind |
| Workflow | Temporal.io |
| Graph DB | Neo4j (knowledge graph + analytics) |
| Vector DB | PostgreSQL + pgvector |
| Task Queue | Redis + Temporal |
| Scanners | Nuclei, ZAP, Trivy, Grype, kube-bench |
| Formal Methods | Z3 SMT Solver |
| RL Framework | Gymnasium + Custom DQN/PPO |
| Deployment | Docker Compose / Kubernetes |

---

## Project Structure

```
sentinel/
├── agents/              # AI agents: recon, vuln, exploit, defense, debate
├── api/                 # FastAPI routes and middleware
├── blue_team/           # Behavioral detection, adaptive WAF, tripwires
├── core/                # Cerebras client, configuration, logging
├── ctem/                # Continuous Threat Exposure Management, diff engine
├── defense/             # MITRE mapping, remediation, forensics
├── events/              # EventBus for inter-agent communication
├── federated/           # Cross-deployment learning with differential privacy
├── formal/              # Property generation, Z3 verification, hybrid fuzzing
├── game_theory/         # Stackelberg, Blotto, FlipIt solvers
├── genome/              # Security Genome: patterns, embeddings, RAG
├── graph/               # Neo4j client, analytics, models
├── inference/           # Active inference, belief models, scanning
├── mcp/                 # MCP server: JSON-RPC, tools, auth
├── orchestration/       # Temporal workflows and activities
├── rag/                 # GraphRAG, HyDE, embeddings, vector store
├── remediation/         # Auto-patch generation, fix library
├── rl/                  # Reinforcement learning: DQN, environment, training
├── sast/                # Static analysis: AST extraction, LLM analyzer
├── self_play/           # Red vs blue co-training, arena, trainer
├── tenancy/             # Multi-tenant isolation: RLS, labels, queues
└── tools/               # Scanners, exploit tools, fuzzers, AI security

frontend/
├── app/                 # Next.js pages and routing
├── components/          # Dashboard, graphs, findings, layout
├── hooks/               # WebSocket, engagement, attack graph hooks
└── lib/                 # API client, types, utilities
```

---

## Stats

- **75,000+ lines** of production Python + TypeScript
- **30,000+ lines** of comprehensive test coverage
- **Formal verification** integration with Z3 SMT solver
- **Reinforcement learning** environment with curriculum learning
- **Game-theoretic optimization** across 3 distinct models
- **Multi-tenant isolation** at database, graph, and queue layers
- **Federated learning** with differential privacy guarantees

---

## License

This project is licensed under the **Business Source License 1.1 (BSL 1.1)**.

- **Non-production use**: Free for development, testing, and research
- **Production use**: Requires commercial license or compliance with Additional Use Grant
- **Change Date**: 2030-02-19 (converts to GPL v2.0+ on this date)
- **Competing use**: Prohibited without explicit permission

For commercial licensing inquiries, please open an issue or contact the author.

See [LICENSE](./LICENSE) for full terms.

---

## Acknowledgments

Built with research insights from:
- CyberBattleSim (Microsoft Research)
- PropertyGPT / Formal verification methods
- WALTZZ (WebAssembly fuzzing)
- FlipIt game theory (van Dijk et al.)
- Stackelberg security games
- Active Inference / Free Energy Principle (Friston)
