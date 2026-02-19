# SENTINEL — Level System (Post-Phase Build)

## How This Works
- Phases 0-9 built the **base platform** (recon, vuln analysis, exploit, Temporal, RAG, blue team, dashboard)
- **Levels** layer research features ON TOP of the base, one at a time
- Each level = 1 markdown spec file → feed to Claude Code → ship → next level
- Levels are grouped into **tiers** by dependency, but within a tier you can do them in any order
- Each level file is self-contained: context, files to create/modify, tests, acceptance criteria

## Prerequisites
Phases 0-9 must be complete (or at minimum Phases 0-7 for Tier 1 levels).

---

## TIER 1 — Foundation Upgrades (no cross-dependencies)
These levels enhance existing systems. Do them in any order.

| Level | Name | Research Block | What It Adds | Est. Size |
|-------|------|---------------|--------------|-----------|
| L01 | EPSS Integration | B10, B6 | EPSS scores on every CVE node, priority ranking in hypothesis engine | Small |
| L02 | Supply Chain Scanner | B12, B5 | SCA + SBOM generation, reachability analysis, dependency confusion detection | Medium |
| L03 | Compliance Report Generator | B10 | Auto-map findings → PCI/SOC2/ISO/NIST controls, generate compliance-ready PDF sections | Medium |
| L04 | LLM Cost Optimizer | B11 | Model router (cheap→expensive tiering), prompt caching, batch API integration | Medium |
| L05 | Container & K8s Scanner | B12, B5 | Trivy/Grype integration, Dockerfile analysis, kube-bench for K8s misconfig | Small |
| L06 | Change-Based Diff Testing | B9 | Git webhook → diff parse → risk score → selective re-test against knowledge graph | Medium |
| L07 | WebSocket Fuzzer | B12, B8 | WS handshake interception, frame mutation, CSWSH detection, Origin validation | Small |

## TIER 2 — Intelligence Layer (builds on Tier 1 concepts)
These add smarts. L01-L07 should mostly exist.

| Level | Name | Research Block | What It Adds | Est. Size |
|-------|------|---------------|--------------|-----------|
| L08 | Hybrid SAST (LLM + AST) | B9 | AST/DFG extraction → LLM reasons over code structure, IRIS-style 2x recall | Large |
| L09 | Auto Threat Modeling | B9 | Ingest repo → generate STRIDE threat model → seed DAST hypotheses | Medium |
| L10 | Predictive Vuln Scoring | B12, B6 | ML model: tech stack + code metrics + EPSS → predict which bug classes to test first | Medium |
| L11 | Business Logic Tester | B5 | BOLA/IDOR differential testing, race condition (single-packet), workflow state machine abuse | Large |
| L12 | gRPC & Protobuf Fuzzer | B12, B8 | Auto-gen requests from .proto, field mutation, binary stream fuzzing | Small |
| L13 | GraphRAG + HyDE Retrieval | B7 | Neo4j entity traversal + vector retrieval, hypothetical document embeddings for better recall | Medium |

## TIER 3 — Advanced Capabilities (builds on Tier 2)

| Level | Name | Research Block | What It Adds | Est. Size |
|-------|------|---------------|--------------|-----------|
| L14 | Auto-Patch Generator | B9 | LLM generates fix → exploit re-run verifies → AST diff analysis → framework-specific patches | Large |
| L15 | Multi-Agent Debate & Review | B3 | 2-3 reviewer agents verify findings, debate protocol reduces FP, Reflexion self-correction | Medium |
| L16 | Knowledge Graph Risk Analytics | B4 | GDS PageRank for risk prioritization, betweenness centrality for chokepoints, Louvain clustering | Medium |
| L17 | CTEM Diff Engine | B4, B10 | Snapshot attack graphs per run, diff across runs, show new/closed paths, verify fixes | Medium |
| L18 | Behavioral Blue Team | B2 | Transformer-based anomaly detection, session profiling, adaptive WAF rule synthesis | Large |
| L19 | AI/LLM App Security | B6 | Prompt injection testing, MCP tool poisoning detection, agent hijacking, data exfiltration checks | Medium |

## TIER 4 — Competitive Moat (builds on Tier 3)

| Level | Name | Research Block | What It Adds | Est. Size |
|-------|------|---------------|--------------|-----------|
| L20 | MCP Server Interface | B10 | Expose Sentinel as MCP server (JSON-RPC), atomic + orchestrator tools, OAuth2 auth | Large |
| L21 | Federated Learning Pipeline | B12, B7 | Aggregate anonymous patterns across customers, differential privacy, global model updates | Large |
| L22 | Formal Verification + Fuzzing | B12 | PropertyGPT-style LLM invariant generation → SMT solver, Driller hybrid fuzzing | Large |
| L23 | RL Pentesting Agent | B12 | CyberBattleSim/PenGym environment, DQN/PPO training, curriculum learning | Large |
| L24 | Stackelberg Game Planner | B12 | MILP-based optimal scan scheduling, resource allocation, provable worst-case guarantees | Medium |

## TIER 5 — Moonshots (independent research projects)

| Level | Name | Research Block | What It Adds | Est. Size |
|-------|------|---------------|--------------|-----------|
| L25 | FlipIt Persistence Game | B12 | RL-trained retest/patch frequency optimizer, control-time metrics | Small |
| L26 | Wasm Binary Fuzzer | B12 | WALTZZ-style stack-invariant Wasm fuzzing, coverage-guided | Medium |
| L27 | Active Inference Agent | B12 | Bayesian belief updates, attention-weighted scanning, uncertainty minimization | Large |
| L28 | Colonel Blotto Allocator | B12 | Multi-stage resource allocation game, enterprise-wide scan budget optimization | Medium |
| L29 | Self-Play Red vs Blue | B12 | AlphaZero-style co-training, minimax adversarial planning with neural heuristics | Large |
| L30 | Multi-Tenant Architecture | B11 | RLS, label-based Neo4j isolation, per-tenant Temporal queues, hybrid agent deployment | Large |
| L31 | Benchmark Harness (Public) | B10 | Open-source benchmark suite, negative controls, transparent methodology, leaderboard | Medium |

---

## Dependency Graph (simplified)
```
TIER 1 (L01-L07) — all independent, do in any order
    ↓
TIER 2 (L08-L13) — L08 benefits from L06, L10 needs L01, L13 enhances all
    ↓
TIER 3 (L14-L19) — L14 needs L08, L15 enhances L14, L17 needs L16
    ↓
TIER 4 (L20-L24) — L21 needs L13, L22 needs L08
    ↓
TIER 5 (L25-L31) — moonshots, mostly independent
```

## How to Feed to Claude Code
```bash
# For each level:
claude "Read LEVEL_XX.md and implement everything. Follow file paths exactly. Run tests after each module. Do NOT modify files outside the spec unless fixing imports."
```

## Total Feature Count: 31 levels covering ALL 12 research blocks