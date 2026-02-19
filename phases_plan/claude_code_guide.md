# CLAUDE CODE EXECUTION GUIDE

## Read This First

You are Claude Code, autonomously implementing the Sentinel AI pentesting platform. This document tells you HOW to consume all the specs, in what order, and how to validate each phase before moving on. Read this entire file before touching any code.

---

## 1. Document Map (Read Order)

```
READ ORDER:
┌─────────────────────────────────────┐
│  1. THIS FILE (you're here)         │
│  2. MASTER_PLAN.md                  │  ← Platform identity, architecture, what exists
│  3. DOCKER_COMPOSE_FULL.md          │  ← Infrastructure setup (run FIRST)
│  4. PHASE_5.md                      │  ← Vulnerability Analysis Agent
│  5. PHASE_6.md                      │  ← Exploitation Agent + Browser Automation
│  6. PHASE_7.md + LLM_CLIENTS.md     │  ← Wire Temporal + Multi-LLM clients
│  7. PHASE_8.md                      │  ← RAG + Genome Feedback Loop
│  8. PHASE_9.md                      │  ← Advanced Blue Team + Red vs Blue
│  9. PHASE_10.md                     │  ← Next.js Dashboard
│ 10. BENCHMARK_HARNESS.md            │  ← Validation (Phase 11)
└─────────────────────────────────────┘
```

**Critical**: Phases 0-4 are ALREADY COMPLETE. The codebase has working recon tools, attack tools, blue team tools, Neo4j knowledge graph, Temporal skeleton, policy engine, genome v1, API, reporting, and EventBus. Do NOT rewrite or overwrite existing code. Extend it.

---

## 2. Pre-Flight Checklist

Before writing any code, complete these steps:

```bash
# 1. Clone and inspect existing code
cd /path/to/sentinel
find src/sentinel -type f -name "*.py" | head -50   # Understand existing structure
cat src/sentinel/__init__.py
ls src/sentinel/tools/
ls src/sentinel/agents/
ls src/sentinel/api/

# 2. Read existing imports and interfaces
# CRITICAL: Every new module must integrate with existing code, not replace it.
# Check these files to understand current interfaces:
cat src/sentinel/tools/base.py          # BaseTool interface — all tools extend this
cat src/sentinel/agents/base.py         # BaseAgent interface — all agents extend this
cat src/sentinel/policy/engine.py       # PolicyEngine — gates all tool execution
cat src/sentinel/events/bus.py          # EventBus — all events publish here
cat src/sentinel/graph/client.py        # Neo4j client — read/write knowledge graph
cat src/sentinel/config.py              # Config loader — env vars and settings
cat src/sentinel/logging.py             # Structured logging — use get_logger(__name__)

# 3. Set up infrastructure
cp .env.example .env
# Fill in API keys: CEREBRAS_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY
docker compose up -d
docker compose ps   # Wait until ALL services show healthy/running

# 4. Verify infrastructure
curl -s http://localhost:7474 > /dev/null && echo "Neo4j: OK" || echo "Neo4j: FAILED"
curl -s http://localhost:8090/JSON/core/view/version/ > /dev/null && echo "ZAP: OK" || echo "ZAP: FAILED"
curl -s http://localhost:3001 > /dev/null && echo "Juice Shop: OK" || echo "Juice Shop: FAILED"
curl -s http://localhost:8080 > /dev/null && echo "Temporal UI: OK" || echo "Temporal UI: FAILED"
psql postgresql://sentinel:sentinel_dev@localhost:5432/sentinel -c "SELECT 1" && echo "Postgres: OK"

# 5. Run existing tests to confirm nothing is broken
pytest tests/ -x --tb=short
```

**Do NOT proceed to Phase 5 until all infrastructure checks pass and existing tests are green.**

---

## 3. Execution Rules

### 3.1 Integration Rules

These are non-negotiable. Every file you create must follow these:

1. **Extend, don't replace.** If `src/sentinel/tools/base.py` defines `BaseTool`, your new tools MUST extend `BaseTool`. If `PolicyEngine` gates execution, your agents MUST call it before running tools.
    
2. **Use existing utilities.** Use `get_logger(__name__)` for logging, `EventBus.publish()` for events, `Neo4jClient` for graph operations, `get_config()` for configuration. Do not create parallel versions.
    
3. **Follow existing patterns.** Look at how existing tools and agents are structured. Match the style — class naming, method signatures, error handling, docstrings.
    
4. **Policy-gated execution.** Every tool call from an agent MUST pass through `PolicyEngine.evaluate()` first. No exceptions. This is a security product.
    
5. **Event publishing.** Every significant action (tool start, tool result, finding created, exploit attempted) MUST publish to `EventBus`. The dashboard (Phase 10) and audit log depend on this.
    
6. **Knowledge graph writes.** Every discovery (host, port, service, endpoint, vulnerability, credential, finding) MUST be written to Neo4j. The attack graph visualization and hypothesis engine depend on this.
    

### 3.2 Coding Standards

```python
# Every new file starts with:
"""
Module docstring — what this does, how it fits in, what depends on it.
"""
from sentinel.logging import get_logger

logger = get_logger(__name__)

# Type hints on all function signatures
# Dataclasses for structured data (not raw dicts)
# Async by default (async def, await)
# Error handling: catch specific exceptions, log them, re-raise or return typed errors
# No print() — use logger.info/debug/warning/error
```

### 3.3 Testing Rules

1. **Write tests alongside code, not after.** Each file `src/sentinel/X/Y.py` gets a corresponding `tests/X/test_Y.py`.
2. **Unit tests mock external dependencies** (LLM calls, Neo4j, HTTP requests, Temporal).
3. **Integration tests use real Docker services** (Juice Shop, ZAP, Neo4j).
4. **Run tests after each file** — do not batch-create 10 files then test. Create, test, fix, move on.

```bash
# After creating each new file:
pytest tests/path/to/test_file.py -x -v
# Fix any failures before moving to next file
```

### 3.4 Validation Gates

After completing each phase, run these checks before moving to the next:

```bash
# Phase gate: ALL must pass
pytest tests/ -x --tb=short                    # All tests green
ruff check src/sentinel/                        # No lint errors
mypy src/sentinel/ --ignore-missing-imports     # Type checking (warnings OK, errors not)
```

---

## 4. Phase-by-Phase Execution

### Phase 5: Vulnerability Analysis Agent

**Dependencies**: Neo4j (graph data from recon), ZAP (docker), existing tools **Create in this order**:

1. `src/sentinel/tools/scanning/nuclei_tool.py` — Test: can it run a Nuclei scan and parse JSON output?
2. `src/sentinel/tools/scanning/zap_tool.py` — Test: can it talk to ZAP API, start spider, start active scan?
3. `src/sentinel/agents/hypothesis_engine.py` — Test: given graph data, does it produce ranked hypotheses?
4. `src/sentinel/agents/vuln_agent.py` (GuardedVulnAgent) — Test: does it test hypotheses with policy gates?
5. `src/sentinel/agents/finding_verifier.py` — Test: does it replay exploits and generate PoC?
6. Integration test: recon data in Neo4j → hypothesis → scan → verified finding → PoC

**Validation gate**:

```bash
# Nuclei can scan Juice Shop
python -c "from sentinel.tools.scanning.nuclei_tool import NucleiTool; ..."
# ZAP can spider Juice Shop
python -c "from sentinel.tools.scanning.zap_tool import ZAPTool; ..."
# Full pipeline: hypothesis → scan → finding
pytest tests/agents/test_vuln_agent.py -x -v
```

---

### Phase 6: Exploitation Agent + Browser Automation

**Dependencies**: Phase 5 findings, Playwright (Docker has it) **Create in this order**:

1. `src/sentinel/tools/exploit/ssrf_tool.py`
2. `src/sentinel/tools/exploit/command_injection_tool.py`
3. `src/sentinel/tools/exploit/file_upload_tool.py`
4. `src/sentinel/tools/exploit/xxe_tool.py`
5. `src/sentinel/tools/exploit/browser_worker.py` — Test: can it launch Playwright, navigate Juice Shop, extract DOM?
6. `src/sentinel/agents/exploit_agent.py` (GuardedExploitAgent) — Test: receives finding, selects tool, executes with policy gate
7. `src/sentinel/tools/exploit/poc_generator.py` — Test: generates Python/Bash replay scripts
8. Integration test: verified finding → exploit agent → successful exploitation → PoC script → graph updated

**Validation gate**:

```bash
# Browser can reach Juice Shop
python -c "from sentinel.tools.exploit.browser_worker import BrowserWorker; ..."
# Exploit pipeline works
pytest tests/agents/test_exploit_agent.py -x -v
# PoC scripts are syntactically valid
pytest tests/tools/exploit/test_poc_generator.py -x -v
```

---

### Phase 7: Wire Temporal Activities + LLM Clients

**Dependencies**: Phases 5-6 (all tools and agents), Temporal server **Create in this order**:

1. `src/sentinel/llm/base.py` — Base LLM client interface
2. `src/sentinel/llm/cerebras_client.py` — Test: mock API call succeeds
3. `src/sentinel/llm/claude_client.py` — Test: mock API call succeeds
4. `src/sentinel/llm/openai_client.py` — Test: mock API call + embedding succeeds
5. `src/sentinel/llm/fallback.py` — Test: falls back correctly on failure
6. `src/sentinel/llm/client.py` (factory) — Test: returns correct provider per task type
7. Rewrite `src/sentinel/activities/recon_activities.py` — calls REAL recon tools
8. Rewrite `src/sentinel/activities/vuln_activities.py` — calls REAL vuln agent
9. Rewrite `src/sentinel/activities/exploit_activities.py` — calls REAL exploit agent
10. Rewrite `src/sentinel/activities/report_activities.py` — calls REAL report generator
11. `src/sentinel/workflows/pentest_workflow.py` — Master workflow with retry policies, signals
12. `src/sentinel/workflows/worker.py` — Registers all activities
13. Integration test: start workflow via Temporal → executes all phases → produces report

**Validation gate**:

```bash
# LLM client factory works
pytest tests/llm/ -x -v
# Activities call real tools (mock the tools, verify wiring)
pytest tests/activities/ -x -v
# Temporal workflow registers and starts
pytest tests/workflows/test_pentest_workflow.py -x -v
# End-to-end: start workflow → verify it progresses through phases
```

**CRITICAL**: After this phase, zero placeholder data should remain in any activity. Every activity must call real tools. Grep to verify:

```bash
grep -r "placeholder\|TODO\|FIXME\|mock_data\|fake_" src/sentinel/activities/ && echo "FAIL: Placeholders found" || echo "PASS"
```

---

### Phase 8: RAG + Genome Feedback Loop

**Dependencies**: Phase 7 (Temporal activities), OpenAI embeddings, pgvector **Create in this order**:

1. `src/sentinel/genome/embedding_store.py` — Test: CRUD operations on pgvector
2. `src/sentinel/genome/rag_pipeline.py` — Test: embed query → retrieve similar → inject context
3. `src/sentinel/genome/genome_v2.py` — Test: pre-engagement intel, post-engagement learning, ExposureScore
4. Wire RAG into hypothesis engine (modify `hypothesis_engine.py` to query genome before generating)
5. Wire post-engagement learning into Temporal (add activity to workflow)
6. Integration test: run engagement → genome learns → second engagement benefits from genome

**Validation gate**:

```bash
# pgvector works
python -c "
import asyncpg, asyncio
async def test():
    conn = await asyncpg.connect('postgresql://sentinel:sentinel_dev@localhost:5432/sentinel')
    await conn.execute('SELECT * FROM sentinel_embeddings LIMIT 1')
    print('pgvector OK')
asyncio.run(test())
"
# Embedding store CRUD
pytest tests/genome/test_embedding_store.py -x -v
# RAG pipeline retrieves relevant context
pytest tests/genome/test_rag_pipeline.py -x -v
# Exposure score calculation
pytest tests/genome/test_genome_v2.py -x -v
```

---

### Phase 9: Advanced Blue Team + Red vs Blue

**Dependencies**: All prior phases (red team must work for adversarial loop) **Create in this order**:

1. `src/sentinel/defense/behavioral_detector.py` — Test: detects SQLi, XSS, scanning, brute force
2. `src/sentinel/defense/active_defense.py` — Test: blocks IP, adds WAF rules, hardens headers
3. `src/sentinel/defense/mitre_mapper.py` — Test: maps findings to ATT&CK techniques
4. `src/sentinel/defense/remediation_verifier.py` — Test: re-runs exploit, confirms blocked
5. `src/sentinel/defense/adversarial_loop.py` — Test: red attacks → blue detects → blue responds → red adapts
6. Integration test: full adversarial loop with metrics tracking

**Validation gate**:

```bash
# Behavioral detection works
pytest tests/defense/test_behavioral_detector.py -x -v
# Adversarial loop runs at least 5 rounds
pytest tests/defense/test_adversarial_loop.py -x -v
# MITRE mapping produces valid technique IDs
pytest tests/defense/test_mitre_mapper.py -x -v
```

---

### Phase 10: Next.js Dashboard

**Dependencies**: All backend APIs, WebSocket server **Create in this order**:

1. Add backend API endpoints to `src/sentinel/api/routes.py` (all endpoints listed in PHASE_10.md)
2. `frontend/lib/types.ts` — TypeScript interfaces
3. `frontend/lib/api.ts` — REST client
4. `frontend/hooks/useWebSocket.ts` — WebSocket connection
5. `frontend/tailwind.config.ts` — Monochrome theme
6. `frontend/components/shared/` — SeverityBadge, CodeBlock, LoadingSpinner, etc.
7. `frontend/app/layout.tsx` — Root layout with sidebar
8. `frontend/app/page.tsx` — Dashboard home
9. `frontend/app/engagements/` — Engagement CRUD pages
10. `frontend/components/graph/AttackGraph.tsx` — D3 force graph
11. `frontend/components/redblue/RedBlueTimeline.tsx` — Red vs Blue view
12. `frontend/components/reports/ExecutiveSummary.tsx` — CISO summary
13. `frontend/components/findings/` — Finding detail, evidence viewer, PoC viewer
14. `frontend/components/diff/` — CTEM diff view
15. Integration test: API → WebSocket → Dashboard renders

**Validation gate**:

```bash
cd frontend
npm install
npm run build          # Must build without errors
npm run lint           # Must pass lint
```

Backend API validation:

```bash
# All new endpoints respond
curl -s http://localhost:8000/api/engagements | python -m json.tool
curl -s http://localhost:8000/api/genome/stats | python -m json.tool
```

---

### Phase 11: Benchmark Harness

**Dependencies**: Entire platform must work **Create in this order**:

1. `src/sentinel/benchmark/targets/juice_shop.py` — Ground truth
2. `src/sentinel/benchmark/metrics.py` — Metrics collection
3. `src/sentinel/benchmark/_api_helpers.py` — API wrappers
4. `src/sentinel/benchmark/runner.py` — Orchestrator
5. `src/sentinel/benchmark/reporter.py` — Terminal/JSON/Markdown output
6. `src/sentinel/benchmark/regression.py` — Regression tracking
7. `src/sentinel/benchmark/cli.py` — CLI commands
8. Run actual benchmark against Juice Shop

**Validation gate**:

```bash
pytest tests/benchmark/ -x -v
# Actual benchmark run (this is the real test)
python -m sentinel.benchmark.cli run --target juice-shop --max-difficulty 3 --timeout 600 --format terminal
```

---

## 5. Dependency Graph

```
Phase 5 (Vuln Analysis)
    ├── depends on: Neo4j (existing), ZAP (Docker), Recon tools (existing)
    └── produces: Verified findings with PoC

Phase 6 (Exploitation)
    ├── depends on: Phase 5 findings, Playwright (Docker)
    └── produces: Successful exploits, attack chains, PoC scripts

Phase 7 (Temporal + LLM)
    ├── depends on: Phases 5-6 (all tools/agents), Temporal server
    └── produces: Real workflow execution, multi-LLM support

Phase 8 (RAG + Genome)
    ├── depends on: Phase 7 (Temporal activities), pgvector, OpenAI embeddings
    └── produces: Learning system, pre-engagement intel, ExposureScore

Phase 9 (Blue Team)
    ├── depends on: All red team phases (5-8) for adversarial loop
    └── produces: Behavioral detection, active defense, MITRE mapping

Phase 10 (Dashboard)
    ├── depends on: All backend (5-9) for data, WebSocket for streaming
    └── produces: User-facing interface

Phase 11 (Benchmark)
    ├── depends on: Everything (full pipeline must work)
    └── produces: Validation metrics, regression tracking
```

**You CAN parallelize**:

- Phases 5 and 6 tools can be built in parallel (they're independent tools)
- LLM clients (Phase 7 part 1) can be built in parallel with Phase 5-6
- Frontend components (Phase 10) can be built in parallel with Phase 9 (they just need API stubs)

**You CANNOT skip**:

- Phase 7 activities MUST wait for Phases 5-6 tools to exist
- Phase 8 genome MUST wait for Phase 7 embedding client
- Phase 9 adversarial loop MUST wait for red team (Phases 5-6) to work
- Phase 11 benchmark MUST wait for everything

---

## 6. Environment Variables

All required env vars — copy `.env.example` to `.env` and fill in:

```bash
# LLM Providers (at least one required)
CEREBRAS_API_KEY=csk-...              # Required for speed tasks
ANTHROPIC_API_KEY=sk-ant-...          # Required for reasoning tasks
OPENAI_API_KEY=sk-...                 # Required for embeddings

# Data Stores (Docker provides defaults)
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=sentinel_dev
DATABASE_URL=postgresql://sentinel:sentinel_dev@localhost:5432/sentinel

# Temporal (Docker provides defaults)
TEMPORAL_HOST=localhost:7233
TEMPORAL_NAMESPACE=default
TEMPORAL_TASK_QUEUE=sentinel-tasks

# Scanning
ZAP_API_URL=http://localhost:8090
ZAP_API_KEY=

# Target
TARGET_URL=http://localhost:3001

# App
LOG_LEVEL=INFO
DEFAULT_LLM_PROVIDER=cerebras
```

---

## 7. Common Pitfalls

1. **Don't create new config systems.** Use existing `get_config()` from `src/sentinel/config.py`. Just add new env vars to it.
    
2. **Don't create new logging.** Use `from sentinel.logging import get_logger`. It's already structured (structlog).
    
3. **Don't create new event systems.** Use existing `EventBus`. Subscribe to events, publish events.
    
4. **Don't mock Juice Shop in integration tests.** It's running in Docker. Hit it directly.
    
5. **Don't hardcode URLs.** Use `get_config()` or environment variables. Docker service names differ from localhost.
    
6. **Don't forget policy checks.** If you write an agent that calls a tool without `PolicyEngine.evaluate()`, it's a bug.
    
7. **Don't forget Neo4j writes.** If your tool discovers something and doesn't write it to the knowledge graph, downstream phases (hypothesis engine, attack graph viz) will be blind to it.
    
8. **Don't forget error handling.** External tools (Nuclei, ZAP, LLM APIs) WILL fail. Handle timeouts, parse errors, API errors gracefully. Log them. Don't crash the workflow.
    
9. **Don't create synchronous code.** Everything is async. Use `async def`, `await`, `aiohttp`, `asyncpg`. If a library is sync-only, wrap it in `asyncio.to_thread()`.
    
10. **Don't skip tests.** If you can't write a test for it, you probably don't understand what it does yet.
    

---

## 8. Success Criteria

The platform is DONE when:

- [ ] `docker compose up -d` starts all services
- [ ] `pytest tests/ -x` — all tests pass
- [ ] `sentinel benchmark run --target juice-shop` — produces benchmark report
- [ ] Detection rate > 50% on difficulty 1-3 Juice Shop vulns
- [ ] At least 3 verified exploits with PoC scripts
- [ ] Temporal workflow runs end-to-end without manual intervention
- [ ] Dashboard renders at `http://localhost:3000` with real data
- [ ] Attack graph visualization shows nodes and edges from Neo4j
- [ ] Red vs Blue adversarial loop runs at least 5 rounds
- [ ] Genome learns from first engagement and uses intel in second
- [ ] Executive report generates with OWASP mapping
- [ ] No placeholder data anywhere in the codebase

---

## 9. Quick Reference: Existing Code Patterns

### How existing tools work:

```python
# src/sentinel/tools/recon/subdomain_tool.py (example pattern)
from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

logger = get_logger(__name__)

class SubdomainTool(BaseTool):
    name = "subdomain_enum"
    description = "Enumerate subdomains for a target domain"
    
    async def execute(self, target: str, **kwargs) -> ToolResult:
        # ... do the work ...
        return ToolResult(success=True, data=results, raw_output=raw)
```

### How existing agents work:

```python
# src/sentinel/agents/recon_agent.py (example pattern)
from sentinel.agents.base import BaseAgent
from sentinel.policy.engine import PolicyEngine

class ReconAgent(BaseAgent):
    async def run(self, target: str):
        # 1. Plan
        plan = await self._plan(target)
        
        # 2. For each action, check policy then execute
        for action in plan:
            policy_result = await self.policy_engine.evaluate(action)
            if policy_result.approved:
                result = await self.tools[action.tool].execute(**action.params)
                await self.event_bus.publish("tool_result", result)
                await self.graph.write(result)
```

### How existing graph writes work:

```python
# Writing to Neo4j
await self.graph.run_query(
    "MERGE (h:Host {address: $addr}) SET h.updated_at = datetime()",
    {"addr": "192.168.1.1"}
)
```

### How existing events work:

```python
# Publishing events
await self.event_bus.publish("finding_new", {
    "engagement_id": self.engagement_id,
    "category": "sqli",
    "severity": "critical",
    "target_url": url,
})
```

Match these patterns exactly. Do not invent new conventions.