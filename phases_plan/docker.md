# DOCKER COMPOSE — Full Infrastructure

## Context

Paste this between MASTER_PLAN.md and PHASE_5.md. Claude Code must run `docker compose up -d` BEFORE starting any phase implementation. This is the unified infrastructure that all phases depend on.

## What This Provides

All services Sentinel needs in a single docker-compose.yml:

1. **Neo4j** — Knowledge graph (attack graph, recon data, relationships)
2. **PostgreSQL + pgvector** — Relational storage + vector embeddings for RAG (Phase 8)
3. **Temporal Server + UI** — Workflow orchestration (Phase 7)
4. **OWASP ZAP** — Proxy scanner (Phase 5)
5. **Juice Shop** — Target application for testing
6. **Sentinel API** — FastAPI backend
7. **Sentinel Worker** — Temporal activity worker
8. **Sentinel Frontend** — Next.js dashboard (Phase 10)

---

## File: `docker-compose.yml`

```yaml
version: "3.8"

services:
  # ============================================================
  # DATA STORES
  # ============================================================

  neo4j:
    image: neo4j:5.18-community
    container_name: sentinel-neo4j
    ports:
      - "7474:7474"  # Browser UI
      - "7687:7687"  # Bolt protocol
    environment:
      NEO4J_AUTH: neo4j/sentinel_dev
      NEO4J_PLUGINS: '["apoc", "graph-data-science"]'
      NEO4J_dbms_memory_heap_max__size: "1G"
      NEO4J_dbms_memory_pagecache_size: "512M"
    volumes:
      - neo4j_data:/data
      - neo4j_logs:/logs
    healthcheck:
      test: ["CMD-SHELL", "neo4j status || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 10
    networks:
      - sentinel-net

  postgres:
    image: pgvector/pgvector:pg16
    container_name: sentinel-postgres
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: sentinel
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: sentinel_dev
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./infra/init-db.sql:/docker-entrypoint-initdb.d/01-init.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sentinel"]
      interval: 5s
      timeout: 3s
      retries: 10
    networks:
      - sentinel-net

  # ============================================================
  # TEMPORAL (Workflow Orchestration)
  # ============================================================

  temporal:
    image: temporalio/auto-setup:1.24
    container_name: sentinel-temporal
    ports:
      - "7233:7233"  # gRPC frontend
    environment:
      - DB=postgresql
      - DB_PORT=5432
      - POSTGRES_USER=sentinel
      - POSTGRES_PWD=sentinel_dev
      - POSTGRES_SEEDS=postgres
      - DYNAMIC_CONFIG_FILE_PATH=config/dynamicconfig/development.yaml
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./infra/temporal-dynamic-config.yaml:/etc/temporal/config/dynamicconfig/development.yaml
    networks:
      - sentinel-net

  temporal-ui:
    image: temporalio/ui:2.26.2
    container_name: sentinel-temporal-ui
    ports:
      - "8080:8080"
    environment:
      TEMPORAL_ADDRESS: temporal:7233
      TEMPORAL_CORS_ORIGINS: http://localhost:3000
    depends_on:
      - temporal
    networks:
      - sentinel-net

  # ============================================================
  # SCANNING TOOLS
  # ============================================================

  zap:
    image: ghcr.io/zaproxy/zaproxy:stable
    container_name: sentinel-zap
    ports:
      - "8090:8090"  # ZAP API
    command: >
      zap.sh -daemon
      -host 0.0.0.0
      -port 8090
      -config api.addrs.addr.name=.*
      -config api.addrs.addr.regex=true
      -config api.disablekey=true
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8090/JSON/core/view/version/"]
      interval: 10s
      timeout: 5s
      retries: 15
      start_period: 30s
    networks:
      - sentinel-net

  # ============================================================
  # TARGET APPLICATION
  # ============================================================

  juice-shop:
    image: bkimminich/juice-shop:latest
    container_name: sentinel-juice-shop
    ports:
      - "3001:3000"
    environment:
      NODE_ENV: unsafe
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000"]
      interval: 10s
      timeout: 5s
      retries: 10
    networks:
      - sentinel-net

  # ============================================================
  # SENTINEL SERVICES
  # ============================================================

  sentinel-api:
    build:
      context: .
      dockerfile: Dockerfile
      target: api
    container_name: sentinel-api
    ports:
      - "8000:8000"
    environment:
      # Data stores
      NEO4J_URI: bolt://neo4j:7687
      NEO4J_USER: neo4j
      NEO4J_PASSWORD: sentinel_dev
      DATABASE_URL: postgresql://sentinel:sentinel_dev@postgres:5432/sentinel
      # Temporal
      TEMPORAL_HOST: temporal:7233
      TEMPORAL_NAMESPACE: default
      TEMPORAL_TASK_QUEUE: sentinel-tasks
      # Scanning tools
      ZAP_API_URL: http://zap:8090
      ZAP_API_KEY: ""
      # Target
      TARGET_URL: http://juice-shop:3000
      # LLM providers (mount from .env)
      CEREBRAS_API_KEY: ${CEREBRAS_API_KEY:-}
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY:-}
      OPENAI_API_KEY: ${OPENAI_API_KEY:-}
      DEFAULT_LLM_PROVIDER: ${DEFAULT_LLM_PROVIDER:-cerebras}
      # App
      LOG_LEVEL: ${LOG_LEVEL:-INFO}
      ENVIRONMENT: development
    volumes:
      - ./src:/app/src
      - ./nuclei-templates:/app/nuclei-templates
    depends_on:
      neo4j:
        condition: service_healthy
      postgres:
        condition: service_healthy
      temporal:
        condition: service_started
      zap:
        condition: service_healthy
      juice-shop:
        condition: service_healthy
    networks:
      - sentinel-net

  sentinel-worker:
    build:
      context: .
      dockerfile: Dockerfile
      target: worker
    container_name: sentinel-worker
    environment:
      NEO4J_URI: bolt://neo4j:7687
      NEO4J_USER: neo4j
      NEO4J_PASSWORD: sentinel_dev
      DATABASE_URL: postgresql://sentinel:sentinel_dev@postgres:5432/sentinel
      TEMPORAL_HOST: temporal:7233
      TEMPORAL_NAMESPACE: default
      TEMPORAL_TASK_QUEUE: sentinel-tasks
      ZAP_API_URL: http://zap:8090
      ZAP_API_KEY: ""
      TARGET_URL: http://juice-shop:3000
      CEREBRAS_API_KEY: ${CEREBRAS_API_KEY:-}
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY:-}
      OPENAI_API_KEY: ${OPENAI_API_KEY:-}
      DEFAULT_LLM_PROVIDER: ${DEFAULT_LLM_PROVIDER:-cerebras}
      LOG_LEVEL: ${LOG_LEVEL:-INFO}
    volumes:
      - ./src:/app/src
      - ./nuclei-templates:/app/nuclei-templates
    depends_on:
      - temporal
      - neo4j
      - postgres
      - zap
    networks:
      - sentinel-net

  sentinel-frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: sentinel-frontend
    ports:
      - "3000:3000"
    environment:
      NEXT_PUBLIC_API_URL: http://localhost:8000
      NEXT_PUBLIC_WS_URL: ws://localhost:8000/ws
    depends_on:
      - sentinel-api
    networks:
      - sentinel-net

# ============================================================
# VOLUMES & NETWORKS
# ============================================================

volumes:
  neo4j_data:
  neo4j_logs:
  postgres_data:

networks:
  sentinel-net:
    driver: bridge
```

---

## File: `Dockerfile`

Multi-stage Dockerfile for API and Worker.

```dockerfile
# ============================================================
# Base stage — shared Python dependencies
# ============================================================
FROM python:3.11-slim AS base

WORKDIR /app

# System deps for Playwright, Neo4j, PostgreSQL
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (for Phase 6 browser automation)
RUN pip install playwright && playwright install chromium --with-deps

# Install Nuclei (for Phase 5 vulnerability scanning)
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/v//')_linux_amd64.zip -o /tmp/nuclei.zip \
    && apt-get update && apt-get install -y unzip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && nuclei -update-templates || true

COPY src/ /app/src/

# ============================================================
# API stage
# ============================================================
FROM base AS api
EXPOSE 8000
CMD ["uvicorn", "sentinel.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ============================================================
# Worker stage
# ============================================================
FROM base AS worker
CMD ["python", "-m", "sentinel.workflows.worker"]
```

---

## File: `frontend/Dockerfile`

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/public ./public
EXPOSE 3000
CMD ["npm", "start"]
```

---

## File: `infra/init-db.sql`

PostgreSQL initialization — creates tables and enables pgvector.

```sql
-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- ============================================================
-- Engagement tracking
-- ============================================================
CREATE TABLE IF NOT EXISTS engagements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'initialized',
    config JSONB NOT NULL DEFAULT '{}',
    summary JSONB,
    temporal_workflow_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_engagements_status ON engagements(status);
CREATE INDEX idx_engagements_created ON engagements(created_at DESC);

-- ============================================================
-- Findings
-- ============================================================
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES engagements(id),
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium',
    target_url TEXT NOT NULL,
    target_param TEXT,
    evidence TEXT,
    remediation TEXT,
    mitre_technique TEXT,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    exploited BOOLEAN NOT NULL DEFAULT FALSE,
    poc_script TEXT,
    replay_commands JSONB,
    http_traces JSONB,
    exposure_score JSONB,
    remediation_status TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_engagement ON findings(engagement_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_category ON findings(category);

-- ============================================================
-- Sentinel Embeddings (Phase 8 — RAG / Genome)
-- ============================================================
CREATE TABLE IF NOT EXISTS sentinel_embeddings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content_type TEXT NOT NULL,           -- 'vulnerability', 'exploit', 'defense', 'chain'
    content_key TEXT NOT NULL,            -- e.g. 'sqli:express:4.x'
    content_text TEXT NOT NULL,           -- Human-readable description
    embedding vector(1536) NOT NULL,     -- text-embedding-3-small
    metadata JSONB NOT NULL DEFAULT '{}', -- category, tech_stack, severity, etc.
    confidence FLOAT NOT NULL DEFAULT 0.5,
    success_count INT NOT NULL DEFAULT 0,
    failure_count INT NOT NULL DEFAULT 0,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- HNSW index for fast cosine similarity search
CREATE INDEX idx_embeddings_vector ON sentinel_embeddings
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE INDEX idx_embeddings_type ON sentinel_embeddings(content_type);
CREATE INDEX idx_embeddings_key ON sentinel_embeddings(content_key);
CREATE INDEX idx_embeddings_confidence ON sentinel_embeddings(confidence DESC);

-- ============================================================
-- Red vs Blue metrics
-- ============================================================
CREATE TABLE IF NOT EXISTS redblue_rounds (
    id SERIAL PRIMARY KEY,
    engagement_id UUID REFERENCES engagements(id),
    round_number INT NOT NULL,
    red_action TEXT NOT NULL,
    red_success BOOLEAN NOT NULL,
    blue_detected BOOLEAN NOT NULL,
    blue_response TEXT,
    detection_latency_ms FLOAT,
    response_latency_ms FLOAT,
    red_adaptation TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_redblue_engagement ON redblue_rounds(engagement_id);

-- ============================================================
-- Audit log (every tool call, every decision)
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    engagement_id UUID REFERENCES engagements(id),
    agent TEXT NOT NULL,           -- 'recon', 'vuln', 'exploit', 'defense'
    action TEXT NOT NULL,          -- 'tool_call', 'decision', 'policy_check'
    tool TEXT,                     -- Tool name if applicable
    input JSONB,
    output JSONB,
    policy_result TEXT,            -- 'approved', 'denied', 'escalated'
    duration_ms FLOAT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_engagement ON audit_log(engagement_id);
CREATE INDEX idx_audit_agent ON audit_log(agent);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);
```

---

## File: `infra/temporal-dynamic-config.yaml`

```yaml
# Temporal dynamic config for development
system.forceSearchAttributesCacheRefreshOnRead:
  - value: true
    constraints: {}
frontend.enableUpdateWorkflowExecution:
  - value: true
    constraints: {}
```

---

## File: `requirements.txt`

Complete Python dependencies for all phases.

```
# Core framework
fastapi==0.111.0
uvicorn[standard]==0.30.0
pydantic==2.7.0
python-dotenv==1.0.1

# Async HTTP
aiohttp==3.9.5
httpx==0.27.0

# Neo4j
neo4j==5.20.0

# PostgreSQL
asyncpg==0.29.0
psycopg2-binary==2.9.9
sqlalchemy==2.0.30

# pgvector
pgvector==0.3.0

# Temporal
temporalio==1.6.0

# Browser automation (Phase 6)
playwright==1.44.0

# LLM providers
anthropic==0.28.0
openai==1.35.0

# Scanning / security
python-owasp-zap-v2.4==0.0.22

# Embeddings + vector math
numpy==1.26.4
scikit-learn==1.5.0

# Report generation
jinja2==3.1.4
weasyprint==62.1
markdown==3.6

# Utilities
structlog==24.2.0
tenacity==8.3.0
pyyaml==6.0.1
click==8.1.7

# Testing
pytest==8.2.0
pytest-asyncio==0.23.7
pytest-cov==5.0.0
aioresponses==0.7.6

# Dev
black==24.4.0
ruff==0.4.0
mypy==1.10.0
```

---

## File: `.env.example`

```bash
# ===== LLM Providers =====
CEREBRAS_API_KEY=csk-your-key-here
ANTHROPIC_API_KEY=sk-ant-your-key-here
OPENAI_API_KEY=sk-your-key-here
DEFAULT_LLM_PROVIDER=cerebras

# ===== Data Stores =====
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=sentinel_dev
DATABASE_URL=postgresql://sentinel:sentinel_dev@localhost:5432/sentinel

# ===== Temporal =====
TEMPORAL_HOST=localhost:7233
TEMPORAL_NAMESPACE=default
TEMPORAL_TASK_QUEUE=sentinel-tasks

# ===== Scanning =====
ZAP_API_URL=http://localhost:8090
ZAP_API_KEY=

# ===== Target =====
TARGET_URL=http://localhost:3001

# ===== App =====
LOG_LEVEL=INFO
ENVIRONMENT=development
```

---

## Startup Sequence

Claude Code should execute in this order:

```bash
# 1. Copy .env.example to .env and fill in API keys
cp .env.example .env

# 2. Start all infrastructure
docker compose up -d

# 3. Wait for health checks
docker compose ps  # All services should show "healthy" or "running"

# 4. Verify services
curl http://localhost:7474          # Neo4j browser
curl http://localhost:8080          # Temporal UI
curl http://localhost:8090/JSON/core/view/version/  # ZAP API
curl http://localhost:3001          # Juice Shop
curl http://localhost:8000/health   # Sentinel API

# 5. Run database migrations (init-db.sql runs automatically via Docker)
# 6. Begin Phase 5 implementation
```

## Acceptance Criteria

- [ ] `docker compose up -d` starts all services without errors
- [ ] Neo4j accessible at bolt://localhost:7687 and browser at :7474
- [ ] PostgreSQL accessible with pgvector extension enabled
- [ ] Temporal server accepting connections at :7233, UI at :8080
- [ ] ZAP daemon running with API accessible at :8090
- [ ] Juice Shop serving at :3001
- [ ] Sentinel API starts and connects to all dependencies
- [ ] Temporal worker registers and polls for tasks
- [ ] `sentinel_embeddings` table exists with HNSW vector index
- [ ] All tables created from init-db.sql