# SENTINEL -- Autonomous AI Pentesting Platform

**Red Team attacks. Blue Team defends. In real-time. Powered by Cerebras.**

SENTINEL is an autonomous penetration testing platform where AI agents
simultaneously attack and defend a target application. Red team agents
discover and exploit vulnerabilities while blue team agents monitor traffic,
detect attacks, and deploy countermeasures. Watch the battle unfold in
real-time through a monochrome dashboard.

Built for the Cerebras "Need for Speed" hackathon. Cerebras inference
speed (1000-1700 tok/s) enables sub-second defensive responses to attacks.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Frontend (3001)                    │
│            Next.js 14 + WebSocket client             │
└─────────────────────┬───────────────────────────────┘
                      │ REST + WebSocket
┌─────────────────────▼───────────────────────────────┐
│                   API (8000)                          │
│         FastAPI + EngagementManager                   │
│              EventBus (in-process)                    │
├──────────┬─────────────────┬────────────────────────┤
│ Red Team │   Orchestrator   │      Blue Team         │
│ ReconAgt │                  │     MonitorAgt         │
│ ExploitA │  Phase Control   │     DefenderAgt        │
│ ReportAg │                  │     ForensicsAgt       │
├──────────┴─────────────────┴────────────────────────┤
│             Tool Layer (14 tools)                     │
│        HTTP reqs, SQL injection, XSS,                │
│        port scan, WAF, network monitor               │
├─────────────────────────────────────────────────────┤
│              CerebrasClient                          │
│         Cerebras Cloud SDK (async)                   │
├─────────────────────────────────────────────────────┤
│            Security Genome                           │
│    Extract -> Dedup -> Enrich -> SQLite              │
└─────────────────────────────────────────────────────┘
            │
┌───────────▼─────────────────┐
│    Juice Shop (3000)         │
│    OWASP vulnerable target   │
└─────────────────────────────┘
```

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

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CEREBRAS_API_KEY` | Yes | Cerebras Cloud API key |
| `NVD_API_KEY` | No | NVD API key for CVE enrichment |
| `SENTINEL_TARGET_URL` | No | Override target URL (default: http://localhost:3000) |

## How It Works

1. **Recon Phase**: Red team agents discover the attack surface (endpoints, technologies, potential vulns)
2. **Attack + Defense Phase**: Red team exploits vulnerabilities while blue team concurrently monitors traffic, detects attacks, deploys WAF rules, and patches
3. **Report Phase**: Both teams generate reports. Red team writes a pentest report; blue team writes an incident response report
4. **Genome Phase**: Findings are processed through the Security Genome pipeline, extracting reusable vulnerability patterns enriched with CWE/CAPEC classifications

## Security Genome

Every finding gets processed through the Genome pipeline:

1. **Extract**: LLM distills structured vulnerability patterns from raw findings
2. **Deduplicate**: Patterns with identical (attack_vector, payload_family, root_cause) are merged
3. **Enrich**: Static CWE/CAPEC mapping + optional NVD CVE lookup
4. **Store**: Patterns persist in SQLite, queryable via API

Query the genome:
```bash
GET /api/genome/stats
GET /api/genome/patterns?cwe_id=CWE-89&severity=critical
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check + target connectivity |
| `/api/engagement/start` | POST | Start a new engagement |
| `/api/engagement/stop` | POST | Stop running engagement |
| `/api/engagement/state` | GET | Current engagement state |
| `/api/engagement/result` | GET | Full result after completion |
| `/api/engagement/events` | GET | Event history (paginated) |
| `/api/engagement/reports` | GET | Red and blue team reports |
| `/api/genome/stats` | GET | Genome database statistics |
| `/api/genome/patterns` | GET | Search genome patterns |
| `/api/export/pdf` | GET | Download PDF pentest report |
| `/api/export/json` | GET | Download raw JSON data |
| `/ws` | WS | Real-time event stream |

## Tech Stack

| Component | Technology |
|-----------|------------|
| LLM | Cerebras Cloud (zai-glm-4.7) |
| Backend | FastAPI + WebSocket + asyncio |
| Frontend | Next.js 14 + TypeScript + Tailwind |
| Target | OWASP Juice Shop |
| Genome DB | SQLite (WAL mode) |
| Reports | WeasyPrint (HTML to PDF) |
| Deployment | Docker Compose (4 services) |

## Project Structure

```
sentinel/
├── core/           # CerebrasClient, models, settings, logging
├── tools/          # 14 security tools (red + blue)
├── agents/         # 6 AI agents + orchestrator
├── events/         # EventBus, Event, EventType
├── api/            # FastAPI app, routes, models
├── genome/         # Security Genome pipeline
├── reporting/      # PDF report generation
frontend/           # Next.js dashboard
docker/             # Dockerfiles + compose
tests/              # Unit + integration tests
```

## License

MIT
