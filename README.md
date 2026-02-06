# SENTINEL

Autonomous AI pentesting platform powered by Cerebras inference. Red team AI agents attack web applications while blue team AI agents defend in real-time.

## The Speed Narrative

The race between attack and defense IS the product. Red team exploits at Cerebras speed (1000-1700 tok/s). Blue team MUST react faster than attacks land. Speed is not nice-to-have. It is the difference between caught and breached.

Demo shows TWO runs:
1. Cerebras-powered blue team: blocks 70-80% of attacks in real-time
2. Simulated slow inference (3-5s delay): blue team blocks 10-20%

## Architecture

- **Red Team Agents**: ReconAgent, ExploitAgent, ReportAgent
- **Blue Team Agents**: MonitorAgent, DefenderAgent, ForensicsAgent
- **Event Bus**: Real-time communication between agents
- **Security Genome**: Cross-session learning with embeddings
- **Frontend**: Monochrome design, live attack/defense visualization

## Tech Stack

- Python 3.11+ with async/await
- Cerebras inference (zai-glm-4.7)
- FastAPI + WebSocket backend
- Next.js frontend (monochrome: shades of gray, white, black ONLY)
- Docker Compose for deployment

## Target

OWASP Juice Shop running in Docker. 100+ documented vulnerabilities, industry standard.

## Setup

```bash
poetry install
cp .env.example .env
# Edit .env with your Cerebras API key (starts with csk-)

# Run tests
poetry run pytest

# Start Juice Shop target
docker compose -f docker-compose.juice-shop.yml up -d
```

## Project Phases

Phase 1: Foundation (LLM client, tools, config, logging)
Phase 2: Security Tools + Juice Shop
Phase 3: Agents + Event Bus + Orchestration
Phase 4: FastAPI + WebSocket Backend
Phase 5: Next.js Frontend (monochrome)
Phase 6: Security Genome + Docker Compose + Demo
