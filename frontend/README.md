# SENTINEL Frontend

Real-time dashboard for the SENTINEL autonomous AI pentesting platform.

## Design

- **Monochrome only**: Shades of gray, white, and black. No color.
- **Typography-driven**: Hierarchy through type size, weight, and spacing.
- **Real-time focus**: WebSocket event streaming, live speed metrics.

## Tech Stack

- Next.js 14 (App Router)
- TypeScript
- Tailwind CSS (monochrome palette)
- Native WebSocket (no socket.io)

## Setup

```bash
# Install dependencies
npm install

# Create .env.local
cp .env.local.example .env.local

# Start dev server (port 3001)
npm run dev
```

## Requirements

Before running, ensure:
1. SENTINEL backend is running on `http://localhost:8000`
2. Juice Shop is running on `http://localhost:3000`

```bash
# Terminal 1: Juice Shop
docker compose -f docker-compose.juice-shop.yml up -d

# Terminal 2: Backend
cd sentinel && poetry run python -m sentinel.api.app

# Terminal 3: Frontend
cd frontend && npm run dev
```

## Architecture

```
src/
├── app/
│   ├── layout.tsx       # Root layout with fonts
│   ├── page.tsx         # Main dashboard (single page)
│   └── globals.css      # Tailwind + monochrome base
├── lib/
│   ├── types.ts         # TypeScript types (matches backend)
│   ├── api.ts           # REST API client
│   └── websocket.ts     # WebSocket connection manager
└── components/
    ├── Header.tsx       # Branding + connection status
    ├── ControlPanel.tsx # Start/stop + config
    ├── StatusBar.tsx    # Live state/phase/elapsed
    ├── EventTimeline.tsx # Scrolling event feed
    ├── EventCard.tsx    # Individual event display
    ├── SpeedMetrics.tsx # Token throughput, latency
    ├── AgentPanel.tsx   # Agent result cards
    ├── ReportViewer.tsx # Red/blue report tabs
    └── LiveIndicator.tsx # Pulsing dot
```

## Key Decisions

| Decision | Rationale |
|----------|-----------|
| Monochrome design | Unique identity, extreme readability, distinguishes from typical neon security dashboards |
| No component library | Full control over monochrome aesthetic |
| Native WebSocket | socket.io is overkill for single connection |
| Next.js rewrite proxy | Avoids CORS during development |
| Port 3001 | Juice Shop uses 3000, backend uses 8000 |
| Single page | Entire demo is one real-time view |

## Environment Variables

```
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws
```

If not set, defaults to:
- API: `/api` (proxied via Next.js rewrite)
- WebSocket: `ws://localhost:8000/ws`
