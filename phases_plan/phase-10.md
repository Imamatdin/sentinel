# PHASE 10: Next.js Dashboard + Multi-Engagement Platform

## Context

Read MASTER_PLAN.md and Phases 5-9 first. The `frontend/` directory has a Next.js skeleton but is empty/minimal. The backend already has REST API (FastAPI) + WebSocket real-time streaming ready. This phase builds the entire frontend and wires it to the backend.

## What This Phase Builds

1. **Real-time engagement dashboard** — live attack progress, finding stream, agent status
2. **Attack graph visualization** — interactive node graph (hosts → services → vulns → exploits → chains)
3. **Engagement management** — create, configure, schedule, compare, history
4. **Red vs Blue live view** — the speed demo (Cerebras vs slow inference side-by-side)
5. **Executive reporting UI** — CISO-level summaries, OWASP Top 10 mapping, CIS benchmark mapping
6. **Multi-engagement diff view** — CTEM continuous verification (new/closed attack paths across runs)
7. **Finding detail pages** — evidence, PoC scripts, HTTP traces, remediation status
8. **Profile & settings** — API keys, notification preferences, engagement scheduling

## Design System

**Monochrome only**: shades of gray, white, black. No color except for severity indicators:

- CRITICAL: `#FF0000` (red)
- HIGH: `#FF6B00` (orange)
- MEDIUM: `#FFD700` (yellow)
- LOW: `#00C853` (green)
- INFO: `#808080` (gray)

Typography: Inter or JetBrains Mono for code. Clean, dense, no unnecessary whitespace. Think Bloomberg terminal meets Figma.

---

## Directory Structure

```
frontend/
├── app/
│   ├── layout.tsx                    # Root layout with sidebar nav
│   ├── page.tsx                      # Dashboard home (active engagements overview)
│   ├── globals.css                   # Tailwind + monochrome theme
│   ├── engagements/
│   │   ├── page.tsx                  # Engagement list
│   │   ├── new/page.tsx              # Create new engagement
│   │   ├── [id]/
│   │   │   ├── page.tsx              # Engagement detail (live view)
│   │   │   ├── findings/page.tsx     # Findings list for engagement
│   │   │   ├── graph/page.tsx        # Attack graph visualization
│   │   │   ├── redblue/page.tsx      # Red vs Blue live view
│   │   │   ├── report/page.tsx       # Report view + export
│   │   │   └── diff/page.tsx         # CTEM diff with previous run
│   ├── findings/
│   │   ├── page.tsx                  # Global findings browser
│   │   └── [id]/page.tsx             # Finding detail (evidence, PoC, traces)
│   ├── genome/
│   │   └── page.tsx                  # Genome dashboard (patterns, learning stats)
│   └── settings/
│       └── page.tsx                  # Settings & API keys
├── components/
│   ├── layout/
│   │   ├── Sidebar.tsx               # Left nav sidebar
│   │   ├── Header.tsx                # Top bar with engagement selector
│   │   └── StatusBar.tsx             # Bottom status bar (WebSocket connection, agent status)
│   ├── dashboard/
│   │   ├── EngagementCard.tsx        # Engagement summary card
│   │   ├── LiveFeed.tsx              # Real-time event stream
│   │   ├── AgentStatusGrid.tsx       # Agent health indicators
│   │   ├── SeverityBreakdown.tsx     # Findings by severity donut/bar
│   │   └── PhaseProgress.tsx         # Recon → Vuln → Exploit → Report progress
│   ├── graph/
│   │   ├── AttackGraph.tsx           # D3/Cytoscape interactive attack graph
│   │   ├── GraphNode.tsx             # Individual node component
│   │   ├── GraphEdge.tsx             # Edge with label
│   │   ├── GraphControls.tsx         # Zoom, filter, layout controls
│   │   └── GraphLegend.tsx           # Node type legend
│   ├── findings/
│   │   ├── FindingCard.tsx           # Finding summary card
│   │   ├── FindingDetail.tsx         # Full finding with evidence
│   │   ├── EvidenceViewer.tsx        # HTTP trace viewer
│   │   ├── PoCViewer.tsx             # PoC script viewer with copy
│   │   ├── RemediationStatus.tsx     # Fix status + retest button
│   │   └── MITREBadge.tsx            # ATT&CK technique badge
│   ├── redblue/
│   │   ├── RedBlueTimeline.tsx       # Timeline of attack/defense rounds
│   │   ├── SpeedComparison.tsx       # Side-by-side: Cerebras vs slow
│   │   ├── DefenseMetrics.tsx        # Detection rate, latency, coverage
│   │   └── RoundDetail.tsx           # Individual round detail
│   ├── reports/
│   │   ├── ExecutiveSummary.tsx      # CISO-level summary panel
│   │   ├── OWASPMapping.tsx          # OWASP Top 10 coverage chart
│   │   ├── CISMapping.tsx            # CIS benchmark mapping
│   │   ├── ExposureScoreCard.tsx     # Exposure score vs CVSS comparison
│   │   └── TrendChart.tsx            # Multi-engagement trend over time
│   ├── diff/
│   │   ├── DiffView.tsx              # Side-by-side engagement comparison
│   │   ├── PathDelta.tsx             # New/closed/persistent paths
│   │   └── RemediationTracker.tsx    # Fix verification progress
│   └── shared/
│       ├── SeverityBadge.tsx         # Color-coded severity indicator
│       ├── LoadingSpinner.tsx        # Minimal loading state
│       ├── CodeBlock.tsx             # Syntax-highlighted code display
│       ├── JsonViewer.tsx            # Collapsible JSON tree
│       ├── TimeAgo.tsx               # Relative timestamp
│       └── EmptyState.tsx            # Empty state placeholders
├── hooks/
│   ├── useWebSocket.ts              # WebSocket connection + reconnect
│   ├── useEngagement.ts             # Engagement CRUD + polling
│   ├── useFindings.ts               # Findings data fetching
│   ├── useLiveFeed.ts               # Real-time event stream
│   └── useAttackGraph.ts            # Graph data transformation
├── lib/
│   ├── api.ts                       # REST API client (fetch wrapper)
│   ├── ws.ts                        # WebSocket client
│   ├── types.ts                     # TypeScript interfaces
│   └── constants.ts                 # API URLs, severity colors, etc.
├── next.config.js
├── tailwind.config.ts
├── tsconfig.json
└── package.json
```

---

## File-by-File Implementation

### 1. `frontend/package.json`

```json
{
  "name": "sentinel-dashboard",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint"
  },
  "dependencies": {
    "next": "^14.2.0",
    "react": "^18.3.0",
    "react-dom": "^18.3.0",
    "d3": "^7.9.0",
    "d3-force": "^3.0.0",
    "@types/d3": "^7.4.0",
    "lucide-react": "^0.400.0",
    "clsx": "^2.1.0",
    "swr": "^2.2.0",
    "zustand": "^4.5.0",
    "react-syntax-highlighter": "^15.5.0",
    "@types/react-syntax-highlighter": "^15.5.0"
  },
  "devDependencies": {
    "typescript": "^5.4.0",
    "@types/react": "^18.3.0",
    "@types/react-dom": "^18.3.0",
    "@types/node": "^20.0.0",
    "tailwindcss": "^3.4.0",
    "postcss": "^8.4.0",
    "autoprefixer": "^10.4.0",
    "eslint": "^8.0.0",
    "eslint-config-next": "^14.2.0"
  }
}
```

### 2. `frontend/tailwind.config.ts`

```typescript
import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Monochrome base
        sentinel: {
          bg: "#0A0A0A",
          surface: "#141414",
          border: "#262626",
          muted: "#404040",
          text: "#E5E5E5",
          bright: "#FFFFFF",
        },
        // Severity only colors allowed
        severity: {
          critical: "#FF0000",
          high: "#FF6B00",
          medium: "#FFD700",
          low: "#00C853",
          info: "#808080",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
```

### 3. `frontend/lib/types.ts`

```typescript
// ===== Core Types =====

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type EngagementStatus =
  | "initialized"
  | "recon"
  | "vuln_analysis"
  | "exploitation"
  | "reporting"
  | "complete"
  | "failed"
  | "paused"; // Waiting for human approval

export interface Engagement {
  id: string;
  target: string;
  status: EngagementStatus;
  created_at: string;
  updated_at: string;
  config: EngagementConfig;
  summary?: EngagementSummary;
}

export interface EngagementConfig {
  target_url: string;
  require_approval: boolean;
  scan_depth: number;
  excluded_paths: string[];
  llm_provider: "cerebras" | "claude" | "openai";
  schedule?: string; // Cron expression for recurring
}

export interface EngagementSummary {
  hosts_found: number;
  endpoints_found: number;
  findings_count: number;
  exploited_count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  duration_seconds: number;
}

// ===== Findings =====

export interface Finding {
  id: string;
  engagement_id: string;
  category: string;
  severity: Severity;
  confidence: string;
  target_url: string;
  target_param?: string;
  evidence: string;
  remediation: string;
  mitre_technique: string;
  verified: boolean;
  exploited: boolean;
  poc_script?: string;
  replay_commands?: string[];
  http_traces?: HTTPTrace[];
  exposure_score?: ExposureScore;
  remediation_status: "open" | "fix_pending" | "fix_verified" | "wont_fix";
  created_at: string;
}

export interface HTTPTrace {
  method: string;
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  elapsed: number;
}

export interface ExposureScore {
  score: number;
  rating: string;
  chain_depth: number;
  privilege_level: string;
  data_sensitivity: string;
  exploit_confidence: number;
}

// ===== Attack Graph =====

export interface GraphNode {
  id: string;
  type: "host" | "port" | "service" | "endpoint" | "vulnerability" | "credential" | "finding";
  label: string;
  severity?: Severity;
  metadata: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string; // "HAS_PORT", "RUNS_SERVICE", "HAS_VULNERABILITY", "ENABLES", etc.
  label?: string;
}

export interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  chains: AttackChain[];
}

export interface AttackChain {
  id: string;
  steps: GraphNode[];
  total_depth: number;
  exposure_score: number;
  crown_jewel: string; // What the chain reaches
}

// ===== Red vs Blue =====

export interface RedBlueRound {
  round_number: number;
  red_action: string;
  red_success: boolean;
  blue_detected: boolean;
  blue_response: string;
  detection_latency_ms: number;
  response_latency_ms: number;
  red_adaptation: string;
}

export interface RedBlueMetrics {
  total_rounds: number;
  red_successes: number;
  blue_detections: number;
  blue_blocks: number;
  avg_detection_latency_ms: number;
  avg_response_latency_ms: number;
  coverage_score: number;
  rounds: RedBlueRound[];
}

// ===== CTEM Diff =====

export interface EngagementDiff {
  engagement_1: string;
  engagement_2: string;
  new_paths: [string, string][]; // [target_url, category]
  closed_paths: [string, string][];
  persistent_paths: [string, string][];
  delta_count: number;
}

// ===== WebSocket Events =====

export type WSEventType =
  | "agent_status"
  | "finding_new"
  | "finding_verified"
  | "exploit_attempt"
  | "exploit_success"
  | "defense_alert"
  | "defense_action"
  | "phase_change"
  | "approval_required"
  | "engagement_complete"
  | "redblue_round";

export interface WSEvent {
  type: WSEventType;
  engagement_id: string;
  timestamp: string;
  data: Record<string, unknown>;
}

// ===== Genome =====

export interface GenomeStats {
  total_patterns: number;
  by_category: Record<string, number>;
  avg_confidence: number;
  top_techniques: { category: string; success_rate: number; count: number }[];
  learning_rate: number; // Patterns added per engagement
}

// ===== Reports =====

export interface OWASPMapping {
  category: string; // "A01:2021 - Broken Access Control", etc.
  findings_count: number;
  severity_breakdown: Record<Severity, number>;
  status: "pass" | "fail" | "partial";
}

export interface CISMapping {
  control_id: string;
  control_name: string;
  status: "compliant" | "non_compliant" | "partial" | "not_tested";
  findings: string[]; // Finding IDs
}
```

### 4. `frontend/lib/api.ts`

```typescript
/**
 * REST API client for Sentinel backend.
 * Wraps fetch with error handling and auth headers.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    ...options,
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(error.detail || `API error: ${res.status}`);
  }

  return res.json();
}

// Engagements
export const api = {
  engagements: {
    list: () => request<any[]>("/api/engagements"),
    get: (id: string) => request<any>(`/api/engagements/${id}`),
    create: (data: any) => request<any>("/api/engagements", { method: "POST", body: JSON.stringify(data) }),
    start: (id: string) => request<any>(`/api/engagements/${id}/start`, { method: "POST" }),
    stop: (id: string) => request<any>(`/api/engagements/${id}/stop`, { method: "POST" }),
    approve: (id: string, approved: boolean) =>
      request<any>(`/api/engagements/${id}/approve`, { method: "POST", body: JSON.stringify({ approved }) }),
    diff: (id1: string, id2: string) => request<any>(`/api/engagements/diff?e1=${id1}&e2=${id2}`),
  },
  findings: {
    list: (engagementId?: string) =>
      request<any[]>(engagementId ? `/api/findings?engagement_id=${engagementId}` : "/api/findings"),
    get: (id: string) => request<any>(`/api/findings/${id}`),
    retest: (id: string) => request<any>(`/api/findings/${id}/retest`, { method: "POST" }),
  },
  graph: {
    get: (engagementId: string) => request<any>(`/api/engagements/${engagementId}/graph`),
    chains: (engagementId: string) => request<any[]>(`/api/engagements/${engagementId}/chains`),
  },
  redblue: {
    start: (engagementId: string) =>
      request<any>(`/api/engagements/${engagementId}/redblue/start`, { method: "POST" }),
    metrics: (engagementId: string) => request<any>(`/api/engagements/${engagementId}/redblue/metrics`),
  },
  genome: {
    stats: () => request<any>("/api/genome/stats"),
    intel: (techStack: string[]) =>
      request<any>("/api/genome/intel", { method: "POST", body: JSON.stringify({ tech_stack: techStack }) }),
  },
  reports: {
    generate: (engagementId: string, type: string) =>
      request<any>(`/api/engagements/${engagementId}/report`, { method: "POST", body: JSON.stringify({ type }) }),
    owasp: (engagementId: string) => request<any[]>(`/api/engagements/${engagementId}/report/owasp`),
    cis: (engagementId: string) => request<any[]>(`/api/engagements/${engagementId}/report/cis`),
    download: (engagementId: string) => `${API_BASE}/api/engagements/${engagementId}/report/download`,
  },
};
```

### 5. `frontend/hooks/useWebSocket.ts`

```typescript
/**
 * WebSocket hook — connects to Sentinel real-time event stream.
 * Auto-reconnects on disconnect. Filters events by engagement.
 */
import { useEffect, useRef, useState, useCallback } from "react";
import { WSEvent } from "@/lib/types";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/ws";

export function useWebSocket(engagementId?: string) {
  const [events, setEvents] = useState<WSEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<NodeJS.Timeout>();

  const connect = useCallback(() => {
    const url = engagementId ? `${WS_URL}?engagement_id=${engagementId}` : WS_URL;
    const ws = new WebSocket(url);

    ws.onopen = () => {
      setConnected(true);
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
    };

    ws.onmessage = (event) => {
      try {
        const data: WSEvent = JSON.parse(event.data);
        setEvents((prev) => [data, ...prev].slice(0, 500)); // Keep last 500
      } catch {}
    };

    ws.onclose = () => {
      setConnected(false);
      reconnectRef.current = setTimeout(connect, 3000); // Reconnect in 3s
    };

    ws.onerror = () => ws.close();
    wsRef.current = ws;
  }, [engagementId]);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
    };
  }, [connect]);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { events, connected, clearEvents };
}
```

### 6. `frontend/components/graph/AttackGraph.tsx`

```typescript
/**
 * AttackGraph — Interactive D3 force-directed graph visualization.
 *
 * Displays: Hosts → Ports → Services → Endpoints → Vulnerabilities → Attack Chains
 * Interactions: zoom, pan, click node for detail, filter by type, highlight chains
 */
"use client";

import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import { GraphNode, GraphEdge, AttackChain, Severity } from "@/lib/types";

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
  chains?: AttackChain[];
  onNodeClick?: (node: GraphNode) => void;
  selectedChain?: string;
}

const NODE_COLORS: Record<string, string> = {
  host: "#E5E5E5",
  port: "#808080",
  service: "#A0A0A0",
  endpoint: "#C0C0C0",
  vulnerability: "#FF6B00", // Uses severity color in practice
  credential: "#FFD700",
  finding: "#FF0000",
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#FF0000",
  high: "#FF6B00",
  medium: "#FFD700",
  low: "#00C853",
  info: "#808080",
};

const NODE_SIZES: Record<string, number> = {
  host: 20,
  port: 8,
  service: 12,
  endpoint: 10,
  vulnerability: 14,
  credential: 12,
  finding: 16,
};

export default function AttackGraph({ nodes, edges, chains, onNodeClick, selectedChain }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [filter, setFilter] = useState<string | null>(null);

  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    // Filter nodes if filter active
    const visibleNodes = filter ? nodes.filter((n) => n.type === filter) : nodes;
    const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));
    const visibleEdges = edges.filter((e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target));

    // Highlight chain if selected
    const chainNodeIds = selectedChain
      ? new Set(chains?.find((c) => c.id === selectedChain)?.steps.map((s) => s.id) || [])
      : null;

    const g = svg.append("g");

    // Zoom
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on("zoom", (event) => g.attr("transform", event.transform));
    svg.call(zoom);

    // Force simulation
    const simulation = d3
      .forceSimulation(visibleNodes as any)
      .force("link", d3.forceLink(visibleEdges as any).id((d: any) => d.id).distance(80))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(30));

    // Edges
    const link = g
      .append("g")
      .selectAll("line")
      .data(visibleEdges)
      .join("line")
      .attr("stroke", "#333")
      .attr("stroke-width", 1)
      .attr("stroke-opacity", (d) =>
        chainNodeIds ? (chainNodeIds.has((d as any).source.id) ? 1 : 0.15) : 0.6
      );

    // Edge labels
    const edgeLabels = g
      .append("g")
      .selectAll("text")
      .data(visibleEdges)
      .join("text")
      .attr("font-size", "8px")
      .attr("fill", "#666")
      .attr("text-anchor", "middle")
      .text((d) => d.type);

    // Nodes
    const node = g
      .append("g")
      .selectAll("circle")
      .data(visibleNodes)
      .join("circle")
      .attr("r", (d) => NODE_SIZES[d.type] || 10)
      .attr("fill", (d) =>
        d.severity ? SEVERITY_COLORS[d.severity] : NODE_COLORS[d.type] || "#808080"
      )
      .attr("stroke", (d) => (chainNodeIds?.has(d.id) ? "#FFF" : "#333"))
      .attr("stroke-width", (d) => (chainNodeIds?.has(d.id) ? 3 : 1))
      .attr("opacity", (d) => (chainNodeIds ? (chainNodeIds.has(d.id) ? 1 : 0.2) : 1))
      .attr("cursor", "pointer")
      .on("click", (event, d) => onNodeClick?.(d))
      .call(
        d3.drag<any, GraphNode>()
          .on("start", (event, d: any) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d: any) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d: any) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      );

    // Node labels
    const labels = g
      .append("g")
      .selectAll("text")
      .data(visibleNodes)
      .join("text")
      .attr("font-size", "10px")
      .attr("fill", "#CCC")
      .attr("text-anchor", "middle")
      .attr("dy", (d) => (NODE_SIZES[d.type] || 10) + 14)
      .text((d) => d.label.length > 20 ? d.label.slice(0, 20) + "…" : d.label);

    // Tick
    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      edgeLabels
        .attr("x", (d: any) => (d.source.x + d.target.x) / 2)
        .attr("y", (d: any) => (d.source.y + d.target.y) / 2);

      node.attr("cx", (d: any) => d.x).attr("cy", (d: any) => d.y);
      labels.attr("x", (d: any) => d.x).attr("y", (d: any) => d.y);
    });

    return () => {
      simulation.stop();
    };
  }, [nodes, edges, filter, selectedChain, chains, onNodeClick]);

  return (
    <div className="relative w-full h-full">
      {/* Filter controls */}
      <div className="absolute top-4 left-4 z-10 flex gap-2">
        {["host", "service", "endpoint", "vulnerability", "finding"].map((type) => (
          <button
            key={type}
            onClick={() => setFilter(filter === type ? null : type)}
            className={`px-3 py-1 text-xs font-mono rounded border ${
              filter === type
                ? "bg-white text-black border-white"
                : "bg-sentinel-surface text-sentinel-text border-sentinel-border hover:border-white"
            }`}
          >
            {type}
          </button>
        ))}
      </div>

      <svg
        ref={svgRef}
        className="w-full h-full bg-sentinel-bg"
        style={{ minHeight: "600px" }}
      />
    </div>
  );
}
```

### 7. `frontend/components/redblue/RedBlueTimeline.tsx`

```typescript
/**
 * Red vs Blue live timeline — shows attack/defense rounds in real-time.
 * The speed narrative visualization.
 */
"use client";

import { RedBlueRound, RedBlueMetrics } from "@/lib/types";

interface Props {
  metrics: RedBlueMetrics;
}

export default function RedBlueTimeline({ metrics }: Props) {
  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard
          label="Detection Rate"
          value={`${(metrics.coverage_score * 100).toFixed(1)}%`}
          good={metrics.coverage_score > 0.7}
        />
        <MetricCard
          label="Avg Detection"
          value={`${metrics.avg_detection_latency_ms.toFixed(1)}ms`}
          good={metrics.avg_detection_latency_ms < 50}
        />
        <MetricCard
          label="Red Successes"
          value={`${metrics.red_successes}/${metrics.total_rounds}`}
          good={metrics.red_successes < metrics.total_rounds * 0.3}
        />
        <MetricCard
          label="Blue Blocks"
          value={`${metrics.blue_blocks}`}
          good={metrics.blue_blocks > metrics.total_rounds * 0.5}
        />
      </div>

      {/* Timeline */}
      <div className="space-y-1 max-h-[500px] overflow-y-auto">
        {metrics.rounds.map((round) => (
          <RoundRow key={round.round_number} round={round} />
        ))}
      </div>
    </div>
  );
}

function MetricCard({ label, value, good }: { label: string; value: string; good: boolean }) {
  return (
    <div className="bg-sentinel-surface border border-sentinel-border p-4 rounded">
      <div className="text-xs text-sentinel-muted font-mono uppercase">{label}</div>
      <div className={`text-2xl font-mono mt-1 ${good ? "text-severity-low" : "text-severity-high"}`}>
        {value}
      </div>
    </div>
  );
}

function RoundRow({ round }: { round: RedBlueRound }) {
  return (
    <div className="flex items-center gap-3 px-3 py-2 bg-sentinel-surface border-l-2 rounded-r text-sm font-mono"
      style={{
        borderLeftColor: round.blue_detected
          ? round.blue_response === "block_ip" ? "#00C853" : "#FFD700"
          : "#FF0000",
      }}
    >
      <span className="text-sentinel-muted w-8">#{round.round_number}</span>

      {/* Red action */}
      <span className="text-red-400 w-40 truncate" title={round.red_action}>
        ⚔ {round.red_action}
      </span>

      {/* Arrow */}
      <span className="text-sentinel-muted">→</span>

      {/* Blue response */}
      <span className={`w-24 ${round.blue_detected ? "text-green-400" : "text-red-400"}`}>
        {round.blue_detected ? `🛡 ${round.blue_response}` : "✗ missed"}
      </span>

      {/* Latency */}
      <span className="text-sentinel-muted text-xs w-20">
        {round.detection_latency_ms.toFixed(1)}ms
      </span>

      {/* Adaptation */}
      {round.red_adaptation && (
        <span className="text-yellow-400 text-xs truncate flex-1" title={round.red_adaptation}>
          ↻ {round.red_adaptation}
        </span>
      )}
    </div>
  );
}
```

### 8. `frontend/components/reports/ExecutiveSummary.tsx`

```typescript
/**
 * ExecutiveSummary — CISO-level engagement summary.
 * No technical jargon. Business impact focus.
 */
"use client";

import { EngagementSummary, Finding, ExposureScore } from "@/lib/types";
import SeverityBadge from "@/components/shared/SeverityBadge";

interface Props {
  summary: EngagementSummary;
  findings: Finding[];
  exposureScores: ExposureScore[];
}

export default function ExecutiveSummary({ summary, findings, exposureScores }: Props) {
  const avgExposure = exposureScores.length
    ? exposureScores.reduce((sum, e) => sum + e.score, 0) / exposureScores.length
    : 0;

  return (
    <div className="space-y-8">
      {/* Risk overview */}
      <section>
        <h2 className="text-lg font-mono text-sentinel-bright mb-4">Risk Overview</h2>
        <div className="grid grid-cols-2 gap-6">
          <div className="bg-sentinel-surface border border-sentinel-border p-6 rounded">
            <div className="text-xs text-sentinel-muted font-mono uppercase mb-2">
              Overall Exposure Score
            </div>
            <div className={`text-5xl font-mono ${
              avgExposure > 0.7 ? "text-severity-critical" :
              avgExposure > 0.5 ? "text-severity-high" :
              avgExposure > 0.3 ? "text-severity-medium" : "text-severity-low"
            }`}>
              {(avgExposure * 100).toFixed(0)}
            </div>
            <div className="text-xs text-sentinel-muted mt-2">
              Based on chain depth × privilege × sensitivity × confidence
            </div>
          </div>

          <div className="bg-sentinel-surface border border-sentinel-border p-6 rounded">
            <div className="text-xs text-sentinel-muted font-mono uppercase mb-4">
              Findings by Severity
            </div>
            <div className="space-y-2">
              {(["critical", "high", "medium", "low"] as const).map((sev) => {
                const count = findings.filter((f) => f.severity === sev).length;
                const pct = findings.length ? (count / findings.length) * 100 : 0;
                return (
                  <div key={sev} className="flex items-center gap-3">
                    <SeverityBadge severity={sev} />
                    <div className="flex-1 bg-sentinel-bg rounded-full h-2">
                      <div
                        className="h-2 rounded-full"
                        style={{
                          width: `${pct}%`,
                          backgroundColor:
                            sev === "critical" ? "#FF0000" :
                            sev === "high" ? "#FF6B00" :
                            sev === "medium" ? "#FFD700" : "#00C853",
                        }}
                      />
                    </div>
                    <span className="text-sm font-mono text-sentinel-text w-8 text-right">
                      {count}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      {/* Key metrics */}
      <section>
        <h2 className="text-lg font-mono text-sentinel-bright mb-4">Key Metrics</h2>
        <div className="grid grid-cols-4 gap-4">
          <StatCard label="Attack Surface" value={`${summary.endpoints_found} endpoints`} />
          <StatCard label="Vulnerabilities Found" value={`${summary.findings_count}`} />
          <StatCard label="Exploits Verified" value={`${summary.exploited_count}`} />
          <StatCard label="Test Duration" value={formatDuration(summary.duration_seconds)} />
        </div>
      </section>

      {/* Top risks */}
      <section>
        <h2 className="text-lg font-mono text-sentinel-bright mb-4">Top Risks Requiring Immediate Action</h2>
        <div className="space-y-3">
          {findings
            .filter((f) => f.severity === "critical" || f.severity === "high")
            .slice(0, 5)
            .map((f) => (
              <div
                key={f.id}
                className="flex items-center gap-4 bg-sentinel-surface border border-sentinel-border p-4 rounded"
              >
                <SeverityBadge severity={f.severity} />
                <div className="flex-1">
                  <div className="text-sm text-sentinel-bright">{f.category.toUpperCase()}</div>
                  <div className="text-xs text-sentinel-muted font-mono">{f.target_url}</div>
                </div>
                <div className="text-xs text-sentinel-muted font-mono">
                  {f.mitre_technique}
                </div>
                <div className={`text-xs px-2 py-1 rounded ${
                  f.remediation_status === "fix_verified" ? "bg-green-900 text-green-300" :
                  f.remediation_status === "open" ? "bg-red-900 text-red-300" : "bg-yellow-900 text-yellow-300"
                }`}>
                  {f.remediation_status.replace("_", " ")}
                </div>
              </div>
            ))}
        </div>
      </section>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-sentinel-surface border border-sentinel-border p-4 rounded">
      <div className="text-xs text-sentinel-muted font-mono uppercase">{label}</div>
      <div className="text-xl font-mono text-sentinel-bright mt-1">{value}</div>
    </div>
  );
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}
```

### 9. `frontend/components/shared/SeverityBadge.tsx`

```typescript
import { Severity } from "@/lib/types";

const COLORS: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-green-600 text-white",
  info: "bg-gray-600 text-white",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono uppercase ${COLORS[severity]}`}>
      {severity}
    </span>
  );
}
```

---

## Backend API Endpoints to Add

These REST endpoints must be added to the existing FastAPI app in `src/sentinel/api/` to support the dashboard:

```python
# src/sentinel/api/routes.py — ADD these endpoints

# === Engagements ===
GET    /api/engagements                          # List all engagements
POST   /api/engagements                          # Create new engagement
GET    /api/engagements/{id}                     # Get engagement detail + summary
POST   /api/engagements/{id}/start               # Start Temporal workflow
POST   /api/engagements/{id}/stop                # Cancel Temporal workflow
POST   /api/engagements/{id}/approve              # Send approval signal to Temporal
GET    /api/engagements/diff?e1={id}&e2={id}     # CTEM diff between two engagements

# === Findings ===
GET    /api/findings?engagement_id={id}           # List findings (optional filter)
GET    /api/findings/{id}                         # Finding detail with evidence, traces, PoC
POST   /api/findings/{id}/retest                  # Re-run exploit to verify remediation

# === Attack Graph ===
GET    /api/engagements/{id}/graph                # Neo4j graph data for visualization
GET    /api/engagements/{id}/chains               # Attack chains

# === Red vs Blue ===
POST   /api/engagements/{id}/redblue/start        # Start adversarial loop
GET    /api/engagements/{id}/redblue/metrics       # Get loop metrics

# === Genome ===
GET    /api/genome/stats                          # Genome learning statistics
POST   /api/genome/intel                          # Pre-engagement intelligence

# === Reports ===
POST   /api/engagements/{id}/report                # Generate report
GET    /api/engagements/{id}/report/owasp          # OWASP Top 10 mapping
GET    /api/engagements/{id}/report/cis            # CIS benchmark mapping
GET    /api/engagements/{id}/report/download        # Download PDF report
```

---

## Tests

### `frontend/__tests__/components/SeverityBadge.test.tsx`

```typescript
import { render, screen } from "@testing-library/react";
import SeverityBadge from "@/components/shared/SeverityBadge";

describe("SeverityBadge", () => {
  it("renders critical badge", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeTruthy();
  });
});
```

### `frontend/__tests__/hooks/useWebSocket.test.ts`

```typescript
// Integration test — needs WebSocket mock
describe("useWebSocket", () => {
  it("connects and receives events", () => {
    // TODO: Mock WebSocket, verify events are received and stored
  });

  it("reconnects on disconnect", () => {
    // TODO: Mock close, verify reconnect after 3s
  });
});
```

---

## Integration Points

1. **Backend API**: New REST endpoints in FastAPI (listed above)
2. **WebSocket**: Existing WebSocket server in `src/sentinel/api/` — already streaming events
3. **Neo4j**: Graph data queried by backend, transformed for D3 visualization
4. **Temporal**: Engagement start/stop/approve wired to Temporal workflow client
5. **Genome**: Stats and pre-engagement intel from GenomeV2
6. **Reports**: PDF generation via existing Jinja2/weasyprint pipeline, download via API

## Acceptance Criteria

- [ ] Dashboard shows active engagements with real-time status
- [ ] WebSocket connection streams events with auto-reconnect
- [ ] Attack graph renders with D3 force layout, zoom/pan/filter/chain highlight
- [ ] Create engagement form → starts Temporal workflow
- [ ] Human approval UI → sends Temporal signal
- [ ] Red vs Blue timeline shows rounds with latency metrics
- [ ] Executive summary renders with exposure scores and severity breakdown
- [ ] OWASP Top 10 mapping chart
- [ ] CTEM diff view shows new/closed/persistent paths
- [ ] Finding detail shows evidence, HTTP traces, PoC script, remediation status
- [ ] Retest button triggers exploit replay and updates remediation status
- [ ] PDF report download works
- [ ] Monochrome design with severity-only color exceptions
- [ ] All components render without errors