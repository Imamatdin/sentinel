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
  | "paused";

// Legacy compat
export type EngagementState = "idle" | "running" | "completed" | "failed";
export type EngagementPhase = "recon" | "attack" | "defense" | "report" | null;

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
  schedule?: string;
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
  type: string;
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
  crown_jewel: string;
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
  new_paths: [string, string][];
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

// Legacy event type
export interface SentinelEvent {
  event_id: number;
  event_type: string;
  source: string;
  timestamp: number;
  data: Record<string, unknown>;
}

// ===== Genome =====

export interface GenomeStats {
  total_patterns: number;
  by_category: Record<string, number>;
  avg_confidence: number;
  top_techniques: { category: string; success_rate: number; count: number }[];
  learning_rate: number;
}

// ===== Reports =====

export interface OWASPMapping {
  category: string;
  findings_count: number;
  severity_breakdown: Record<Severity, number>;
  status: "pass" | "fail" | "partial";
}

export interface CISMapping {
  control_id: string;
  control_name: string;
  status: "compliant" | "non_compliant" | "partial" | "not_tested";
  findings: string[];
}

// Legacy types for backward compat
export interface AgentResult {
  agent_name: string;
  success: boolean;
  duration: number;
  tool_calls_made: number;
  input_tokens: number;
  output_tokens: number;
  total_llm_time: number;
  error: string | null;
  findings_summary: string | null;
}

export interface SpeedStats {
  total_tokens: number;
  total_llm_time_seconds: number;
  total_tool_calls: number;
  avg_tokens_per_second: number;
  engagement_wall_clock_seconds: number;
  attack_to_first_defense_seconds: number | null;
}

export interface EngagementResult {
  success: boolean;
  target_url: string;
  duration: number;
  event_count: number;
  phases: Record<string, unknown>;
  agents: Record<string, AgentResult>;
  speed_stats: SpeedStats;
  red_report: string;
  blue_report: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  juice_shop_reachable: boolean;
  juice_shop_url: string;
  engagement_active: boolean;
}

// ===== Utility functions =====

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${(seconds % 60).toFixed(0)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

export function formatTimestamp(ts: number): string {
  const date = new Date(ts * 1000);
  return date.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function classifyEvent(eventType: string): "red" | "blue" | "system" {
  if (eventType.startsWith("red.")) return "red";
  if (eventType.startsWith("blue.")) return "blue";
  return "system";
}

export function formatEventType(eventType: string): string {
  const parts = eventType.split(".");
  const name = parts.length > 1 ? parts.slice(1).join(".") : parts[0];
  return name
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
