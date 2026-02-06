// ── Core types matching backend API models ──

export type EngagementState = 'idle' | 'running' | 'completed' | 'failed';
export type EngagementPhase = 'recon' | 'attack' | 'report' | null;

export interface SentinelEvent {
  event_id: number;
  event_type: string;
  source: string;
  timestamp: number;
  data: Record<string, unknown>;
}

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

// ── Utility functions ──

export function formatDuration(seconds: number): string {
  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`;
  }
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}m ${secs.toFixed(0)}s`;
}

export function formatTimestamp(ts: number): string {
  const date = new Date(ts * 1000);
  return date.toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function classifyEvent(eventType: string): 'red' | 'blue' | 'system' {
  if (eventType.startsWith('red.')) return 'red';
  if (eventType.startsWith('blue.')) return 'blue';
  return 'system';
}

export function formatEventType(eventType: string): string {
  // "red.tool_call" -> "Tool Call", "orchestrator.phase_transition" -> "Phase Transition"
  const parts = eventType.split('.');
  const name = parts.length > 1 ? parts.slice(1).join('.') : parts[0];
  return name
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}
