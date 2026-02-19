import type { Severity } from "./types";

export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
export const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/ws";

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#FF0000",
  high: "#FF6B00",
  medium: "#FFD700",
  low: "#00C853",
  info: "#808080",
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const NODE_COLORS: Record<string, string> = {
  host: "#E5E5E5",
  port: "#808080",
  service: "#A0A0A0",
  endpoint: "#C0C0C0",
  vulnerability: "#FF6B00",
  credential: "#FFD700",
  finding: "#FF0000",
};

export const NODE_SIZES: Record<string, number> = {
  host: 20,
  port: 8,
  service: 12,
  endpoint: 10,
  vulnerability: 14,
  credential: 12,
  finding: 16,
};

export const PHASE_LABELS: Record<string, string> = {
  initialized: "Initialized",
  recon: "Reconnaissance",
  vuln_analysis: "Vulnerability Analysis",
  exploitation: "Exploitation",
  reporting: "Reporting",
  complete: "Complete",
  failed: "Failed",
  paused: "Awaiting Approval",
};
