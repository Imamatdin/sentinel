import type { HealthResponse, EngagementResult } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

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

export const api = {
  // Legacy endpoints (backward compat)
  health: () => request<HealthResponse>("/api/health"),
  startEngagement: (config: Record<string, unknown>) =>
    request<{ status: string }>("/api/engagement/start", {
      method: "POST",
      body: JSON.stringify(config),
    }),
  stopEngagement: () =>
    request<{ status: string }>("/api/engagement/stop", { method: "POST" }),
  getState: () => request("/api/engagement/state"),
  getResult: () => request<EngagementResult>("/api/engagement/result"),
  getReports: () =>
    request<{ red_report: string; blue_report: string }>("/api/engagement/reports"),
  getEvents: (sinceId = 0, limit = 100) =>
    request(`/api/engagement/events?since_id=${sinceId}&limit=${limit}`),

  // Engagements CRUD
  engagements: {
    list: () => request<any[]>("/api/engagements"),
    get: (id: string) => request<any>(`/api/engagements/${id}`),
    create: (data: any) =>
      request<any>("/api/engagements", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    start: (id: string) =>
      request<any>(`/api/engagements/${id}/start`, { method: "POST" }),
    stop: (id: string) =>
      request<any>(`/api/engagements/${id}/stop`, { method: "POST" }),
    approve: (id: string, approved: boolean) =>
      request<any>(`/api/engagements/${id}/approve`, {
        method: "POST",
        body: JSON.stringify({ approved }),
      }),
    diff: (id1: string, id2: string) =>
      request<any>(`/api/engagements/diff?e1=${id1}&e2=${id2}`),
  },

  // Findings
  findings: {
    list: (engagementId?: string) =>
      request<any[]>(
        engagementId
          ? `/api/findings?engagement_id=${engagementId}`
          : "/api/findings"
      ),
    get: (id: string) => request<any>(`/api/findings/${id}`),
    retest: (id: string) =>
      request<any>(`/api/findings/${id}/retest`, { method: "POST" }),
  },

  // Attack Graph
  graph: {
    get: (engagementId: string) =>
      request<any>(`/api/engagements/${engagementId}/graph`),
    chains: (engagementId: string) =>
      request<any[]>(`/api/engagements/${engagementId}/chains`),
  },

  // Red vs Blue
  redblue: {
    start: (engagementId: string) =>
      request<any>(`/api/engagements/${engagementId}/redblue/start`, {
        method: "POST",
      }),
    metrics: (engagementId: string) =>
      request<any>(`/api/engagements/${engagementId}/redblue/metrics`),
  },

  // Genome
  genome: {
    stats: () => request<any>("/api/genome/stats"),
    intel: (techStack: string[]) =>
      request<any>("/api/genome/intel", {
        method: "POST",
        body: JSON.stringify({ tech_stack: techStack }),
      }),
  },

  // Reports
  reports: {
    generate: (engagementId: string, type: string) =>
      request<any>(`/api/engagements/${engagementId}/report`, {
        method: "POST",
        body: JSON.stringify({ type }),
      }),
    owasp: (engagementId: string) =>
      request<any[]>(`/api/engagements/${engagementId}/report/owasp`),
    cis: (engagementId: string) =>
      request<any[]>(`/api/engagements/${engagementId}/report/cis`),
    download: (engagementId: string) =>
      `${API_BASE}/api/engagements/${engagementId}/report/download`,
  },
};
