import type { HealthResponse, EngagementResult } from './types';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || '';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...init?.headers,
    },
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`API ${res.status}: ${body}`);
  }

  return res.json() as Promise<T>;
}

export const api = {
  health(): Promise<HealthResponse> {
    return request<HealthResponse>('/api/health');
  },

  startEngagement(config: Record<string, unknown>): Promise<{ status: string }> {
    return request<{ status: string }>('/api/engagement/start', {
      method: 'POST',
      body: JSON.stringify(config),
    });
  },

  stopEngagement(): Promise<{ status: string }> {
    return request<{ status: string }>('/api/engagement/stop', {
      method: 'POST',
    });
  },

  getState() {
    return request('/api/engagement/state');
  },

  getResult(): Promise<EngagementResult> {
    return request<EngagementResult>('/api/engagement/result');
  },

  getReports(): Promise<{ red_report: string; blue_report: string }> {
    return request('/api/engagement/reports');
  },

  getEvents(sinceId = 0, limit = 100) {
    return request(`/api/engagement/events?since_id=${sinceId}&limit=${limit}`);
  },
};
