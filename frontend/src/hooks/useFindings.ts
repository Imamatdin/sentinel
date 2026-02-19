"use client";

import useSWR from "swr";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";

export function useFindings(engagementId?: string) {
  const { data, error, isLoading, mutate } = useSWR<Finding[]>(
    engagementId ? `/api/findings?engagement_id=${engagementId}` : "/api/findings",
    () => api.findings.list(engagementId),
    { refreshInterval: 5000 }
  );

  return {
    findings: data || [],
    error,
    isLoading,
    refresh: mutate,
  };
}

export function useFinding(id: string) {
  const { data, error, isLoading, mutate } = useSWR<Finding>(
    id ? `/api/findings/${id}` : null,
    () => api.findings.get(id),
  );

  return {
    finding: data,
    error,
    isLoading,
    refresh: mutate,
  };
}
