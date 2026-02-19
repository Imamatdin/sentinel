"use client";

import useSWR from "swr";
import { api } from "@/lib/api";
import type { Engagement } from "@/lib/types";

export function useEngagements() {
  const { data, error, isLoading, mutate } = useSWR<Engagement[]>(
    "/api/engagements",
    () => api.engagements.list(),
    { refreshInterval: 5000 }
  );

  return {
    engagements: data || [],
    error,
    isLoading,
    refresh: mutate,
  };
}

export function useEngagement(id: string) {
  const { data, error, isLoading, mutate } = useSWR<Engagement>(
    id ? `/api/engagements/${id}` : null,
    () => api.engagements.get(id),
    { refreshInterval: 3000 }
  );

  return {
    engagement: data,
    error,
    isLoading,
    refresh: mutate,
  };
}
