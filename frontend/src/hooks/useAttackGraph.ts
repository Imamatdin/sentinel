"use client";

import useSWR from "swr";
import { api } from "@/lib/api";
import type { AttackGraph } from "@/lib/types";

export function useAttackGraph(engagementId: string) {
  const { data: graphData, error: graphError, isLoading: graphLoading } = useSWR(
    engagementId ? `/api/engagements/${engagementId}/graph` : null,
    () => api.graph.get(engagementId),
  );

  const { data: chainsData, error: chainsError, isLoading: chainsLoading } = useSWR(
    engagementId ? `/api/engagements/${engagementId}/chains` : null,
    () => api.graph.chains(engagementId),
  );

  const graph: AttackGraph | null = graphData
    ? {
        nodes: graphData.nodes || [],
        edges: graphData.edges || [],
        chains: chainsData || [],
      }
    : null;

  return {
    graph,
    error: graphError || chainsError,
    isLoading: graphLoading || chainsLoading,
  };
}
