"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import useSWR from "swr";
import { api } from "@/lib/api";
import RedBlueTimeline from "@/components/redblue/RedBlueTimeline";
import SpeedComparison from "@/components/redblue/SpeedComparison";
import LoadingSpinner from "@/components/shared/LoadingSpinner";
import EmptyState from "@/components/shared/EmptyState";
import type { RedBlueMetrics } from "@/lib/types";

export default function RedBluePage() {
  const params = useParams();
  const id = params.id as string;
  const [starting, setStarting] = useState(false);

  const { data: metrics, error, mutate } = useSWR<RedBlueMetrics>(
    `/api/engagements/${id}/redblue/metrics`,
    () => api.redblue.metrics(id),
    { refreshInterval: 2000 }
  );

  const handleStart = async () => {
    setStarting(true);
    try {
      await api.redblue.start(id);
      mutate();
    } catch {
      // Error handled by SWR
    } finally {
      setStarting(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-mono text-sentinel-bright">Red vs Blue</h1>
        <button onClick={handleStart} disabled={starting} className="btn-primary">
          {starting ? "Starting..." : "Run Adversarial Loop"}
        </button>
      </div>

      {!metrics || metrics.total_rounds === 0 ? (
        <EmptyState
          title="No Data"
          description="Start the adversarial loop to see red vs blue metrics."
        />
      ) : (
        <div className="space-y-6">
          <RedBlueTimeline metrics={metrics} />
          <SpeedComparison metrics={metrics} />
        </div>
      )}
    </div>
  );
}
