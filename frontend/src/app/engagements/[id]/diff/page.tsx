"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import { api } from "@/lib/api";
import { useEngagements } from "@/hooks/useEngagement";
import DiffView from "@/components/diff/DiffView";
import EmptyState from "@/components/shared/EmptyState";
import type { EngagementDiff } from "@/lib/types";

export default function DiffPage() {
  const params = useParams();
  const currentId = params.id as string;
  const { engagements } = useEngagements();
  const [compareId, setCompareId] = useState("");
  const [diff, setDiff] = useState<EngagementDiff | null>(null);
  const [loading, setLoading] = useState(false);

  const otherEngagements = engagements.filter((e) => e.id !== currentId);

  const handleCompare = async () => {
    if (!compareId) return;
    setLoading(true);
    try {
      const result = await api.engagements.diff(currentId, compareId);
      setDiff(result);
    } catch {
      // Handled
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-lg font-mono text-sentinel-bright">CTEM Diff</h1>

      {/* Comparison selector */}
      <div className="flex items-end gap-3">
        <div className="flex-1">
          <label className="block text-xs font-mono text-sentinel-muted uppercase mb-1">
            Compare with
          </label>
          <select
            value={compareId}
            onChange={(e) => setCompareId(e.target.value)}
            className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm font-mono text-sentinel-text outline-none"
          >
            <option value="">Select engagement...</option>
            {otherEngagements.map((e) => (
              <option key={e.id} value={e.id}>
                {e.target} ({e.status})
              </option>
            ))}
          </select>
        </div>
        <button
          onClick={handleCompare}
          disabled={!compareId || loading}
          className="btn-primary"
        >
          {loading ? "Comparing..." : "Compare"}
        </button>
      </div>

      {diff ? (
        <DiffView diff={diff} />
      ) : (
        <EmptyState
          title="No Comparison"
          description="Select a previous engagement to compare attack paths."
        />
      )}
    </div>
  );
}
