"use client";

import useSWR from "swr";
import { api } from "@/lib/api";
import LoadingSpinner from "@/components/shared/LoadingSpinner";
import EmptyState from "@/components/shared/EmptyState";
import type { GenomeStats } from "@/lib/types";

export default function GenomePage() {
  const { data: stats, isLoading } = useSWR<GenomeStats>(
    "/api/genome/stats",
    () => api.genome.stats(),
    { refreshInterval: 10000 }
  );

  if (isLoading) return <LoadingSpinner />;
  if (!stats) return <EmptyState title="No Genome Data" description="Complete engagements to build the pattern database." />;

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-lg font-mono text-sentinel-bright">Genome Dashboard</h1>

      {/* Stats grid */}
      <div className="grid grid-cols-4 gap-4">
        <div className="panel p-4">
          <div className="text-xs text-sentinel-muted font-mono uppercase">Total Patterns</div>
          <div className="text-2xl font-mono text-sentinel-bright mt-1">{stats.total_patterns}</div>
        </div>
        <div className="panel p-4">
          <div className="text-xs text-sentinel-muted font-mono uppercase">Avg Confidence</div>
          <div className="text-2xl font-mono text-sentinel-bright mt-1">
            {(stats.avg_confidence * 100).toFixed(1)}%
          </div>
        </div>
        <div className="panel p-4">
          <div className="text-xs text-sentinel-muted font-mono uppercase">Categories</div>
          <div className="text-2xl font-mono text-sentinel-bright mt-1">
            {Object.keys(stats.by_category).length}
          </div>
        </div>
        <div className="panel p-4">
          <div className="text-xs text-sentinel-muted font-mono uppercase">Learning Rate</div>
          <div className="text-2xl font-mono text-sentinel-bright mt-1">
            {stats.learning_rate.toFixed(1)}/eng
          </div>
        </div>
      </div>

      {/* Category breakdown */}
      <div className="panel">
        <div className="panel-header">Patterns by Category</div>
        <div className="p-4 space-y-2">
          {Object.entries(stats.by_category)
            .sort(([, a], [, b]) => b - a)
            .map(([category, count]) => (
              <div key={category} className="flex items-center gap-3 text-xs font-mono">
                <span className="text-sentinel-text w-40">{category}</span>
                <div className="flex-1 bg-sentinel-bg rounded-full h-2">
                  <div
                    className="h-2 rounded-full bg-sentinel-muted"
                    style={{
                      width: `${(count / stats.total_patterns) * 100}%`,
                    }}
                  />
                </div>
                <span className="text-sentinel-muted w-8 text-right">{count}</span>
              </div>
            ))}
        </div>
      </div>

      {/* Top techniques */}
      {stats.top_techniques.length > 0 && (
        <div className="panel">
          <div className="panel-header">Top Techniques</div>
          <div className="p-4 space-y-2">
            {stats.top_techniques.map((tech) => (
              <div
                key={tech.category}
                className="flex items-center gap-3 text-xs font-mono"
              >
                <span className="text-sentinel-text flex-1">{tech.category}</span>
                <span className="text-sentinel-muted">
                  {(tech.success_rate * 100).toFixed(0)}% success
                </span>
                <span className="text-sentinel-muted">{tech.count} uses</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
