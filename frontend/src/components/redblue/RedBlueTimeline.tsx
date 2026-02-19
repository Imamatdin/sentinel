"use client";

import type { RedBlueMetrics, RedBlueRound } from "@/lib/types";

interface Props {
  metrics: RedBlueMetrics;
}

export default function RedBlueTimeline({ metrics }: Props) {
  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard
          label="Detection Rate"
          value={`${(metrics.coverage_score * 100).toFixed(1)}%`}
          good={metrics.coverage_score > 0.7}
        />
        <MetricCard
          label="Avg Detection"
          value={`${metrics.avg_detection_latency_ms.toFixed(1)}ms`}
          good={metrics.avg_detection_latency_ms < 50}
        />
        <MetricCard
          label="Red Successes"
          value={`${metrics.red_successes}/${metrics.total_rounds}`}
          good={metrics.red_successes < metrics.total_rounds * 0.3}
        />
        <MetricCard
          label="Blue Blocks"
          value={`${metrics.blue_blocks}`}
          good={metrics.blue_blocks > metrics.total_rounds * 0.5}
        />
      </div>

      {/* Timeline */}
      <div className="space-y-1 max-h-[500px] overflow-y-auto">
        {metrics.rounds.map((round) => (
          <RoundRow key={round.round_number} round={round} />
        ))}
      </div>
    </div>
  );
}

function MetricCard({ label, value, good }: { label: string; value: string; good: boolean }) {
  return (
    <div className="bg-sentinel-surface border border-sentinel-border p-4 rounded">
      <div className="text-xs text-sentinel-muted font-mono uppercase">{label}</div>
      <div className={`text-2xl font-mono mt-1 ${good ? "text-severity-low" : "text-severity-high"}`}>
        {value}
      </div>
    </div>
  );
}

function RoundRow({ round }: { round: RedBlueRound }) {
  return (
    <div
      className="flex items-center gap-3 px-3 py-2 bg-sentinel-surface border-l-2 rounded-r text-sm font-mono"
      style={{
        borderLeftColor: round.blue_detected
          ? round.blue_response === "block_ip"
            ? "#00C853"
            : "#FFD700"
          : "#FF0000",
      }}
    >
      <span className="text-sentinel-muted w-8">#{round.round_number}</span>
      <span className="text-red-400 w-40 truncate" title={round.red_action}>
        {round.red_action}
      </span>
      <span className="text-sentinel-muted">-&gt;</span>
      <span className={`w-24 ${round.blue_detected ? "text-green-400" : "text-red-400"}`}>
        {round.blue_detected ? round.blue_response : "missed"}
      </span>
      <span className="text-sentinel-muted text-xs w-20">
        {round.detection_latency_ms.toFixed(1)}ms
      </span>
      {round.red_adaptation && (
        <span className="text-yellow-400 text-xs truncate flex-1" title={round.red_adaptation}>
          {round.red_adaptation}
        </span>
      )}
    </div>
  );
}
