"use client";

import type { RedBlueMetrics } from "@/lib/types";

interface Props {
  metrics: RedBlueMetrics;
}

export default function SpeedComparison({ metrics }: Props) {
  // Simulated comparison: actual detection latency vs hypothetical 200ms inference
  const fastLatency = metrics.avg_detection_latency_ms + 1; // +1ms Cerebras inference
  const slowLatency = metrics.avg_detection_latency_ms + 200; // +200ms traditional
  const speedup = slowLatency / Math.max(fastLatency, 0.001);

  return (
    <div className="panel">
      <div className="panel-header">Speed Comparison: Cerebras vs Traditional</div>
      <div className="p-4">
        <div className="grid grid-cols-2 gap-6">
          {/* Fast */}
          <div className="space-y-2">
            <div className="text-xs font-mono text-sentinel-muted uppercase">
              Cerebras (~1ms inference)
            </div>
            <div className="text-3xl font-mono text-severity-low">
              {fastLatency.toFixed(1)}ms
            </div>
            <div className="text-xs font-mono text-sentinel-muted">
              Effective response time
            </div>
          </div>

          {/* Slow */}
          <div className="space-y-2">
            <div className="text-xs font-mono text-sentinel-muted uppercase">
              Traditional (~200ms inference)
            </div>
            <div className="text-3xl font-mono text-severity-high">
              {slowLatency.toFixed(1)}ms
            </div>
            <div className="text-xs font-mono text-sentinel-muted">
              Effective response time
            </div>
          </div>
        </div>

        <div className="mt-6 pt-4 border-t border-sentinel-border text-center">
          <div className="text-4xl font-mono text-sentinel-bright">
            {speedup.toFixed(0)}x
          </div>
          <div className="text-xs font-mono text-sentinel-muted uppercase mt-1">
            Faster with Cerebras
          </div>
        </div>
      </div>
    </div>
  );
}
