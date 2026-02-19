"use client";

import type { RedBlueMetrics } from "@/lib/types";

interface Props {
  metrics: RedBlueMetrics;
}

export default function DefenseMetrics({ metrics }: Props) {
  return (
    <div className="panel">
      <div className="panel-header">Defense Effectiveness</div>
      <div className="p-4 grid grid-cols-2 gap-4 text-xs font-mono">
        <div>
          <div className="text-sentinel-muted">Coverage</div>
          <div className="text-xl text-sentinel-bright">
            {(metrics.coverage_score * 100).toFixed(1)}%
          </div>
        </div>
        <div>
          <div className="text-sentinel-muted">Avg Response</div>
          <div className="text-xl text-sentinel-bright">
            {metrics.avg_response_latency_ms.toFixed(1)}ms
          </div>
        </div>
        <div>
          <div className="text-sentinel-muted">Detections</div>
          <div className="text-xl text-sentinel-bright">{metrics.blue_detections}</div>
        </div>
        <div>
          <div className="text-sentinel-muted">Blocks</div>
          <div className="text-xl text-sentinel-bright">{metrics.blue_blocks}</div>
        </div>
      </div>
    </div>
  );
}
