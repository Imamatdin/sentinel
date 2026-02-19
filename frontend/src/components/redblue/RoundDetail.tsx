"use client";

import type { RedBlueRound } from "@/lib/types";

interface Props {
  round: RedBlueRound;
}

export default function RoundDetail({ round }: Props) {
  return (
    <div className="panel p-4 space-y-3 text-xs font-mono">
      <div className="flex items-center justify-between">
        <span className="text-sentinel-bright">Round #{round.round_number}</span>
        <span
          className={
            round.red_success ? "text-severity-critical" : "text-severity-low"
          }
        >
          {round.red_success ? "RED SUCCESS" : "BLUE WIN"}
        </span>
      </div>

      <div className="space-y-1">
        <div>
          <span className="text-sentinel-muted">Red Action: </span>
          <span className="text-red-400">{round.red_action}</span>
        </div>
        <div>
          <span className="text-sentinel-muted">Blue Detected: </span>
          <span className={round.blue_detected ? "text-green-400" : "text-red-400"}>
            {round.blue_detected ? "Yes" : "No"}
          </span>
        </div>
        <div>
          <span className="text-sentinel-muted">Blue Response: </span>
          <span className="text-sentinel-text">{round.blue_response}</span>
        </div>
        <div>
          <span className="text-sentinel-muted">Detection Latency: </span>
          <span className="text-sentinel-text">
            {round.detection_latency_ms.toFixed(2)}ms
          </span>
        </div>
      </div>

      {round.red_adaptation && (
        <div className="text-yellow-400 border-t border-sentinel-border pt-2">
          Adaptation: {round.red_adaptation}
        </div>
      )}
    </div>
  );
}
