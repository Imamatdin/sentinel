"use client";

import type { EngagementStatus } from "@/lib/types";
import { PHASE_LABELS } from "@/lib/constants";

interface Props {
  currentPhase: EngagementStatus;
}

const PHASES: EngagementStatus[] = [
  "initialized",
  "recon",
  "vuln_analysis",
  "exploitation",
  "reporting",
  "complete",
];

export default function PhaseProgress({ currentPhase }: Props) {
  const currentIndex = PHASES.indexOf(currentPhase);

  return (
    <div className="panel">
      <div className="panel-header">Phase Progress</div>
      <div className="p-4">
        <div className="flex items-center gap-1">
          {PHASES.map((phase, i) => {
            const isComplete = i < currentIndex;
            const isCurrent = i === currentIndex;
            const isFailed = currentPhase === "failed";

            return (
              <div key={phase} className="flex-1 flex flex-col items-center gap-1">
                <div
                  className={`w-full h-1.5 rounded-full ${
                    isComplete
                      ? "bg-severity-low"
                      : isCurrent
                      ? isFailed
                        ? "bg-severity-critical"
                        : "bg-severity-medium"
                      : "bg-sentinel-border"
                  }`}
                />
                <span className="text-[9px] font-mono text-sentinel-muted text-center">
                  {PHASE_LABELS[phase] || phase}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
