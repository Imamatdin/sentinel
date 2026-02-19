"use client";

import type { Severity } from "@/lib/types";
import { SEVERITY_COLORS } from "@/lib/constants";
import SeverityBadge from "@/components/shared/SeverityBadge";

interface Props {
  counts: Record<Severity, number>;
}

export default function SeverityBreakdown({ counts }: Props) {
  const total = Object.values(counts).reduce((sum, c) => sum + c, 0);

  return (
    <div className="panel">
      <div className="panel-header">Findings by Severity</div>
      <div className="p-4 space-y-3">
        {(["critical", "high", "medium", "low", "info"] as Severity[]).map((sev) => {
          const count = counts[sev] || 0;
          const pct = total > 0 ? (count / total) * 100 : 0;
          return (
            <div key={sev} className="flex items-center gap-3">
              <SeverityBadge severity={sev} />
              <div className="flex-1 bg-sentinel-bg rounded-full h-2">
                <div
                  className="h-2 rounded-full transition-all"
                  style={{
                    width: `${pct}%`,
                    backgroundColor: SEVERITY_COLORS[sev],
                  }}
                />
              </div>
              <span className="text-sm font-mono text-sentinel-text w-8 text-right">
                {count}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
