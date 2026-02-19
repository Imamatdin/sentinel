"use client";

import Link from "next/link";
import type { Engagement } from "@/lib/types";
import { PHASE_LABELS } from "@/lib/constants";
import SeverityBadge from "@/components/shared/SeverityBadge";
import TimeAgo from "@/components/shared/TimeAgo";

interface Props {
  engagement: Engagement;
}

export default function EngagementCard({ engagement }: Props) {
  const summary = engagement.summary;

  return (
    <Link href={`/engagements/${engagement.id}`}>
      <div className="panel hover:border-sentinel-muted transition-colors cursor-pointer">
        <div className="p-4 space-y-3">
          {/* Header */}
          <div className="flex items-center justify-between">
            <span className="text-sm font-mono text-sentinel-bright truncate max-w-[200px]">
              {engagement.target}
            </span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted">
              {PHASE_LABELS[engagement.status] || engagement.status}
            </span>
          </div>

          {/* Summary stats */}
          {summary && (
            <div className="grid grid-cols-4 gap-2 text-center">
              {summary.critical > 0 && (
                <div>
                  <SeverityBadge severity="critical" />
                  <div className="text-xs font-mono mt-1">{summary.critical}</div>
                </div>
              )}
              {summary.high > 0 && (
                <div>
                  <SeverityBadge severity="high" />
                  <div className="text-xs font-mono mt-1">{summary.high}</div>
                </div>
              )}
              {summary.medium > 0 && (
                <div>
                  <SeverityBadge severity="medium" />
                  <div className="text-xs font-mono mt-1">{summary.medium}</div>
                </div>
              )}
              {summary.low > 0 && (
                <div>
                  <SeverityBadge severity="low" />
                  <div className="text-xs font-mono mt-1">{summary.low}</div>
                </div>
              )}
            </div>
          )}

          {/* Footer */}
          <div className="flex items-center justify-between text-xs text-sentinel-muted font-mono">
            <span>{summary ? `${summary.findings_count} findings` : "No data"}</span>
            <TimeAgo date={engagement.updated_at} />
          </div>
        </div>
      </div>
    </Link>
  );
}
