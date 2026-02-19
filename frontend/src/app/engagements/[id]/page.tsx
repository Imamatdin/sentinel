"use client";

import { useParams } from "next/navigation";
import Link from "next/link";
import { useEngagement } from "@/hooks/useEngagement";
import { useLiveFeed } from "@/hooks/useLiveFeed";
import { useFindings } from "@/hooks/useFindings";
import { api } from "@/lib/api";
import { PHASE_LABELS } from "@/lib/constants";
import PhaseProgress from "@/components/dashboard/PhaseProgress";
import SeverityBreakdown from "@/components/dashboard/SeverityBreakdown";
import LiveFeed from "@/components/dashboard/LiveFeed";
import LoadingSpinner from "@/components/shared/LoadingSpinner";

export default function EngagementDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const { engagement, isLoading } = useEngagement(id);
  const { events, connected } = useLiveFeed(id);
  const { findings } = useFindings(id);

  if (isLoading) return <LoadingSpinner />;
  if (!engagement) {
    return (
      <div className="p-6 text-sentinel-muted font-mono">Engagement not found</div>
    );
  }

  const isPaused = engagement.status === "paused";
  const isActive = !["complete", "failed"].includes(engagement.status);

  const severityCounts = {
    critical: engagement.summary?.critical || 0,
    high: engagement.summary?.high || 0,
    medium: engagement.summary?.medium || 0,
    low: engagement.summary?.low || 0,
    info: 0,
  };

  const handleApprove = async (approved: boolean) => {
    await api.engagements.approve(id, approved);
  };

  const handleStop = async () => {
    await api.engagements.stop(id);
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-mono text-sentinel-bright">{engagement.target}</h1>
          <p className="text-xs font-mono text-sentinel-muted mt-1">
            {PHASE_LABELS[engagement.status] || engagement.status} | {findings.length} findings
          </p>
        </div>
        <div className="flex gap-2">
          {isPaused && (
            <>
              <button onClick={() => handleApprove(true)} className="btn-primary">
                Approve
              </button>
              <button onClick={() => handleApprove(false)} className="btn-danger">
                Deny
              </button>
            </>
          )}
          {isActive && !isPaused && (
            <button onClick={handleStop} className="btn-danger">
              Stop
            </button>
          )}
        </div>
      </div>

      {/* Navigation tabs */}
      <nav className="flex gap-1 border-b border-sentinel-border pb-px">
        {[
          { href: `/engagements/${id}`, label: "Overview" },
          { href: `/engagements/${id}/findings`, label: "Findings" },
          { href: `/engagements/${id}/graph`, label: "Attack Graph" },
          { href: `/engagements/${id}/redblue`, label: "Red vs Blue" },
          { href: `/engagements/${id}/report`, label: "Report" },
          { href: `/engagements/${id}/diff`, label: "CTEM Diff" },
        ].map((tab) => (
          <Link
            key={tab.href}
            href={tab.href}
            className="px-4 py-2 text-xs font-mono text-sentinel-muted hover:text-sentinel-text border-b-2 border-transparent hover:border-sentinel-muted transition-colors"
          >
            {tab.label}
          </Link>
        ))}
      </nav>

      {/* Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">
          <PhaseProgress currentPhase={engagement.status} />
          <LiveFeed events={events} />
        </div>
        <div className="space-y-4">
          <SeverityBreakdown counts={severityCounts} />
          <div className="panel">
            <div className="panel-header">Summary</div>
            <div className="p-4 space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-sentinel-muted">Hosts</span>
                <span className="text-sentinel-text">{engagement.summary?.hosts_found || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sentinel-muted">Endpoints</span>
                <span className="text-sentinel-text">{engagement.summary?.endpoints_found || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sentinel-muted">Exploited</span>
                <span className="text-sentinel-text">{engagement.summary?.exploited_count || 0}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
