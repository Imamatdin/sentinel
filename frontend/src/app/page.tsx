"use client";

import Link from "next/link";
import { useEngagements } from "@/hooks/useEngagement";
import { useLiveFeed } from "@/hooks/useLiveFeed";
import EngagementCard from "@/components/dashboard/EngagementCard";
import LiveFeed from "@/components/dashboard/LiveFeed";
import EmptyState from "@/components/shared/EmptyState";
import LoadingSpinner from "@/components/shared/LoadingSpinner";

export default function DashboardHome() {
  const { engagements, isLoading } = useEngagements();
  const { events, connected } = useLiveFeed();

  const activeEngagements = engagements.filter(
    (e) => !["complete", "failed"].includes(e.status)
  );
  const recentEngagements = engagements
    .filter((e) => ["complete", "failed"].includes(e.status))
    .slice(0, 6);

  return (
    <div className="p-6 space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-mono text-sentinel-bright">Dashboard</h1>
          <p className="text-xs font-mono text-sentinel-muted mt-1">
            {connected ? "Connected" : "Disconnected"} | {engagements.length} engagements
          </p>
        </div>
        <Link href="/engagements/new" className="btn-primary">
          New Engagement
        </Link>
      </div>

      {isLoading ? (
        <LoadingSpinner />
      ) : (
        <>
          {/* Active engagements */}
          {activeEngagements.length > 0 && (
            <section>
              <h2 className="text-sm font-mono text-sentinel-muted uppercase tracking-wider mb-3">
                Active
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {activeEngagements.map((eng) => (
                  <EngagementCard key={eng.id} engagement={eng} />
                ))}
              </div>
            </section>
          )}

          {/* Live feed */}
          <section className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <LiveFeed events={events} />
            </div>
            <div className="space-y-4">
              <div className="panel">
                <div className="panel-header">Quick Stats</div>
                <div className="p-4 grid grid-cols-2 gap-3">
                  <StatBox label="Total" value={String(engagements.length)} />
                  <StatBox label="Active" value={String(activeEngagements.length)} />
                  <StatBox
                    label="Findings"
                    value={String(
                      engagements.reduce(
                        (sum, e) => sum + (e.summary?.findings_count || 0),
                        0
                      )
                    )}
                  />
                  <StatBox
                    label="Critical"
                    value={String(
                      engagements.reduce(
                        (sum, e) => sum + (e.summary?.critical || 0),
                        0
                      )
                    )}
                  />
                </div>
              </div>
            </div>
          </section>

          {/* Recent engagements */}
          {recentEngagements.length > 0 && (
            <section>
              <h2 className="text-sm font-mono text-sentinel-muted uppercase tracking-wider mb-3">
                Recent
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {recentEngagements.map((eng) => (
                  <EngagementCard key={eng.id} engagement={eng} />
                ))}
              </div>
            </section>
          )}

          {engagements.length === 0 && (
            <EmptyState
              title="No Engagements"
              description="Create your first engagement to start pentesting."
              action={
                <Link href="/engagements/new" className="btn-primary">
                  New Engagement
                </Link>
              }
            />
          )}
        </>
      )}
    </div>
  );
}

function StatBox({ label, value }: { label: string; value: string }) {
  return (
    <div className="text-center">
      <div className="text-xl font-mono text-sentinel-bright">{value}</div>
      <div className="text-[10px] font-mono text-sentinel-muted uppercase">{label}</div>
    </div>
  );
}
