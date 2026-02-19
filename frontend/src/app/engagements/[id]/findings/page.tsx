"use client";

import { useParams } from "next/navigation";
import Link from "next/link";
import { useFindings } from "@/hooks/useFindings";
import SeverityBadge from "@/components/shared/SeverityBadge";
import LoadingSpinner from "@/components/shared/LoadingSpinner";
import EmptyState from "@/components/shared/EmptyState";

export default function EngagementFindingsPage() {
  const params = useParams();
  const id = params.id as string;
  const { findings, isLoading } = useFindings(id);

  if (isLoading) return <LoadingSpinner />;

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-lg font-mono text-sentinel-bright">Findings</h1>

      {findings.length === 0 ? (
        <EmptyState title="No Findings" description="No vulnerabilities discovered yet." />
      ) : (
        <div className="space-y-2">
          {findings.map((finding) => (
            <Link
              key={finding.id}
              href={`/findings/${finding.id}`}
              className="panel block hover:border-sentinel-muted transition-colors"
            >
              <div className="p-4 flex items-center gap-4">
                <SeverityBadge severity={finding.severity} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-mono text-sentinel-bright">
                    {finding.category.toUpperCase()}
                  </div>
                  <div className="text-xs font-mono text-sentinel-muted truncate">
                    {finding.target_url}
                    {finding.target_param && ` [${finding.target_param}]`}
                  </div>
                </div>
                <div className="text-xs font-mono text-sentinel-muted">
                  {finding.mitre_technique}
                </div>
                <div
                  className={`text-xs px-2 py-0.5 rounded font-mono ${
                    finding.verified
                      ? "bg-green-900 text-green-300"
                      : "bg-sentinel-bg text-sentinel-muted"
                  }`}
                >
                  {finding.verified ? "Verified" : "Unverified"}
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
