"use client";

import { useState } from "react";
import { useFindings } from "@/hooks/useFindings";
import FindingCard from "@/components/findings/FindingCard";
import LoadingSpinner from "@/components/shared/LoadingSpinner";
import EmptyState from "@/components/shared/EmptyState";
import type { Severity } from "@/lib/types";

export default function FindingsPage() {
  const { findings, isLoading } = useFindings();
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");

  const filtered =
    severityFilter === "all"
      ? findings
      : findings.filter((f) => f.severity === severityFilter);

  if (isLoading) return <LoadingSpinner />;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-mono text-sentinel-bright">All Findings</h1>
        <div className="flex gap-1">
          {(["all", "critical", "high", "medium", "low"] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1 text-xs font-mono rounded border ${
                severityFilter === sev
                  ? "bg-sentinel-border text-sentinel-bright border-sentinel-muted"
                  : "border-sentinel-border text-sentinel-muted hover:text-sentinel-text"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState title="No Findings" description="No vulnerabilities match the current filter." />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}
