"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import useSWR from "swr";
import { api } from "@/lib/api";
import ExecutiveSummary from "@/components/reports/ExecutiveSummary";
import OWASPMapping from "@/components/reports/OWASPMapping";
import LoadingSpinner from "@/components/shared/LoadingSpinner";
import EmptyState from "@/components/shared/EmptyState";
import { useEngagement } from "@/hooks/useEngagement";
import { useFindings } from "@/hooks/useFindings";

export default function ReportPage() {
  const params = useParams();
  const id = params.id as string;
  const { engagement } = useEngagement(id);
  const { findings } = useFindings(id);
  const [generating, setGenerating] = useState(false);

  const { data: owaspData } = useSWR(
    `/api/engagements/${id}/report/owasp`,
    () => api.reports.owasp(id)
  );

  const handleGenerate = async (type: string) => {
    setGenerating(true);
    try {
      await api.reports.generate(id, type);
    } catch {
      // Handled
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = () => {
    window.open(api.reports.download(id), "_blank");
  };

  if (!engagement) return <LoadingSpinner />;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-mono text-sentinel-bright">Report</h1>
        <div className="flex gap-2">
          <button
            onClick={() => handleGenerate("executive")}
            disabled={generating}
            className="btn-secondary"
          >
            Generate Report
          </button>
          <button onClick={handleDownload} className="btn-primary">
            Download PDF
          </button>
        </div>
      </div>

      {engagement.summary ? (
        <div className="space-y-6">
          <ExecutiveSummary
            summary={engagement.summary}
            findings={findings}
            exposureScores={findings
              .filter((f) => f.exposure_score)
              .map((f) => f.exposure_score!)}
          />
          {owaspData && <OWASPMapping mappings={owaspData} />}
        </div>
      ) : (
        <EmptyState
          title="No Report Data"
          description="Complete an engagement to generate reports."
        />
      )}
    </div>
  );
}
