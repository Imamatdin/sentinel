"use client";

import { useParams } from "next/navigation";
import { useFinding } from "@/hooks/useFindings";
import { api } from "@/lib/api";
import FindingDetail from "@/components/findings/FindingDetail";
import LoadingSpinner from "@/components/shared/LoadingSpinner";

export default function FindingDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const { finding, isLoading, refresh } = useFinding(id);

  const handleRetest = async () => {
    await api.findings.retest(id);
    refresh();
  };

  if (isLoading) return <LoadingSpinner />;
  if (!finding) {
    return (
      <div className="p-6 text-sentinel-muted font-mono">Finding not found</div>
    );
  }

  return (
    <div className="p-6 max-w-4xl">
      <FindingDetail finding={finding} onRetest={handleRetest} />
    </div>
  );
}
