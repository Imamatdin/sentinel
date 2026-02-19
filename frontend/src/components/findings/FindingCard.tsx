import Link from "next/link";
import type { Finding } from "@/lib/types";
import SeverityBadge from "@/components/shared/SeverityBadge";
import MITREBadge from "@/components/findings/MITREBadge";

interface Props {
  finding: Finding;
}

export default function FindingCard({ finding }: Props) {
  return (
    <Link href={`/findings/${finding.id}`}>
      <div className="panel hover:border-sentinel-muted transition-colors cursor-pointer p-4">
        <div className="flex items-center gap-3 mb-2">
          <SeverityBadge severity={finding.severity} />
          <span className="text-sm font-mono text-sentinel-bright flex-1">
            {finding.category.toUpperCase()}
          </span>
          {finding.verified && (
            <span className="text-[10px] px-1.5 py-0.5 bg-green-900 text-green-300 rounded font-mono">
              VERIFIED
            </span>
          )}
        </div>
        <div className="text-xs font-mono text-sentinel-muted truncate">{finding.target_url}</div>
        <div className="flex items-center gap-2 mt-2">
          <MITREBadge technique={finding.mitre_technique} />
          <span className="text-[10px] font-mono text-sentinel-muted">
            {finding.remediation_status.replace("_", " ")}
          </span>
        </div>
      </div>
    </Link>
  );
}
