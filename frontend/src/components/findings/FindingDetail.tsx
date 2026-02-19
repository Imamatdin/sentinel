"use client";

import type { Finding } from "@/lib/types";
import SeverityBadge from "@/components/shared/SeverityBadge";
import CodeBlock from "@/components/shared/CodeBlock";
import MITREBadge from "@/components/findings/MITREBadge";
import EvidenceViewer from "@/components/findings/EvidenceViewer";
import PoCViewer from "@/components/findings/PoCViewer";
import RemediationStatus from "@/components/findings/RemediationStatus";

interface Props {
  finding: Finding;
  onRetest?: () => void;
}

export default function FindingDetail({ finding, onRetest }: Props) {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <SeverityBadge severity={finding.severity} />
        <h2 className="text-lg font-mono text-sentinel-bright">
          {finding.category.toUpperCase()}
        </h2>
        <MITREBadge technique={finding.mitre_technique} />
      </div>

      {/* Target */}
      <div className="panel p-4 space-y-2 text-xs font-mono">
        <div className="flex gap-2">
          <span className="text-sentinel-muted w-20">Target:</span>
          <span className="text-sentinel-text">{finding.target_url}</span>
        </div>
        {finding.target_param && (
          <div className="flex gap-2">
            <span className="text-sentinel-muted w-20">Param:</span>
            <span className="text-sentinel-text">{finding.target_param}</span>
          </div>
        )}
        <div className="flex gap-2">
          <span className="text-sentinel-muted w-20">Confidence:</span>
          <span className="text-sentinel-text">{finding.confidence}</span>
        </div>
        <div className="flex gap-2">
          <span className="text-sentinel-muted w-20">Verified:</span>
          <span className={finding.verified ? "text-green-400" : "text-sentinel-muted"}>
            {finding.verified ? "Yes" : "No"}
          </span>
        </div>
      </div>

      {/* Evidence */}
      {finding.evidence && (
        <div>
          <h3 className="text-sm font-mono text-sentinel-muted uppercase mb-2">Evidence</h3>
          <CodeBlock code={finding.evidence} title="Evidence" />
        </div>
      )}

      {/* HTTP Traces */}
      {finding.http_traces && finding.http_traces.length > 0 && (
        <EvidenceViewer traces={finding.http_traces} />
      )}

      {/* PoC Script */}
      {finding.poc_script && <PoCViewer script={finding.poc_script} commands={finding.replay_commands} />}

      {/* Remediation */}
      <div>
        <h3 className="text-sm font-mono text-sentinel-muted uppercase mb-2">Remediation</h3>
        <div className="panel p-4 text-sm font-mono text-sentinel-text">
          {finding.remediation}
        </div>
      </div>

      {/* Remediation Status */}
      <RemediationStatus status={finding.remediation_status} onRetest={onRetest} />

      {/* Exposure Score */}
      {finding.exposure_score && (
        <div>
          <h3 className="text-sm font-mono text-sentinel-muted uppercase mb-2">Exposure Score</h3>
          <div className="panel p-4 grid grid-cols-3 gap-4 text-xs font-mono">
            <div>
              <div className="text-sentinel-muted">Score</div>
              <div className="text-xl text-sentinel-bright">
                {(finding.exposure_score.score * 100).toFixed(0)}
              </div>
            </div>
            <div>
              <div className="text-sentinel-muted">Rating</div>
              <div className="text-sentinel-text">{finding.exposure_score.rating}</div>
            </div>
            <div>
              <div className="text-sentinel-muted">Chain Depth</div>
              <div className="text-sentinel-text">{finding.exposure_score.chain_depth}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
