"use client";

interface Props {
  status: "open" | "fix_pending" | "fix_verified" | "wont_fix";
  onRetest?: () => void;
}

const STATUS_STYLES: Record<string, string> = {
  open: "bg-red-900 text-red-300 border-red-800",
  fix_pending: "bg-yellow-900 text-yellow-300 border-yellow-800",
  fix_verified: "bg-green-900 text-green-300 border-green-800",
  wont_fix: "bg-sentinel-surface text-sentinel-muted border-sentinel-border",
};

const STATUS_LABELS: Record<string, string> = {
  open: "Open",
  fix_pending: "Fix Pending",
  fix_verified: "Fix Verified",
  wont_fix: "Won't Fix",
};

export default function RemediationStatus({ status, onRetest }: Props) {
  return (
    <div>
      <h3 className="text-sm font-mono text-sentinel-muted uppercase mb-2">
        Remediation Status
      </h3>
      <div className="flex items-center gap-3">
        <span
          className={`px-3 py-1 text-xs font-mono rounded border ${STATUS_STYLES[status]}`}
        >
          {STATUS_LABELS[status]}
        </span>
        {onRetest && status !== "fix_verified" && (
          <button onClick={onRetest} className="btn-secondary text-xs">
            Retest
          </button>
        )}
      </div>
    </div>
  );
}
