"use client";

interface RemediationItem {
  finding_id: string;
  category: string;
  target_url: string;
  status: "open" | "fix_pending" | "fix_verified" | "wont_fix";
}

interface Props {
  items: RemediationItem[];
}

const STATUS_STYLES: Record<string, string> = {
  open: "bg-red-900 text-red-300",
  fix_pending: "bg-yellow-900 text-yellow-300",
  fix_verified: "bg-green-900 text-green-300",
  wont_fix: "bg-sentinel-surface text-sentinel-muted",
};

export default function RemediationTracker({ items }: Props) {
  const fixRate = items.length
    ? items.filter((i) => i.status === "fix_verified").length / items.length
    : 0;

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-mono text-sentinel-muted uppercase">Remediation Progress</h3>
        <span className="text-sm font-mono text-sentinel-bright">
          {(fixRate * 100).toFixed(0)}% Fixed
        </span>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-sentinel-bg rounded-full h-2 mb-4">
        <div
          className="h-2 rounded-full bg-severity-low transition-all"
          style={{ width: `${fixRate * 100}%` }}
        />
      </div>

      <div className="space-y-1">
        {items.map((item) => (
          <div
            key={item.finding_id}
            className="flex items-center gap-3 px-3 py-2 bg-sentinel-surface rounded text-xs font-mono"
          >
            <span className={`px-2 py-0.5 rounded ${STATUS_STYLES[item.status]}`}>
              {item.status.replace("_", " ")}
            </span>
            <span className="text-sentinel-text">{item.category}</span>
            <span className="text-sentinel-muted truncate flex-1">{item.target_url}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
