import { NODE_COLORS, NODE_SIZES } from "@/lib/constants";

const NODE_TYPES = [
  { type: "host", label: "Host" },
  { type: "service", label: "Service" },
  { type: "endpoint", label: "Endpoint" },
  { type: "vulnerability", label: "Vulnerability" },
  { type: "finding", label: "Finding" },
  { type: "credential", label: "Credential" },
];

export default function GraphLegend() {
  return (
    <div className="panel">
      <div className="panel-header">Legend</div>
      <div className="p-3 space-y-2">
        {NODE_TYPES.map(({ type, label }) => (
          <div key={type} className="flex items-center gap-2 text-xs font-mono">
            <svg width="16" height="16">
              <circle
                cx="8"
                cy="8"
                r={Math.min(NODE_SIZES[type] || 8, 7)}
                fill={NODE_COLORS[type] || "#808080"}
              />
            </svg>
            <span className="text-sentinel-text">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
