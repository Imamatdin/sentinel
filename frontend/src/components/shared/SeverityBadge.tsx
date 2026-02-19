import { Severity } from "@/lib/types";

const COLORS: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-green-600 text-white",
  info: "bg-gray-600 text-white",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono uppercase ${COLORS[severity]}`}>
      {severity}
    </span>
  );
}
