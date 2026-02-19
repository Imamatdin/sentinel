"use client";

import { useState } from "react";

interface Props {
  data: unknown;
  defaultExpanded?: boolean;
}

export default function JsonViewer({ data, defaultExpanded = false }: Props) {
  const [expanded, setExpanded] = useState(defaultExpanded);

  const json = typeof data === "string" ? data : JSON.stringify(data, null, 2);

  return (
    <div className="bg-sentinel-bg border border-sentinel-border rounded">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-3 py-2 text-left text-xs font-mono text-sentinel-muted hover:text-sentinel-text flex items-center gap-2"
      >
        <span>{expanded ? "[-]" : "[+]"}</span>
        <span>JSON ({typeof data === "object" && data ? Object.keys(data as object).length : 0} keys)</span>
      </button>
      {expanded && (
        <pre className="px-3 pb-3 overflow-x-auto">
          <code className="text-xs font-mono text-sentinel-text">{json}</code>
        </pre>
      )}
    </div>
  );
}
