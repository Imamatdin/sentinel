"use client";

import { useState } from "react";
import type { HTTPTrace } from "@/lib/types";

interface Props {
  traces: HTTPTrace[];
}

export default function EvidenceViewer({ traces }: Props) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const trace = traces[selectedIndex];

  if (!trace) return null;

  return (
    <div>
      <h3 className="text-sm font-mono text-sentinel-muted uppercase mb-2">HTTP Traces</h3>
      <div className="panel">
        {/* Trace selector */}
        {traces.length > 1 && (
          <div className="flex gap-1 px-3 pt-3">
            {traces.map((_, i) => (
              <button
                key={i}
                onClick={() => setSelectedIndex(i)}
                className={`px-2 py-0.5 text-xs font-mono rounded ${
                  i === selectedIndex
                    ? "bg-sentinel-border text-sentinel-bright"
                    : "text-sentinel-muted hover:text-sentinel-text"
                }`}
              >
                #{i + 1}
              </button>
            ))}
          </div>
        )}

        <div className="p-3 space-y-3 text-xs font-mono">
          {/* Request line */}
          <div className="text-sentinel-bright">
            {trace.method} {trace.url} HTTP/1.1
          </div>

          {/* Headers */}
          <div className="space-y-0.5">
            {Object.entries(trace.headers).map(([key, value]) => (
              <div key={key}>
                <span className="text-sentinel-muted">{key}: </span>
                <span className="text-sentinel-text">{value}</span>
              </div>
            ))}
          </div>

          {/* Body */}
          {trace.body && (
            <pre className="bg-sentinel-bg p-2 rounded overflow-x-auto text-sentinel-text">
              {trace.body}
            </pre>
          )}

          {/* Response */}
          <div className="border-t border-sentinel-border pt-2">
            <span className="text-sentinel-muted">Status: </span>
            <span
              className={
                trace.status >= 400 ? "text-severity-high" : "text-severity-low"
              }
            >
              {trace.status}
            </span>
            <span className="text-sentinel-muted ml-4">
              {trace.elapsed.toFixed(0)}ms
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
