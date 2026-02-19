"use client";

import { useState } from "react";

interface Props {
  code: string;
  language?: string;
  title?: string;
}

export default function CodeBlock({ code, language, title }: Props) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-sentinel-bg border border-sentinel-border rounded overflow-hidden">
      {(title || language) && (
        <div className="flex items-center justify-between px-3 py-1.5 border-b border-sentinel-border">
          <span className="text-xs font-mono text-sentinel-muted">
            {title || language}
          </span>
          <button
            onClick={handleCopy}
            className="text-xs font-mono text-sentinel-muted hover:text-sentinel-text transition-colors"
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      )}
      <pre className="p-3 overflow-x-auto">
        <code className="text-xs font-mono text-sentinel-text leading-relaxed">
          {code}
        </code>
      </pre>
    </div>
  );
}
