"use client";

import CodeBlock from "@/components/shared/CodeBlock";

interface Props {
  script: string;
  commands?: string[];
}

export default function PoCViewer({ script, commands }: Props) {
  return (
    <div>
      <h3 className="text-sm font-mono text-sentinel-muted uppercase mb-2">
        Proof of Concept
      </h3>

      <CodeBlock code={script} language="python" title="PoC Script" />

      {commands && commands.length > 0 && (
        <div className="mt-3">
          <div className="text-xs font-mono text-sentinel-muted mb-1">Replay Commands</div>
          {commands.map((cmd, i) => (
            <CodeBlock key={i} code={cmd} language="bash" />
          ))}
        </div>
      )}
    </div>
  );
}
