"use client";

interface Props {
  connected?: boolean;
}

export default function Header({ connected = false }: Props) {
  return (
    <header className="h-10 bg-sentinel-surface border-b border-sentinel-border flex items-center justify-between px-4">
      <div className="text-xs font-mono text-sentinel-muted">
        Autonomous AI Pentesting Platform
      </div>
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5">
          <div
            className={`w-1.5 h-1.5 rounded-full ${
              connected ? "bg-severity-low" : "bg-severity-critical"
            }`}
          />
          <span className="text-[10px] font-mono text-sentinel-muted">
            {connected ? "Connected" : "Disconnected"}
          </span>
        </div>
      </div>
    </header>
  );
}
