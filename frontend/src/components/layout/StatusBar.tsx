"use client";

interface Props {
  connected?: boolean;
  activeEngagement?: string;
  eventCount?: number;
}

export default function StatusBar({ connected = false, activeEngagement, eventCount = 0 }: Props) {
  return (
    <footer className="h-6 bg-sentinel-surface border-t border-sentinel-border flex items-center justify-between px-4 text-[10px] font-mono text-sentinel-muted">
      <div className="flex items-center gap-4">
        <span>
          WS: {connected ? "OK" : "DISCONNECTED"}
        </span>
        {activeEngagement && (
          <span>ENG: {activeEngagement}</span>
        )}
      </div>
      <div className="flex items-center gap-4">
        <span>Events: {eventCount}</span>
        <span>SENTINEL v0.1.0</span>
      </div>
    </footer>
  );
}
