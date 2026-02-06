import { LiveIndicator } from './LiveIndicator';

interface HeaderProps {
  connected: boolean;
}

export function Header({ connected }: HeaderProps) {
  return (
    <header className="border-b border-sentinel-800 bg-sentinel-950/80 backdrop-blur-sm sticky top-0 z-50">
      <div className="max-w-[1600px] mx-auto px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold tracking-tight">
            SENTINEL
          </h1>
          <span className="text-sentinel-600 text-xs font-mono hidden sm:inline">
            Autonomous AI Pentesting
          </span>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-sentinel-500">
          <LiveIndicator active={connected} />
          <span>{connected ? 'Connected' : 'Disconnected'}</span>
        </div>
      </div>
    </header>
  );
}
