import type { EngagementState, EngagementPhase } from '@/lib/types';
import { formatDuration } from '@/lib/types';
import { LiveIndicator } from './LiveIndicator';

interface StatusBarProps {
  state: EngagementState;
  phase: EngagementPhase;
  elapsed: number | null;
  eventCount: number;
}

export function StatusBar({ state, phase, elapsed, eventCount }: StatusBarProps) {
  const isRunning = state === 'running';

  return (
    <div className="panel">
      <div className="panel-body">
        <div className="flex items-center justify-between flex-wrap gap-4">
          {/* State */}
          <div className="flex items-center gap-3">
            <LiveIndicator active={isRunning} size="md" />
            <div>
              <p className="text-sm font-semibold uppercase tracking-wider">
                {state}
              </p>
              {phase && (
                <p className="text-xs text-sentinel-500 font-mono">
                  Phase: {phase}
                </p>
              )}
            </div>
          </div>

          {/* Metrics row */}
          <div className="flex gap-8">
            <Metric label="Elapsed" value={elapsed ? formatDuration(elapsed) : '--'} />
            <Metric label="Events" value={eventCount.toLocaleString()} />
          </div>
        </div>
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="text-right">
      <p className="text-lg font-mono font-semibold">{value}</p>
      <p className="text-xs text-sentinel-500 uppercase tracking-wider">{label}</p>
    </div>
  );
}
