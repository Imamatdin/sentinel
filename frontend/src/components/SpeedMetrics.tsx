import type { SentinelEvent, SpeedStats } from '@/lib/types';
import { LiveIndicator } from './LiveIndicator';

interface SpeedMetricsProps {
  events: SentinelEvent[];
  speedStats: Partial<SpeedStats>;
  isLive: boolean;
}

export function SpeedMetrics({ events, speedStats, isLive }: SpeedMetricsProps) {
  // Count events by team
  const redEvents = events.filter((e) => e.event_type.startsWith('red.')).length;
  const blueEvents = events.filter((e) => e.event_type.startsWith('blue.')).length;

  return (
    <div className="panel">
      <div className="panel-header flex items-center gap-2">
        <span>Speed Metrics</span>
        {isLive && <LiveIndicator active={true} />}
      </div>
      <div className="panel-body space-y-3">
        <MetricRow
          label="Tokens/sec"
          value={speedStats.avg_tokens_per_second?.toLocaleString() || '--'}
          highlight
        />
        <MetricRow
          label="Total Tokens"
          value={speedStats.total_tokens?.toLocaleString() || '--'}
        />
        <MetricRow
          label="Tool Calls"
          value={speedStats.total_tool_calls?.toLocaleString() || '--'}
        />
        <MetricRow
          label="LLM Time"
          value={
            speedStats.total_llm_time_seconds
              ? `${speedStats.total_llm_time_seconds.toFixed(1)}s`
              : '--'
          }
        />
        {speedStats.attack_to_first_defense_seconds != null && (
          <MetricRow
            label="Attack to Defense"
            value={`${speedStats.attack_to_first_defense_seconds.toFixed(1)}s`}
            highlight
          />
        )}

        {/* Event breakdown */}
        <div className="border-t border-sentinel-800 pt-3 mt-3">
          <p className="text-xs text-sentinel-500 uppercase tracking-wider mb-2">
            Event Breakdown
          </p>
          <div className="grid grid-cols-2 gap-2">
            <div className="text-center">
              <p className="text-lg font-mono font-semibold">{redEvents}</p>
              <p className="text-xs text-sentinel-500">Red Team</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-mono font-semibold">{blueEvents}</p>
              <p className="text-xs text-sentinel-500">Blue Team</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricRow({
  label,
  value,
  highlight = false,
}: {
  label: string;
  value: string;
  highlight?: boolean;
}) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-sentinel-500 font-mono uppercase">{label}</span>
      <span
        className={`font-mono font-semibold ${
          highlight ? 'text-lg text-sentinel-100' : 'text-sm text-sentinel-300'
        }`}
      >
        {value}
      </span>
    </div>
  );
}
