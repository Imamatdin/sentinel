import type { SentinelEvent } from '@/lib/types';
import { classifyEvent, formatEventType, formatTimestamp } from '@/lib/types';

interface EventCardProps {
  event: SentinelEvent;
}

export function EventCard({ event }: EventCardProps) {
  const team = classifyEvent(event.event_type);
  const label = formatEventType(event.event_type);
  const time = formatTimestamp(event.timestamp);

  // Determine badge style based on team
  const badgeClass = {
    red: 'badge-red',
    blue: 'badge-blue',
    system: 'badge-system',
  }[team];

  const teamLabel = {
    red: 'RED',
    blue: 'BLUE',
    system: 'SYS',
  }[team];

  // Extract display content from event data
  const detail = formatEventDetail(event);

  return (
    <div className="px-4 py-2.5 hover:bg-sentinel-800/30 transition-colors">
      <div className="flex items-start gap-3">
        {/* Timestamp */}
        <span className="text-xs font-mono text-sentinel-600 whitespace-nowrap pt-0.5">
          {time}
        </span>

        {/* Team badge */}
        <span className={`badge ${badgeClass} whitespace-nowrap`}>
          {teamLabel}
        </span>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-sentinel-200">
              {label}
            </span>
            <span className="text-xs font-mono text-sentinel-500">
              {event.source}
            </span>
          </div>

          {detail && (
            <p className="text-xs font-mono text-sentinel-400 mt-1 truncate">
              {detail}
            </p>
          )}
        </div>

        {/* Event ID */}
        <span className="text-xs font-mono text-sentinel-700">
          #{event.event_id}
        </span>
      </div>
    </div>
  );
}

function formatEventDetail(event: SentinelEvent): string {
  const d = event.data;

  switch (event.event_type) {
    case 'red.tool_call':
      return `${d.tool}(${formatArgs(d.arguments as Record<string, unknown>)})`;

    case 'red.tool_result':
      if (d.error) return `ERROR: ${d.error}`;
      return `${d.tool} completed in ${d.execution_time}s`;

    case 'red.finding':
      return (d.findings as Record<string, unknown>)?.summary
        ? String((d.findings as Record<string, unknown>).summary).slice(0, 120)
        : String(d.phase || '');

    case 'blue.alert':
      return String(d.analysis || '').slice(0, 120);

    case 'blue.waf_rule':
      return String(d.summary || '').slice(0, 120);

    case 'blue.defense_action':
      return `${d.tool} ${d.success ? 'OK' : 'FAILED'}`;

    case 'orchestrator.phase_transition':
      return `Phase: ${d.phase}`;

    case 'agent.start':
      return `${d.agent} starting`;

    case 'agent.error':
      return `${d.agent}: ${d.error}`;

    default:
      return '';
  }
}

function formatArgs(args: Record<string, unknown> | undefined): string {
  if (!args) return '';
  const entries = Object.entries(args);
  if (entries.length === 0) return '';

  return entries
    .slice(0, 3)
    .map(([k, v]) => {
      const val = String(v);
      return `${k}=${val.length > 40 ? val.slice(0, 40) + '...' : val}`;
    })
    .join(', ');
}
