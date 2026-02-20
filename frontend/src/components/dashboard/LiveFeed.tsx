"use client";

import type { WSEvent } from "@/lib/types";

interface Props {
  events: WSEvent[];
  maxItems?: number;
}

export default function LiveFeed({ events, maxItems = 50 }: Props) {
  // Filter out malformed events (missing timestamp or type)
  const validEvents = events.filter(
    (e) => e.timestamp && e.type && !isNaN(new Date(e.timestamp).getTime())
  );
  const displayEvents = validEvents.slice(0, maxItems);

  return (
    <div className="panel">
      <div className="panel-header flex items-center justify-between">
        <span>Live Feed</span>
        <span className="text-[10px] text-sentinel-muted">{validEvents.length} events</span>
      </div>
      <div className="max-h-[400px] overflow-y-auto timeline-scroll">
        {displayEvents.length === 0 ? (
          <div className="p-4 text-center text-sm text-sentinel-muted font-mono">
            No events yet. Start the engagement to see live activity.
          </div>
        ) : (
          displayEvents.map((event, i) => (
            <div
              key={`${event.timestamp}-${i}`}
              className="px-4 py-2 border-b border-sentinel-border/50 text-xs font-mono flex items-center gap-3"
            >
              <span className="text-sentinel-muted w-16 shrink-0">
                {new Date(event.timestamp).toLocaleTimeString("en-US", { hour12: false })}
              </span>
              <span className="text-sentinel-text truncate">{event.type}</span>
              {event.data?.message != null && (
                <span className="text-sentinel-muted truncate flex-1">
                  {String(event.data.message)}
                </span>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
