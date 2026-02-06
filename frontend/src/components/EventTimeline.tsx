'use client';

import { useEffect, useRef } from 'react';
import type { SentinelEvent } from '@/lib/types';
import { EventCard } from './EventCard';
import { LiveIndicator } from './LiveIndicator';

interface EventTimelineProps {
  events: SentinelEvent[];
  isLive: boolean;
}

export function EventTimeline({ events, isLive }: EventTimelineProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const autoScrollRef = useRef(true);

  // Auto-scroll to bottom when new events arrive
  useEffect(() => {
    if (autoScrollRef.current && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events.length]);

  // Detect manual scroll to disable auto-scroll
  const handleScroll = () => {
    if (!scrollRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
    autoScrollRef.current = scrollHeight - scrollTop - clientHeight < 100;
  };

  // Show last N events for performance (full list in memory)
  const visibleEvents = events.slice(-200);

  return (
    <div className="panel flex flex-col" style={{ height: '600px' }}>
      <div className="panel-header flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span>Event Timeline</span>
          {isLive && <LiveIndicator active={true} />}
        </div>
        <span className="text-sentinel-600 normal-case tracking-normal">
          {events.length} events
        </span>
      </div>

      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto timeline-scroll"
      >
        {visibleEvents.length === 0 ? (
          <div className="p-8 text-center text-sentinel-600 font-mono text-sm">
            Waiting for events...
          </div>
        ) : (
          <div className="divide-y divide-sentinel-800/50">
            {visibleEvents.map((event) => (
              <EventCard key={event.event_id} event={event} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
