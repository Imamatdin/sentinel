"use client";

import { useMemo } from "react";
import { useWebSocket } from "./useWebSocket";
import type { WSEvent, WSEventType } from "@/lib/types";

export function useLiveFeed(engagementId?: string, filterTypes?: WSEventType[]) {
  const { events, connected, clearEvents } = useWebSocket(engagementId);

  const filteredEvents = useMemo(() => {
    if (!filterTypes || filterTypes.length === 0) return events;
    return events.filter((e) => filterTypes.includes(e.type));
  }, [events, filterTypes]);

  const latestByType = useMemo(() => {
    const map: Record<string, WSEvent> = {};
    for (const event of events) {
      if (!map[event.type]) {
        map[event.type] = event;
      }
    }
    return map;
  }, [events]);

  return {
    events: filteredEvents,
    allEvents: events,
    connected,
    clearEvents,
    latestByType,
    eventCount: events.length,
  };
}
