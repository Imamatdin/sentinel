"use client";

import { useEffect, useState } from "react";

function getTimeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffMs = now - then;
  const diffSec = Math.floor(diffMs / 1000);

  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}

export default function TimeAgo({ date }: { date: string }) {
  const [text, setText] = useState(getTimeAgo(date));

  useEffect(() => {
    const interval = setInterval(() => setText(getTimeAgo(date)), 30000);
    return () => clearInterval(interval);
  }, [date]);

  return (
    <span className="text-xs font-mono text-sentinel-muted" title={date}>
      {text}
    </span>
  );
}
