"use client";

import type { EngagementDiff } from "@/lib/types";
import PathDelta from "./PathDelta";

interface Props {
  diff: EngagementDiff;
}

export default function DiffView({ diff }: Props) {
  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="grid grid-cols-4 gap-4">
        <div className="panel p-4 text-center">
          <div className="text-2xl font-mono text-severity-critical">
            {diff.new_paths.length}
          </div>
          <div className="text-xs font-mono text-sentinel-muted uppercase">New Paths</div>
        </div>
        <div className="panel p-4 text-center">
          <div className="text-2xl font-mono text-severity-low">
            {diff.closed_paths.length}
          </div>
          <div className="text-xs font-mono text-sentinel-muted uppercase">Closed Paths</div>
        </div>
        <div className="panel p-4 text-center">
          <div className="text-2xl font-mono text-sentinel-text">
            {diff.persistent_paths.length}
          </div>
          <div className="text-xs font-mono text-sentinel-muted uppercase">Persistent</div>
        </div>
        <div className="panel p-4 text-center">
          <div className="text-2xl font-mono text-sentinel-bright">
            {diff.delta_count}
          </div>
          <div className="text-xs font-mono text-sentinel-muted uppercase">Total Delta</div>
        </div>
      </div>

      {/* Path details */}
      {diff.new_paths.length > 0 && (
        <PathDelta title="New Attack Paths" paths={diff.new_paths} type="new" />
      )}
      {diff.closed_paths.length > 0 && (
        <PathDelta title="Closed Attack Paths" paths={diff.closed_paths} type="closed" />
      )}
      {diff.persistent_paths.length > 0 && (
        <PathDelta
          title="Persistent Attack Paths"
          paths={diff.persistent_paths}
          type="persistent"
        />
      )}
    </div>
  );
}
