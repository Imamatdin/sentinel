'use client';

import { useState } from 'react';
import type { EngagementState } from '@/lib/types';

interface ControlPanelProps {
  state: EngagementState;
  juiceShopReachable: boolean;
  onStart: (config: Record<string, unknown>) => void;
  onStop: () => void;
}

export function ControlPanel({ state, juiceShopReachable, onStart, onStop }: ControlPanelProps) {
  const [targetUrl, setTargetUrl] = useState('http://localhost:3000');
  const [monitorCycles, setMonitorCycles] = useState(10);
  const [exploitIterations, setExploitIterations] = useState(15);
  const [skipRecon, setSkipRecon] = useState(false);
  const [skipReports, setSkipReports] = useState(false);

  const isRunning = state === 'running';
  const canStart = state !== 'running' && juiceShopReachable;

  const handleStart = () => {
    onStart({
      target_url: targetUrl,
      monitor_max_cycles: monitorCycles,
      exploit_max_iterations: exploitIterations,
      skip_recon: skipRecon,
      skip_reports: skipReports,
    });
  };

  return (
    <div className="panel">
      <div className="panel-header flex items-center justify-between">
        <span>Configuration</span>
        {!juiceShopReachable && (
          <span className="text-sentinel-500 normal-case tracking-normal text-xs">
            Juice Shop unreachable
          </span>
        )}
      </div>
      <div className="panel-body space-y-3">
        {/* Target URL */}
        <div>
          <label className="block text-xs text-sentinel-500 mb-1 font-mono">Target</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            disabled={isRunning}
            className="w-full bg-sentinel-950 border border-sentinel-700 rounded px-3 py-1.5
                       text-sm font-mono text-sentinel-200 focus:outline-none focus:border-sentinel-500
                       disabled:opacity-50"
          />
        </div>

        {/* Config grid */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-sentinel-500 mb-1 font-mono">Monitor Cycles</label>
            <input
              type="number"
              value={monitorCycles}
              onChange={(e) => setMonitorCycles(Number(e.target.value))}
              disabled={isRunning}
              min={1}
              max={50}
              className="w-full bg-sentinel-950 border border-sentinel-700 rounded px-3 py-1.5
                         text-sm font-mono text-sentinel-200 focus:outline-none focus:border-sentinel-500
                         disabled:opacity-50"
            />
          </div>
          <div>
            <label className="block text-xs text-sentinel-500 mb-1 font-mono">Exploit Iters</label>
            <input
              type="number"
              value={exploitIterations}
              onChange={(e) => setExploitIterations(Number(e.target.value))}
              disabled={isRunning}
              min={1}
              max={30}
              className="w-full bg-sentinel-950 border border-sentinel-700 rounded px-3 py-1.5
                         text-sm font-mono text-sentinel-200 focus:outline-none focus:border-sentinel-500
                         disabled:opacity-50"
            />
          </div>
        </div>

        {/* Checkboxes */}
        <div className="flex gap-4">
          <label className="flex items-center gap-2 text-xs text-sentinel-400 cursor-pointer">
            <input
              type="checkbox"
              checked={skipRecon}
              onChange={(e) => setSkipRecon(e.target.checked)}
              disabled={isRunning}
              className="rounded border-sentinel-600"
            />
            Skip Recon
          </label>
          <label className="flex items-center gap-2 text-xs text-sentinel-400 cursor-pointer">
            <input
              type="checkbox"
              checked={skipReports}
              onChange={(e) => setSkipReports(e.target.checked)}
              disabled={isRunning}
              className="rounded border-sentinel-600"
            />
            Skip Reports
          </label>
        </div>

        {/* Action button */}
        {isRunning ? (
          <button
            onClick={onStop}
            className="w-full py-2 text-sm font-mono uppercase tracking-wider
                       border border-sentinel-600 text-sentinel-300 rounded
                       hover:bg-sentinel-800 transition-colors"
          >
            Stop Engagement
          </button>
        ) : (
          <button
            onClick={handleStart}
            disabled={!canStart}
            className="w-full py-2 text-sm font-mono uppercase tracking-wider
                       bg-sentinel-100 text-sentinel-950 rounded font-semibold
                       hover:bg-white transition-colors
                       disabled:opacity-30 disabled:cursor-not-allowed"
          >
            Start Engagement
          </button>
        )}
      </div>
    </div>
  );
}
