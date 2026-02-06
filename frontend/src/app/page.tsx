'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import type {
  SentinelEvent,
  EngagementState,
  EngagementPhase,
  EngagementResult,
  SpeedStats,
} from '@/lib/types';
import { api } from '@/lib/api';
import { SentinelWebSocket } from '@/lib/websocket';
import { Header } from '@/components/Header';
import { ControlPanel } from '@/components/ControlPanel';
import { StatusBar } from '@/components/StatusBar';
import { EventTimeline } from '@/components/EventTimeline';
import { SpeedMetrics } from '@/components/SpeedMetrics';
import { AgentPanel } from '@/components/AgentPanel';
import { ReportViewer } from '@/components/ReportViewer';

export default function Dashboard() {
  // Connection state
  const [connected, setConnected] = useState(false);
  const [juiceShopReachable, setJuiceShopReachable] = useState(false);

  // Engagement state
  const [engState, setEngState] = useState<EngagementState>('idle');
  const [phase, setPhase] = useState<EngagementPhase>(null);
  const [eventCount, setEventCount] = useState(0);
  const [elapsed, setElapsed] = useState<number | null>(null);

  // Events
  const [events, setEvents] = useState<SentinelEvent[]>([]);

  // Result
  const [result, setResult] = useState<EngagementResult | null>(null);
  const [showReports, setShowReports] = useState(false);

  // Speed stats (live updates)
  const [liveSpeed, setLiveSpeed] = useState<Partial<SpeedStats>>({});

  // WebSocket ref
  const wsRef = useRef<SentinelWebSocket | null>(null);

  // Health check on mount
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const health = await api.health();
        setJuiceShopReachable(health.juice_shop_reachable);
      } catch {
        setJuiceShopReachable(false);
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  // WebSocket setup
  useEffect(() => {
    const ws = new SentinelWebSocket({
      onConnection: setConnected,

      onEvent: (event) => {
        setEvents((prev) => [...prev, event]);
        setEventCount((c) => c + 1);
      },

      onState: (state, phase, count, elapsed) => {
        setEngState(state);
        setPhase(phase);
        setEventCount(count);
        setElapsed(elapsed);
      },

      onResult: (res) => {
        setLiveSpeed(res.speed_stats);
        // Fetch full result
        api.getResult().then(setResult).catch(() => {});
      },
    });

    ws.connect();
    wsRef.current = ws;

    return () => {
      ws.disconnect();
    };
  }, []);

  // Start engagement
  const handleStart = useCallback(async (config: Record<string, unknown>) => {
    try {
      setEvents([]);
      setResult(null);
      setShowReports(false);
      setLiveSpeed({});
      await api.startEngagement(config);
    } catch (err) {
      console.error('Failed to start engagement:', err);
    }
  }, []);

  // Stop engagement
  const handleStop = useCallback(async () => {
    try {
      await api.stopEngagement();
    } catch (err) {
      console.error('Failed to stop engagement:', err);
    }
  }, []);

  const isRunning = engState === 'running';
  const isComplete = engState === 'completed' || engState === 'failed';

  return (
    <div className="min-h-screen flex flex-col">
      <Header connected={connected} />

      <main className="flex-1 max-w-[1600px] mx-auto w-full px-4 py-4 space-y-4">
        {/* Top row: Controls + Status */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <ControlPanel
            state={engState}
            juiceShopReachable={juiceShopReachable}
            onStart={handleStart}
            onStop={handleStop}
          />
          <div className="lg:col-span-2">
            <StatusBar
              state={engState}
              phase={phase}
              elapsed={elapsed}
              eventCount={eventCount}
            />
          </div>
        </div>

        {/* Main content: Timeline + Side panels */}
        {(isRunning || isComplete) && (
          <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
            {/* Event Timeline - takes 3 columns */}
            <div className="xl:col-span-3">
              <EventTimeline events={events} isLive={isRunning} />
            </div>

            {/* Side panel - speed metrics + agents */}
            <div className="space-y-4">
              <SpeedMetrics
                events={events}
                speedStats={result?.speed_stats || liveSpeed}
                isLive={isRunning}
              />
              {result && (
                <AgentPanel agents={result.agents} />
              )}
            </div>
          </div>
        )}

        {/* Reports section (after completion) */}
        {isComplete && result && (
          <div>
            <button
              onClick={() => setShowReports(!showReports)}
              className="mb-4 px-4 py-2 text-sm font-mono uppercase tracking-wider
                         border border-sentinel-700 text-sentinel-300
                         hover:bg-sentinel-800 transition-colors rounded"
            >
              {showReports ? 'Hide Reports' : 'View Reports'}
            </button>

            {showReports && (
              <ReportViewer
                redReport={result.red_report}
                blueReport={result.blue_report}
              />
            )}
          </div>
        )}

        {/* Idle state - show instructions */}
        {engState === 'idle' && (
          <div className="panel">
            <div className="p-12 text-center">
              <p className="text-sentinel-500 font-mono text-sm uppercase tracking-widest mb-4">
                Ready
              </p>
              <p className="text-sentinel-400 text-lg max-w-xl mx-auto leading-relaxed">
                Configure engagement parameters above and start the assessment.
                Events will stream here in real-time as red team agents attack
                and blue team agents defend.
              </p>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-sentinel-900 py-3 px-4 text-center">
        <p className="text-sentinel-600 text-xs font-mono">
          SENTINEL v0.1.0 &middot; Powered by Cerebras Inference
        </p>
      </footer>
    </div>
  );
}
