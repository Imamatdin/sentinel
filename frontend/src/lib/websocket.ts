import type { SentinelEvent, EngagementState, EngagementPhase } from './types';

interface WebSocketCallbacks {
  onConnection: (connected: boolean) => void;
  onEvent: (event: SentinelEvent) => void;
  onState: (
    state: EngagementState,
    phase: EngagementPhase,
    eventCount: number,
    elapsed: number | null,
  ) => void;
  onResult: (result: { speed_stats: Record<string, number | null> }) => void;
}

export class SentinelWebSocket {
  private ws: WebSocket | null = null;
  private callbacks: WebSocketCallbacks;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private shouldReconnect = true;

  constructor(callbacks: WebSocketCallbacks) {
    this.callbacks = callbacks;
  }

  connect(): void {
    this.shouldReconnect = true;
    this.doConnect();
  }

  disconnect(): void {
    this.shouldReconnect = false;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.callbacks.onConnection(false);
  }

  private doConnect(): void {
    const wsUrl =
      process.env.NEXT_PUBLIC_WS_URL ||
      `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`;

    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      this.callbacks.onConnection(true);
    };

    this.ws.onclose = () => {
      this.callbacks.onConnection(false);
      this.ws = null;
      if (this.shouldReconnect) {
        this.reconnectTimer = setTimeout(() => this.doConnect(), 2000);
      }
    };

    this.ws.onerror = () => {
      // onclose will fire after this, triggering reconnect
    };

    this.ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        this.handleMessage(data);
      } catch {
        // Ignore unparseable messages
      }
    };
  }

  private handleMessage(data: Record<string, unknown>): void {
    switch (data.type) {
      case 'event':
        this.callbacks.onEvent({
          event_id: data.event_id as number,
          event_type: data.event_type as string,
          source: data.source as string,
          timestamp: data.timestamp as number,
          data: (data.data as Record<string, unknown>) || {},
        });
        break;

      case 'state':
        this.callbacks.onState(
          data.state as EngagementState,
          (data.phase as EngagementPhase) || null,
          (data.event_count as number) || 0,
          (data.elapsed_seconds as number) || null,
        );
        break;

      case 'result':
        this.callbacks.onResult({
          speed_stats: (data.speed_stats as Record<string, number | null>) || {},
        });
        break;

      case 'pong':
      case 'replay_complete':
        // Handled silently
        break;
    }
  }
}
