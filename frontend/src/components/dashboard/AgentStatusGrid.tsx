"use client";

interface AgentStatus {
  name: string;
  status: "idle" | "running" | "complete" | "error";
  lastAction?: string;
}

interface Props {
  agents: AgentStatus[];
}

const STATUS_COLORS: Record<string, string> = {
  idle: "bg-sentinel-muted",
  running: "bg-severity-medium",
  complete: "bg-severity-low",
  error: "bg-severity-critical",
};

export default function AgentStatusGrid({ agents }: Props) {
  return (
    <div className="panel">
      <div className="panel-header">Agents</div>
      <div className="p-3 space-y-2">
        {agents.length === 0 ? (
          <div className="text-xs text-sentinel-muted font-mono text-center py-2">
            No active agents
          </div>
        ) : (
          agents.map((agent) => (
            <div
              key={agent.name}
              className="flex items-center gap-2 text-xs font-mono"
            >
              <div className={`w-2 h-2 rounded-full ${STATUS_COLORS[agent.status]}`} />
              <span className="text-sentinel-text">{agent.name}</span>
              {agent.lastAction && (
                <span className="text-sentinel-muted truncate flex-1">
                  {agent.lastAction}
                </span>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
