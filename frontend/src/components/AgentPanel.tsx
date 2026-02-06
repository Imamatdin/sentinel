import type { AgentResult } from '@/lib/types';
import { formatDuration } from '@/lib/types';

interface AgentPanelProps {
  agents: Record<string, AgentResult>;
}

export function AgentPanel({ agents }: AgentPanelProps) {
  const agentList = Object.values(agents);

  if (agentList.length === 0) return null;

  return (
    <div className="panel">
      <div className="panel-header">Agents</div>
      <div className="divide-y divide-sentinel-800/50">
        {agentList.map((agent) => (
          <AgentCard key={agent.agent_name} agent={agent} />
        ))}
      </div>
    </div>
  );
}

function AgentCard({ agent }: { agent: AgentResult }) {
  const isRed = agent.agent_name.includes('recon') ||
                agent.agent_name.includes('exploit') ||
                agent.agent_name.includes('red');

  return (
    <div className="px-4 py-3">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <span className={`badge ${isRed ? 'badge-red' : 'badge-blue'}`}>
            {isRed ? 'RED' : 'BLUE'}
          </span>
          <span className="text-sm font-medium">
            {agent.agent_name.replace(/_/g, ' ')}
          </span>
        </div>
        <span className={`text-xs font-mono ${agent.success ? 'text-sentinel-400' : 'text-sentinel-500'}`}>
          {agent.success ? 'OK' : 'FAIL'}
        </span>
      </div>

      <div className="grid grid-cols-3 gap-2 text-xs text-sentinel-500 font-mono">
        <span>{formatDuration(agent.duration)}</span>
        <span>{agent.tool_calls_made} calls</span>
        <span>{agent.output_tokens} tok</span>
      </div>

      {agent.error && (
        <p className="text-xs text-sentinel-500 mt-1 truncate">
          {agent.error}
        </p>
      )}
    </div>
  );
}
