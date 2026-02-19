"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import dynamic from "next/dynamic";
import { useAttackGraph } from "@/hooks/useAttackGraph";
import LoadingSpinner from "@/components/shared/LoadingSpinner";
import EmptyState from "@/components/shared/EmptyState";
import GraphLegend from "@/components/graph/GraphLegend";
import type { GraphNode } from "@/lib/types";

const AttackGraph = dynamic(() => import("@/components/graph/AttackGraph"), {
  ssr: false,
  loading: () => <LoadingSpinner />,
});

export default function GraphPage() {
  const params = useParams();
  const id = params.id as string;
  const { graph, isLoading } = useAttackGraph(id);
  const [selectedChain, setSelectedChain] = useState<string | undefined>();
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  if (isLoading) return <LoadingSpinner />;
  if (!graph || graph.nodes.length === 0) {
    return <EmptyState title="No Graph Data" description="Run an engagement to populate the attack graph." />;
  }

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-lg font-mono text-sentinel-bright">Attack Graph</h1>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3 panel" style={{ height: "700px" }}>
          <AttackGraph
            nodes={graph.nodes}
            edges={graph.edges}
            chains={graph.chains}
            selectedChain={selectedChain}
            onNodeClick={setSelectedNode}
          />
        </div>

        <div className="space-y-4">
          <GraphLegend />

          {/* Chains */}
          {graph.chains.length > 0 && (
            <div className="panel">
              <div className="panel-header">Attack Chains</div>
              <div className="p-2 space-y-1 max-h-[300px] overflow-y-auto">
                {graph.chains.map((chain) => (
                  <button
                    key={chain.id}
                    onClick={() =>
                      setSelectedChain(
                        selectedChain === chain.id ? undefined : chain.id
                      )
                    }
                    className={`w-full text-left px-3 py-2 text-xs font-mono rounded transition-colors ${
                      selectedChain === chain.id
                        ? "bg-sentinel-border text-sentinel-bright"
                        : "hover:bg-sentinel-bg text-sentinel-text"
                    }`}
                  >
                    <div>{chain.crown_jewel}</div>
                    <div className="text-sentinel-muted">
                      Depth: {chain.total_depth} | Score: {chain.exposure_score.toFixed(2)}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Selected node detail */}
          {selectedNode && (
            <div className="panel">
              <div className="panel-header">Node Detail</div>
              <div className="p-3 text-xs font-mono space-y-1">
                <div>
                  <span className="text-sentinel-muted">Type: </span>
                  <span className="text-sentinel-text">{selectedNode.type}</span>
                </div>
                <div>
                  <span className="text-sentinel-muted">Label: </span>
                  <span className="text-sentinel-text">{selectedNode.label}</span>
                </div>
                {selectedNode.severity && (
                  <div>
                    <span className="text-sentinel-muted">Severity: </span>
                    <span className="text-sentinel-text">{selectedNode.severity}</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
