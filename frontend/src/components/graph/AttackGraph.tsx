"use client";

import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import { GraphNode, GraphEdge, AttackChain, Severity } from "@/lib/types";
import { SEVERITY_COLORS, NODE_COLORS, NODE_SIZES } from "@/lib/constants";

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
  chains?: AttackChain[];
  onNodeClick?: (node: GraphNode) => void;
  selectedChain?: string;
}

export default function AttackGraph({ nodes, edges, chains, onNodeClick, selectedChain }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [filter, setFilter] = useState<string | null>(null);

  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    const visibleNodes = filter ? nodes.filter((n) => n.type === filter) : nodes;
    const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));
    const visibleEdges = edges.filter(
      (e) => visibleNodeIds.has(e.source as string) && visibleNodeIds.has(e.target as string)
    );

    const chainNodeIds = selectedChain
      ? new Set(chains?.find((c) => c.id === selectedChain)?.steps.map((s) => s.id) || [])
      : null;

    const g = svg.append("g");

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on("zoom", (event) => g.attr("transform", event.transform));
    svg.call(zoom);

    const simulation = d3
      .forceSimulation(visibleNodes as any)
      .force(
        "link",
        d3
          .forceLink(visibleEdges as any)
          .id((d: any) => d.id)
          .distance(80)
      )
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(30));

    // Edges
    const link = g
      .append("g")
      .selectAll("line")
      .data(visibleEdges)
      .join("line")
      .attr("stroke", "#333")
      .attr("stroke-width", 1)
      .attr("stroke-opacity", (d: any) =>
        chainNodeIds ? (chainNodeIds.has(d.source?.id || d.source) ? 1 : 0.15) : 0.6
      );

    // Edge labels
    const edgeLabels = g
      .append("g")
      .selectAll("text")
      .data(visibleEdges)
      .join("text")
      .attr("font-size", "8px")
      .attr("fill", "#666")
      .attr("text-anchor", "middle")
      .text((d) => d.type);

    // Nodes
    const node = g
      .append("g")
      .selectAll("circle")
      .data(visibleNodes)
      .join("circle")
      .attr("r", (d) => NODE_SIZES[d.type] || 10)
      .attr("fill", (d) =>
        d.severity ? SEVERITY_COLORS[d.severity] : NODE_COLORS[d.type] || "#808080"
      )
      .attr("stroke", (d) => (chainNodeIds?.has(d.id) ? "#FFF" : "#333"))
      .attr("stroke-width", (d) => (chainNodeIds?.has(d.id) ? 3 : 1))
      .attr("opacity", (d) => (chainNodeIds ? (chainNodeIds.has(d.id) ? 1 : 0.2) : 1))
      .attr("cursor", "pointer")
      .on("click", (_event, d) => onNodeClick?.(d))
      .call(
        d3
          .drag<any, GraphNode>()
          .on("start", (event, d: any) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d: any) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d: any) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      );

    // Node labels
    const labels = g
      .append("g")
      .selectAll("text")
      .data(visibleNodes)
      .join("text")
      .attr("font-size", "10px")
      .attr("fill", "#CCC")
      .attr("text-anchor", "middle")
      .attr("dy", (d) => (NODE_SIZES[d.type] || 10) + 14)
      .text((d) => (d.label.length > 20 ? d.label.slice(0, 20) + "..." : d.label));

    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      edgeLabels
        .attr("x", (d: any) => (d.source.x + d.target.x) / 2)
        .attr("y", (d: any) => (d.source.y + d.target.y) / 2);

      node.attr("cx", (d: any) => d.x).attr("cy", (d: any) => d.y);
      labels.attr("x", (d: any) => d.x).attr("y", (d: any) => d.y);
    });

    return () => {
      simulation.stop();
    };
  }, [nodes, edges, filter, selectedChain, chains, onNodeClick]);

  return (
    <div className="relative w-full h-full">
      <div className="absolute top-4 left-4 z-10 flex gap-2">
        {["host", "service", "endpoint", "vulnerability", "finding"].map((type) => (
          <button
            key={type}
            onClick={() => setFilter(filter === type ? null : type)}
            className={`px-3 py-1 text-xs font-mono rounded border ${
              filter === type
                ? "bg-white text-black border-white"
                : "bg-sentinel-surface text-sentinel-text border-sentinel-border hover:border-white"
            }`}
          >
            {type}
          </button>
        ))}
      </div>
      <svg ref={svgRef} className="w-full h-full bg-sentinel-bg" style={{ minHeight: "600px" }} />
    </div>
  );
}
