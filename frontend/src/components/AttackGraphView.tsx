import { useMemo } from "react";
import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { GraphEdge, GraphNode } from "../api/types";
import { SEVERITY_COLOR } from "./ui";

const ZONE_ORDER = ["external", "dmz", "corporate", "management", "server", "ot"];

/** Deterministic layered layout: one column per network zone. */
export function AttackGraphView({
  nodes,
  edges,
  height = 520,
  onSelect,
  selected,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  height?: number;
  onSelect?: (id: string) => void;
  selected?: string | null;
}) {
  const { rfNodes, rfEdges } = useMemo(() => {
    const rank = (z: string) => (ZONE_ORDER.indexOf(z) === -1 ? 99 : ZONE_ORDER.indexOf(z));
    const zones = [...new Set(nodes.map((n) => n.zone))].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
    const counters: Record<string, number> = {};
    const rfNodes: Node[] = nodes.map((n) => {
      const col = zones.indexOf(n.zone);
      const row = (counters[n.zone] = (counters[n.zone] ?? -1) + 1);
      const border = n.compromised ? "#ef4444" : SEVERITY_COLOR[n.criticality] ?? "#64748b";
      return {
        id: n.id,
        position: { x: col * 230, y: row * 92 + (col % 2) * 30 },
        data: {
          label: (
            <div style={{ textAlign: "left" }}>
              <div style={{ fontWeight: 600, fontSize: 12 }}>{n.compromised ? "⚠ " : ""}{n.label}</div>
              <div style={{ fontSize: 10, opacity: 0.75 }}>
                {n.zone} · {n.criticality}{n.vulns?.length ? ` · ${n.vulns.length} KEV` : ""}
              </div>
            </div>
          ),
        },
        style: {
          background: n.compromised ? "rgba(239,68,68,.18)" : "#111a2e",
          color: "#e2e8f0",
          border: `2px solid ${border}`,
          borderRadius: 8,
          width: 180,
          padding: 6,
          boxShadow: selected === n.id ? "0 0 0 3px #22d3ee" : undefined,
        },
      };
    });
    const rfEdges: Edge[] = edges.map((e, i) => ({
      id: `${e.source}-${e.target}-${i}`,
      source: e.source,
      target: e.target,
      animated: e.on_attack_path,
      label: e.on_attack_path ? `p=${e.probability.toFixed(2)}` : undefined,
      labelStyle: { fill: "#fca5a5", fontSize: 10 },
      labelBgStyle: { fill: "#0b1220" },
      style: {
        stroke: e.on_attack_path ? "#ef4444" : "rgba(148,163,184,.25)",
        strokeWidth: e.on_attack_path ? 2.5 : 1,
      },
      markerEnd: e.on_attack_path ? { type: MarkerType.ArrowClosed, color: "#ef4444" } : undefined,
    }));
    return { rfNodes, rfEdges };
  }, [nodes, edges, selected]);

  return (
    <div style={{ height, border: "1px solid rgba(148,163,184,.15)", borderRadius: 8 }}>
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        fitView
        colorMode="dark"
        nodesConnectable={false}
        onNodeClick={(_, n) => onSelect?.(n.id)}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={24} color="rgba(148,163,184,.12)" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
