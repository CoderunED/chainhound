import { useEffect, useMemo } from "react";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
} from "reactflow";
import "reactflow/dist/style.css";

const TYPE_COLOR = {
  user:   "#68BA7F",
  role:   "#f59e0b",
  policy: "#ef4444",
};

function buildLayout(graphData) {
  if (!graphData) return { nodes: [], edges: [] };

  const nodes = graphData.nodes.map((n) => {
    const col = { user: 0, role: 1, policy: 2 }[n.type] ?? 1;
    const typeNodes = graphData.nodes.filter((x) => x.type === n.type);
    const row = typeNodes.indexOf(n);
    return {
      id: n.id,
      position: { x: col * 320 + 60, y: row * 140 + 60 },
      data: { label: n.name, type: n.type },
      style: {
        background: "var(--surface, #fff)",
        border: `1.5px solid ${TYPE_COLOR[n.type] ?? "#888"}`,
        color: "var(--text, #253D2C)",
        borderRadius: 8,
        padding: "10px 16px",
        fontFamily: "'DM Mono', monospace",
        fontSize: 13,
        minWidth: 180,
      },
    };
  });

  const edges = graphData.edges.map((e, i) => ({
    id: `e${i}`,
    source: e.source,
    target: e.target,
    label: e.type,
    animated: e.type === "CAN_ASSUME",
    style: { stroke: e.type === "CAN_ASSUME" ? "#f59e0b" : "#94a3b8", strokeWidth: 2 },
    labelStyle: { fill: "#7a9c85", fontSize: 11, fontFamily: "'DM Mono', monospace" },
    labelBgStyle: { fill: "var(--surface, #fff)" },
  }));

  return { nodes, edges };
}

export default function GraphView({ graphData }) {
  const { nodes: initNodes, edges: initEdges } = useMemo(() => buildLayout(graphData), [graphData]);
  const [nodes, setNodes, onNodesChange] = useNodesState(initNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initEdges);

  useEffect(() => {
    const { nodes: n, edges: e } = buildLayout(graphData);
    setNodes(n);
    setEdges(e);
  }, [graphData]);

  if (!graphData) return <p className="empty">No graph data.</p>;

  return (
    <div style={{ width: "100%", height: 520, borderRadius: 12, overflow: "hidden", border: "0.5px solid var(--border, #c8e6d0)" }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        attributionPosition="bottom-right"
      >
        <Background color="var(--border-soft, #e8f2eb)" gap={24} />
        <Controls style={{ background: "var(--surface, #fff)", border: "0.5px solid var(--border, #c8e6d0)" }} />
        <MiniMap
          nodeColor={(n) => TYPE_COLOR[n.data?.type] ?? "#888"}
          style={{ background: "var(--chip-bg, #f4fef7)" }}
        />
      </ReactFlow>

      <div className="graph-legend">
        {Object.entries(TYPE_COLOR).map(([type, color]) => (
          <span key={type} className="legend-item">
            <span className="legend-dot" style={{ background: color }} />
            {type}
          </span>
        ))}
        <span className="legend-item"><span className="legend-line animated" />CAN_ASSUME</span>
        <span className="legend-item"><span className="legend-line" />HAS_POLICY</span>
      </div>
    </div>
  );
}
