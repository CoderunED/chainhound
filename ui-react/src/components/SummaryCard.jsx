export default function SummaryCard({ summary, onScan, scanning }) {
  if (!summary) return null;

  const { total_nodes, total_edges, total_paths, severity_breakdown } = summary;

  const stats = [
    { label: "Nodes",    value: total_nodes,                        color: "var(--teal)" },
    { label: "Edges",    value: total_edges,                        color: "var(--teal)" },
    { label: "Paths",    value: total_paths,                        color: "var(--amber)" },
    { label: "Critical", value: severity_breakdown?.CRITICAL ?? 0,  color: "var(--red)" },
    { label: "High",     value: severity_breakdown?.HIGH ?? 0,      color: "var(--orange)" },
    { label: "Medium",   value: severity_breakdown?.MEDIUM ?? 0,    color: "var(--yellow)" },
  ];

  return (
    <div className="summary-bar">
      {stats.map((s) => (
        <div className="stat-chip" key={s.label}>
          <span className="stat-value" style={{ color: s.color }}>{s.value}</span>
          <span className="stat-label">{s.label}</span>
        </div>
      ))}
      <button className={`scan-btn ${scanning ? "scanning" : ""}`} onClick={onScan} disabled={scanning}>
        {scanning ? "Scanning…" : "⟳ Re-scan"}
      </button>
    </div>
  );
}
