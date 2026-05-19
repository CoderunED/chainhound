const SCORE_COLOR = {
  CRITICAL: "#E24B4A",
  HIGH:     "#EF9F27",
  MEDIUM:   "#e6c700",
  LOW:      "#68BA7F",
  NONE:     "#7a9c85",
};

export default function PathsTable({ paths, findings, onSelect, selected }) {
  if (!paths?.length) return <p className="empty">No paths found.</p>;

  // Build lookup: path_id -> full findings array from findings_merged.json
  const findingsByPathId = {};
  if (findings?.length) {
    for (const record of findings) {
      findingsByPathId[record.path_id] = record.findings ?? [];
    }
  }

  return (
    <div className="paths-table-wrap">
      <div className="section-label">Attack paths</div>
      <table className="paths-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Severity</th>
            <th>Score</th>
            <th>Hops</th>
            <th>Attack Chain</th>
          </tr>
        </thead>
        <tbody>
          {paths.map((p) => (
            <tr
              key={p.path_id}
              className={selected?.path_id === p.path_id ? "selected" : ""}
              onClick={() => onSelect(p)}
            >
              <td className="mono">{p.path_id}</td>
              <td>
                <span className={`badge badge-${p.top_severity}`}>
                  {p.top_severity}
                </span>
              </td>
              <td>
                <div className="score-bar-wrap">
                  <div className="score-track">
                    <div className="score-bar" style={{ width: `${p.final_score}%`, background: SCORE_COLOR[p.top_severity] }} />
                  </div>
                  <span className="score-num mono">{p.final_score}</span>
                </div>
              </td>
              <td className="mono">{p.hop_count}</td>
              <td className="chain">{p.path.join(" → ")}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {selected && (
        <div className="path-detail">
          <h3>Path {selected.path_id} — Findings</h3>
          {(findingsByPathId[selected.path_id] ?? selected.matched_findings ?? []).map((f, i) => (
            <div className="finding-row" key={i}>
              <span className={`badge badge-${f.severity}`}>{f.severity}</span>
              <span className="finding-name">{f.policy_name}</span>
              <span className="mono" style={{ fontSize: 10, color: "var(--muted)", marginLeft: 4 }}>
                {f.detector ?? ""}
              </span>
              <span className="finding-reason">
                {Array.isArray(f.reasons) ? f.reasons.join(" · ") : f.issue}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
