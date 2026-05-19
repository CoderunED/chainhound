import { useState } from "react";

function renderMarkdown(text) {
  const lines = text.split("\n");
  const out = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (/^### /.test(line)) {
      out.push(<h3 key={i} className="md-h3">{line.slice(4)}</h3>);
    } else if (/^## /.test(line)) {
      out.push(<h2 key={i} className="md-h2">{line.slice(3)}</h2>);
    } else if (/^# /.test(line)) {
      out.push(<h1 key={i} className="md-h1">{line.slice(2)}</h1>);
    } else if (/^\|/.test(line)) {
      const rows = [];
      while (i < lines.length && /^\|/.test(lines[i])) {
        rows.push(lines[i]);
        i++;
      }
      const headers = rows[0].split("|").filter(Boolean).map((c) => c.trim());
      const body = rows.slice(2).map((r) => r.split("|").filter(Boolean).map((c) => c.trim()));
      out.push(
        <table key={`table-${i}`} className="md-table">
          <thead><tr>{headers.map((h, j) => <th key={j}>{h}</th>)}</tr></thead>
          <tbody>{body.map((row, j) => <tr key={j}>{row.map((c, k) => <td key={k}>{c}</td>)}</tr>)}</tbody>
        </table>
      );
      continue;
    } else if (/^- /.test(line)) {
      const items = [];
      while (i < lines.length && /^- /.test(lines[i])) {
        items.push(lines[i].slice(2));
        i++;
      }
      out.push(<ul key={`ul-${i}`} className="md-ul">{items.map((it, j) => <li key={j}>{inlineFormat(it)}</li>)}</ul>);
      continue;
    } else if (/^\d+\. /.test(line)) {
      const items = [];
      while (i < lines.length && /^\d+\. /.test(lines[i])) {
        items.push(lines[i].replace(/^\d+\. /, ""));
        i++;
      }
      out.push(<ol key={`ol-${i}`} className="md-ol">{items.map((it, j) => <li key={j}>{inlineFormat(it)}</li>)}</ol>);
      continue;
    } else if (/^---/.test(line)) {
      out.push(<hr key={i} className="md-hr" />);
    } else if (line.trim() === "") {
      out.push(<div key={i} className="md-spacer" />);
    } else {
      out.push(<p key={i} className="md-p">{inlineFormat(line)}</p>);
    }
    i++;
  }
  return out;
}

function inlineFormat(text) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, i) => {
    if (/^\*\*/.test(part)) return <strong key={i}>{part.slice(2, -2)}</strong>;
    if (/^`/.test(part))    return <code key={i} className="md-code">{part.slice(1, -1)}</code>;
    return part;
  });
}

export default function NarrativePanel({ narratives }) {
  const [active, setActive] = useState(0);

  if (!narratives?.length) return <p className="empty">No narratives generated.</p>;

  const n = narratives[active];

  return (
    <div className="narrative-wrap">

      {/* Export button — always visible */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end" }}>
        <button
          className="scan-btn"
          onClick={() => window.open("http://localhost:8000/export/pdf", "_blank")}
        >
          ↓ Export PDF
        </button>
      </div>

      {/* Tab row — only when multiple narratives */}
      {narratives.length > 1 && (
        <div className="narrative-tabs">
          {narratives.map((n, i) => (
            <button
              key={i}
              className={`nar-tab ${active === i ? "active" : ""}`}
              onClick={() => setActive(i)}
            >
              Path {n.path_id}
              <span className={`badge badge-${n.severity}`} style={{ marginLeft: 6 }}>
                {n.severity}
              </span>
            </button>
          ))}
        </div>
      )}

      {/* Meta bar */}
      <div className="narrative-meta">
        <span className={`badge badge-${n.severity}`}>{n.severity}</span>
        <span className="mono" style={{ color: "var(--muted)", fontSize: 12 }}>
          {n.attack_chain}
        </span>
        <span className="score-pill">Score: {n.score}/100</span>
      </div>

      {/* Narrative body */}
      <div className="narrative-body">
        {renderMarkdown(n.narrative)}
      </div>

    </div>
  );
}
