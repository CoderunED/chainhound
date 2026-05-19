import { useEffect, useState } from "react";
import { fetchSummary, fetchPaths, fetchFindings, fetchGraph, fetchNarratives, runScan } from "./api";
import SummaryCard from "./components/SummaryCard";
import PathsTable from "./components/PathsTable";
import GraphView from "./components/GraphView";
import NarrativePanel from "./components/NarrativePanel";
import "./App.css";

const TABS = ["Findings", "Graph", "Narratives"];

export default function App() {
  const [tab, setTab]           = useState(0);
  const [theme, setTheme]       = useState("light");
  const [summary, setSummary]   = useState(null);
  const [paths, setPaths]       = useState([]);
  const [findings, setFindings] = useState([]);
  const [graph, setGraph]       = useState(null);
  const [narratives, setNarr]   = useState([]);
  const [selected, setSelected] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading]   = useState(true);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  async function loadAll() {
    setLoading(true);
    try {
      const [s, p, f, g, n] = await Promise.all([
        fetchSummary(), fetchPaths(), fetchFindings(), fetchGraph(), fetchNarratives(),
      ]);
      setSummary(s);
      setPaths(p);
      setFindings(f);
      setGraph(g);
      setNarr(n);
    } catch (e) {
      console.error("Failed to load data", e);
    }
    setLoading(false);
  }

  async function handleScan() {
    setScanning(true);
    await runScan();
    await loadAll();
    setScanning(false);
  }

  useEffect(() => { loadAll(); }, []);

  return (
    <div className="app">
      <header className="header">
        <div className="logo">
          <span className="logo-icon">🐕</span>
          <span className="logo-text">Chain<span className="logo-accent">Hound</span></span>
        </div>
        <nav className="tabs">
          {TABS.map((t, i) => (
            <button key={t} className={`tab ${tab === i ? "active" : ""}`} onClick={() => setTab(i)}>
              {t}
            </button>
          ))}
        </nav>
        <div className="header-right">
          <div className="theme-toggle">
            <button className={`theme-btn ${theme === "light" ? "active" : ""}`} onClick={() => setTheme("light")}>Light</button>
            <button className={`theme-btn ${theme === "dark" ? "active" : ""}`} onClick={() => setTheme("dark")}>Dark</button>
          </div>
          <span className="status-dot" />
          <span className="status-text">AWS · 569664406751</span>
        </div>
      </header>

      <SummaryCard summary={summary} onScan={handleScan} scanning={scanning} />

      <main className="main">
        {loading ? (
          <div className="loading">
            <div className="spinner" />
            <span>Loading scan data…</span>
          </div>
        ) : (
          <>
            {tab === 0 && <PathsTable paths={paths} findings={findings} onSelect={setSelected} selected={selected} />}
            {tab === 1 && <GraphView graphData={graph} />}
            {tab === 2 && <NarrativePanel narratives={narratives} />}
          </>
        )}
      </main>
    </div>
  );
}
