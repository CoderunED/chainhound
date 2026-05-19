const BASE = "http://localhost:8000";

export async function fetchSummary()    { return (await fetch(`${BASE}/summary`)).json(); }
export async function fetchFindings()   { return (await fetch(`${BASE}/findings`)).json(); }
export async function fetchGraph()      { return (await fetch(`${BASE}/graph`)).json(); }
export async function fetchNarratives() { return (await fetch(`${BASE}/narratives`)).json(); }
export async function fetchPaths()      { return (await fetch(`${BASE}/paths`)).json(); }
export async function runScan()         { return (await fetch(`${BASE}/scan`)).json(); }
