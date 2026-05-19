import json
import os
import subprocess
import sys
from pathlib import Path
from fastapi.responses import StreamingResponse
from api.pdf_exporter import generate_pdf
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
app = FastAPI(title="ChainHound API", version="1.0.0")

# Allow React dev server on port 5173
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173","http://localhost:5175",
        "http://127.0.0.1:5175","http://localhost:5176"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR = Path("data")

PIPELINE = [
    ["python", "collector/iam_collector.py"],
    ["python", "normalizer/iam_normalizer.py"],
    ["python", "graph/graph_builder.py"],
    ["python", "risk/risk_detector.py"],
    ["python", "risk/risk_scorer.py"],
    ["python", "risk/path_ranker.py"],
    ["python", "risk/findings_merger.py"],
    ["python", "ai/narrative_generator.py"],
]


def load_json_file(filename: str):
    path = DATA_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"{filename} not found. Run /scan first.")
    with open(path) as f:
        return json.load(f)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "service": "ChainHound API"}


@app.get("/scan")
def scan():
    """Run the full ChainHound pipeline end-to-end."""
    results = []

    for step in PIPELINE:
        label = " ".join(step)
        try:
            result = subprocess.run(
                step,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                return {
                    "status": "error",
                    "failed_step": label,
                    "stderr": result.stderr.strip(),
                    "completed_steps": results,
                }
            results.append({"step": label, "status": "ok"})
        except subprocess.TimeoutExpired:
            return {"status": "error", "failed_step": label, "error": "timeout"}

    return {"status": "complete", "steps": results}


@app.get("/graph")
def get_graph():
    """Full graph: nodes, edges, adjacency list, raw paths."""
    return load_json_file("graph.json")


@app.get("/findings")
def get_findings():
    """Merged findings: enriched attack paths with policy documents."""
    return load_json_file("findings_merged.json")


@app.get("/paths")
def get_paths():
    """Ranked attack paths with scores."""
    return load_json_file("paths.json")


@app.get("/narratives")
def get_narratives():
    """AI-generated attack narratives per path."""
    return load_json_file("narratives.json")
@app.get("/export/pdf")
def export_pdf():
    """Generate and stream a full PDF report."""
    buf = generate_pdf()
    filename = f"chainhound_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get("/summary")
def get_summary():
    """High-level summary across all data files."""
    graph = load_json_file("graph.json")
    paths = load_json_file("paths.json")
    narratives = load_json_file("narratives.json")

    critical = sum(1 for p in paths if p["top_severity"] == "CRITICAL")
    high     = sum(1 for p in paths if p["top_severity"] == "HIGH")
    medium   = sum(1 for p in paths if p["top_severity"] == "MEDIUM")

    return {
        "total_nodes":     graph["summary"]["total_nodes"],
        "total_edges":     graph["summary"]["total_edges"],
        "total_paths":     len(paths),
        "total_narratives": len(narratives),
        "severity_breakdown": {
            "CRITICAL": critical,
            "HIGH":     high,
            "MEDIUM":   medium,
        },
        "top_paths": [
            {
                "path_id":      p["path_id"],
                "final_score":  p["final_score"],
                "top_severity": p["top_severity"],
                "chain":        " -> ".join(p["path"]),
            }
            for p in paths[:5]  # top 5
        ],
    }
