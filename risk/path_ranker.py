import json
import os

GRAPH_PATH = "data/graph.json"
FINDINGS_SCORED_PATH = "data/findings_scored.json"
OUTPUT_PATH = "data/paths.json"


def load_json(path):
    with open(path) as f:
        return json.load(f)


def arn_to_name(arn):
    return arn.split("/")[-1] if "/" in arn else arn


def rank_paths(graph, findings_scored):
    findings_by_name = {}
    for finding in findings_scored:
        name = finding.get("policy_name") or finding.get("principal_name")
        if name:
            findings_by_name[name] = finding

    ranked_paths = []

    for i, path_arns in enumerate(graph.get("paths", [])):
        path_names = [arn_to_name(arn) for arn in path_arns]
        hop_count = len(path_arns) - 1

        matched_findings = []
        for name in path_names:
            if name in findings_by_name:
                matched_findings.append(findings_by_name[name])

        if matched_findings:
            base_score = max(f["risk_score"] for f in matched_findings)
            top_finding = max(matched_findings, key=lambda f: f["risk_score"])
            top_severity = top_finding["severity"]
        else:
            base_score = 0
            top_severity = "NONE"

        hop_bonus = min(hop_count * 2, 10)
        final_score = min(base_score + hop_bonus, 100)

        ranked_paths.append({
            "path_id": i + 1,
            "path": path_names,
            "path_arns": path_arns,
            "hop_count": hop_count,
            "base_score": base_score,
            "hop_bonus": hop_bonus,
            "final_score": final_score,
            "top_severity": top_severity,
            "matched_findings": [
                {
                    "policy_name": f.get("policy_name"),
                    "severity": f["severity"],
                    "risk_score": f["risk_score"],
                    "issue": f.get("issue", ""),
                }
                for f in matched_findings
            ],
        })

    ranked_paths.sort(key=lambda p: (-p["final_score"], -p["hop_count"]))
    return ranked_paths


def main():
    print("[*] Loading graph and findings...")
    graph = load_json(GRAPH_PATH)
    findings_scored = load_json(FINDINGS_SCORED_PATH)

    print(f"    Paths found:    {len(graph.get('paths', []))}")
    print(f"    Findings found: {len(findings_scored)}")

    ranked = rank_paths(graph, findings_scored)

    os.makedirs("data", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(ranked, f, indent=2)

    print(f"\n[+] Ranked {len(ranked)} path(s) -> {OUTPUT_PATH}\n")

    for p in ranked:
        print(f"  Path {p['path_id']} [{p['top_severity']}] score={p['final_score']}/100  hops={p['hop_count']}")
        print(f"    Route: {' -> '.join(p['path'])}")
        for f in p["matched_findings"]:
            print(f"    Finding: {f['policy_name']} — {f['issue']}")
        print()


if __name__ == "__main__":
    main()
