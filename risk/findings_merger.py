import json
import os

PATHS_PATH = "data/paths.json"
FINDINGS_SCORED_PATH = "data/findings_scored.json"
GRAPH_PATH = "data/graph.json"
OUTPUT_PATH = "data/findings_merged.json"


def load_json(path):
    with open(path) as f:
        return json.load(f)


def merge(paths, findings_scored, graph):
    # Lookups
    findings_by_name = {}
    for f in findings_scored:
        name = f.get("policy_name") or f.get("principal_name")
        if name:
            findings_by_name[name] = f

    nodes_by_name = {}
    for node in graph.get("nodes", []):
        nodes_by_name[node["name"]] = node

    merged = []

    for path in paths:
        # Enrich each node in the path with its type and ARN
        enriched_nodes = []
        for name in path["path"]:
            node = nodes_by_name.get(name, {})
            enriched_nodes.append({
                "name": name,
                "type": node.get("type", "unknown"),
                "arn": node.get("arn", "unknown"),
            })

        # Attach full finding detail (including policy document) to each matched finding
        enriched_findings = []
        for mf in path["matched_findings"]:
            policy_name = mf["policy_name"]
            full_finding = findings_by_name.get(policy_name, {})
            # issue is a string in paths.json, normalize to list for consistency
            issue = mf.get("issue", "")
            reasons = [issue] if issue else mf.get("reasons", [])
            enriched_findings.append({
                "policy_name": policy_name,
                "severity": mf["severity"],
                "score": mf.get("risk_score") or mf.get("score", 0),
                "reasons": reasons,
                "policy_document": full_finding.get("policy_document", None),
                "wildcards": {
                    "wildcard_action": full_finding.get("wildcard_action", False),
                    "wildcard_resource": full_finding.get("wildcard_resource", False),
                },
                "sensitive_services": full_finding.get("sensitive_services", []),
            })

        merged.append({
            "path_id": path["path_id"],
            "final_score": path["final_score"],
            "top_severity": path["top_severity"],
            "hop_count": path["hop_count"],
            "path": path["path"],
            "path_arns": path["path_arns"],
            "nodes": enriched_nodes,
            "findings": enriched_findings,
            # Summary fields for the AI prompt
            "summary": {
                "entry_point": path["path"][0],
                "terminal_policy": path["path"][-1],
                "hops": path["hop_count"],
                "score": path["final_score"],
                "severity": path["top_severity"],
                "attack_chain": " -> ".join(path["path"]),
            }
        })

    return merged


def main():
    print("[*] Loading paths, findings, and graph...")
    paths = load_json(PATHS_PATH)
    findings_scored = load_json(FINDINGS_SCORED_PATH)
    graph = load_json(GRAPH_PATH)

    print(f"    Paths:    {len(paths)}")
    print(f"    Findings: {len(findings_scored)}")
    print(f"    Nodes:    {len(graph.get('nodes', []))}")

    merged = merge(paths, findings_scored, graph)

    os.makedirs("data", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(merged, f, indent=2)

    print(f"\n[+] Merged {len(merged)} record(s) -> {OUTPUT_PATH}\n")

    for m in merged:
        s = m["summary"]
        print(f"  Path {m['path_id']} [{s['severity']}] score={s['score']}/100")
        print(f"    Chain:  {s['attack_chain']}")
        print(f"    Entry:  {s['entry_point']}")
        print(f"    Target: {s['terminal_policy']}")
        print(f"    Hops:   {s['hops']}")
        for f in m["findings"]:
            print(f"    Finding: {f['policy_name']} — {', '.join(f['reasons'])}")
            if f["policy_document"]:
                print(f"    Policy doc: {json.dumps(f['policy_document'])}")
        print()


if __name__ == "__main__":
    main()
