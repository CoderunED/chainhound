import json
import os

def build_graph():
    with open("data/normalized/principals.json") as f:
        nodes = json.load(f)

    with open("data/normalized/edges.json") as f:
        edges = json.load(f)

    # Index nodes by ID for quick lookup
    node_index = {node["id"]: node for node in nodes}

    # Build adjacency list (who can reach what)
    adjacency = {}
    for edge in edges:
        src = edge["source"]
        tgt = edge["target"]
        if src not in adjacency:
            adjacency[src] = []
        adjacency[src].append({
            "target": tgt,
            "type": edge["type"]
        })

    # Find all attack paths using DFS
    # A path is: user -> role(s) -> policy
    paths = []

    def dfs(current_arn, current_path, visited):
        current_node = node_index.get(current_arn)
        if not current_node:
            return

        # If we've reached a policy node, record the path
        if current_node["type"] == "policy":
            paths.append(list(current_path))
            return

        neighbors = adjacency.get(current_arn, [])
        for neighbor in neighbors:
            tgt = neighbor["target"]
            if tgt not in visited:
                visited.add(tgt)
                current_path.append(tgt)
                dfs(tgt, current_path, visited)
                current_path.pop()
                visited.remove(tgt)

    # Start DFS from every user node
    for node in nodes:
        if node["type"] == "user":
            dfs(node["id"], [node["id"]], {node["id"]})

    # Build graph output
    graph = {
        "nodes": nodes,
        "edges": edges,
        "adjacency": adjacency,
        "paths": paths,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_paths": len(paths),
            "users": len([n for n in nodes if n["type"] == "user"]),
            "roles": len([n for n in nodes if n["type"] == "role"]),
            "policies": len([n for n in nodes if n["type"] == "policy"])
        }
    }

    os.makedirs("data", exist_ok=True)
    with open("data/graph.json", "w") as f:
        json.dump(graph, f, indent=2)

    print(f"[+] Graph built")
    print(f"    Nodes:  {graph['summary']['total_nodes']}")
    print(f"    Edges:  {graph['summary']['total_edges']}")
    print(f"    Paths:  {graph['summary']['total_paths']}")
    print()
    print("[*] Attack paths found:")
    for i, path in enumerate(paths):
        # Resolve ARNs to names for readability
        names = []
        for arn in path:
            node = node_index.get(arn)
            names.append(node["name"] if node else arn)
        print(f"    Path {i+1}: {' -> '.join(names)}")

    return graph

if __name__ == "__main__":
    build_graph()
