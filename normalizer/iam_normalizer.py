import json
import os

def normalize():
    with open("data/raw/iam_snapshot.json") as f:
        snapshot = json.load(f)

    nodes = []
    edges = []

    # --- User nodes ---
    for user in snapshot["users"]:
        nodes.append({
            "id": user["arn"],
            "type": "user",
            "name": user["name"],
            "arn": user["arn"]
        })

    # --- Role nodes + CAN_ASSUME edges from trust policies ---
    for role in snapshot["roles"]:
        # Skip AWS service roles
        if "aws-service-role" in role["arn"]:
            continue

        nodes.append({
            "id": role["arn"],
            "type": "role",
            "name": role["name"],
            "arn": role["arn"]
        })

        # Parse trust policy to find who can assume this role
        for statement in role["trust_policy"].get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue
            if statement.get("Action") != "sts:AssumeRole":
                continue

            principal = statement.get("Principal", {})

            # Only care about AWS principals (users/roles), not services
            aws_principal = principal.get("AWS")
            if not aws_principal:
                continue

            # Can be a string or a list
            if isinstance(aws_principal, str):
                aws_principal = [aws_principal]

            for source_arn in aws_principal:
                edges.append({
                    "source": source_arn,
                    "target": role["arn"],
                    "type": "CAN_ASSUME"
                })

    # --- Policy nodes + HAS_POLICY edges ---
    for policy in snapshot["policies"]:
        nodes.append({
            "id": policy["arn"],
            "type": "policy",
            "name": policy["name"],
            "arn": policy["arn"],
            "document": policy["document"]
        })

    # Link roles to their attached policies
    for role in snapshot["roles"]:
        if "aws-service-role" in role["arn"]:
            continue
        for attached in role.get("attached_policies", []):
            edges.append({
                "source": role["arn"],
                "target": attached["arn"],
                "type": "HAS_POLICY"
            })

    # Link users to their attached policies
    for user in snapshot["users"]:
        for attached in user.get("attached_policies", []):
            edges.append({
                "source": user["arn"],
                "target": attached["arn"],
                "type": "HAS_POLICY"
            })

    # --- Save ---
    os.makedirs("data/normalized", exist_ok=True)

    with open("data/normalized/principals.json", "w") as f:
        json.dump(nodes, f, indent=2)

    with open("data/normalized/edges.json", "w") as f:
        json.dump(edges, f, indent=2)

    print(f"[+] Normalization complete")
    print(f"    Nodes: {len(nodes)}")
    print(f"    Edges: {len(edges)}")
    return nodes, edges

if __name__ == "__main__":
    normalize()
