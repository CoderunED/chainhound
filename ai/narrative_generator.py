import json
import os
import anthropic

FINDINGS_MERGED_PATH = "data/findings_merged.json"
OUTPUT_PATH = "data/narratives.json"


def load_json(path):
    with open(path) as f:
        return json.load(f)


def build_prompt(record):
    s = record["summary"]
    nodes = record["nodes"]
    findings = record["findings"]

    # Build node descriptions
    node_lines = []
    for n in nodes:
        node_lines.append(f"  - {n['name']} (type: {n['type']}, ARN: {n['arn']})")
    nodes_text = "\n".join(node_lines)

    # Build finding descriptions
    finding_lines = []
    for f in findings:
        reasons = ", ".join(f["reasons"])
        doc = json.dumps(f.get("policy_document"), indent=2) if f.get("policy_document") else "N/A"
        finding_lines.append(
            f"  Policy: {f['policy_name']}\n"
            f"  Severity: {f['severity']} | Score: {f['score']}/100\n"
            f"  Reasons: {reasons}\n"
            f"  Policy Document:\n{doc}"
        )
    findings_text = "\n\n".join(finding_lines)

    prompt = f"""You are a cloud security analyst writing an attack path report for a security team.

Below is a detected IAM privilege escalation path in AWS. Analyze it and write a clear, technical narrative that explains:
1. Who the attacker is (entry point)
2. How they move through each hop (what IAM action they use at each step)
3. What they ultimately gain access to (terminal policy and its permissions)
4. Why this is dangerous (blast radius, data at risk)
5. A recommended remediation

Be specific, use the actual resource names, and write in a professional security report tone.
Do NOT use placeholder language like "[attacker]" — use the actual principal names.

---

ATTACK PATH SUMMARY
- Chain: {s['attack_chain']}
- Entry Point: {s['entry_point']}
- Terminal Policy: {s['terminal_policy']}
- Hops: {s['hops']}
- Risk Score: {s['score']}/100
- Severity: {s['severity']}

NODES IN PATH
{nodes_text}

FINDINGS
{findings_text}

---

Write the narrative now:"""

    return prompt


def generate_narrative(client, record):
    prompt = build_prompt(record)

    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    return message.content[0].text


def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY environment variable not set.")

    client = anthropic.Anthropic(api_key=api_key)

    print("[*] Loading merged findings...")
    records = load_json(FINDINGS_MERGED_PATH)
    print(f"    Records: {len(records)}")

    narratives = []

    for record in records:
        s = record["summary"]
        print(f"\n[*] Generating narrative for Path {record['path_id']} [{s['severity']}] — {s['attack_chain']}")

        narrative_text = generate_narrative(client, record)

        narratives.append({
            "path_id": record["path_id"],
            "severity": s["severity"],
            "score": s["score"],
            "attack_chain": s["attack_chain"],
            "narrative": narrative_text,
        })

        print(f"[+] Done. Preview:\n")
        # Print first 300 chars as preview
        print(f"    {narrative_text[:300].strip()}...")
        print()

    os.makedirs("data", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(narratives, f, indent=2)

    print(f"\n[+] Saved {len(narratives)} narrative(s) -> {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
