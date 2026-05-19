import json
import os

SENSITIVE_SERVICES = [
    "iam", "sts", "s3", "ec2", "lambda",
    "secretsmanager", "ssm", "kms", "cloudtrail"
]

# ── Privilege escalation action sets ──────────────────────────────────────────

PASSROLE_ACTIONS = {"iam:passrole"}

IAM_ESCALATION_ACTIONS = {
    "iam:createpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:attachgrouppolicy",
    "iam:putuserolicy",
    "iam:putrolepolicy",
    "iam:addusertgroup",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateloginprofile",
    "iam:sedefaultpolicyversion",
}

COMPUTE_ACTIONS = {
    "lambda:createfunction",
    "lambda:updatefunctioncode",
    "lambda:invokefunction",
    "ec2:runinstances",
    "ecs:runtask",
    "glue:createjob",
    "glue:updatejob",
    "sagemaker:createtrainingjob",
}

ASSUME_ROLE_ACTIONS = {"sts:assumerole"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_actions(action):
    """Always return a flat list of lowercase action strings."""
    if isinstance(action, str):
        return [action.lower()]
    if isinstance(action, list):
        return [a.lower() for a in action]
    return []

def is_wildcard_action(action):
    if isinstance(action, str):
        return action == "*" or action.endswith(":*")
    if isinstance(action, list):
        return any(is_wildcard_action(a) for a in action)
    return False

def is_wildcard_resource(resource):
    if isinstance(resource, str):
        return resource == "*"
    if isinstance(resource, list):
        return any(r == "*" for r in resource)
    return False

def get_sensitive_services(action):
    found = []
    for a in normalize_actions(action):
        service = a.split(":")[0]
        if service in SENSITIVE_SERVICES:
            found.append(service)
    return list(set(found))

def actions_intersect(action, target_set):
    """Check if any action in the statement matches the target set."""
    normalized = normalize_actions(action)
    # Also handle wildcard — iam:* covers all iam actions
    for a in normalized:
        if a in target_set:
            return True
        service = a.split(":")[0]
        if f"{service}:*" in target_set or a == "*":
            return True
    return False

def has_action(action, target_set):
    return actions_intersect(action, target_set)


# ── Analyzers ─────────────────────────────────────────────────────────────────

def analyze_policy(policy):
    findings = []
    document = policy.get("document", {})
    statements = document.get("Statement", [])

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        action   = stmt.get("Action", [])
        resource = stmt.get("Resource", [])
        wc_action   = is_wildcard_action(action)
        wc_resource = is_wildcard_resource(resource)
        sensitive   = get_sensitive_services(action)

        base = {
            "policy_name": policy["name"],
            "policy_arn":  policy["arn"],
            "action":      action,
            "resource":    resource,
            "sensitive_services": sensitive,
        }

        # ── Existing: wildcard detections ────────────────────────────────────
        if wc_action and wc_resource:
            findings.append({**base,
                "issue": "Wildcard action on wildcard resource",
                "severity": "CRITICAL",
                "detector": "wildcard"
            })
        elif wc_action:
            findings.append({**base,
                "issue": "Wildcard action on specific resource",
                "severity": "HIGH",
                "detector": "wildcard"
            })
        elif wc_resource and sensitive:
            findings.append({**base,
                "issue": "Sensitive service action on wildcard resource",
                "severity": "HIGH",
                "detector": "wildcard"
            })

        # ── New: iam:PassRole ─────────────────────────────────────────────────
        if has_action(action, PASSROLE_ACTIONS) or wc_action:
            if wc_resource:
                findings.append({**base,
                    "issue": "iam:PassRole on wildcard resource — can pass any role to AWS services",
                    "severity": "CRITICAL",
                    "detector": "passrole"
                })
            else:
                findings.append({**base,
                    "issue": "iam:PassRole on specific resource — may allow role escalation via AWS services",
                    "severity": "HIGH",
                    "detector": "passrole"
                })

        # ── New: IAM self-escalation actions ─────────────────────────────────
        matched_iam = [
            a for a in normalize_actions(action)
            if a in IAM_ESCALATION_ACTIONS
        ]
        if matched_iam or wc_action:
            triggers = matched_iam if matched_iam else ["wildcard covers IAM"]
            findings.append({**base,
                "issue": f"IAM escalation action(s) detected: {', '.join(triggers)}",
                "severity": "CRITICAL",
                "detector": "iam_escalation"
            })

        # ── New: sts:AssumeRole on wildcard ───────────────────────────────────
        if has_action(action, ASSUME_ROLE_ACTIONS) and wc_resource:
            findings.append({**base,
                "issue": "sts:AssumeRole on wildcard resource — can assume any role in the account",
                "severity": "CRITICAL",
                "detector": "assume_role_wildcard"
            })

        # ── New: Compute + PassRole combo (Lambda/EC2 escalation) ─────────────
        has_compute  = has_action(action, COMPUTE_ACTIONS) or wc_action
        has_passrole = has_action(action, PASSROLE_ACTIONS) or wc_action
        if has_compute and has_passrole:
            findings.append({**base,
                "issue": "Compute action + iam:PassRole — can deploy Lambda/EC2 with a privileged role",
                "severity": "CRITICAL",
                "detector": "compute_passrole"
            })

    # Deduplicate by (policy_name, detector, issue)
    seen = set()
    deduped = []
    for f in findings:
        key = (f["policy_name"], f.get("detector"), f["issue"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped


def detect_risks():
    with open("data/normalized/principals.json") as f:
        nodes = json.load(f)

    all_findings = []
    policies = [n for n in nodes if n["type"] == "policy"]

    for policy in policies:
        findings = analyze_policy(policy)
        all_findings.extend(findings)

    os.makedirs("data", exist_ok=True)
    with open("data/findings.json", "w") as f:
        json.dump(all_findings, f, indent=2)

    print(f"[+] Risk detection complete")
    print(f"    Policies scanned: {len(policies)}")
    print(f"    Findings:         {len(all_findings)}")
    print()
    for f in all_findings:
        print(f"    [{f['severity']}] {f['policy_name']} — {f['issue']}")
        print(f"             detector: {f['detector']}")

    return all_findings


if __name__ == "__main__":
    detect_risks()
