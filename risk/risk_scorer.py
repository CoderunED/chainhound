import json
import os

SEVERITY_BASE_SCORES = {
    "CRITICAL": 90,
    "HIGH":     70,
    "MEDIUM":   40,
    "LOW":      20
}

WILDCARD_ACTION_BONUS   = 10
WILDCARD_RESOURCE_BONUS = 10
SENSITIVE_SERVICE_BONUS = 5

# Bonus per detector type — reflects real-world exploitability
DETECTOR_BONUS = {
    "wildcard":             0,   # already captured by wildcard bonuses
    "passrole":             8,   # active exploitation path
    "iam_escalation":       10,  # persistence risk, high severity
    "assume_role_wildcard": 8,   # lateral movement across account
    "compute_passrole":     12,  # most dangerous — code execution + privilege
}


def score_finding(finding):
    score = SEVERITY_BASE_SCORES.get(finding["severity"], 20)

    action   = finding.get("action", [])
    resource = finding.get("resource", [])
    sensitive = finding.get("sensitive_services", [])
    detector  = finding.get("detector", "wildcard")

    # Wildcard action bonus
    if isinstance(action, str):
        if action == "*" or action.endswith(":*"):
            score += WILDCARD_ACTION_BONUS
    elif isinstance(action, list):
        if any(a == "*" or a.endswith(":*") for a in action):
            score += WILDCARD_ACTION_BONUS

    # Wildcard resource bonus
    if resource == "*" or (isinstance(resource, list) and "*" in resource):
        score += WILDCARD_RESOURCE_BONUS

    # Sensitive service bonus
    score += len(sensitive) * SENSITIVE_SERVICE_BONUS

    # Detector-specific exploitability bonus
    score += DETECTOR_BONUS.get(detector, 0)

    return min(score, 100)


def score_risks():
    with open("data/findings.json") as f:
        findings = json.load(f)

    scored = []
    for finding in findings:
        risk_score = score_finding(finding)
        scored.append({**finding, "risk_score": risk_score})

    scored.sort(key=lambda x: x["risk_score"], reverse=True)

    with open("data/findings_scored.json", "w") as f:
        json.dump(scored, f, indent=2)

    print(f"[+] Scoring complete")
    for f in scored:
        print(f"    [{f['severity']}] {f['policy_name']} ({f.get('detector','?')}) — score: {f['risk_score']}/100")

    return scored


if __name__ == "__main__":
    score_risks()
