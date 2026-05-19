import boto3
import json
import os
from datetime import datetime,timezone

def collect_iam():
    client = boto3.client('iam')
    snapshot = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "users": [],
        "roles": [],
        "policies": []
    }

    # --- Users ---
    print("[*] Collecting users...")
    paginator = client.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            user_data = {
                "name": user['UserName'],
                "arn": user['Arn'],
                "user_id": user['UserId'],
                "attached_policies": []
            }
            # Get policies attached directly to user
            attached = client.list_attached_user_policies(UserName=user['UserName'])
            for policy in attached['AttachedPolicies']:
                user_data['attached_policies'].append({
                    "name": policy['PolicyName'],
                    "arn": policy['PolicyArn']
                })
            snapshot['users'].append(user_data)

    # --- Roles ---
    print("[*] Collecting roles...")
    paginator = client.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            role_data = {
                "name": role['RoleName'],
                "arn": role['Arn'],
                "role_id": role['RoleId'],
                "trust_policy": role['AssumeRolePolicyDocument'],
                "attached_policies": []
            }
            # Get policies attached to role
            attached = client.list_attached_role_policies(RoleName=role['RoleName'])
            for policy in attached['AttachedPolicies']:
                role_data['attached_policies'].append({
                    "name": policy['PolicyName'],
                    "arn": policy['PolicyArn']
                })
            snapshot['roles'].append(role_data)

    # --- Customer managed policies (with their actual statements) ---
    print("[*] Collecting policies...")
    paginator = client.get_paginator('list_policies')
    for page in paginator.paginate(Scope='Local'):  # Local = customer managed only
        for policy in page['Policies']:
            # Get the actual policy document
            version = client.get_policy_version(
                PolicyArn=policy['Arn'],
                VersionId=policy['DefaultVersionId']
            )
            policy_data = {
                "name": policy['PolicyName'],
                "arn": policy['Arn'],
                "policy_id": policy['PolicyId'],
                "document": version['PolicyVersion']['Document']
            }
            snapshot['policies'].append(policy_data)

    # --- Save ---
    os.makedirs("data/raw", exist_ok=True)
    output_path = "data/raw/iam_snapshot.json"
    with open(output_path, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)

    print(f"[+] Snapshot saved to {output_path}")
    print(f"    Users:    {len(snapshot['users'])}")
    print(f"    Roles:    {len(snapshot['roles'])}")
    print(f"    Policies: {len(snapshot['policies'])}")
    return snapshot

if __name__ == "__main__":
    collect_iam()
