#!/usr/bin/env python3
"""
find_key_references.py

Find references to an AWS Access Key ID across common AWS services so you can locate
where static credentials are configured. This does NOT query CloudTrail (use CloudTrail Lake/Athena
for historical usage). Instead, it scans configuration stores.

Scanned:
- AWS Lambda environment variables
- AWS Secrets Manager secret values (JSON/text)
- AWS Systems Manager Parameter Store values
- AWS CodeBuild project environment variables
- (Optional) Amazon ECS task definition container environment variables

Usage:
  python find_key_references.py --access-key-id AKIA... --regions us-east-1,us-west-2
  python find_key_references.py --access-key-id AKIA... --regions us-east-1 --include-ecs

Notes:
- Requires boto3 (pip install boto3, botocore).
- Your IAM principal must have read permissions for each service queried.
- Scanning all SSM parameters can be slow in large accounts.
"""
import argparse
import base64
import json
from typing import Dict, List

import boto3
from botocore.exceptions import ClientError


def search_in_text(text: str, needle: str) -> bool:
    return needle in text if text else False


def scan_lambda(region: str, key_id: str):
    client = boto3.client("lambda", region_name=region)
    findings = []
    paginator = client.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            try:
                conf = client.get_function_configuration(FunctionName=fn["FunctionName"])
            except ClientError:
                continue
            env = (conf.get("Environment") or {}).get("Variables") or {}
            hit_keys = [k for k, v in env.items() if isinstance(v, str) and key_id in v]
            if hit_keys:
                findings.append({
                    "service": "lambda",
                    "region": region,
                    "resource": fn["FunctionName"],
                    "detail": f"Env vars containing key id: {', '.join(hit_keys)}"
                })
    return findings


def scan_secrets_manager(region: str, key_id: str):
    client = boto3.client("secretsmanager", region_name=region)
    findings = []
    paginator = client.get_paginator("list_secrets")
    for page in paginator.paginate():
        for meta in page.get("SecretList", []):
            sid = meta["ARN"]
            try:
                val = client.get_secret_value(SecretId=sid)
            except ClientError:
                continue
            text = ""
            if "SecretString" in val:
                text = val["SecretString"]
            elif "SecretBinary" in val:
                try:
                    import base64 as b64
                    text = b64.b64decode(val["SecretBinary"]).decode("utf-8", errors="ignore")
                except Exception:
                    text = ""
            if text and key_id in text:
                findings.append({
                    "service": "secretsmanager",
                    "region": region,
                    "resource": meta.get("Name", sid),
                    "detail": "SecretString/SecretBinary contains the key id"
                })
    return findings


def scan_ssm_parameters(region: str, key_id: str):
    client = boto3.client("ssm", region_name=region)
    findings = []
    paginator = client.get_paginator("describe_parameters")
    for page in paginator.paginate():
        names = [p["Name"] for p in page.get("Parameters", [])]
        if not names:
            continue
        # Fetch values in batches of 10 (API limit 10 per call)
        for i in range(0, len(names), 10):
            batch = names[i:i+10]
            try:
                resp = client.get_parameters(Names=batch, WithDecryption=True)
            except ClientError:
                continue
            for par in resp.get("Parameters", []):
                val = par.get("Value", "")
                if isinstance(val, str) and key_id in val:
                    findings.append({
                        "service": "ssm-parameter-store",
                        "region": region,
                        "resource": par["Name"],
                        "detail": "Parameter value contains the key id"
                    })
    return findings


def scan_codebuild(region: str, key_id: str):
    client = boto3.client("codebuild", region_name=region)
    findings = []
    try:
        projects = client.list_projects().get("projects", [])
    except ClientError:
        return findings
    for i in range(0, len(projects), 100):
        batch = projects[i:i+100]
        try:
            resp = client.batch_get_projects(names=batch)
        except ClientError:
            continue
        for proj in resp.get("projects", []):
            env = (proj.get("environment") or {}).get("environmentVariables", [])
            hits = [e["name"] for e in env if isinstance(e.get("value"), str) and key_id in e.get("value", "")]
            if hits:
                findings.append({
                    "service": "codebuild",
                    "region": region,
                    "resource": proj.get("name"),
                    "detail": f"Environment variables containing key id: {', '.join(hits)}"
                })
    return findings


def scan_ecs(region: str, key_id: str):
    client = boto3.client("ecs", region_name=region)
    findings = []
    paginator = client.get_paginator("list_task_definitions")
    for page in paginator.paginate(status="ACTIVE"):
        arns = page.get("taskDefinitionArns", [])
        for arn in arns:
            try:
                td = client.describe_task_definition(taskDefinition=arn)
            except ClientError:
                continue
            family = td["taskDefinition"]["family"]
            containers = td["taskDefinition"].get("containerDefinitions", [])
            for c in containers:
                env = c.get("environment", [])
                hits = [e["name"] for e in env if isinstance(e.get("value"), str) and key_id in e.get("value", "")]
                if hits:
                    findings.append({
                        "service": "ecs-taskdef",
                        "region": region,
                        "resource": f"{family} / {c.get('name')}",
                        "detail": f"Container env vars containing key id: {', '.join(hits)}"
                    })
    return findings


def main():
    ap = argparse.ArgumentParser(description="Find references to an AWS Access Key ID across common services.")
    ap.add_argument("--access-key-id", required=True, help="Access Key ID to search for, e.g., AKIA...")
    ap.add_argument("--regions", default="", help="Comma-separated list of regions. If empty, use boto3 default.")
    ap.add_argument("--include-ecs", action="store_true", help="Include ECS task definition scan (can be slow).")
    args = ap.parse_args()

    regions = [r.strip() for r in args.regions.split(",") if r.strip()] or [None]

    all_findings: List[Dict] = []

    for region in regions:
        all_findings.extend(scan_lambda(region, args.access_key_id))
        all_findings.extend(scan_secrets_manager(region, args.access_key_id))
        all_findings.extend(scan_ssm_parameters(region, args.access_key_id))
        all_findings.extend(scan_codebuild(region, args.access_key_id))
        if args.include_ecs:
            all_findings.extend(scan_ecs(region, args.access_key_id))

    # Print report
    print("\n=== Findings ===")
    if not all_findings:
        print("No references found.")
    else:
        for f in all_findings:
            print(f"[{f['service']}] {f['region'] or 'default'} :: {f['resource']} :: {f['detail']}")

    # Also output JSON
    print("\nJSON:")
    print(json.dumps(all_findings, indent=2))


if __name__ == "__main__":
    main()
