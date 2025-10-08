#!/usr/bin/env python3
"""
find_user_references.py

Find where an IAM *user* is referenced/used by scanning for that user's access keys (and optionally
the username/ARN strings) across common AWS configuration stores. Optionally, produce a recent
CloudTrail activity summary (services used by that user).

Scans CONFIG (string search):
- AWS Lambda environment variables
- AWS Secrets Manager secret values (JSON/text)
- AWS Systems Manager Parameter Store values
- AWS CodeBuild project environment variables
- (Optional) Amazon ECS task definition environment variables

Optional ACTIVITY (logs):
- CloudTrail LookupEvents (last ~90 days) summarized by service for the IAM Username

Usage:
  python find_user_references.py --iam-user my-ci-user --regions us-east-1,us-west-2
  python find_user_references.py --iam-user my-ci-user --regions us-east-1 --include-ecs --include-username-match
  python find_user_references.py --iam-user my-ci-user --cloudtrail-summary

Requirements:
- boto3, botocore
- Permissions:
  * iam:ListAccessKeys, iam:GetUser
  * lambda:ListFunctions, lambda:GetFunctionConfiguration
  * secretsmanager:ListSecrets, secretsmanager:GetSecretValue
  * ssm:DescribeParameters, ssm:GetParameters
  * codebuild:ListProjects, codebuild:BatchGetProjects
  * ecs:ListTaskDefinitions, ecs:DescribeTaskDefinition (if --include-ecs)
  * cloudtrail:LookupEvents (if --cloudtrail-summary)
"""
import argparse
import base64
import json
from collections import Counter
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError


def get_user_access_keys(username: str, region: Optional[str] = None) -> List[str]:
    iam = boto3.client("iam", region_name=region)
    resp = iam.list_access_keys(UserName=username)
    return [k["AccessKeyId"] for k in resp.get("AccessKeyMetadata", [])]


def get_user_identifiers(username: str, region: Optional[str] = None) -> Dict[str, str]:
    iam = boto3.client("iam", region_name=region)
    info = {"username": username, "arn": ""}
    try:
        u = iam.get_user(UserName=username)
        info["arn"] = u["User"]["Arn"]
    except ClientError:
        pass
    return info


def _contains_any(text: str, needles: List[str]) -> List[str]:
    if not isinstance(text, str):
        return []
    return [n for n in needles if n and n in text]


def scan_lambda(region: str, needles: List[str]):
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
            hit_keys = []
            for k, v in env.items():
                hits = _contains_any(v, needles)
                if hits:
                    hit_keys.append(f"{k} ({'|'.join(hits)})")
            if hit_keys:
                findings.append({
                    "service": "lambda",
                    "region": region,
                    "resource": fn["FunctionName"],
                    "detail": f"Env vars containing matches: {', '.join(hit_keys)}"
                })
    return findings


def scan_secrets_manager(region: str, needles: List[str]):
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
            hits = _contains_any(text, needles)
            if hits:
                findings.append({
                    "service": "secretsmanager",
                    "region": region,
                    "resource": meta.get("Name", sid),
                    "detail": f"Secret contains matches: {', '.join(hits)}"
                })
    return findings


def scan_ssm_parameters(region: str, needles: List[str]):
    client = boto3.client("ssm", region_name=region)
    findings = []
    paginator = client.get_paginator("describe_parameters")
    for page in paginator.paginate():
        names = [p["Name"] for p in page.get("Parameters", [])]
        if not names:
            continue
        for i in range(0, len(names), 10):
            batch = names[i:i+10]
            try:
                resp = client.get_parameters(Names=batch, WithDecryption=True)
            except ClientError:
                continue
            for par in resp.get("Parameters", []):
                val = par.get("Value", "")
                hits = _contains_any(val, needles)
                if hits:
                    findings.append({
                        "service": "ssm-parameter-store",
                        "region": region,
                        "resource": par["Name"],
                        "detail": f"Parameter contains matches: {', '.join(hits)}"
                    })
    return findings


def scan_codebuild(region: str, needles: List[str]):
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
            hits = []
            for e in env:
                v = e.get("value", "")
                sub = _contains_any(v, needles)
                if sub:
                    hits.append(f"{e['name']} ({'|'.join(sub)})")
            if hits:
                findings.append({
                    "service": "codebuild",
                    "region": region,
                    "resource": proj.get("name"),
                    "detail": f"Env vars containing matches: {', '.join(hits)}"
                })
    return findings


def scan_ecs(region: str, needles: List[str]):
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
                hits = []
                for e in env:
                    v = e.get("value", "")
                    sub = _contains_any(v, needles)
                    if sub:
                        hits.append(f"{e['name']} ({'|'.join(sub)})")
                if hits:
                    findings.append({
                        "service": "ecs-taskdef",
                        "region": region,
                        "resource": f"{family} / {c.get('name')}",
                        "detail": f"Container env vars containing matches: {', '.join(hits)}"
                    })
    return findings


def cloudtrail_summary_by_service(username: str, region: Optional[str] = None):
    ct = boto3.client("cloudtrail", region_name=region)
    token = None
    counts = Counter()
    while True:
        kwargs = {
            "LookupAttributes": [{"AttributeKey": "Username", "AttributeValue": username}],
            "MaxResults": 50,
        }
        if token:
            kwargs["NextToken"] = token
        try:
            resp = ct.lookup_events(**kwargs)
        except ClientError:
            break
        for ev in resp.get("Events", []):
            try:
                detail = json.loads(ev.get("CloudTrailEvent", "{}"))
                svc = detail.get("eventSource", "")
                if svc:
                    counts[svc] += 1
            except Exception:
                continue
        token = resp.get("NextToken")
        if not token:
            break
    return dict(counts.most_common())


def main():
    ap = argparse.ArgumentParser(description="Find references/usages of an IAM user across AWS config stores; optional CloudTrail summary.")
    ap.add_argument("--iam-user", required=True, help="IAM username to search for (e.g., my-ci-user)")
    ap.add_argument("--regions", default="", help="Comma-separated AWS regions to scan for config. If empty, use boto3 default.")
    ap.add_argument("--include-ecs", action="store_true", help="Include ECS task definition scan (slower).")
    ap.add_argument("--include-username-match", action="store_true",
                    help="Also search for username/ARN strings (in addition to access key IDs).")
    ap.add_argument("--cloudtrail-summary", action="store_true",
                    help="Summarize CloudTrail events by service for this Username (last ~90 days).")
    args = ap.parse_args()

    regions = [r.strip() for r in args.regions.split(",") if r.strip()] or [None]

    aks = get_user_access_keys(args.iam_user)
    ident = get_user_identifiers(args.iam_user)
    needles = aks.copy()
    if args.include_username_match:
        if ident.get("username"):
            needles.append(ident["username"])
        if ident.get("arn"):
            needles.append(ident["arn"])

    print(f"[*] IAM user: {args.iam_user}")
    print(f"[*] Access keys found: {len(aks)}")
    if aks:
        print("    - " + "\n    - ".join(aks))
    if args.include_username_match:
        print(f"[*] Also searching for username/ARN strings. ARN: {ident.get('arn','(unknown)')}")

    all_findings: List[Dict] = []

    for region in regions:
        all_findings.extend(scan_lambda(region, needles))
        all_findings.extend(scan_secrets_manager(region, needles))
        all_findings.extend(scan_ssm_parameters(region, needles))
        all_findings.extend(scan_codebuild(region, needles))
        if args.include_ecs:
            all_findings.extend(scan_ecs(region, needles))

    print('\n=== CONFIG FINDINGS ===')
    if not all_findings:
        print('No references found in scanned config stores.')
    else:
        for f in all_findings:
            print(f"[{f['service']}] {f['region'] or 'default'} :: {f['resource']} :: {f['detail']}")

    if args.cloudtrail_summary:
        print("\n=== CLOUDTRAIL SUMMARY (last ~90d, by eventSource) ===")
        summary = cloudtrail_summary_by_service(args.iam_user)
        if not summary:
            print("No events found or insufficient permissions.")
        else:
            for svc, cnt in summary.items():
                print(f"{svc}: {cnt}")

    print("\nJSON:")
    out = {
        "iam_user": args.iam_user,
        "needles": needles,
        "findings": all_findings,
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
