#!/usr/bin/env python3
"""
bedrock_auditor.py — AI-Powered AWS Security Auditor using Amazon Bedrock
=========================================================================
Runs your existing aws-auditor checks, then passes findings to Claude
(via AWS Bedrock) for AI-powered analysis, severity scoring, remediation
advice, and dynamic suggestions for additional checks to run.

Usage:
    python bedrock_auditor.py                        # run all checks
    python bedrock_auditor.py --checks iam sg        # specific checks
    python bedrock_auditor.py --output report.json   # save full report
    python bedrock_auditor.py --region us-east-1     # custom region

Requirements:
    pip install boto3 colorama

IAM Permissions needed:
    - SecurityAudit (existing)
    - bedrock:InvokeModel on anthropic.claude-* ARNs
"""

import argparse
import json
import subprocess
import sys
import os
from datetime import datetime
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

BEDROCK_MODEL_ID = "amazon.nova-lite-v1:0"  # fast + cheap
BEDROCK_REGION   = "us-east-1"                                # change if needed

# ─────────────────────────────────────────────
# Color helpers
# ─────────────────────────────────────────────

def red(t):    return f"{Fore.RED}{t}{Style.RESET_ALL}"    if COLOR else t
def yellow(t): return f"{Fore.YELLOW}{t}{Style.RESET_ALL}" if COLOR else t
def green(t):  return f"{Fore.GREEN}{t}{Style.RESET_ALL}"  if COLOR else t
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}"   if COLOR else t
def bold(t):   return f"{Style.BRIGHT}{t}{Style.RESET_ALL}" if COLOR else t

def severity_color(sev: str) -> str:
    sev = sev.upper()
    if sev == "HIGH":     return red(f"[{sev}]")
    if sev == "MEDIUM":   return yellow(f"[{sev}]")
    if sev == "LOW":      return green(f"[{sev}]")
    return f"[{sev}]"

# ─────────────────────────────────────────────
# Step 1: Run existing auditor, capture JSON
# ─────────────────────────────────────────────

def run_existing_auditor(checks: Optional[list]) -> list:
    """
    Calls main.py --output /tmp/audit_raw.json to capture findings.
    Returns list of finding dicts.
    """
    tmp_output = "/tmp/audit_raw.json"
    cmd = [sys.executable, "main.py", "--output", tmp_output]

    if checks:
        cmd += ["--checks"] + checks

    print(bold("\n━━━ Phase 1: Running AWS Security Checks ━━━"))
    print(cyan(f"  Command: {' '.join(cmd)}\n"))

    try:
        result = subprocess.run(cmd, capture_output=False, text=True)
    except FileNotFoundError:
        print(red("  ✗ main.py not found. Run this script from your aws-auditor root directory."))
        sys.exit(1)

    if not os.path.exists(tmp_output):
        print(red("  ✗ main.py did not produce output JSON. Check your aws-auditor setup."))
        sys.exit(1)

    with open(tmp_output) as f:
        data = json.load(f)

    # Support both list format and {"findings": [...]} format
    findings = data if isinstance(data, list) else data.get("findings", [])
    print(green(f"\n  ✓ Captured {len(findings)} finding(s) from auditor."))
    return findings

# ─────────────────────────────────────────────
# Step 2: Call Bedrock (Claude) for AI analysis
# ─────────────────────────────────────────────

def build_prompt(findings: list) -> str:
    findings_text = json.dumps(findings, indent=2)
    return f"""You are an expert AWS Cloud Security Engineer performing a security audit review.

Below are raw findings from an automated AWS security scanner. Your job is to:

1. Analyze each finding and assign a risk score (1-10)
2. Write a clear, concise remediation for each finding
3. Suggest 3-5 ADDITIONAL AWS security checks that were NOT run but would be valuable
   (be specific — name the AWS service, what to check, and why)
4. Write an executive summary (3-4 sentences) of the overall security posture

Return your response as valid JSON only — no markdown, no preamble, no explanation outside the JSON.

Schema:
{{
  "executive_summary": "string",
  "overall_risk": "LOW | MEDIUM | HIGH | CRITICAL",
  "analyzed_findings": [
    {{
      "title": "string (match original finding title)",
      "original_severity": "string",
      "risk_score": integer (1-10),
      "ai_severity": "LOW | MEDIUM | HIGH | CRITICAL",
      "remediation": "string (step-by-step, actionable)",
      "aws_docs_hint": "string (service + feature name to look up)"
    }}
  ],
  "suggested_additional_checks": [
    {{
      "check_name": "string",
      "aws_service": "string",
      "what_to_look_for": "string",
      "why_it_matters": "string",
      "severity_if_found": "LOW | MEDIUM | HIGH | CRITICAL"
    }}
  ]
}}

Raw findings:
{findings_text}
"""

def invoke_bedrock(findings: list) -> dict:
    """Sends findings to Claude via Bedrock and returns parsed JSON analysis."""
    print(bold("\n━━━ Phase 2: AI Analysis via AWS Bedrock ━━━"))
    print(cyan(f"  Model  : {BEDROCK_MODEL_ID}"))
    print(cyan(f"  Region : {BEDROCK_REGION}"))
    print(cyan(f"  Sending {len(findings)} finding(s) for analysis...\n"))

    try:
        client = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)
    except NoCredentialsError:
        print(red("  ✗ No AWS credentials found. Run: aws configure"))
        sys.exit(1)

    prompt = build_prompt(findings)

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    try:
        response = client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(body),
            contentType="application/json",
            accept="application/json"
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg  = e.response["Error"]["Message"]
        print(red(f"  ✗ Bedrock API error [{code}]: {msg}"))
        if code == "AccessDeniedException":
            print(yellow("  → Attach bedrock:InvokeModel permission to your IAM user/role."))
            print(yellow(f"  → Resource ARN: arn:aws:bedrock:{BEDROCK_REGION}::foundation-model/{BEDROCK_MODEL_ID}"))
        sys.exit(1)

    raw = json.loads(response["body"].read())
    text = raw["content"][0]["text"].strip()

    # Strip any accidental markdown fences
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    text = text.strip()

    try:
        analysis = json.loads(text)
        print(green("  ✓ Bedrock analysis received and parsed successfully."))
        return analysis
    except json.JSONDecodeError as e:
        print(red(f"  ✗ Failed to parse Bedrock response as JSON: {e}"))
        print(yellow("  Raw response:"))
        print(text[:500])
        sys.exit(1)

# ─────────────────────────────────────────────
# Step 3: Print AI-enhanced report
# ─────────────────────────────────────────────

def print_report(findings: list, analysis: dict) -> None:
    print(bold("\n" + "═" * 60))
    print(bold("  AI-POWERED AWS SECURITY AUDIT REPORT"))
    print(bold("  Powered by Amazon Bedrock + Claude"))
    print(bold("  " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    print(bold("═" * 60))

    # Executive summary
    overall = analysis.get("overall_risk", "UNKNOWN")
    color_fn = red if overall in ("HIGH", "CRITICAL") else yellow if overall == "MEDIUM" else green
    print(f"\n{bold('OVERALL RISK:')} {color_fn(overall)}")
    print(f"\n{bold('EXECUTIVE SUMMARY:')}")
    print(f"  {analysis.get('executive_summary', 'N/A')}\n")

    # Analyzed findings
    print(bold("─" * 60))
    print(bold("  FINDINGS WITH AI ANALYSIS"))
    print(bold("─" * 60))

    analyzed = analysis.get("analyzed_findings", [])
    for i, item in enumerate(analyzed, 1):
        ai_sev   = item.get("ai_severity", "UNKNOWN")
        score    = item.get("risk_score", "?")
        title    = item.get("title", "Unknown Finding")
        remediation = item.get("remediation", "N/A")
        docs     = item.get("aws_docs_hint", "")

        print(f"\n  {bold(str(i)+'.')} {severity_color(ai_sev)} {bold(title)}")
        print(f"     Risk Score  : {score}/10")
        print(f"     Remediation : {remediation}")
        if docs:
            print(f"     AWS Docs    : {cyan(docs)}")

    # Suggested additional checks
    print(f"\n{bold('─' * 60)}")
    print(bold("  AI-SUGGESTED ADDITIONAL CHECKS"))
    print(bold("─" * 60))

    suggestions = analysis.get("suggested_additional_checks", [])
    for i, s in enumerate(suggestions, 1):
        sev  = s.get("severity_if_found", "UNKNOWN")
        name = s.get("check_name", "N/A")
        svc  = s.get("aws_service", "")
        what = s.get("what_to_look_for", "")
        why  = s.get("why_it_matters", "")

        print(f"\n  {bold(str(i)+'.')} {severity_color(sev)} {bold(name)}")
        if svc:  print(f"     Service     : {cyan(svc)}")
        if what: print(f"     Check For   : {what}")
        if why:  print(f"     Why         : {why}")

    # Summary counts
    total = len(analyzed)
    high  = sum(1 for f in analyzed if f.get("ai_severity") in ("HIGH", "CRITICAL"))
    med   = sum(1 for f in analyzed if f.get("ai_severity") == "MEDIUM")
    low   = sum(1 for f in analyzed if f.get("ai_severity") == "LOW")

    print(f"\n{bold('═' * 60)}")
    print(f"  Total Findings : {total}  |  "
          f"{red('High/Critical: '+str(high))}  |  "
          f"{yellow('Medium: '+str(med))}  |  "
          f"{green('Low: '+str(low))}")
    print(bold("═" * 60 + "\n"))

# ─────────────────────────────────────────────
# Step 4: Save full report
# ─────────────────────────────────────────────

def save_report(findings: list, analysis: dict, output_path: str) -> None:
    report = {
        "generated_at": datetime.now().isoformat(),
        "model": BEDROCK_MODEL_ID,
        "raw_findings": findings,
        "ai_analysis": analysis
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(green(f"  ✓ Full report saved to: {output_path}\n"))

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="AI-Powered AWS Security Auditor using Amazon Bedrock"
    )
    parser.add_argument(
        "--checks", nargs="+",
        choices=["iam", "s3", "cloudtrail", "sg"],
        help="Specific checks to run (default: all)"
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Path to save the full JSON report (optional)"
    )
    parser.add_argument(
        "--region", type=str, default=BEDROCK_REGION,
        help=f"AWS region for Bedrock (default: {BEDROCK_REGION})"
    )
    parser.add_argument(
        "--model", type=str, default=BEDROCK_MODEL_ID,
        help="Bedrock model ID to use"
    )
    return parser.parse_args()

def main():
    args = parse_args()

    # Allow region/model override via args
    global BEDROCK_REGION, BEDROCK_MODEL_ID
    BEDROCK_REGION   = args.region
    BEDROCK_MODEL_ID = args.model

    print(bold(cyan("\n  AWS Bedrock AI Auditor — Starting...\n")))

    # Phase 1: run auditor
    findings = run_existing_auditor(args.checks)

    if not findings:
        print(yellow("\n  No findings returned by auditor. Nothing to analyze."))
        sys.exit(0)

    # Phase 2: Bedrock analysis
    analysis = invoke_bedrock(findings)

    # Phase 3: print report
    print_report(findings, analysis)

    # Phase 4: save if requested
    if args.output:
        save_report(findings, analysis, args.output)

if __name__ == "__main__":
    main()