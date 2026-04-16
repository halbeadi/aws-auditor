#!/usr/bin/env python3
"""
groq_auditor.py — AI-Powered AWS Security Auditor using Groq + Llama 3
"""

import argparse
import json
import subprocess
import sys
import os
from datetime import datetime
from typing import Optional

from groq import Groq

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

GROQ_MODEL = "llama-3.3-70b-versatile"

def red(t):    return f"{Fore.RED}{t}{Style.RESET_ALL}"    if COLOR else t
def yellow(t): return f"{Fore.YELLOW}{t}{Style.RESET_ALL}" if COLOR else t
def green(t):  return f"{Fore.GREEN}{t}{Style.RESET_ALL}"  if COLOR else t
def cyan(t):   return f"{Fore.CYAN}{t}{Style.RESET_ALL}"   if COLOR else t
def bold(t):   return f"{Style.BRIGHT}{t}{Style.RESET_ALL}" if COLOR else t

def severity_color(sev):
    sev = sev.upper()
    if sev in ("HIGH","CRITICAL"): return red(f"[{sev}]")
    if sev == "MEDIUM":            return yellow(f"[{sev}]")
    return green(f"[{sev}]")

def run_existing_auditor(checks):
    tmp_output = "/tmp/audit_raw.json"
    cmd = [sys.executable, "main.py", "--output", tmp_output]
    if checks:
        cmd += ["--checks"] + checks
    print(bold("\n━━━ Phase 1: Running AWS Security Checks ━━━"))
    subprocess.run(cmd, text=True)
    if not os.path.exists(tmp_output):
        print(red("  ✗ main.py did not produce output JSON."))
        sys.exit(1)
    with open(tmp_output) as f:
        data = json.load(f)
    findings = data if isinstance(data, list) else data.get("findings", [])
    print(green(f"\n  ✓ Captured {len(findings)} finding(s) from auditor."))
    return findings

def invoke_groq(findings, api_key):
    print(bold("\n━━━ Phase 2: AI Analysis via Groq + Llama 3 ━━━"))
    print(cyan(f"  Model  : {GROQ_MODEL}"))
    print(cyan(f"  Sending {len(findings)} finding(s) for analysis...\n"))

    client = Groq(api_key=api_key)

    prompt = f"""You are an expert AWS Cloud Security Engineer performing a security audit review.

Below are raw findings from an automated AWS security scanner. Your job is to:
1. Analyze each finding and assign a risk score (1-10)
2. Write a clear, concise remediation for each finding
3. Suggest 3-5 ADDITIONAL AWS security checks not already run
4. Write an executive summary (3-4 sentences) of the overall security posture

Return your response as valid JSON only — no markdown, no preamble.

Schema:
{{
  "executive_summary": "string",
  "overall_risk": "LOW | MEDIUM | HIGH | CRITICAL",
  "analyzed_findings": [
    {{
      "title": "string",
      "original_severity": "string",
      "risk_score": integer,
      "ai_severity": "LOW | MEDIUM | HIGH | CRITICAL",
      "remediation": "string",
      "aws_docs_hint": "string"
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
{json.dumps(findings, indent=2)}"""

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=4096,
        temperature=0.3
    )

    text = response.choices[0].message.content.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    text = text.strip()

    try:
        analysis = json.loads(text)
        print(green("  ✓ Groq analysis received and parsed successfully."))
        return analysis
    except json.JSONDecodeError as e:
        print(red(f"  ✗ Failed to parse response as JSON: {e}"))
        print(text[:500])
        sys.exit(1)

def print_report(findings, analysis):
    print(bold("\n" + "═"*60))
    print(bold("  AI-POWERED AWS SECURITY AUDIT REPORT"))
    print(bold("  Powered by Groq + Llama 3"))
    print(bold("  " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    print(bold("═"*60))

    overall = analysis.get("overall_risk", "UNKNOWN")
    color_fn = red if overall in ("HIGH","CRITICAL") else yellow if overall == "MEDIUM" else green
    print(f"\n{bold('OVERALL RISK:')} {color_fn(overall)}")
    print(f"\n{bold('EXECUTIVE SUMMARY:')}")
    print(f"  {analysis.get('executive_summary','N/A')}\n")

    print(bold("─"*60))
    print(bold("  FINDINGS WITH AI ANALYSIS"))
    print(bold("─"*60))

    for i, item in enumerate(analysis.get("analyzed_findings",[]), 1):
        print(f"\n  {bold(str(i)+'.')} {severity_color(item.get('ai_severity','?'))} {bold(item.get('title',''))}")
        print(f"     Risk Score  : {item.get('risk_score','?')}/10")
        print(f"     Remediation : {item.get('remediation','N/A')}")
        if item.get('aws_docs_hint'):
            print(f"     AWS Docs    : {cyan(item['aws_docs_hint'])}")

    print(f"\n{bold('─'*60)}")
    print(bold("  AI-SUGGESTED ADDITIONAL CHECKS"))
    print(bold("─"*60))

    for i, s in enumerate(analysis.get("suggested_additional_checks",[]), 1):
        print(f"\n  {bold(str(i)+'.')} {severity_color(s.get('severity_if_found','?'))} {bold(s.get('check_name',''))}")
        if s.get('aws_service'):  print(f"     Service     : {cyan(s['aws_service'])}")
        if s.get('what_to_look_for'): print(f"     Check For   : {s['what_to_look_for']}")
        if s.get('why_it_matters'):   print(f"     Why         : {s['why_it_matters']}")

    analyzed = analysis.get("analyzed_findings",[])
    high = sum(1 for f in analyzed if f.get("ai_severity") in ("HIGH","CRITICAL"))
    med  = sum(1 for f in analyzed if f.get("ai_severity") == "MEDIUM")
    low  = sum(1 for f in analyzed if f.get("ai_severity") == "LOW")

    print(f"\n{bold('═'*60)}")
    print(f"  Total: {len(analyzed)}  |  {red('High/Critical: '+str(high))}  |  {yellow('Medium: '+str(med))}  |  {green('Low: '+str(low))}")
    print(bold("═"*60+"\n"))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checks", nargs="+", choices=["iam","s3","cloudtrail","sg"])
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--api-key", type=str, default=os.environ.get("GROQ_API_KEY"))
    args = parser.parse_args()

    if not args.api_key:
        print(red("  ✗ No Groq API key found. Set GROQ_API_KEY env var or use --api-key"))
        sys.exit(1)

    print(bold(cyan("\n  AWS Groq AI Auditor — Starting...\n")))
    findings = run_existing_auditor(args.checks)
    if not findings:
        print(yellow("\n  No findings. Nothing to analyze."))
        sys.exit(0)

    analysis = invoke_groq(findings, args.api_key)
    print_report(findings, analysis)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"generated_at": datetime.now().isoformat(), "model": GROQ_MODEL,
                       "raw_findings": findings, "ai_analysis": analysis}, f, indent=2)
        print(green(f"  ✓ Report saved to: {args.output}\n"))

if __name__ == "__main__":
    main()
