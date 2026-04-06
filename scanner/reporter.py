import json
from colorama import Fore, Style, init

init(autoreset=True)

SEVERITY_COLOR = {
    "HIGH":   Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW":    Fore.CYAN,
}

def print_report(findings):
    print(f"\n{'='*55}")
    print(f"  AWS Security Audit Report")
    print(f"{'='*55}")
    if not findings:
        print(Fore.GREEN + "  No issues found. Your AWS account looks clean!")
        return
    for f in findings:
        color = SEVERITY_COLOR.get(f["severity"], "")
        print(f"\n  [{color}{f['severity']}{Style.RESET_ALL}] {f['type']}")
        print(f"         {f['detail']}")
    high   = len([f for f in findings if f["severity"] == "HIGH"])
    medium = len([f for f in findings if f["severity"] == "MEDIUM"])
    low    = len([f for f in findings if f["severity"] == "LOW"])
    print(f"\n{'='*55}")
    print(f"  Total: {len(findings)} | High: {high} | Medium: {medium} | Low: {low}")
    print(f"{'='*55}\n")

def save_json(findings, path="report.json"):
    with open(path, "w") as f:
        json.dump({"findings": findings}, f, indent=2)
    print(f"  Report saved to {path}")
