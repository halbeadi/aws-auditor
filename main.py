import argparse
from scanner.iam_check import check_iam
from scanner.s3_check import check_s3
from scanner.cloudtrail_check import check_cloudtrail
from scanner.sg_check import check_security_groups
from scanner.reporter import print_report, save_json

def main():
    parser = argparse.ArgumentParser(description="AWS Auditor — Cloud Security Scanner")
    parser.add_argument("--output", default="report.json", help="Output JSON report path")
    parser.add_argument("--checks", nargs="+",
                        choices=["iam", "s3", "cloudtrail", "sg", "all"],
                        default=["all"], help="Which checks to run")
    args = parser.parse_args()

    run_all = "all" in args.checks
    findings = []

    print("\n  AWS Auditor — Starting security scan...\n")

    if run_all or "iam" in args.checks:
        print("  [*] Checking IAM...")
        findings += check_iam()

    if run_all or "s3" in args.checks:
        print("  [*] Checking S3 buckets...")
        findings += check_s3()

    if run_all or "cloudtrail" in args.checks:
        print("  [*] Checking CloudTrail...")
        findings += check_cloudtrail()

    if run_all or "sg" in args.checks:
        print("  [*] Checking Security Groups...")
        findings += check_security_groups()

    print_report(findings)
    save_json(findings, args.output)

if __name__ == "__main__":
    main()
