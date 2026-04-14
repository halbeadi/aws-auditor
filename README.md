# aws-auditor

A lightweight and automated AWS security auditing tool designed to identify misconfigurations, enforce best practices, and improve your cloud security posture — now with **AI-powered analysis via Amazon Bedrock**.

---

## 🚀 What It Does

Scans your AWS account across 4 security domains:

| Check | What it looks for | Severity |
| --- | --- | --- |
| **IAM** | Root MFA, user MFA, old access keys | HIGH/MEDIUM |
| **S3** | Public buckets, missing versioning | HIGH/LOW |
| **CloudTrail** | Logging disabled, missing validation | HIGH/MEDIUM |
| **Security Groups** | Dangerous ports open to 0.0.0.0/0 | HIGH |

---

## 🤖 AI-Powered Auditor (Bedrock)

`bedrock_auditor.py` extends the base auditor with an Amazon Bedrock integration — findings are fed to an LLM (Amazon Nova) for intelligent analysis.

### How it works

```
Phase 1 → Runs all AWS security checks (IAM, S3, CloudTrail, SGs)
Phase 2 → Sends findings to Amazon Nova via Bedrock API
Phase 3 → AI returns risk scores, remediations, and suggested new checks
Phase 4 → Prints AI-enhanced report (optionally saves JSON)
```

### AI Report includes

- **Risk score (1–10)** for each finding
- **AI-reassessed severity** (LOW / MEDIUM / HIGH / CRITICAL)
- **Step-by-step remediation** per finding
- **5 dynamically suggested additional checks** the scanner didn't run
- **Executive summary** of overall security posture

### Bedrock IAM Setup

Create a custom policy with least-privilege — scoped to exact model ARN:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BedrockInvokeModels",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-*"
    }
  ]
}
```

> ⚠️ Never use `"Resource": "*"` — always scope to the specific model ARN.

### Usage

```bash
python bedrock_auditor.py                        # run all checks
python bedrock_auditor.py --checks iam sg        # specific checks
python bedrock_auditor.py --output report.json   # save full JSON report
python bedrock_auditor.py --region us-west-2     # custom region
python bedrock_auditor.py --model amazon.nova-lite-v1:0  # custom model
```

### Additional requirement

```bash
pip install boto3 colorama
aws configure   # ensure credentials have SecurityAudit + Bedrock permissions
```

---

## 📸 Sample Output

```
AWS Auditor — Starting security scan...
[*] Checking IAM...
[*] Checking S3 buckets...
[*] Checking CloudTrail...
[*] Checking Security Groups...

AWS Security Audit Report
=======================================================
[HIGH]   Security Group Open to World
         SG 'launch-wizard-1' allows SSH (port 22) from 0.0.0.0/0
[MEDIUM] IAM User MFA Disabled
         User 'aws-auditor-user' does not have MFA enabled
[LOW]    S3 Versioning Disabled
         Bucket 'my-bucket' does not have versioning enabled

Total: 3 | High: 1 | Medium: 1 | Low: 1
=======================================================

━━━ Phase 2: AI Analysis via AWS Bedrock ━━━
  Model  : amazon.nova-lite-v1:0
  Region : us-east-1
  Sending 3 finding(s) for analysis...
  ✓ Bedrock analysis received.

════════════════════════════════════════════════════════════
  AI-POWERED AWS SECURITY AUDIT REPORT
  Powered by Amazon Bedrock + Nova
════════════════════════════════════════════════════════════

OVERALL RISK: HIGH

EXECUTIVE SUMMARY:
  The account has one critical exposure (unrestricted SSH) that requires
  immediate remediation. MFA gaps and missing versioning increase risk
  of credential compromise and data loss. Overall posture needs hardening.

──────────────────────────────────────────────────────────
  FINDINGS WITH AI ANALYSIS
──────────────────────────────────────────────────────────

  1. [HIGH] Security Group Open to World
     Risk Score  : 9/10
     Remediation : Restrict port 22 inbound rule to your specific IP CIDR.
                   Use EC2 Instance Connect or SSM Session Manager instead.
     AWS Docs    : EC2 Security Groups → Inbound Rules

  2. [MEDIUM] IAM User MFA Disabled
     Risk Score  : 7/10
     Remediation : Enable virtual MFA via IAM Console → Users → Security credentials.
                   Enforce MFA with an IAM policy condition: aws:MultiFactorAuthPresent.
     AWS Docs    : IAM → MFA → Virtual MFA devices

──────────────────────────────────────────────────────────
  AI-SUGGESTED ADDITIONAL CHECKS
──────────────────────────────────────────────────────────

  1. [HIGH] Root Account MFA Check
     Service     : AWS IAM
     Check For   : Root account MFA disabled
     Why         : Root has unrestricted access — must be protected

  2. [MEDIUM] S3 Public Access Block
     Service     : Amazon S3
     Check For   : Account-level public access block not enabled
     Why         : Prevents accidental bucket exposure across all buckets
```

---

## 🛠️ Tech Stack

| Component | Technology |
| --- | --- |
| Core language | Python 3 |
| AWS SDK | boto3 |
| AI/LLM | Amazon Bedrock (Nova) |
| Terminal output | colorama |

---

## 🏗️ Project Structure

```
aws-auditor/
├── scanner/
│   ├── iam_check.py          # IAM misconfigurations
│   ├── s3_check.py           # S3 bucket security
│   ├── cloudtrail_check.py   # Audit logging checks
│   ├── sg_check.py           # Security group checks
│   └── reporter.py           # Terminal + JSON output
├── main.py                   # Base CLI auditor
├── bedrock_auditor.py        # AI-powered Bedrock auditor
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

```bash
git clone https://github.com/halbeadi/aws-auditor.git
cd aws-auditor
pip install -r requirements.txt
```

Configure AWS credentials:

```bash
aws configure
```

> Use an IAM user with `SecurityAudit` + `BedrockInvokeModels` policies — never use root credentials.

---

## 💻 Usage

**Base auditor:**

```bash
python main.py                        # all checks
python main.py --checks iam sg        # specific checks
python main.py --output report.json   # save JSON report
```

**AI-powered Bedrock auditor:**

```bash
python bedrock_auditor.py
python bedrock_auditor.py --checks iam s3
python bedrock_auditor.py --output ai_report.json
```

---

## 🧪 Real World Results

Tested against a live AWS account and found:

- SSH port 22 open to `0.0.0.0/0` on a production EC2 instance **(HIGH — risk score 9/10)**
- IAM user missing MFA **(MEDIUM — risk score 7/10)**
- S3 versioning disabled on CloudTrail buckets **(LOW)**
- AI suggested 5 additional checks not in the original scanner

The HIGH finding was immediately remediated by restricting SSH access to a specific IP — verified by re-running the auditor.

---

## 🔒 Security Notes

- **Read-only by design** — uses `SecurityAudit` policy, cannot modify resources
- **Bedrock IAM scoped to exact model ARN** — not wildcard `*`
- **No credentials in code** — uses `aws configure` / environment variables only
- **Prompts and responses are NOT used to train AWS models** — Bedrock contractual guarantee

---

## ⚠️ Legal Disclaimer

Only run against AWS accounts you own or have explicit permission to audit.

---

## 👤 Author

**Aditya Halbe** — Cloud & DevSecOps Engineer | CEH Certified  
[GitHub](https://github.com/halbeadi) · [LinkedIn](https://linkedin.com/in/aditya-halbe) · [pyshala.in](https://pyshala.in)
