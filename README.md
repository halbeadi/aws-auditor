# aws-auditor

A lightweight and automated AWS security auditing tool designed to identify misconfigurations, enforce best practices, and improve your cloud security posture.

---

## 🚀 What It Does

Scans your AWS account across 4 security domains:

| Check | What it looks for | Severity |
|---|---|---|
| **IAM** | Root MFA, user MFA, old access keys | HIGH/MEDIUM |
| **S3** | Public buckets, missing versioning | HIGH/LOW |
| **CloudTrail** | Logging disabled, missing validation | HIGH/MEDIUM |
| **Security Groups** | Dangerous ports open to 0.0.0.0/0 | HIGH |

---

## 📸 Sample Output
AWS Auditor — Starting security scan...
[] Checking IAM...
[] Checking S3 buckets...
[] Checking CloudTrail...
[] Checking Security Groups...
=======================================================
AWS Security Audit Report
[HIGH]   Security Group Open to World
SG 'launch-wizard-1' allows SSH (port 22) from 0.0.0.0/0
[MEDIUM] IAM User MFA Disabled
User 'aws-auditor-user' does not have MFA enabled
[LOW]    S3 Versioning Disabled
Bucket 'my-bucket' does not have versioning enabled
=======================================================
Total: 3 | High: 1 | Medium: 1 | Low: 1

---

## 🛠️ Tech Stack

- **Python 3** — core language
- **boto3** — AWS SDK for Python
- **colorama** — colored terminal output

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

> Use an IAM user with `SecurityAudit` policy attached — never use root credentials.

---

## 💻 Usage

**Run all checks:**
```bash
python main.py
```

**Run specific checks:**
```bash
python main.py --checks iam
python main.py --checks s3
python main.py --checks cloudtrail
python main.py --checks sg
python main.py --checks iam sg
```

**With custom report output:**
```bash
python main.py --output report.json
```

---

## 🏗️ Project Structure
aws-auditor/
├── scanner/
│   ├── iam_check.py         # IAM misconfigurations
│   ├── s3_check.py          # S3 bucket security
│   ├── cloudtrail_check.py  # Audit logging checks
│   ├── sg_check.py          # Security group checks
│   └── reporter.py          # Terminal + JSON output
├── main.py                  # CLI entrypoint
├── requirements.txt
└── README.md

---

## 🧪 Real World Results

Tested against a live AWS account and found:

- SSH port 22 open to `0.0.0.0/0` on a production EC2 instance **(HIGH)**
- IAM user missing MFA **(MEDIUM)**
- S3 versioning disabled on CloudTrail buckets **(LOW)**

The HIGH finding was immediately remediated by restricting SSH access to a specific IP — verified by re-running the auditor.

---

## 🔒 Security Note

This tool is **read-only** by design. It uses AWS `SecurityAudit` policy which only allows read access — it cannot modify or delete any resources.

---

## ⚠️ Legal Disclaimer

Only run against AWS accounts you own or have explicit permission to audit.

---

## 👤 Author

**Aditya halbe** — Cloud & DevSecOps Engineer
CEH Certified 
[GitHub](https://github.com/halbeadi) · [LinkedIn](https://linkedin.com/in/aditya-halbe)
