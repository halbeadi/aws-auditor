import boto3

def check_iam():
    findings = []
    client = boto3.client("iam")

    # Check if root account has MFA enabled
    summary = client.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) == 0:
        findings.append({
            "type": "Root MFA Disabled",
            "severity": "HIGH",
            "detail": "Root account does not have MFA enabled",
        })

    # Check for access keys on root account
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        findings.append({
            "type": "Root Access Keys Present",
            "severity": "HIGH",
            "detail": "Root account has active access keys — should be deleted",
        })

    # Check IAM users for MFA
    users = client.list_users()["Users"]
    for user in users:
        mfa = client.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
        if not mfa:
            findings.append({
                "type": "IAM User MFA Disabled",
                "severity": "MEDIUM",
                "detail": f"User '{user['UserName']}' does not have MFA enabled",
            })

        # Check for old access keys (over 90 days)
        keys = client.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
        for key in keys:
            from datetime import datetime, timezone
            age = (datetime.now(timezone.utc) - key["CreateDate"]).days
            if age > 90:
                findings.append({
                    "type": "Old Access Key",
                    "severity": "MEDIUM",
                    "detail": f"User '{user['UserName']}' has access key older than 90 days ({age} days)",
                })

    return findings
