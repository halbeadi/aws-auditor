import boto3

def check_cloudtrail():
    findings = []
    client = boto3.client("cloudtrail")

    trails = client.describe_trails()["trailList"]

    if not trails:
        findings.append({
            "type": "CloudTrail Not Enabled",
            "severity": "HIGH",
            "detail": "No CloudTrail trails found — API activity is not being logged",
        })
        return findings

    for trail in trails:
        name = trail["Name"]
        status = client.get_trail_status(Name=trail["TrailARN"])

        if not status.get("IsLogging"):
            findings.append({
                "type": "CloudTrail Logging Disabled",
                "severity": "HIGH",
                "detail": f"Trail '{name}' exists but logging is turned off",
            })

        if not trail.get("LogFileValidationEnabled"):
            findings.append({
                "type": "CloudTrail Log Validation Disabled",
                "severity": "MEDIUM",
                "detail": f"Trail '{name}' does not have log file validation enabled",
            })

        if not trail.get("IsMultiRegionTrail"):
            findings.append({
                "type": "CloudTrail Not Multi-Region",
                "severity": "MEDIUM",
                "detail": f"Trail '{name}' is not capturing events from all regions",
            })

    return findings
