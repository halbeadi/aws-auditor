import boto3
from botocore.exceptions import ClientError

def check_s3():
    findings = []
    client = boto3.client("s3")

    buckets = client.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]

        # Check for public access block
        try:
            pub = client.get_public_access_block(Bucket=name)
            config = pub["PublicAccessBlockConfiguration"]
            if not all([
                config.get("BlockPublicAcls"),
                config.get("IgnorePublicAcls"),
                config.get("BlockPublicPolicy"),
                config.get("RestrictPublicBuckets"),
            ]):
                findings.append({
                    "type": "S3 Public Access Not Fully Blocked",
                    "severity": "HIGH",
                    "detail": f"Bucket '{name}' does not have all public access blocks enabled",
                })
        except ClientError:
            findings.append({
                "type": "S3 Public Access Block Missing",
                "severity": "HIGH",
                "detail": f"Bucket '{name}' has no public access block configuration",
            })

        # Check for versioning
        versioning = client.get_bucket_versioning(Bucket=name)
        if versioning.get("Status") != "Enabled":
            findings.append({
                "type": "S3 Versioning Disabled",
                "severity": "LOW",
                "detail": f"Bucket '{name}' does not have versioning enabled",
            })

    return findings
