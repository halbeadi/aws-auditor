import boto3

DANGEROUS_PORTS = [22, 3389, 3306, 5432, 27017, 6379]
PORT_NAMES = {
    22: "SSH", 3389: "RDP", 3306: "MySQL",
    5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"
}

def check_security_groups():
    findings = []
    client = boto3.client("ec2")

    sgs = client.describe_security_groups()["SecurityGroups"]

    for sg in sgs:
        name = sg.get("GroupName", sg["GroupId"])
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port   = rule.get("ToPort", 65535)

            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    for port in DANGEROUS_PORTS:
                        if from_port <= port <= to_port:
                            findings.append({
                                "type": "Security Group Open to World",
                                "severity": "HIGH",
                                "detail": f"SG '{name}' allows {PORT_NAMES[port]} (port {port}) from 0.0.0.0/0",
                            })

            for ipv6_range in rule.get("Ipv6Ranges", []):
                if ipv6_range.get("CidrIpv6") == "::/0":
                    for port in DANGEROUS_PORTS:
                        if from_port <= port <= to_port:
                            findings.append({
                                "type": "Security Group Open to World (IPv6)",
                                "severity": "HIGH",
                                "detail": f"SG '{name}' allows {PORT_NAMES[port]} (port {port}) from ::/0",
                            })

    return findings
