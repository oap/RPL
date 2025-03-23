#!/usr/bin/env python3
import json
import sys

# Group all configuration constants into a single dictionary
CONFIG = {
    "vpc": {
        "expected_name": "COMP2045-RPL-VPC",
        "expected_cidr": "10.0.0.0/16",
        "max_score": 10,
        # We split the score: base VPC (4 points) + subnets/gateways (6 points)
        "base_score": 4,
        "subnet_score": 6,
        "expected_subnet_count": 2,
    },
    "security_groups": {
        "expected_app_sg_name": "COMP2045-RPL-APP-SG",
        "expected_nfs_sg_name": "COMP2045-RPL-NFS-SG",
        "expected_inbound_ports": [22, 80, 443, 2049],
        "max_score": 10,
    },
    "efs": {
        "expected_name": "COMP2045-RPL-EFS",
        "expected_performance_mode": "generalPurpose",
        "expected_throughput_mode": "bursting",
        "expected_mount_targets": 2,
        "expected_backup_tag_value": "enabled",
        "max_score": 10,
    },
    "s3": {
        "expected_versioning": "Enabled",
        "expected_encryption": "AES256",
        "expected_lifecycle_rule_id": "zeroday",
        "expected_lifecycle_storage_class": "INTELLIGENT_TIERING",
        "expected_lifecycle_transition_days": 0,
        "expected_policy_keyword": "LabRole",
        "max_score": 10,
    },
    "ec2": {
        "expected_name": "COMP2045-RPL-APP",
        "expected_instance_type": "t2.medium",
        "expected_efs_mount": "/mnt/efs",
        "max_score": 10,
    },
    "elastic_ip": {
        "max_score": 5,
    },
    "cloudwatch": {
        "expected_alarm_name": "COMP2045-RPL-ALARM",
        "max_score": 10,
    },
    "backup": {
        "expected_backup_plan_name": "COMP2045-RPL-BACKUP",
        "max_score": 10,
    },
    "custom_app": {
        "max_score": 10,
    },
    "submission": {
        "expected_vpc": "COMP2045-RPL-VPC",
        "expected_ec2": "COMP2045-RPL-APP",
        "vpc_score": 2,
        "ec2_score": 3,
        "max_score": 5,
    },
}

def analyze_vpc_setup(data, config=CONFIG["vpc"]):
    score = 0
    report = []
    expected_name = config["expected_name"]
    expected_cidr = config["expected_cidr"]
    base_score = config["base_score"]
    subnet_score = config["subnet_score"]
    expected_subnet_count = config["expected_subnet_count"]

    # Check for VPC with expected name and CIDR
    vpcs = data.get("vpcs", {}).get("Vpcs", [])
    target_vpc = None
    for vpc in vpcs:
        for tag in vpc.get("Tags", []):
            if tag.get("Key") == "Name" and tag.get("Value") == expected_name:
                target_vpc = vpc
                break
        if target_vpc:
            break

    if not target_vpc:
        report.append(f"✖ Expected VPC '{expected_name}' not found.")
        return score, "\n".join(report)
    else:
        cidr = target_vpc.get("CidrBlock", "")
        if cidr == expected_cidr:
            report.append(f"✔ VPC with correct CIDR block ({expected_cidr}) found.")
            score += base_score
        else:
            report.append(f"✖ VPC found but with CIDR {cidr} (expected {expected_cidr}).")
    
    # Check for public subnets in the VPC
    vpc_id = target_vpc.get("VpcId")
    subnets = data.get("subnets", {}).get("Subnets", [])
    public_subnets = [s for s in subnets if s.get("VpcId") == vpc_id and s.get("MapPublicIpOnLaunch") == True]
    report.append(f"Found {len(public_subnets)} public subnet(s) in VPC {vpc_id}.")
    if len(public_subnets) == expected_subnet_count:
        # Check if they are in different AZs
        azs = set(s.get("AvailabilityZone") for s in public_subnets)
        if len(azs) >= expected_subnet_count:
            report.append("✔ Exactly two public subnets in different Availability Zones are configured.")
            score += subnet_score
        else:
            report.append("✖ Public subnets are not in different Availability Zones.")
            score += int(subnet_score * 0.5)
    elif len(public_subnets) > 0:
        report.append("✖ Incorrect number of public subnets (expected exactly two).")
        score += int(subnet_score * 0.5)
    else:
        report.append("✖ No public subnets found in the VPC.")

    # Note: Gateway configuration (Internet Gateway & S3 Gateway) is required by the rubric,
    # but since our JSON does not include these details, we add a note.
    report.append("ℹ️ Gateway configuration not verified due to missing data.")
    return score, "\n".join(report)

def analyze_security_groups(data, config=CONFIG["security_groups"]):
    score = 0
    report = []
    expected_app_sg_name = config["expected_app_sg_name"]
    expected_nfs_sg_name = config["expected_nfs_sg_name"]
    expected_inbound_ports = config["expected_inbound_ports"]
    max_score = config["max_score"]

    sgs = data.get("security_groups", {}).get("SecurityGroups", [])
    app_sg = None
    nfs_sg = None
    for sg in sgs:
        if sg.get("GroupName") == expected_app_sg_name:
            app_sg = sg
        elif sg.get("GroupName") == expected_nfs_sg_name:
            nfs_sg = sg

    if app_sg and nfs_sg:
        report.append("✔ Both expected security groups found.")
        # Check inbound rules for APP SG
        inbound = app_sg.get("IpPermissions", [])
        ports_status = {port: False for port in expected_inbound_ports}
        for rule in inbound:
            fp = rule.get("FromPort")
            tp = rule.get("ToPort")
            if fp is not None and tp is not None and fp == tp and fp in ports_status:
                ports_status[fp] = True
        missing_inbound = [str(p) for p, present in ports_status.items() if not present]
        if missing_inbound:
            report.append("✖ APP SG is missing inbound rule(s) for port(s): " + ", ".join(missing_inbound))
            partial = max_score // 2
        else:
            report.append("✔ APP SG inbound rules are correctly configured.")
            partial = max_score // 2

        # Check outbound rules for both SGs (should allow all traffic: protocol -1, CIDR 0.0.0.0/0)
        def check_outbound(sg):
            for rule in sg.get("IpPermissionsEgress", []):
                if rule.get("IpProtocol") == "-1":
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            return True
            return False

        app_egress = check_outbound(app_sg)
        nfs_egress = check_outbound(nfs_sg)
        if app_egress and nfs_egress:
            report.append("✔ Outbound rules for both SGs allow all traffic.")
            partial += max_score // 4
        else:
            report.append("✖ One or both SGs are missing proper outbound rules.")

        # Check NFS SG inbound: should allow port 2049 from APP SG
        nfs_inbound = nfs_sg.get("IpPermissions", [])
        nfs_rule_found = False
        for rule in nfs_inbound:
            if rule.get("FromPort") == 2049 and rule.get("ToPort") == 2049:
                for pair in rule.get("UserIdGroupPairs", []):
                    if pair.get("GroupId") == app_sg.get("GroupId"):
                        nfs_rule_found = True
                        break
        if nfs_rule_found:
            report.append("✔ NFS SG inbound rule correctly allows NFS (2049) from APP SG.")
            partial += max_score // 4
        else:
            report.append("✖ NFS SG inbound rule missing or incorrect for NFS (2049) from APP SG.")
        score = partial
    else:
        report.append("✖ One or both of the expected security groups are missing.")
    return score, "\n".join(report)

def analyze_efs_setup(data, config=CONFIG["efs"]):
    score = 0
    report = []
    expected_name = config["expected_name"]
    expected_pm = config["expected_performance_mode"]
    expected_tm = config["expected_throughput_mode"]
    expected_mounts = config["expected_mount_targets"]
    expected_backup = config["expected_backup_tag_value"]
    max_score = config["max_score"]

    efs_list = data.get("efs_all", {}).get("FileSystems", [])
    target_efs = None
    for fs in efs_list:
        for tag in fs.get("Tags", []):
            if tag.get("Key") == "Name" and tag.get("Value") == expected_name:
                target_efs = fs
                break
        if target_efs:
            break

    if not target_efs:
        report.append(f"✖ Expected EFS '{expected_name}' not found.")
        return 0, "\n".join(report)
    else:
        pm = target_efs.get("PerformanceMode", "")
        tm = target_efs.get("ThroughputMode", "")
        mount_targets = target_efs.get("NumberOfMountTargets", 0)
        report.append(f"Found EFS with PerformanceMode '{pm}' and ThroughputMode '{tm}'.")
        report.append("✔ Performance mode is correct." if pm == expected_pm else f"✖ Performance mode is {pm} (expected {expected_pm}).")
        report.append("✔ Throughput mode is correct." if tm.lower() == expected_tm.lower() else f"✖ Throughput mode is {tm} (expected {expected_tm}).")
        if mount_targets >= expected_mounts:
            report.append(f"✔ Mount targets configured in at least {expected_mounts} subnets.")
        else:
            report.append(f"✖ Insufficient mount targets (expected at least {expected_mounts}).")
        backup_enabled = any(tag.get("Key") == "aws:elasticfilesystem:default-backup" and 
                             tag.get("Value").lower() == expected_backup.lower() 
                             for tag in target_efs.get("Tags", []))
        report.append("✔ Automatic backup is enabled." if backup_enabled else "✖ Automatic backup is not enabled.")
        # Award full score if all conditions are met
        if pm == expected_pm and tm.lower() == expected_tm.lower() and mount_targets >= expected_mounts and backup_enabled:
            score = max_score
        elif pm == expected_pm and mount_targets >= expected_mounts and backup_enabled:
            score = int(0.7 * max_score)
        else:
            score = int(0.5 * max_score)
    return score, "\n".join(report)

def analyze_s3_bucket(data, config=CONFIG["s3"]):
    score = 0
    report = []
    expected_versioning = config["expected_versioning"]
    expected_encryption = config["expected_encryption"]
    expected_lifecycle_rule_id = config["expected_lifecycle_rule_id"]
    expected_lifecycle_sc = config["expected_lifecycle_storage_class"]
    expected_lifecycle_days = config["expected_lifecycle_transition_days"]
    expected_policy_keyword = config["expected_policy_keyword"]
    max_score = config["max_score"]

    s3_data = data.get("s3", {})
    buckets = s3_data.get("buckets_list", [])
    if not buckets:
        report.append("✖ No S3 buckets found.")
        return 0, "\n".join(report)
    bucket_name = buckets[0]  # Assuming the first bucket is the one to check
    details = s3_data.get("buckets_details", {}).get(bucket_name, {})
    versioning = details.get("versioning", {}).get("Status", "")
    encryption = details.get("encryption", {})
    lifecycle = details.get("lifecycle", {})
    policy = details.get("policy", {}).get("Policy", "")
    
    report.append("✔ Versioning is enabled." if versioning == expected_versioning else "✖ Versioning is not enabled.")
    encryption_algo = None
    try:
        encryption_algo = encryption["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
    except Exception:
        pass
    report.append(f"✔ Encryption is set to {expected_encryption}." if encryption_algo == expected_encryption else f"✖ Encryption is {encryption_algo} (expected {expected_encryption}).")
    lifecycle_rules = lifecycle.get("Rules", [])
    lifecycle_ok = any(rule.get("ID") == expected_lifecycle_rule_id and any(
        t.get("Days") == expected_lifecycle_days and t.get("StorageClass") == expected_lifecycle_sc
        for t in rule.get("Transitions", [])) for rule in lifecycle_rules)
    report.append("✔ Lifecycle policy is correctly configured (Intelligent Tiering after 0 days)." if lifecycle_ok else "✖ Lifecycle policy is not correctly configured.")
    report.append(f"✔ Bucket policy grants access to {expected_policy_keyword}." if expected_policy_keyword in policy else f"✖ Bucket policy does not grant access to {expected_policy_keyword}.")
    
    if versioning == expected_versioning and encryption_algo == expected_encryption and lifecycle_ok and expected_policy_keyword in policy:
        score = max_score
    else:
        score = int(0.7 * max_score)
    return score, "\n".join(report)

def analyze_ec2_and_efs_mount(data, config=CONFIG["ec2"]):
    score = 0
    report = []
    expected_name = config["expected_name"]
    expected_instance_type = config["expected_instance_type"]
    expected_mount = config["expected_efs_mount"]
    max_score = config["max_score"]

    ec2_reservations = data.get("ec2", {}).get("Reservations", [])
    target_instance = None
    for res in ec2_reservations:
        for inst in res.get("Instances", []):
            for tag in inst.get("Tags", []):
                if tag.get("Key") == "Name" and tag.get("Value") == expected_name:
                    target_instance = inst
                    break
            if target_instance:
                break
        if target_instance:
            break

    if not target_instance:
        report.append(f"✖ EC2 instance '{expected_name}' not found.")
        return 0, "\n".join(report)

    instance_type = target_instance.get("InstanceType", "")
    report.append(f"✔ Instance type is {expected_instance_type}." if instance_type == expected_instance_type else f"✖ Instance type is {instance_type} (expected {expected_instance_type}).")
    report.append("✔ EBS volume is attached." if target_instance.get("BlockDeviceMappings", []) else "✖ No EBS volume found.")
    mount_check = data.get("efs_mount_check", {}).get("efs_mount_check", {})
    stdout = mount_check.get("StandardOutputContent", "")
    if expected_mount in stdout:
        report.append(f"✔ EFS is mounted on {expected_mount}.")
        score = max_score
    else:
        report.append(f"✖ EFS is not mounted on {expected_mount}.")
        score = max_score // 2
    return score, "\n".join(report)

def analyze_elastic_ip(data, config=CONFIG["elastic_ip"]):
    score = 0
    report = []
    max_score = config["max_score"]
    ec2_reservations = data.get("ec2", {}).get("Reservations", [])
    target_instance = None
    for res in ec2_reservations:
        for inst in res.get("Instances", []):
            for tag in inst.get("Tags", []):
                if tag.get("Key") == "Name" and tag.get("Value") == CONFIG["ec2"]["expected_name"]:
                    target_instance = inst
                    break
            if target_instance:
                break
        if target_instance:
            break
    if not target_instance:
        report.append("✖ EC2 instance not found.")
        return 0, "\n".join(report)
    public_ip = target_instance.get("PublicIpAddress", "")
    if public_ip:
        report.append(f"✔ Elastic IP {public_ip} is associated with the instance.")
        score = max_score
    else:
        report.append("✖ No public IP found (Elastic IP missing).")
    return score, "\n".join(report)

def analyze_cloudwatch_monitoring(data, config=CONFIG["cloudwatch"]):
    score = 0
    report = []
    expected_alarm_name = config["expected_alarm_name"]
    max_score = config["max_score"]
    cw = data.get("cloudwatch_alarms", {})
    alarms = cw.get("MetricAlarms", [])
    alarm_names = [a.get("AlarmName", "") for a in alarms]
    if expected_alarm_name in alarm_names:
        report.append(f"✔ CloudWatch alarm '{expected_alarm_name}' is configured.")
        score = max_score
    else:
        report.append(f"✖ Expected CloudWatch alarm '{expected_alarm_name}' not found. Found: " + ", ".join(alarm_names))
    sns_topics = data.get("sns_topics", {}).get("Topics", [])
    topic_arns = [t.get("TopicArn", "") for t in sns_topics]
    report.append(f"✔ SNS topic '{expected_alarm_name}' is configured." if any(expected_alarm_name in arn for arn in topic_arns)
                  else f"✖ Expected SNS topic '{expected_alarm_name}' not found.")
    return score, "\n".join(report)

def analyze_backup_plan(data, config=CONFIG["backup"]):
    score = 0
    report = []
    expected_backup_plan_name = config["expected_backup_plan_name"]
    max_score = config["max_score"]
    backup_plans = data.get("backup_plans", {}).get("BackupPlansList", [])
    plan_names = [p.get("BackupPlanName", "") for p in backup_plans]
    if expected_backup_plan_name in plan_names:
        report.append(f"✔ Backup plan '{expected_backup_plan_name}' is configured.")
        # Although detailed rules are not available, we note that the plan exists.
        report.append("ℹ️ Detailed retention and schedule rules were not verifiable from the JSON data.")
        score = max_score  # If needed, this can be adjusted to partial credit.
    else:
        report.append(f"✖ Expected backup plan '{expected_backup_plan_name}' not found. Found: " + ", ".join(plan_names))
    return score, "\n".join(report)

def analyze_custom_app_deployment(data, config=CONFIG["custom_app"]):
    score = 0
    report = []
    # Rubric expects the app to be deployed, running on port 80 and accessible via the Elastic IP.
    # Since the JSON data does not provide explicit evidence (e.g., app logs or connectivity checks),
    # we mark this as not provided.
    report.append("✖ No explicit evidence of custom app deployment was found in the project data.")
    return score, "\n".join(report)

def analyze_submission_accuracy(data, config=CONFIG["submission"]):
    score = 0
    report = []
    expected_vpc = config["expected_vpc"]
    expected_ec2 = config["expected_ec2"]
    vpc_score = config["vpc_score"]
    ec2_score = config["ec2_score"]
    max_score = config["max_score"]

    vpcs = data.get("vpcs", {}).get("Vpcs", [])
    vpc_names = [tag.get("Value") for v in vpcs for tag in v.get("Tags", []) if tag.get("Key") == "Name"]
    if expected_vpc in vpc_names:
        report.append("✔ VPC name is correctly submitted.")
        score += vpc_score
    else:
        report.append("✖ VPC name does not match expected submission.")
    ec2_reservations = data.get("ec2", {}).get("Reservations", [])
    instance_names = [tag.get("Value") for res in ec2_reservations for inst in res.get("Instances", []) for tag in inst.get("Tags", []) if tag.get("Key") == "Name"]
    if expected_ec2 in instance_names:
        report.append("✔ EC2 instance name is correctly submitted.")
        score += ec2_score
    else:
        report.append("✖ EC2 instance name is incorrect or missing.")
    return score, "\n".join(report)

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_project.py <project.json>")
        sys.exit(1)
    filename = sys.argv[1]
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        sys.exit(1)

    total = 0
    sections = []

    s, r = analyze_vpc_setup(data)
    sections.append("=== VPC Setup ===\n" + r + f"\nScore: {s}/{CONFIG['vpc']['max_score']}\n")
    total += s

    s, r = analyze_security_groups(data)
    sections.append("=== Security Groups ===\n" + r + f"\nScore: {s}/{CONFIG['security_groups']['max_score']}\n")
    total += s

    s, r = analyze_efs_setup(data)
    sections.append("=== EFS Setup ===\n" + r + f"\nScore: {s}/{CONFIG['efs']['max_score']}\n")
    total += s

    s, r = analyze_s3_bucket(data)
    sections.append("=== S3 Bucket ===\n" + r + f"\nScore: {s}/{CONFIG['s3']['max_score']}\n")
    total += s

    s, r = analyze_ec2_and_efs_mount(data)
    sections.append("=== EC2 Instance and EFS Mount ===\n" + r + f"\nScore: {s}/{CONFIG['ec2']['max_score']}\n")
    total += s

    s, r = analyze_elastic_ip(data)
    sections.append("=== Elastic IP ===\n" + r + f"\nScore: {s}/{CONFIG['elastic_ip']['max_score']}\n")
    total += s

    s, r = analyze_cloudwatch_monitoring(data)
    sections.append("=== CloudWatch Monitoring ===\n" + r + f"\nScore: {s}/{CONFIG['cloudwatch']['max_score']}\n")
    total += s

    s, r = analyze_backup_plan(data)
    sections.append("=== AWS Backup Plan ===\n" + r + f"\nScore: {s}/{CONFIG['backup']['max_score']}\n")
    total += s

    s, r = analyze_custom_app_deployment(data)
    sections.append("=== Custom App Deployment ===\n" + r + f"\nScore: {s}/{CONFIG['custom_app']['max_score']}\n")
    total += s

    s, r = analyze_submission_accuracy(data)
    sections.append("=== Submission Accuracy ===\n" + r + f"\nScore: {s}/{CONFIG['submission']['max_score']}\n")
    total += s

    report = "\n".join(sections)
    report += "\n========================================\n"
    report += f"Total Score: {total}/100\n"
    print(report)

if __name__ == "__main__":
    main()
