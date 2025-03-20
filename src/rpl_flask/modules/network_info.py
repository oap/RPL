import boto3
from config import AWS_REGION

ec2_client = boto3.client("ec2", region_name=AWS_REGION)

def get_vpc_details():
    """Retrieve VPC details."""
    response = ec2_client.describe_vpcs()
    vpcs = [{"VPC ID": vpc["VpcId"], "CIDR Block": vpc["CidrBlock"], "State": vpc["State"]} for vpc in response["Vpcs"]]
    return vpcs

def get_security_groups():
    """Retrieve security groups and their rules."""
    response = ec2_client.describe_security_groups()
    security_groups = [
        {"Group Name": sg["GroupName"], "Group ID": sg["GroupId"], "Inbound Rules": sg["IpPermissions"], "Outbound Rules": sg["IpPermissionsEgress"]}
        for sg in response["SecurityGroups"]
    ]
    return security_groups

# Main function for testing
if __name__ == "__main__":
    print("Testing VPC Information...")
    vpc_data = get_vpc_details()
    print(json.dumps(vpc_data, indent=4))

    print("\nTesting Security Groups...")
    sg_data = get_security_groups()
    print(json.dumps(sg_data, indent=4))