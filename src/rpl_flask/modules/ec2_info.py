import boto3
from config import AWS_REGION

ec2_client = boto3.client("ec2", region_name=AWS_REGION)

def list_instances():
    """Get all EC2 instances information."""
    response = ec2_client.describe_instances()
    instances_info = []
    
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instance_data = {
                "Instance ID": instance["InstanceId"],
                "State": instance["State"]["Name"],
                "Type": instance["InstanceType"],
                "Private IP": instance.get("PrivateIpAddress", "N/A"),
                "Public IP": instance.get("PublicIpAddress", "N/A"),
                "VPC ID": instance["VpcId"],
                "Subnet ID": instance["SubnetId"],
                "Security Groups": [sg["GroupName"] for sg in instance["SecurityGroups"]]
            }
            instances_info.append(instance_data)
    
    return instances_info

# Main function for standalone execution
if __name__ == "__main__":
    print("Testing EC2 Instance Information...")
    data = list_instances()
    print(json.dumps(data, indent=4))