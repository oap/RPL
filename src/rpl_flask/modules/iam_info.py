import requests

def check_iam_role():
    """Check if an IAM role is attached to the EC2 instance."""
    try:
        url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return {"IAM Role": response.text.strip()}
        else:
            return {"IAM Role": "No IAM Role Attached"}
    except requests.RequestException:
        return {"IAM Role": "Error accessing IAM Role metadata"}

# Main function for testing
if __name__ == "__main__":
    print("Testing IAM Role Detection...")
    role_data = check_iam_role()
    print(json.dumps(role_data, indent=4))
