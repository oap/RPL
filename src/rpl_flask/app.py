from flask import Flask, jsonify, render_template
from modules.ec2_info import list_instances
from modules.network_info import get_vpc_details, get_security_groups
from modules.iam_info import check_iam_role
import json
import logging

# Setup logging
logging.basicConfig(filename="/var/log/ec2_monitor.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Initialize Flask app
app = Flask(__name__, template_folder="templates", static_folder="static")

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/instances')
def instances():
    data = list_instances()
    with open("/var/log/ec2_instances.json", "w") as file:
        json.dump(data, file, indent=4)
    logging.info("EC2 instance data retrieved and logged.")
    return render_template("instances.html", instances=data)

@app.route('/vpcs')
def vpcs():
    data = get_vpc_details()
    with open("/var/log/vpc_info.json", "w") as file:
        json.dump(data, file, indent=4)
    logging.info("VPC data retrieved and logged.")
    return render_template("vpcs.html", vpcs=data)

@app.route('/security-groups')
def security_groups():
    data = get_security_groups()
    with open("/var/log/security_groups.json", "w") as file:
        json.dump(data, file, indent=4)
    logging.info("Security group data retrieved and logged.")
    return render_template("security_groups.html", security_groups=data)

@app.route('/iam-role')
def iam_role():
    data = check_iam_role()
    logging.info(f"IAM Role Data: {data}")
    return render_template("iam_role.html", iam_role=data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
