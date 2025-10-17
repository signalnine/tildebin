#!/usr/bin/env python
# Script to manage EC2 instances (start, stop, restart)

from __future__ import print_function  # This makes Python 2 behave like Python 3 for print
import argparse
import sys
import os
from datetime import datetime


def main():
    parser = argparse.ArgumentParser(description="Manage EC2 instances (start, stop, restart)")
    parser.add_argument("action", choices=["start", "stop", "restart"], 
                        help="Action to perform on the instance")
    parser.add_argument("instance_id", 
                        help="ID of the EC2 instance to manage")
    parser.add_argument("-r", "--region", default="us-west-2", 
                        help="Specify the AWS region (default: us-west-2)")
    
    args = parser.parse_args()

    action = args.action
    instance_id = args.instance_id
    region = args.region

    # Set your region in here or set EC2_REGION as an environment variable:
    ec2_url = "https://{}.ec2.amazonaws.com".format(region)

    # Check for AWS credentials
    aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID') or os.environ.get('AWS_ACCESS_KEY')
    aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY') or os.environ.get('AWS_SECRET_KEY')

    if not aws_access_key or not aws_secret_key:
        print("""Please set environment variables AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY
This would look something like:
  export AWS_ACCESS_KEY_ID=JFIOQNAKEIFJJAKDLIJA
  export AWS_SECRET_KEY=3jfioajkle+OnfAEV5OIvj5nLnRy2jfklZRop3nn
Alternatively, you can use AWS_ACCESS_KEY & AWS_SECRET_KEY
""")
        sys.exit(1)

    # Override region from environment variable if set
    region = os.environ.get('EC2_REGION', region)
    ec2_url = "https://{}.ec2.amazonaws.com".format(region)

    # Override URL from environment variable if set
    ec2_url = os.environ.get('EC2_URL', ec2_url)

    # Import boto only when we actually need it - after argument parsing and credential checks
    try:
        import boto
    except ImportError:
        print("Error: The 'boto' library is required to run this script.")
        print("You can install it using: pip install boto")
        sys.exit(1)

    try:
        ec2_conn = boto.connect_ec2_endpoint(ec2_url, aws_access_key, aws_secret_key)
    except Exception as e:
        print("Error connecting to EC2: {}".format(str(e)))
        sys.exit(1)

    try:
        if action == "start":
            ec2_conn.start_instances([instance_id])
            print("Started instance: {}".format(instance_id))
        elif action == "stop":
            ec2_conn.stop_instances([instance_id])
            print("Stopped instance: {}".format(instance_id))
        elif action == "restart":
            ec2_conn.reboot_instances([instance_id])
            print("Restarted instance: {}".format(instance_id))
    except Exception as e:
        print("Error performing action '{}': {}".format(action, str(e)))
        sys.exit(1)


if __name__ == "__main__":
    main()