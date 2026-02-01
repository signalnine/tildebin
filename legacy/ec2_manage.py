#!/usr/bin/env python3
# Script to manage EC2 instances (start, stop, restart)

import argparse
import sys
import os


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

    # Override region from environment variable if set
    region = os.environ.get('EC2_REGION', region)

    # Import boto3
    try:
        import boto3
    except ImportError:
        print("Error: The 'boto3' library is required to run this script.")
        print("You can install it using: pip install boto3")
        sys.exit(1)

    try:
        ec2_conn = boto3.client('ec2', region_name=region)
    except Exception as e:
        print("Error connecting to EC2: {}".format(str(e)))
        sys.exit(1)

    try:
        if action == "start":
            ec2_conn.start_instances(InstanceIds=[instance_id])
            print("Started instance: {}".format(instance_id))
        elif action == "stop":
            ec2_conn.stop_instances(InstanceIds=[instance_id])
            print("Stopped instance: {}".format(instance_id))
        elif action == "restart":
            ec2_conn.reboot_instances(InstanceIds=[instance_id])
            print("Restarted instance: {}".format(instance_id))
    except Exception as e:
        print("Error performing action '{}': {}".format(action, str(e)))
        sys.exit(1)


if __name__ == "__main__":
    main()