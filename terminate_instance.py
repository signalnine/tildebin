#!/usr/bin/env python3
# Script to terminate EC2 instances with user confirmation
# This follows the same patterns as ec2_manage.py

import argparse
import sys
import os


def confirm_action(instance_id, region):
    """Prompt user for confirmation before terminating an instance"""
    print("You are about to TERMINATE instance: {}".format(instance_id))
    print("Region: {}".format(region))
    confirmation = input("Are you sure you want to terminate this instance? This action cannot be undone. (yes/no): ")
    return confirmation.lower() in ['yes', 'y']


def main():
    parser = argparse.ArgumentParser(description="Terminate an EC2 instance with confirmation")
    parser.add_argument("instance_id",
                        help="ID of the EC2 instance to terminate")
    parser.add_argument("-r", "--region", default="us-west-2",
                        help="Specify the AWS region (default: us-west-2)")

    args = parser.parse_args()

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

    # Get instance details to show user before confirmation
    try:
        response = ec2_conn.describe_instances(InstanceIds=[instance_id])
        reservations = response['Reservations']

        if not reservations or not reservations[0]['Instances']:
            print("Error: Instance {} not found in region {}".format(instance_id, region))
            sys.exit(1)

        instance = reservations[0]['Instances'][0]

        # Extract instance name from tags
        name_tag = 'N/A'
        if 'Tags' in instance:
            for tag in instance['Tags']:
                if tag['Key'] == 'Name':
                    name_tag = tag['Value']
                    break

        print("Instance Details:")
        print("  Name: {}".format(name_tag))
        print("  ID: {}".format(instance['InstanceId']))
        print("  Type: {}".format(instance.get('InstanceType', 'N/A')))
        print("  State: {}".format(instance['State']['Name']))
        print("")

    except Exception as e:
        print("Error retrieving instance details: {}".format(str(e)))
        sys.exit(1)

    # Confirm with user before terminating
    if not confirm_action(instance_id, region):
        print("Termination cancelled by user.")
        sys.exit(0)

    try:
        ec2_conn.terminate_instances(InstanceIds=[instance_id])
        print("Terminated instance: {}".format(instance_id))
    except Exception as e:
        print("Error terminating instance '{}': {}".format(instance_id, str(e)))
        sys.exit(1)


if __name__ == "__main__":
    main()