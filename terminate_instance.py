#!/usr/bin/env python
# Script to terminate EC2 instances with user confirmation
# This follows the same patterns as ec2_manage.py

from __future__ import print_function  # This makes Python 2 behave like Python 3 for print
import argparse
import sys
import os

def confirm_action(instance_id, region):
    """Prompt user for confirmation before terminating an instance"""
    response = raw_input if sys.version_info[0] == 2 else input
    print("You are about to TERMINATE instance: {}".format(instance_id))
    print("Region: {}".format(region))
    confirmation = response("Are you sure you want to terminate this instance? This action cannot be undone. (yes/no): ")
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

    # Set your region in here or set EC2_REGION as an environment variable:
    ec2_url = "https://{}.ec2.amazonaws.com".format(region)

    # Check for AWS credentials
    aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID') or os.environ.get('AWS_ACCESS_KEY')
    aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY') or os.environ.get('AWS_SECRET_KEY')

    if not aws_access_key or not aws_secret_key:
        print("""Please set environment variables AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY
This would look something like:
  export AWS_ACCESS_KEY_ID=JFIOQNAKEIFJJAKDLIJA
  export AWS_SECRET_ACCESS_KEY=3jfioajkle+OnfAEV5OIvj5nLnRy2jfklZRop3nn
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

    # Get instance details to show user before confirmation
    try:
        reservations = ec2_conn.get_all_instances(instance_ids=[instance_id])
        instances = [inst for reservation in reservations for inst in reservation.instances]
        
        if not instances:
            print("Error: Instance {} not found in region {}".format(instance_id, region))
            sys.exit(1)
            
        instance = instances[0]
        print("Instance Details:")
        print("  Name: {}".format(instance.tags.get('Name', 'N/A')))
        print("  ID: {}".format(instance.id))
        print("  Type: {}".format(instance.instance_type))
        print("  State: {}".format(instance.state))
        print("")
        
    except Exception as e:
        print("Error retrieving instance details: {}".format(str(e)))
        sys.exit(1)

    # Confirm with user before terminating
    if not confirm_action(instance_id, region):
        print("Termination cancelled by user.")
        sys.exit(0)

    try:
        ec2_conn.terminate_instances([instance_id])
        print("Terminated instance: {}".format(instance_id))
    except Exception as e:
        print("Error terminating instance '{}': {}".format(instance_id, str(e)))
        sys.exit(1)


if __name__ == "__main__":
    main()