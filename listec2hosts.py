#!/usr/bin/env python
# Largely adapted from fec2din: https://github.com/epheph/fec2din

from __future__ import print_function  # This makes Python 2 behave like Python 3 for print
import argparse
import sys
import os
from datetime import datetime


def main():
    parser = argparse.ArgumentParser(description="List EC2 instances")
    parser.add_argument("-a", "--all", action="store_true", 
                        help="Include all instances, not just running instances")
    parser.add_argument("-r", "--region", default="us-west-2", 
                        help="Specify the AWS region (default: us-west-2)")
    parser.add_argument("--format", choices=["plain", "table"], default="plain",
                        help="Output format (default: plain)")
    parser.add_argument("--boto3", action="store_true", 
                        help="Use the newer boto3 library instead of boto (deprecated)")
    
    args = parser.parse_args()

    show_all_instances = args.all
    region = args.region
    use_boto3 = args.boto3

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

    if use_boto3:
        # Use the newer boto3 library
        try:
            import boto3
        except ImportError:
            print("Error: The 'boto3' library is required to run this script with --boto3 option.")
            print("You can install it using: pip install boto3")
            sys.exit(1)

        try:
            ec2_conn = boto3.client('ec2', region_name=region)
        except Exception as e:
            print("Error connecting to EC2 with boto3: {}".format(str(e)))
            sys.exit(1)

        try:
            response = ec2_conn.describe_instances()
            reservations = response['Reservations']
        except Exception as e:
            print("Error retrieving instances: {}".format(str(e)))
            sys.exit(1)
    else:
        # Set your region in here or set EC2_REGION as an environment variable:
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
            reservations = ec2_conn.get_all_instances()
        except Exception as e:
            print("Error retrieving instances: {}".format(str(e)))
            sys.exit(1)

    instances = []
    for reservation in reservations:
        if args.boto3:
            # Handle boto3 response format
            for instance in reservation['Instances']:
                # Check instance state for boto3
                if instance['State']['Name'] != "running" and not show_all_instances:
                    continue  # Skip this instance
                else:
                    # Extract instance information for boto3
                    name_tag = 'N/A'
                    if 'Tags' in instance:
                        for tag in instance['Tags']:
                            if tag['Key'] == 'Name':
                                name_tag = tag['Value']
                                break
                    
                    instance_info = {
                        'name': name_tag,
                        'id': instance['InstanceId'],
                        'type': instance.get('InstanceType', 'N/A'),
                        'placement': instance.get('Placement', {}).get('AvailabilityZone', 'N/A'),
                        'public_ip': instance.get('PublicIpAddress', 'N/A'),
                        'private_ip': instance.get('PrivateIpAddress', 'N/A'),
                        'state': instance['State']['Name']
                    }
        else:
            # Handle boto response format
            for instance in reservation.instances:
                if instance.state != "running" and not show_all_instances:
                    continue  # Skip this instance
                else:
                    instance_info = {
                        'name': instance.tags.get('Name', 'N/A'),
                        'id': instance.id,
                        'type': instance.instance_type,
                        'placement': instance.placement,
                        'public_ip': instance.ip_address or 'N/A',
                        'private_ip': instance.private_ip_address or 'N/A',
                        'state': instance.state
                    }
        
        # Print instance info
        if args.format == "table" and not instances:
            # Print header for table format
            print("{:<30} {:<20} {:<15} {:<15} {:<15} {:<15} {:<12}".format(
                "Name", "ID", "Type", "Placement", "Public IP", "Private IP", "State"))
            print("-" * 135)

        if args.format == "table":
            print("{:<30} {:<20} {:<15} {:<15} {:<15} {:<15} {:<12}".format(
                instance_info['name'], 
                instance_info['id'], 
                instance_info['type'], 
                instance_info['placement'], 
                instance_info['public_ip'], 
                instance_info['private_ip'],
                instance_info['state']))
        else:
            # Original format for backward compatibility
            instance_title = "%s %s %s %s %s %s %s" % (
                instance_info['name'], 
                instance_info['id'], 
                instance_info['type'], 
                instance_info['placement'], 
                instance_info['public_ip'], 
                instance_info['private_ip'],
                instance_info['state'])
            print(instance_title)

if __name__ == "__main__":
    main()
