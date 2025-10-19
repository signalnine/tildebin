#!/usr/bin/env python3
# Largely adapted from fec2din: https://github.com/epheph/fec2din

import argparse
import sys
import os


def main():
    parser = argparse.ArgumentParser(description="List EC2 instances")
    parser.add_argument("-a", "--all", action="store_true",
                        help="Include all instances, not just running instances")
    parser.add_argument("-r", "--region", default="us-west-2",
                        help="Specify the AWS region (default: us-west-2)")
    parser.add_argument("--format", choices=["plain", "table"], default="plain",
                        help="Output format (default: plain)")

    args = parser.parse_args()

    show_all_instances = args.all
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
        response = ec2_conn.describe_instances()
        reservations = response['Reservations']
    except Exception as e:
        print("Error retrieving instances: {}".format(str(e)))
        sys.exit(1)

    instances = []
    for reservation in reservations:
        # Handle boto3 response format
        for instance in reservation['Instances']:
            # Check instance state
            if instance['State']['Name'] != "running" and not show_all_instances:
                continue  # Skip this instance

            # Extract instance information
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

            instances.append(instance_info)

if __name__ == "__main__":
    main()
