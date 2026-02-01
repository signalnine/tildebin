#!/usr/bin/env python3
# Script to stop all running EC2 instances in a region with user confirmation

import argparse
import sys
import os


def main():
    parser = argparse.ArgumentParser(description="Stop all running EC2 instances in a region")
    parser.add_argument("-r", "--region", default="us-west-2",
                        help="Specify the AWS region (default: us-west-2)")
    parser.add_argument("--force", action="store_true",
                        help="Force stop without confirmation prompt")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show instances that would be stopped without actually stopping them")
    
    args = parser.parse_args()

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
        # Get all running instances
        response = ec2_conn.describe_instances(
            Filters=[
                {
                    'Name': 'instance-state-name',
                    'Values': ['running']
                }
            ]
        )
        
        running_instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                name_tag = 'N/A'
                if 'Tags' in instance:
                    for tag in instance['Tags']:
                        if tag['Key'] == 'Name':
                            name_tag = tag['Value']
                            break
                
                instance_info = {
                    'id': instance['InstanceId'],
                    'name': name_tag,
                    'type': instance.get('InstanceType', 'N/A'),
                    'state': instance['State']['Name']
                }
                running_instances.append(instance_info)
        
        if not running_instances:
            print("No running instances found in region: {}".format(region))
            sys.exit(0)
        
        print("Found {} running instances in region: {}".format(len(running_instances), region))
        for instance in running_instances:
            print("  - {} ({}) - {}".format(instance['id'], instance['name'], instance['type']))
        
        if not args.force and not args.dry_run:
            confirmation = input("\nDo you really want to stop ALL these instances? (yes/no): ")
            if confirmation.lower() not in ['yes', 'y']:
                print("Operation cancelled.")
                sys.exit(0)
        
        if args.dry_run:
            print("\nDRY RUN: Would stop the following instances:")
            for instance in running_instances:
                print("  - {} ({})".format(instance['id'], instance['name']))
            sys.exit(0)
        
        # Stop all running instances
        instance_ids = [instance['id'] for instance in running_instances]
        ec2_conn.stop_instances(InstanceIds=instance_ids)
        print("\nStopped {} instances successfully.".format(len(instance_ids)))
        
    except Exception as e:
        print("Error retrieving or stopping instances: {}".format(str(e)))
        sys.exit(1)


if __name__ == "__main__":
    main()