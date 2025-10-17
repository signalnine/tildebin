#!/usr/bin/env python3
"""
A script to summarize EC2 instances by tags across regions using boto3.
This script provides tag-based filtering and summary statistics for EC2 resources.

Features:
- Filter instances by tag key/value pairs
- Support for multiple regions
- Summary of instances by tag values
- JSON and plain text output formats
"""

import argparse
import sys


def get_ec2_instances_by_tag(regions, tag_filter=None):
    """
    Retrieve EC2 instances across multiple regions and group by tag values
    
    Args:
        regions (list): List of AWS region names
        tag_filter (dict): Dictionary with tag key and value to filter by
    
    Returns:
        dict: Grouped instances by tag values
    """
    # Import boto3 and other dependencies only when needed
    import boto3
    from collections import defaultdict
    from botocore.exceptions import NoCredentialsError, ClientError
    
    tag_summary = defaultdict(list)
    
    for region in regions:
        try:
            ec2 = boto3.client('ec2', region_name=region)
            # Get all instances (running, stopped, etc.)
            response = ec2.describe_instances()
        except NoCredentialsError:
            print("Error: AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.")
            sys.exit(1)
        except ClientError as e:
            print(f"Error accessing region {region}: {str(e)}")
            continue
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Check if instance matches tag filter
                if tag_filter:
                    instance_matches = False
                    if 'Tags' in instance:
                        for tag in instance['Tags']:
                            if tag['Key'] == tag_filter['key']:
                                if tag_filter.get('value') is None or tag['Value'] == tag_filter['value']:
                                    instance_matches = True
                                    break
                    if not instance_matches:
                        continue
                
                # Determine the tag value to group by
                tag_value = 'No tags'
                if 'Tags' in instance:
                    for tag in instance['Tags']:
                        if tag['Key'] == tag_filter['key'] if tag_filter else 'Name':
                            tag_value = tag['Value']
                            break
                
                # Add instance info to summary
                instance_info = {
                    'id': instance['InstanceId'],
                    'type': instance.get('InstanceType', 'N/A'),
                    'state': instance['State']['Name'],
                    'region': region,
                    'private_ip': instance.get('PrivateIpAddress', 'N/A'),
                    'public_ip': instance.get('PublicIpAddress', 'N/A')
                }
                tag_summary[tag_value].append(instance_info)
    
    return dict(tag_summary)


def print_summary_plain(summary_data):
    """Print the summary in plain text format"""
    if not summary_data:
        print("No instances found matching the criteria.")
        return
    
    for tag_value, instances in summary_data.items():
        print(f"\n{tag_value}: ({len(instances)} instances)")
        print("-" * (len(tag_value) + 20))
        for instance in instances:
            print(f"  {instance['id']} | {instance['type']} | {instance['state']} | "
                  f"{instance['private_ip']} | {instance['public_ip']} | {instance['region']}")


def print_summary_json(summary_data):
    """Print the summary in JSON format"""
    # Convert defaultdict to regular dict for JSON serialization
    regular_dict = {k: v for k, v in summary_data.items()}
    import json
    print(json.dumps(regular_dict, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Summarize EC2 instances by tags")
    parser.add_argument("--tag-key", help="The tag key to group instances by")
    parser.add_argument("--tag-value", help="Optional tag value to filter by")
    parser.add_argument("--regions", nargs="+", default=["us-west-2", "us-east-1"], 
                        help="AWS regions to scan (default: us-west-2 us-east-1)")
    parser.add_argument("--format", choices=["plain", "json"], default="plain",
                        help="Output format (default: plain)")
    
    args = parser.parse_args()
    
    # Check if help was requested or required args are missing
    if not args.tag_key:
        parser.print_help()
        print("\nError: --tag-key is required")
        sys.exit(1)
    
    # Prepare tag filter
    tag_filter = {'key': args.tag_key}
    if args.tag_value:
        tag_filter['value'] = args.tag_value
    
    # Get instance summary
    summary = get_ec2_instances_by_tag(args.regions, tag_filter)
    
    # Print results
    if args.format == "json":
        print_summary_json(summary)
    else:
        print_summary_plain(summary)


if __name__ == "__main__":
    main()