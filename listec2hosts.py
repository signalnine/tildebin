#!/usr/bin/env python
# Largely adapted from fec2din: https://github.com/epheph/fec2din

import argparse
import sys
import os
import boto
from datetime import datetime

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


    # You can uncomment and set these, or set the env variables AWS_ACCESS_KEY & AWS_SECRET_KEY
    # AWS_ACCESS_KEY="aaaaaaaaaaaaaaaaaaaa"
    # AWS_SECRET_KEY="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    # Set your region in here or set EC2_REGION as an environment variable:
    ec2_url = "https://{}.ec2.amazonaws.com".format(region)

    try:
        AWS_ACCESS_KEY
    except NameError:
        try:
            AWS_ACCESS_KEY = os.environ['AWS_ACCESS_KEY']
            AWS_SECRET_KEY = os.environ['AWS_SECRET_KEY']
        except KeyError:
            print("""Please set environment variables AWS_ACCESS_KEY & AWS_SECRET_KEY
This would look something like:
  export AWS_ACCESS_KEY=JFIOQNAKEIFJJAKDLIJA
  export AWS_SECRET_KEY=3jfioajkle+OnfAEV5OIvj5nLnRy2jfklZRop3nn
""")
            sys.exit(1)


    try:
        region = os.environ['EC2_REGION']
        ec2_url = "https://{}.ec2.amazonaws.com".format(region)
    except KeyError:
        pass

    try:
        ec2_url = os.environ['EC2_URL']
    except KeyError:
        pass

    ec2_conn = boto.connect_ec2_endpoint(ec2_url, AWS_ACCESS_KEY, AWS_SECRET_KEY)
    reservations = ec2_conn.get_all_instances()

    instances = []
    for reservation in reservations:
        for instance in reservation.instances:
            if instance.state != "running" and not show_all_instances:
                # sys.stderr.write("Disqualifying instance %s: not running" % ( instance.id ) )
                # Might be interesting to show a count of disqualified instances?
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
                    print instance_title

if __name__ == "__main__":
    main()
