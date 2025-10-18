#!/usr/bin/env python3
"""
A script to list EC2 EBS volumes with filtering and formatting options.
This follows the same patterns as other scripts in this collection.
"""

import argparse
import sys
import os
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description="List EC2 EBS volumes")
    parser.add_argument("-f", "--filters", nargs="*", 
                        help="Filters to apply (e.g., 'status=available', 'attachment.status=attached')")
    parser.add_argument("-r", "--region", default="us-west-2", 
                        help="Specify the AWS region (default: us-west-2)")
    parser.add_argument("--format", choices=["plain", "table", "json"], default="plain",
                        help="Output format (default: plain)")
    parser.add_argument("--boto3", action="store_true", 
                        help="Use the newer boto3 library instead of boto (deprecated)")
    
    args = parser.parse_args()

    filters = args.filters or []
    region = args.region
    use_boto3 = args.boto3

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
            # Parse filters from command line arguments
            parsed_filters = []
            for f in filters:
                if '=' in f:
                    key, value = f.split('=', 1)
                    parsed_filters.append({
                        'Name': key,
                        'Values': [value]
                    })
            
            response = ec2_conn.describe_volumes(Filters=parsed_filters)
            volumes = response['Volumes']
        except Exception as e:
            print("Error retrieving volumes: {}".format(str(e)))
            sys.exit(1)
    else:
        # For backward compatibility with boto (though boto doesn't have volume management)
        print("This script requires boto3 for volume management. Please use --boto3 flag.")
        sys.exit(1)

    # Process volumes and format output
    if args.format == "json":
        import json
        # Prepare volume data for JSON
        volume_data = []
        for volume in volumes:
            volume_info = {
                'id': volume['VolumeId'],
                'size': volume['Size'],
                'state': volume['State'],
                'type': volume['VolumeType'],
                'availability_zone': volume['AvailabilityZone'],
                'create_time': volume['CreateTime'].isoformat(),
                'encrypted': volume.get('Encrypted', False),
                'attachments': []
            }
            for attachment in volume.get('Attachments', []):
                volume_info['attachments'].append({
                    'instance_id': attachment['InstanceId'],
                    'device': attachment['Device'],
                    'attach_time': attachment['AttachTime'].isoformat(),
                    'status': attachment['State']
                })
            volume_data.append(volume_info)
        
        print(json.dumps(volume_data, indent=2))
    elif args.format == "table":
        # Print header for table format
        print("{:<20} {:<8} {:<12} {:<15} {:<15} {:<22} {:<10}".format(
            "Volume ID", "Size", "State", "Type", "AZ", "Create Time", "Encrypted"))
        print("-" * 110)
        
        for volume in volumes:
            create_time = volume['CreateTime'].strftime('%Y-%m-%d %H:%M:%S')
            encrypted = 'Yes' if volume.get('Encrypted', False) else 'No'
            print("{:<20} {:<8} {:<12} {:<15} {:<15} {:<22} {:<10}".format(
                volume['VolumeId'], 
                str(volume['Size']), 
                volume['State'], 
                volume['VolumeType'], 
                volume['AvailabilityZone'],
                create_time,
                encrypted))
    else:  # plain format
        for volume in volumes:
            volume_title = "%s %s %s %s %s %s %s" % (
                volume['VolumeId'], 
                volume['Size'], 
                volume['State'], 
                volume['VolumeType'], 
                volume['AvailabilityZone'],
                volume['CreateTime'].strftime('%Y-%m-%d %H:%M:%S'),
                'encrypted' if volume.get('Encrypted', False) else 'not-encrypted')
            print(volume_title)

if __name__ == "__main__":
    main()