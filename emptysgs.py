#!/usr/bin/env python3
# find security groups that aren't being utilized
import argparse
import sys
import os


def main():
    parser = argparse.ArgumentParser(description="Find unused EC2 Security Groups")
    parser.add_argument("-r", "--region", default="us-east-1",
                        help="Specify the AWS region (default: us-east-1)")
    
    args = parser.parse_args()

    region = args.region

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

    # Import boto3 only when we actually need it - after argument parsing and credential checks
    try:
        import boto3
    except ImportError:
        print("Error: The 'boto3' library is required to run this script.")
        print("You can install it using: pip install boto3")
        sys.exit(1)

    try:
        ec2 = boto3.client('ec2', region_name=region)
    except Exception as e:
        print("Error connecting to EC2: {}".format(str(e)))
        sys.exit(1)

    try:
        # Get all security groups
        response = ec2.describe_security_groups()
        sgs = response['SecurityGroups']

        for sg in sgs:
            # Check if the security group has no network interfaces attached
            # Using describe_network_interfaces to check usage
            ni_response = ec2.describe_network_interfaces(
                Filters=[{'Name': 'group-id', 'Values': [sg['GroupId']]}]
            )
            if len(ni_response['NetworkInterfaces']) == 0:
                print("{0}\t{1}".format(sg['GroupId'], sg['GroupName']))
    except Exception as e:
        print("Error retrieving security groups: {}".format(str(e)))
        sys.exit(1)


if __name__ == "__main__":
    main()