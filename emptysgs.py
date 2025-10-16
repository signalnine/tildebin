#!/usr/bin/env python3
# find security groups that aren't being utilized
import boto3

EC2_REGION = 'us-east-1'
ec2 = boto3.client('ec2', region_name=EC2_REGION)

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
