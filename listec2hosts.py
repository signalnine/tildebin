#!/usr/bin/python

import argparse
import sys
import os
import boto
import re
# from pprint import pprint
# from inspect import getmembers
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument("ec2_filter", nargs='?', type=str,
                    help="Specify filter value, which is auto-detected (i.e. i-591f571ab, web-server (security group), 10.54.101.47, db-master (tag)")
parser.add_argument("-a", "--all", nargs='?', default=False, help="Include all instances, not just running instances")
args = parser.parse_args()

if args.all == False:
  show_all_instances = False
else:
  show_all_instances = True

ec2_filter = args.ec2_filter


# You can uncomment and set these, or set the env variables AWSAccessKeyId & AWSSecretKey
# AWS_ACCESS_KEY="aaaaaaaaaaaaaaaaaaaa"
# AWS_SECRET_KEY="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

ec2_url="https://us-west-2.ec2.amazonaws.com"

try:
  AWS_ACCESS_KEY
except NameError:
  try:
    AWS_ACCESS_KEY=os.environ['AWS_ACCESS_KEY']
    AWS_SECRET_KEY=os.environ['AWS_SECRET_KEY']
  except KeyError:
    print """Please set environment variables AWS_ACCESS_KEY & AWS_SECRET_KEY
Please note that while ec2-describe-instances and other CLI tools use
EC2_CERT & EC2_PRIVATE_KEY, fec2din uses the access key & secret key.
This would look something like:
  export AWS_ACCESS_KEY=JFIOQNAKEIFJJAKDLIJA
  export AWS_SECRET_KEY=3jfioajkle+OnfAEV5OIvj5nLnRy2jfklZRop3nn
"""
    sys.exit(1)


try:
  ec2_url = "https://%s.ec2.amazonaws.com" % os.environ['EC2_REGION']
except KeyError:
  pass

try:
  ec2_url = os.environ['EC2_URL']
except KeyError:
  pass

ec2_conn = boto.connect_ec2_endpoint(ec2_url, AWS_ACCESS_KEY, AWS_SECRET_KEY)

if ec2_filter:
  if re.match( "^i-", ec2_filter ):
    # Instance ID, like: i-581f38e4
    ec2_filter_dict = { "instance-id": ec2_filter }
    show_all_instances = True # override, since this can only return 1 instance
    reservations = ec2_conn.get_all_instances( filters=ec2_filter_dict)
  elif re.match( "^[a-z][0-9]\......", ec2_filter ):
    # Instance Type, like m1.small
    ec2_filter_dict = { "instance-type": ec2_filter }
    reservations = ec2_conn.get_all_instances(filters=ec2_filter_dict)
  elif re.match( "^10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}$", ec2_filter ):
    # Private IP, like 10.45.37.122
    ec2_filter_dict = { "private-ip-address": ec2_filter }
    show_all_instances = True # override, since this can only return 1 instance
    reservations = ec2_conn.get_all_instances(filters=ec2_filter_dict)
  elif re.match( "^(ip|domU)-.*.ec2.internal$", ec2_filter ):
    # Private hostname, like ip-10-20-43-129.ec2.internal
    ec2_filter_dict = { "private-dns-name": ec2_filter }
    show_all_instances = True # override, since this can only return 1 instance
    reservations = ec2_conn.get_all_instances(filters=ec2_filter_dict)
  elif re.match( "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ec2_filter ):
    # Public IP, like 23.101.47.232
    ec2_filter_dict = { "ip-address": ec2_filter }
    show_all_instances = True # override, since this can only return 1 instance
    reservations = ec2_conn.get_all_instances(filters=ec2_filter_dict)
  else:
    # Could be a named tag or a security group? Let's just try each
    ec2_filter_dict = { "tag:Name": ec2_filter }
    reservations = ec2_conn.get_all_instances(filters=ec2_filter_dict)
    if len( reservations ) == 0:
      ec2_filter_dict = { "group-name": ec2_filter }
      reservations = ec2_conn.get_all_instances(filters=ec2_filter_dict)

else:
  reservations = ec2_conn.get_all_instances()


running_instances = {}
for reservation in reservations:
  for instance in reservation.instances:
    if instance.state != "running" and not show_all_instances:
      # sys.stderr.write("Disqualifying instance %s: not running\n\n" % ( instance.id ) )
      # Might be interesting to show a count of disqualified instances?
      pass
    else:
      # pprint (getmembers(instance))
      az = instance.placement
      instance_type = instance.instance_type
      running_instances[ (instance_type, az ) ] = running_instances.get( (instance_type, az ) , 0 ) + 1
      if 'Name' in instance.tags:
        instance_title = "%s %s" % ( instance.tags['Name'], instance.id )

        # We're printing out non-name tags later, this doesn't delete in amazon
        del instance.tags['Name']
      else:
        instance_title = "%s" % instance.id
      print "%s" % instance_title


