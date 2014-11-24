#!/usr/bin/python
# Largely adapted from fec2din: https://github.com/epheph/fec2din

import argparse
import sys
import os
import boto
import re
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument("-a", "--all", nargs='?', default=False, help="Include all instances, not just running instances")
args = parser.parse_args()

if args.all == False:
  show_all_instances = False
else:
  show_all_instances = True



# You can uncomment and set these, or set the env variables AWSAccessKeyId & AWSSecretKey
# AWS_ACCESS_KEY="aaaaaaaaaaaaaaaaaaaa"
# AWS_SECRET_KEY="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# Set your region in here or set E2_REGION as an environment variable:
ec2_url="https://us-west-2.ec2.amazonaws.com"

try:
  AWS_ACCESS_KEY
except NameError:
  try:
    AWS_ACCESS_KEY=os.environ['AWS_ACCESS_KEY']
    AWS_SECRET_KEY=os.environ['AWS_SECRET_KEY']
  except KeyError:
    print """Please set environment variables AWS_ACCESS_KEY & AWS_SECRET_KEY
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


