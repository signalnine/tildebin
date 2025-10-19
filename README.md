tildebin
========

small utilities for your ~/bin/

## Scripts

### AWS EC2 Management
- `listec2hosts.py`: List EC2 instances with options for region, output format, and instance state filtering
- `ec2_tag_summary.py`: Summarize EC2 instances by tags across regions
- `ec2_manage.py`: Manage EC2 instances (start, stop, restart)
- `terminate_instance.py`: Terminate an EC2 instance with user confirmation
- `emptysgs.py`: Find unused AWS EC2 Security Groups
- `listvolumes.py`: List EC2 EBS volumes with filtering and formatting options
- `grephosts.sh`: Filter EC2 host output based on a search query

### SSH Operations
- `acrosshosts.sh`: Execute a command on multiple hosts via SSH
- `useradd.sh`: Create a user account with SSH access on multiple hosts

### System Utilities
- `generate_fstab.sh`: Generate an /etc/fstab file from current mounts using UUIDs

## Usage

### listec2hosts.py
```
python listec2hosts.py [-a] [-r region] [--format format] [--boto3]
  -a, --all: Include all instances, not just running instances
  -r, --region: Specify the AWS region (default: us-west-2)
  --format: Output format, either 'plain' or 'table' (default: plain)
  --boto3: Use the newer boto3 library instead of boto (deprecated)
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region
  - `EC2_URL`: Override the default EC2 URL

### ec2_manage.py
```
python ec2_manage.py [action] [instance_id] [-r region] [--boto3]
  action: Action to perform - 'start', 'stop', or 'restart'
  instance_id: ID of the EC2 instance to manage
  -r, --region: Specify the AWS region (default: us-west-2)
  --boto3: Use the newer boto3 library instead of boto (deprecated)
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region
  - `EC2_URL`: Override the default EC2 URL

### acrosshosts.sh
```
acrosshosts.sh [hostlist.txt] [command]
```

### useradd.sh
```
useradd.sh [hostlist.txt] [username] [sshpubkey]
```

### grephosts.sh
```
grephosts.sh [search query]
```

### generate_fstab.sh
```
generate_fstab.sh
```

### emptysgs.py
```
python emptysgs.py [-r region]
  -r, --region: Specify the AWS region (default: us-east-1)
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region

### ec2_tag_summary.py
```
python ec2_tag_summary.py --tag-key TAG_KEY [--tag-value TAG_VALUE] [--regions REGION1 REGION2 ...] [--format FORMAT]
  --tag-key: The tag key to group instances by (required)
  --tag-value: Optional tag value to filter by
  --regions: AWS regions to scan (default: us-west-2 us-east-1)
  --format: Output format, either 'plain' or 'json' (default: plain)
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region

### terminate_instance.py
```
python terminate_instance.py [instance_id] [-r region]
  instance_id: ID of the EC2 instance to terminate
  -r, --region: Specify the AWS region (default: us-west-2)
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region
  - `EC2_URL`: Override the default EC2 URL

### listvolumes.py
```
python listvolumes.py [-f filters] [-r region] [--format format] [--boto3]
  -f, --filters: Filters to apply (e.g., 'status=available', 'attachment.status=attached')
  -r, --region: Specify the AWS region (default: us-west-2)
  --format: Output format, either 'plain', 'table', or 'json' (default: plain)
  --boto3: Use the newer boto3 library instead of boto (deprecated)
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region
