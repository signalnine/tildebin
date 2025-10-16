tildebin
========

small utilities for your ~/bin/

## Scripts

### AWS EC2 Management
- `listec2hosts.py`: List EC2 instances with options for region, output format, and instance state filtering
- `emptysgs.py`: Find unused AWS EC2 Security Groups
- `grephosts.sh`: Filter EC2 host output based on a search query

### SSH Operations
- `acrosshosts.sh`: Execute a command on multiple hosts via SSH
- `useradd.sh`: Create a user account with SSH access on multiple hosts

### System Utilities
- `generate_fstab.sh`: Generate an /etc/fstab file from current mounts using UUIDs

## Usage

### listec2hosts.py
```
python listec2hosts.py [-a] [-r region] [--format format]
  -a, --all: Include all instances, not just running instances
  -r, --region: Specify the AWS region (default: us-west-2)
  --format: Output format, either 'plain' or 'table' (default: plain)
```

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
python emptysgs.py
```
