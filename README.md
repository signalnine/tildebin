tildebin
========

small utilities for your ~/bin/

## Testing

Run all tests:
```bash
make test
```

See [tests/README.md](tests/README.md) for detailed testing documentation.

## Scripts

### AWS EC2 Management
- `listec2hosts.py`: List EC2 instances with options for region, output format, and instance state filtering
- `ec2_tag_summary.py`: Summarize EC2 instances by tags across regions
- `ec2_manage.py`: Manage EC2 instances (start, stop, restart)
- `terminate_instance.py`: Terminate an EC2 instance with user confirmation
- `stop_all_instances.py`: Stop all running EC2 instances in a region with user confirmation
- `emptysgs.py`: Find unused AWS EC2 Security Groups
- `listvolumes.py`: List EC2 EBS volumes with filtering and formatting options
- `grephosts.sh`: Filter EC2 host output based on a search query

### SSH Operations
- `acrosshosts.sh`: Execute a command on multiple hosts via SSH
- `useradd.sh`: Create a user account with SSH access on multiple hosts

### Baremetal System Monitoring
- `disk_health_check.py`: Monitor disk health using SMART attributes
- `check_raid.py`: Check status of hardware and software RAID arrays
- `network_bond_status.sh`: Check status of network bonded interfaces
- `system_inventory.py`: Generate hardware inventory for baremetal systems
- `filesystem_usage_tracker.py`: Track filesystem usage and identify large directories

### Kubernetes Management
- `kubernetes_node_health.py`: Check Kubernetes node health and resource availability
- `k8s_pod_resource_audit.py`: Audit pod resource usage and identify resource issues

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

### stop_all_instances.py
```
python stop_all_instances.py [-r region] [--force] [--dry-run]
  -r, --region: Specify the AWS region (default: us-west-2)
  --force: Force stop without confirmation prompt
  --dry-run: Show instances that would be stopped without actually stopping them
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region

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

### disk_health_check.py
```
python disk_health_check.py [-d disk] [-v] [--format format] [--warn-only]
  -d, --disk: Specific disk to check (e.g., /dev/sda)
  -v, --verbose: Show detailed SMART attributes
  --format: Output format, either 'plain' or 'json' (default: plain)
  --warn-only: Only show disks with warnings or failures
```

Requirements:
  - smartmontools package (smartctl command)
  - Ubuntu/Debian: `sudo apt-get install smartmontools`
  - RHEL/CentOS: `sudo yum install smartmontools`

### check_raid.py
```
python check_raid.py [-t type] [-v] [--format format] [--warn-only]
  -t, --type: Type of RAID to check - 'all', 'software', or 'hardware' (default: all)
  -v, --verbose: Show detailed information
  --format: Output format, either 'plain' or 'json' (default: plain)
  --warn-only: Only show arrays with warnings or failures
```

Requirements:
  - Software RAID: /proc/mdstat (built-in on Linux)
  - LSI/Broadcom hardware RAID: MegaCli
  - HP hardware RAID: hpacucli/ssacli
  - Requires root privileges for hardware RAID detection

### network_bond_status.sh
```
network_bond_status.sh [-b bond] [-v] [-j]
  -b, --bond: Check specific bond interface
  -v, --verbose: Show detailed information
  -j, --json: Output in JSON format
```

Requirements:
  - Linux bonding module loaded
  - /proc/net/bonding directory

### system_inventory.py
```
python system_inventory.py [--format format] [-o output] [--include-pci]
  --format: Output format, either 'plain' or 'json' (default: plain)
  -o, --output: Output file (default: stdout)
  --include-pci: Include PCI device listing
```

Note: Run as root for additional hardware details from dmidecode

### filesystem_usage_tracker.py
```
python filesystem_usage_tracker.py <path> [-d depth] [-n top] [--format format] [-q]
  path: Root filesystem path to scan (required)
  -d, --depth: Maximum directory depth to traverse (default: 3)
  -n, --top: Number of top entries to display (default: 10)
  --format: Output format, either 'plain', 'table', or 'json' (default: table)
  -q, --quiet: Suppress progress messages
```

Requirements:
  - du command-line tool (coreutils package, usually pre-installed)

Exit codes:
  - 0: Successful scan
  - 1: Error during scanning (permission denied, path not found, etc.)
  - 2: Usage error (invalid arguments)

Features:
  - Identifies large directories consuming the most disk space
  - Multiple output formats for scripting and human readability
  - Configurable depth and result count
  - Parallel processing with du for performance
  - Graceful error handling with helpful messages

Examples:
```bash
# Scan /var for large directories (default: depth 3, show top 10)
filesystem_usage_tracker.py /var

# Show top 20 directories in /home with detailed tree (depth 5)
filesystem_usage_tracker.py /home -d 5 -n 20

# Get JSON output for monitoring or scripting
filesystem_usage_tracker.py /opt --format json

# Quiet mode - suppress progress messages
filesystem_usage_tracker.py /var -q

# Scan with plain format (space-separated values)
filesystem_usage_tracker.py /usr --format plain
```

### kubernetes_node_health.py
```
python kubernetes_node_health.py [--format format] [--warn-only]
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show nodes with warnings or issues
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - Optional: metrics-server for resource usage metrics

Exit codes:
  - 0: All nodes healthy
  - 1: One or more nodes unhealthy or warnings detected
  - 2: Usage error or kubectl not available

Examples:
```bash
# Check all nodes with plain output
kubernetes_node_health.py

# Show only problematic nodes
kubernetes_node_health.py --warn-only

# Get JSON output for monitoring integration
kubernetes_node_health.py --format json

# Combine options
kubernetes_node_health.py -f json -w
```

### k8s_pod_resource_audit.py
```
python k8s_pod_resource_audit.py [--namespace NAMESPACE] [--format format] [--warn-only] [--show-quotas]
  --namespace, -n: Namespace to audit (default: all namespaces)
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show pods with warnings or issues
  --show-quotas, -q: Show resource quota information
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - Optional: metrics-server for current resource usage metrics

Exit codes:
  - 0: No resource issues detected
  - 1: Resource issues found (warnings)
  - 2: Usage error or kubectl not available

Features:
  - Detects pods with no resource requests/limits set
  - Identifies OOMKilled pods and excessive restarts
  - Shows pods in CrashLoopBackOff or other error states
  - Reports evicted pods
  - Displays current resource usage (when metrics-server available)
  - Shows namespace resource quota utilization

Examples:
```bash
# Audit all pods across all namespaces
k8s_pod_resource_audit.py

# Audit pods in production namespace only
k8s_pod_resource_audit.py -n production

# Show only pods with issues
k8s_pod_resource_audit.py --warn-only

# Get JSON output for monitoring integration
k8s_pod_resource_audit.py --format json

# Show resource quotas along with pod status
k8s_pod_resource_audit.py --show-quotas

# Combine options: only problematic pods in JSON format
k8s_pod_resource_audit.py -w -f json -n kube-system
```
