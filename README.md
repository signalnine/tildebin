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
- `cpu_frequency_monitor.py`: Monitor CPU frequency scaling and governor settings
- `hardware_temperature_monitor.py`: Monitor hardware temperature sensors and fan speeds
- `ipmi_sel_monitor.py`: Monitor IPMI System Event Log (SEL) for hardware errors and critical events
- `memory_health_monitor.py`: Monitor memory health, ECC errors, and memory pressure
- `network_interface_health.py`: Monitor network interface health and error statistics
- `network_bond_status.sh`: Check status of network bonded interfaces
- `ntp_drift_monitor.py`: Monitor NTP/Chrony time synchronization and detect clock drift
- `pcie_health_monitor.py`: Monitor PCIe device health, link status, and error counters
- `system_inventory.py`: Generate hardware inventory for baremetal systems
- `filesystem_usage_tracker.py`: Track filesystem usage and identify large directories
- `sysctl_audit.py`: Audit kernel parameters (sysctl) against a baseline configuration

### Kubernetes Management
- `kubernetes_node_health.py`: Check Kubernetes node health and resource availability
- `k8s_pod_resource_audit.py`: Audit pod resource usage and identify resource issues
- `k8s_pv_health_check.py`: Check persistent volume health and storage status
- `k8s_deployment_status.py`: Monitor Deployment and StatefulSet rollout status and replica availability
- `k8s_statefulset_health.py`: Monitor StatefulSet health with detailed pod and PVC status checking
- `k8s_dns_health_monitor.py`: Monitor DNS health including CoreDNS/kube-dns pod status and resolution testing
- `k8s_event_monitor.py`: Monitor Kubernetes events to track cluster issues and anomalies
- `k8s_node_capacity_planner.py`: Analyze cluster capacity and forecast resource allocation
- `k8s_cpu_throttling_detector.py`: Detect pods experiencing or at risk of CPU throttling
- `k8s_ingress_cert_checker.py`: Check Ingress certificates for expiration and health status
- `k8s_node_drain_readiness.py`: Analyze node drainability and orchestrate graceful node maintenance
- `k8s_memory_pressure_analyzer.py`: Detect memory pressure on nodes and analyze pod memory usage patterns
- `k8s_pod_eviction_risk_analyzer.py`: Identify pods at risk of eviction due to resource pressure or QoS class
- `k8s_node_restart_monitor.py`: Monitor node restart activity and detect nodes with excessive restarts
- `k8s_pod_count_analyzer.py`: Audit pod counts, scaling configuration, and resource quota usage
- `k8s_orphaned_resources_finder.py`: Find orphaned and unused resources (ConfigMaps, Secrets, PVCs, Services, ServiceAccounts)
- `k8s_container_restart_analyzer.py`: Analyze container restart patterns and identify root causes with remediation suggestions
- `k8s_network_policy_audit.py`: Audit network policies and identify security gaps, unprotected pods, and configuration issues

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
acrosshosts.sh [OPTIONS] <hostlist> <command>
  <hostlist>    File containing list of hosts (one per line)
  <command>     Command to execute on each host

Options:
  -j, --jobs N          Run N jobs in parallel (default: 1)
  -t, --timeout N       SSH connection timeout in seconds (default: 30)
  -u, --user USER       SSH username (default: current user)
  -s, --strict          Enable strict host key checking (default: disabled)
  -o, --ssh-opts OPTS   Additional SSH options (quoted string)
  -T, --teleport        Use Teleport (tsh ssh) instead of regular SSH
  -v, --verbose         Verbose output (show SSH commands)
  -q, --quiet           Quiet mode (only show errors)
  -n, --dry-run         Show what would be executed without running
  -h, --help            Display help message
```

Features:
  - Parallel execution with configurable job count
  - Support for both standard SSH and Teleport (tsh ssh)
  - Configurable SSH timeout (prevents hanging on unreachable hosts)
  - Comprehensive error handling and reporting
  - Dry-run mode for safety before destructive operations
  - Support for comments and empty lines in hostlist
  - Color-coded output (success/failure indicators)
  - Summary report showing succeeded and failed hosts

Exit codes:
  - 0: All hosts succeeded
  - 1: One or more hosts failed
  - 2: Usage error or invalid arguments

Examples:
```bash
# Run uptime on all hosts
acrosshosts.sh hosts.txt "uptime"

# Run with 5 parallel connections
acrosshosts.sh -j 5 hosts.txt "df -h"

# Use specific user with verbose output
acrosshosts.sh -u admin -v hosts.txt "systemctl status nginx"

# Dry run to see what would execute
acrosshosts.sh -n hosts.txt "rm -rf /tmp/old_files"

# Custom timeout and SSH options
acrosshosts.sh -t 10 -o "-p 2222" hosts.txt "hostname"

# Use Teleport for secure access
acrosshosts.sh -T hosts.txt "uptime"

# Use Teleport with parallel execution and specific user
acrosshosts.sh -T -j 5 -u admin hosts.txt "systemctl status app"
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

### hardware_temperature_monitor.py
```
python hardware_temperature_monitor.py [-f format] [-w] [-v]
  -f, --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show sensors with warnings or critical status
  -v, --verbose: Show detailed threshold information
```

Requirements:
  - lm-sensors package (sensors command)
  - Ubuntu/Debian: `sudo apt-get install lm-sensors`
  - RHEL/CentOS: `sudo yum install lm_sensors`
  - Run `sensors-detect` after installation to configure sensors

Exit codes:
  - 0: All temperatures normal
  - 1: Warning or critical temperatures detected
  - 2: Usage error or missing dependencies

Features:
  - Monitor CPU, GPU, and motherboard temperatures
  - Track fan speeds and detect fan failures
  - Compare readings against hardware thresholds
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode to focus on thermal issues
  - JSON output for monitoring system integration

Examples:
```bash
# Check all temperature sensors
hardware_temperature_monitor.py

# Show only warnings and critical temperatures
hardware_temperature_monitor.py --warn-only

# Detailed output with all thresholds
hardware_temperature_monitor.py --verbose

# JSON output for monitoring integration
hardware_temperature_monitor.py --format json

# Table format with warnings only
hardware_temperature_monitor.py --format table --warn-only
```

Use Case: In large-scale baremetal datacenters, thermal issues can lead to hardware throttling, system instability, or permanent damage. This script provides visibility into temperature sensors and fan speeds across servers, making it ideal for proactive thermal monitoring and capacity planning. Critical for high-density deployments where cooling is a concern.

### ipmi_sel_monitor.py
```
python ipmi_sel_monitor.py [-f format] [-w] [-v] [--hours N] [--clear]
  -f, --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show warning and critical events
  -v, --verbose: Show detailed SEL information
  --hours: Only show events from the last N hours
  --clear: Clear SEL after displaying (requires root privileges)
```

Requirements:
  - ipmitool package
  - Ubuntu/Debian: `sudo apt-get install ipmitool`
  - RHEL/CentOS: `sudo yum install ipmitool`
  - Requires root privileges or proper IPMI user permissions

Exit codes:
  - 0: No critical events or only informational events
  - 1: Warning or critical events detected
  - 2: Usage error or missing dependencies

Features:
  - Monitor IPMI System Event Log (SEL) for hardware failures
  - Detect power supply failures, memory ECC errors, fan failures
  - Track temperature threshold violations and voltage anomalies
  - Categorize events by severity (CRITICAL, WARNING, INFO)
  - Filter events by time range (e.g., last 24 hours)
  - Multiple output formats (plain, JSON, table)
  - SEL clearing capability for maintenance
  - JSON output for monitoring system integration

Examples:
```bash
# Check all SEL entries
ipmi_sel_monitor.py

# Show only warnings and critical events
ipmi_sel_monitor.py --warn-only

# Show events from last 24 hours
ipmi_sel_monitor.py --hours 24

# JSON output for monitoring integration
ipmi_sel_monitor.py --format json

# Table format with recent warnings
ipmi_sel_monitor.py --format table --warn-only --hours 48

# Clear SEL after viewing (requires root)
sudo ipmi_sel_monitor.py --clear
```

Use Case: The IPMI System Event Log is a critical component of hardware monitoring in baremetal datacenters. It captures hardware-level events that may not be visible to the operating system, including power supply failures, memory errors, thermal events, and fan failures. This script provides proactive detection of hardware issues before they cause system downtime, making it essential for large-scale baremetal fleet management. The SEL often contains early warning signs of impending hardware failures, allowing for preventive maintenance.

### memory_health_monitor.py
```
python memory_health_monitor.py [--format format] [--warn-only] [--verbose]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only: Only show memory issues (warnings/critical)
  --verbose: Show detailed DIMM information
```

Requirements:
  - Linux kernel with EDAC support for ECC error monitoring (/sys/devices/system/edac/mc)
  - /proc/meminfo for memory usage statistics (available on all Linux systems)
  - ECC-capable hardware and enabled EDAC kernel modules for full functionality

Exit codes:
  - 0: No memory errors detected
  - 1: Memory warnings or errors detected
  - 2: Usage error or missing dependencies

Features:
  - Monitor ECC (Error-Correcting Code) memory errors
  - Detect correctable (CE) and uncorrectable (UE) memory errors
  - Per-DIMM error tracking with location information
  - Memory pressure analysis (RAM and swap usage)
  - Multiple memory controller support
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode to focus on failing DIMMs
  - JSON output for monitoring system integration

Examples:
```bash
# Check memory health and ECC errors
memory_health_monitor.py

# Show only issues (warnings/critical)
memory_health_monitor.py --warn-only

# Detailed DIMM information
memory_health_monitor.py --verbose

# JSON output for monitoring integration
memory_health_monitor.py --format json

# Table format with warnings only
memory_health_monitor.py --format table --warn-only
```

Use Case: In large-scale baremetal environments, memory failures are a leading cause of system crashes and data corruption. ECC memory can detect and correct single-bit errors, but tracking these errors is critical for predictive maintenance. This script monitors ECC error counts at both the memory controller and individual DIMM level, enabling proactive replacement of failing DIMMs before uncorrectable errors occur. It also monitors memory pressure to detect capacity issues. Essential for maintaining reliability in production baremetal infrastructure.

### cpu_frequency_monitor.py
```
python cpu_frequency_monitor.py [--format format] [--expected-governor governor] [--warn-only] [--verbose] [--no-throttle-check]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --expected-governor: Expected governor (e.g., performance, powersave)
  --warn-only: Only show CPUs with warnings or issues
  --verbose: Show detailed information for all CPUs
  --no-throttle-check: Disable throttling detection
```

Requirements:
  - Linux kernel with cpufreq support (sysfs interface at /sys/devices/system/cpu)
  - Most modern Linux systems have this enabled by default

Exit codes:
  - 0: All CPUs configured correctly
  - 1: Issues detected (wrong governor, throttling, scaling limits)
  - 2: Usage error or missing cpufreq interface

Features:
  - Monitor current CPU frequencies across all cores
  - Verify CPU governor settings (performance, powersave, ondemand, etc.)
  - Detect CPU throttling or frequency capping
  - Identify scaling limit constraints
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode to focus on problem CPUs
  - JSON output for monitoring system integration

Examples:
```bash
# Check CPU frequency status
cpu_frequency_monitor.py

# Verify all CPUs are using 'performance' governor
cpu_frequency_monitor.py --expected-governor performance

# Show only CPUs with issues
cpu_frequency_monitor.py --warn-only

# Detailed output for all CPUs
cpu_frequency_monitor.py --verbose

# JSON output for monitoring integration
cpu_frequency_monitor.py --format json

# Table format showing all CPUs
cpu_frequency_monitor.py --format table

# Check without false positives from normal frequency scaling
cpu_frequency_monitor.py --no-throttle-check
```

Use Case: In large-scale baremetal environments, incorrect CPU governor settings or unexpected frequency throttling can severely impact workload performance. This script helps identify nodes running at reduced clock speeds due to thermal throttling, power management misconfiguration, or BIOS settings. Essential for Kubernetes worker nodes and compute-intensive workloads where consistent CPU performance is critical. Use in your monitoring stack to detect performance degradation before it impacts production services.

### network_interface_health.py
```
python network_interface_health.py [-i interface] [-v] [--format format] [--warn-only]
  -i, --interface: Specific interface to check (e.g., eth0)
  -v, --verbose: Show detailed error statistics
  --format: Output format, either 'plain' or 'json' (default: plain)
  --warn-only: Only show interfaces with warnings or errors
```

Requirements:
  - ip command-line tool (iproute2 package, usually pre-installed)
  - ethtool command-line tool (optional, for speed/duplex info)

Exit codes:
  - 0: All interfaces healthy
  - 1: One or more interfaces degraded or down
  - 2: Usage error or missing dependencies

Features:
  - Monitor RX/TX packet errors, drops, and overruns
  - Detect interface link state (UP/DOWN)
  - Display speed and duplex mode (with ethtool)
  - Show interface IP addresses and MTU
  - JSON output for monitoring integration
  - Warn-only mode to focus on problem interfaces

Examples:
```bash
# Check all network interfaces
network_interface_health.py

# Check specific interface with detailed stats
network_interface_health.py -i eth0 -v

# Show only interfaces with errors
network_interface_health.py --warn-only

# Output as JSON for monitoring
network_interface_health.py --format json
```

### ntp_drift_monitor.py
```
python ntp_drift_monitor.py [-f format] [-v] [-w threshold] [-c threshold]
  -f, --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed synchronization information
  -w, --warn-threshold: Warning threshold for time offset in seconds (default: 0.100)
  -c, --crit-threshold: Critical threshold for time offset in seconds (default: 1.000)
```

Requirements:
  - chrony (recommended) or ntp daemon
  - Ubuntu/Debian: `sudo apt-get install chrony`
  - RHEL/CentOS: `sudo yum install chrony`

Exit codes:
  - 0: Time synchronized within acceptable limits
  - 1: Warning or critical drift detected
  - 2: Usage error or missing dependencies

Features:
  - Monitor NTP/Chrony time synchronization status
  - Detect clock drift and offset from reference time
  - Check stratum level and reference source
  - Track RMS offset and frequency drift (chrony)
  - Multiple output formats (plain, JSON, table)
  - Configurable warning and critical thresholds
  - Critical for distributed systems, databases, and K8s clusters

Examples:
```bash
# Check time synchronization status
ntp_drift_monitor.py

# Show detailed sync information
ntp_drift_monitor.py --verbose

# Output as JSON for monitoring systems
ntp_drift_monitor.py --format json

# Custom thresholds (warn at 50ms, critical at 500ms)
ntp_drift_monitor.py --warn-threshold 0.050 --crit-threshold 0.500

# Table format for overview
ntp_drift_monitor.py --format table
```

Use Case: Time synchronization is critical for distributed systems, Kubernetes clusters, databases (especially distributed ones), and certificate validation. Clock drift can cause authentication failures, data inconsistencies, and cluster coordination issues. This script monitors NTP/Chrony status to detect and alert on time synchronization problems before they impact services.

Use Case: In large baremetal environments, network interface errors can indicate hardware problems, driver issues, or network congestion. This script provides quick visibility into interface health across all network adapters, making it ideal for periodic health checks or monitoring integration.

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

### sysctl_audit.py
```
python sysctl_audit.py [-b baseline] [--save file] [-p parameter] [-v] [--warn-only] [--format format]
  -b, --baseline: Baseline configuration file to compare against
  --save: Save current sysctl values as a baseline file
  -p, --parameter: Check a specific parameter value
  -v, --verbose: Show all parameters including matches
  --warn-only, -w: Only show parameters with warnings or mismatches
  --format: Output format, either 'plain' or 'json' (default: plain)
```

Requirements:
  - sysctl command-line tool (procps-ng package on Linux)
  - Read access to /proc/sys or appropriate permissions for sysctl

Exit codes:
  - 0: All parameters match baseline (or parameter found)
  - 1: One or more parameters differ from baseline
  - 2: Usage error, missing dependencies, or file not found

Features:
  - Create baseline snapshots of current kernel parameters
  - Compare system settings against baseline configuration
  - JSON output for integration with monitoring systems
  - Verbose mode to verify all settings match baseline
  - Warn-only mode to see only deviations

Examples:
```bash
# Create a baseline of current kernel settings
sysctl_audit.py --save baseline.conf

# Check if system matches baseline
sysctl_audit.py -b baseline.conf

# Show only mismatched parameters
sysctl_audit.py -b baseline.conf --warn-only

# Check a specific parameter
sysctl_audit.py -p net.ipv4.ip_forward

# Get JSON output for monitoring integration
sysctl_audit.py -b baseline.conf --format json

# Show all parameters with their match status
sysctl_audit.py -b baseline.conf --verbose
```

Use Case: In large baremetal deployments, ensuring consistent kernel settings across all hosts is critical. Create a baseline on a reference system, then use this script in your provisioning or monitoring pipeline to verify all nodes have the correct sysctl configuration.

### pcie_health_monitor.py
```
python pcie_health_monitor.py [--format format] [--warn-only] [--verbose]
  --format, -f: Output format, either 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show devices with warnings or critical status
  --verbose, -v: Show detailed device information including N/A devices
```

Requirements:
  - lspci command-line tool (pciutils package on Linux)
  - Read access to PCIe configuration space

Exit codes:
  - 0: All PCIe devices healthy
  - 1: Warning or critical conditions detected
  - 2: Usage error or missing dependencies

Features:
  - Monitor PCIe link speed and width (detect degradation)
  - Check for PCIe errors (correctable, uncorrectable, fatal)
  - Compare current link status vs. device capabilities
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode for monitoring integration
  - Detect devices running below capability (x16 at x8, Gen3 at Gen2)

Examples:
```bash
# Check all PCIe devices
pcie_health_monitor.py

# Show only devices with issues
pcie_health_monitor.py --warn-only

# Output as JSON for monitoring systems
pcie_health_monitor.py --format json

# Show table format with all details
pcie_health_monitor.py --format table --verbose
```

Use Case: In baremetal environments with GPUs, NVMe storage, or high-speed networking, PCIe link degradation can cause significant performance issues that are difficult to diagnose. This script detects PCIe devices running below their capabilities (such as a GPU running at x8 instead of x16, or a Gen3 device downgraded to Gen2), as well as devices with error counters indicating hardware problems. Regular monitoring can catch failing risers, thermal issues, or marginal PCIe slots before they cause complete failures.

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

### k8s_pv_health_check.py
```
python k8s_pv_health_check.py [--format format] [--warn-only]
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show PVs with warnings or issues
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All persistent volumes healthy
  - 1: One or more PVs unhealthy or warnings detected
  - 2: Usage error or kubectl not available

Features:
  - Detects persistent volumes in unhealthy states
  - Verifies PVCs are bound to existing volumes
  - Identifies released volumes with Retain policy
  - Warns about unusually small storage capacity
  - Cross-references PVs and PVCs for consistency
  - Supports plain text and JSON output formats

Examples:
```bash
# Check all persistent volumes with plain output
k8s_pv_health_check.py

# Show only volumes with issues
k8s_pv_health_check.py --warn-only

# Get JSON output for monitoring integration
k8s_pv_health_check.py --format json

# Combine options: only problematic volumes in JSON format
k8s_pv_health_check.py -w -f json
```

### k8s_deployment_status.py
```
python k8s_deployment_status.py [--namespace NAMESPACE] [--format format] [--warn-only]
  --namespace, -n: Namespace to check (default: all namespaces)
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show deployments/statefulsets with issues
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All deployments/statefulsets healthy and fully rolled out
  - 1: One or more deployments/statefulsets not ready or unhealthy
  - 2: Usage error or kubectl not available

Features:
  - Monitors Deployment and StatefulSet rollout status
  - Tracks replica availability (desired, ready, updated, available)
  - Detects stalled rollouts and pending replicas
  - Shows currently deployed image versions
  - Checks Progressing and Available conditions
  - Supports plain text and JSON output formats

Examples:
```bash
# Check all deployments and statefulsets with plain output
k8s_deployment_status.py

# Show only deployments with issues
k8s_deployment_status.py --warn-only

# Check specific namespace
k8s_deployment_status.py -n production

# Get JSON output for monitoring integration
k8s_deployment_status.py --format json

# Combine options: production namespace, only problematic, JSON format
k8s_deployment_status.py -n production -w -f json
```

### k8s_statefulset_health.py
```
python k8s_statefulset_health.py [--namespace NAMESPACE] [--format format] [--warn-only]
  --namespace, -n: Namespace to check (default: all namespaces)
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show StatefulSets with issues or warnings
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All StatefulSets healthy with all pods ready
  - 1: One or more StatefulSets unhealthy or have warnings
  - 2: Usage error or kubectl not available

Features:
  - StatefulSet-specific health monitoring beyond basic replica counts
  - Checks pod readiness and ordering (StatefulSets maintain stable pod identities)
  - Validates PersistentVolumeClaim binding status for each pod
  - Detects partition rollout status (for staged rollouts)
  - Monitors pod restart counts and container readiness
  - Identifies volume attachment issues
  - Validates StatefulSet update strategy configuration
  - Per-pod issue reporting for granular troubleshooting
  - Supports plain text and JSON output formats

Examples:
```bash
# Check all StatefulSets with plain output
k8s_statefulset_health.py

# Show only StatefulSets with issues
k8s_statefulset_health.py --warn-only

# Check specific namespace
k8s_statefulset_health.py -n production

# Get JSON output for monitoring integration
k8s_statefulset_health.py --format json

# Combine options: production namespace, only problematic, JSON format
k8s_statefulset_health.py -n production -w -f json
```

### k8s_dns_health_monitor.py
```
python k8s_dns_health_monitor.py [--namespace NAMESPACE] [--format format] [--warn-only] [--no-dns-test] [--test-domain DOMAIN]
  --namespace, -n: Namespace where DNS pods are running (default: kube-system)
  --format, -f: Output format, either 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show output if issues or warnings are detected
  --no-dns-test: Skip DNS resolution test (faster but less thorough)
  --test-domain: Domain to test DNS resolution (default: kubernetes.default.svc.cluster.local)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All DNS components healthy
  - 1: DNS issues detected
  - 2: Usage error or kubectl not available

Features:
  - Monitors CoreDNS/kube-dns pod health and readiness
  - Tests actual DNS resolution from within the cluster
  - Checks DNS service ClusterIP and endpoint availability
  - Tracks pod restart counts that may indicate instability
  - Validates DNS ConfigMap presence
  - Detects common DNS failure modes (no ready endpoints, service misconfiguration)
  - Supports plain text, JSON, and table output formats

Examples:
```bash
# Check DNS health with plain output
k8s_dns_health_monitor.py

# JSON output for monitoring systems
k8s_dns_health_monitor.py --format json

# Check DNS in a specific namespace
k8s_dns_health_monitor.py --namespace custom-dns

# Only show problems
k8s_dns_health_monitor.py --warn-only

# Skip DNS resolution test (faster)
k8s_dns_health_monitor.py --no-dns-test

# Test resolution of a custom domain
k8s_dns_health_monitor.py --test-domain my-service.production.svc.cluster.local

# Table format for easy reading
k8s_dns_health_monitor.py --format table
```

### k8s_event_monitor.py
```
python k8s_event_monitor.py [--namespace NAMESPACE] [--minutes MINUTES] [--format format] [--warn-only] [--categories]
  --namespace, -n: Namespace to monitor (default: all namespaces)
  --minutes, -m: Show events from last N minutes (default: all events)
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show warnings and errors
  --categories, -c: Show event category summary
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No critical events found
  - 1: Warning or error events detected
  - 2: Usage error or kubectl not available

Features:
  - Aggregates all events from a Kubernetes cluster
  - Filters events by namespace and time window
  - Categorizes events by type and reason
  - Tracks repeated events with count
  - Separates errors from warnings for quick identification
  - Supports multiple output formats (plain text and JSON)

Examples:
```bash
# Show all events across all namespaces
k8s_event_monitor.py

# Monitor only production namespace
k8s_event_monitor.py -n production

# Show events from the last 30 minutes
k8s_event_monitor.py --minutes 30

# Only show warnings and errors
k8s_event_monitor.py --warn-only

# Get JSON output for monitoring integration
k8s_event_monitor.py --format json

# Combine options: recent errors/warnings in JSON format
k8s_event_monitor.py -w -f json -m 60

# Show event category summary
k8s_event_monitor.py --categories
```

### k8s_node_capacity_planner.py
```
python k8s_node_capacity_planner.py [--format format] [--warn-only]
  --format, -f: Output format, either 'table', 'plain', 'json', or 'summary' (default: table)
  --warn-only, -w: Only show nodes with WARNING or CRITICAL capacity status
```

Requirements:
  - Python kubernetes library: `pip install kubernetes`
  - kubectl configured to access the Kubernetes cluster
  - Access to a Kubernetes cluster

Exit codes:
  - 0: Successfully analyzed cluster capacity
  - 1: Error accessing cluster or missing dependencies
  - 2: Usage error (invalid arguments)

Features:
  - Analyzes node allocatable resources (CPU, memory, pod count)
  - Calculates current pod requests and utilization percentages
  - Identifies nodes approaching capacity thresholds
  - Automatic capacity status determination (OK, MODERATE, WARNING, CRITICAL)
  - Multiple output formats for different use cases
  - Cluster-wide capacity summary and forecasting
  - Graceful handling of nodes with missing resource information

Output Formats:
  - **table**: Human-readable columnar format showing all nodes (default)
  - **plain**: Space-separated values for easy scripting
  - **json**: Machine-parseable JSON format with detailed metrics
  - **summary**: High-level cluster capacity overview with recommendations

Capacity Status Thresholds:
  - **OK**: < 50% utilization (lowest of CPU, memory, or pod count)
  - **MODERATE**: 50-75% utilization
  - **WARNING**: 75-90% utilization
  - **CRITICAL**: > 90% utilization

Examples:
```bash
# View all nodes with current capacity (default table format)
k8s_node_capacity_planner.py

# Show only nodes approaching capacity limits
k8s_node_capacity_planner.py --warn-only

# Get cluster-wide capacity summary
k8s_node_capacity_planner.py --format summary

# JSON output for monitoring integration
k8s_node_capacity_planner.py --format json

# Plain format for scripting/shell tools
k8s_node_capacity_planner.py --format plain

# Combine options: only critical nodes in JSON format
k8s_node_capacity_planner.py -w -f json
```

Use Cases:
  - **Capacity Planning**: Identify when cluster needs additional nodes
  - **Resource Management**: Detect underutilized or overprovisioned nodes
  - **Admission Control**: Understand which node can safely accept new workloads
  - **Cost Optimization**: Identify opportunities to consolidate workloads
  - **Monitoring Integration**: Export metrics via JSON for dashboards and alerting
  - **Baremetal Deployments**: Critical for on-premises K8s where adding hardware is expensive

### k8s_cpu_throttling_detector.py
```
python k8s_cpu_throttling_detector.py [--namespace NAMESPACE] [--format format] [--warn-only]
  --namespace, -n: Namespace to check (default: all namespaces)
  --format, -f: Output format, either 'plain', 'table', or 'json' (default: table)
  --warn-only, -w: Only show pods at risk of throttling
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - Optional: metrics-server for current CPU usage metrics

Exit codes:
  - 0: No throttled pods detected
  - 1: One or more pods experiencing throttling or at risk
  - 2: Usage error or kubectl not available

Features:
  - Detects pods with very low CPU limits that may cause throttling
  - Identifies pods with no CPU requests/limits set (at risk)
  - Tracks pods currently using >75% of their CPU limit (when metrics available)
  - Flags pods using >90% of limit as HIGH priority
  - Multiple output formats for integration with monitoring systems

Examples:
```bash
# Check all pods with table output
k8s_cpu_throttling_detector.py

# Show only at-risk pods
k8s_cpu_throttling_detector.py --warn-only

# Check specific namespace
k8s_cpu_throttling_detector.py -n production

# Get JSON output for monitoring integration
k8s_cpu_throttling_detector.py --format json

# Combine options: production namespace, only problematic, JSON format
k8s_cpu_throttling_detector.py -n production -w -f json
```

Use Cases:
  - **Performance Troubleshooting**: Identify workloads being throttled due to CPU limits
  - **Resource Optimization**: Find pods with insufficient CPU allocation
  - **Capacity Planning**: Detect applications needing more CPU resources
  - **Monitoring Integration**: Export throttling risks via JSON for dashboards
  - **Multi-tenant Environments**: Identify noisy neighbors affecting other pods

### k8s_ingress_cert_checker.py
```
python k8s_ingress_cert_checker.py [--namespace NAMESPACE] [--format FORMAT] [--warn-only]
  --namespace, -n: Kubernetes namespace to check (default: all namespaces)
  --format, -f: Output format - 'plain' or 'json' (default: plain)
  --warn-only, -w: Show only ingresses with warnings or issues
  --help, -h: Show this help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - Optional: openssl for certificate parsing

Exit codes:
  - 0: All ingresses healthy, certificates valid
  - 1: Certificate warnings/expiration or ingress issues detected
  - 2: Usage error or kubectl not available

Features:
  - Checks TLS certificate expiration dates and warnings
  - Monitors ingress backend service status and health
  - Verifies load balancer IP/hostname assignment
  - Detects missing or invalid TLS secrets
  - Identifies service endpoints for backend availability
  - Supports per-namespace or cluster-wide checking

Examples:
```bash
# Check all ingresses across cluster
k8s_ingress_cert_checker.py

# Check ingresses in production namespace
k8s_ingress_cert_checker.py -n production

# Show only ingresses with issues
k8s_ingress_cert_checker.py --warn-only

# Get JSON output for monitoring systems
k8s_ingress_cert_checker.py --format json

# Check production namespace, only problematic, JSON format
k8s_ingress_cert_checker.py -n production -w -f json
```

Use Cases:
  - **Certificate Expiration Prevention**: Proactive monitoring to prevent certificate-based outages
  - **Ingress Health Monitoring**: Verify load balancer assignment and backend connectivity
  - **TLS Configuration Auditing**: Detect missing or misconfigured TLS secrets
  - **Operational Dashboards**: Export ingress status via JSON for monitoring integration
  - **Multi-namespace Environments**: Monitor ingress health across multiple namespaces
  - **Incident Prevention**: Catch certificate expiration before impacting services

### k8s_node_drain_readiness.py
```
python k8s_node_drain_readiness.py [node] [--action ACTION] [--format FORMAT] [--warn-only] [--dry-run] [--force] [--grace-period SECONDS]
  node: Node name to check/drain (not required for --action check-all)
  --action: Action to perform - 'check', 'drain', 'uncordon', or 'check-all' (default: check)
  --format, -f: Output format - 'plain', 'table', or 'json' (default: table)
  --warn-only, -w: Only show pods with eviction issues
  --dry-run: Simulate action without making changes
  --force: Force drain including pods with emptyDir data (for drain action)
  --grace-period: Grace period for pod termination in seconds (default: 30)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - Sufficient permissions to cordon/drain nodes

Exit codes:
  - 0: Node is safe to drain / action succeeded
  - 1: Node has issues preventing safe drain / action failed
  - 2: Usage error or kubectl not available

Features:
  - Analyzes pod constraints (local storage, critical annotations, PDB conflicts)
  - Identifies stateful workloads requiring manual intervention
  - Respects PodDisruptionBudgets for high-availability applications
  - Gracefully cordons nodes to prevent new pod scheduling
  - Drains pods with configurable grace period
  - Uncordons nodes after maintenance is complete
  - Supports cluster-wide readiness assessment
  - Dry-run mode for validation before actual operations

Examples:
```bash
# Check if a node is safe to drain
k8s_node_drain_readiness.py node-1

# Show only problematic pods
k8s_node_drain_readiness.py node-1 --warn-only

# Simulate drain without making changes
k8s_node_drain_readiness.py node-1 --action drain --dry-run

# Actually drain a node with 60 second grace period
k8s_node_drain_readiness.py node-1 --action drain --grace-period 60

# Drain with force flag for stateful workloads
k8s_node_drain_readiness.py node-1 --action drain --force

# Uncordon a node after maintenance
k8s_node_drain_readiness.py node-1 --action uncordon

# Check all nodes for drainability
k8s_node_drain_readiness.py --action check-all

# Get JSON output for automation
k8s_node_drain_readiness.py node-1 --format json
```

Use Cases:
  - **Node Maintenance**: Safely prepare nodes for patching, reboots, or hardware maintenance
  - **Rolling Upgrades**: Orchestrate graceful node decommissioning during cluster upgrades
  - **Resource Optimization**: Identify pods preventing node consolidation or scale-down
  - **Capacity Planning**: Detect workloads with constraints (local storage, affinity) affecting scheduling
  - **Automation Integration**: Export drain readiness via JSON for orchestration scripts
  - **Incident Response**: Quickly isolate problematic nodes while ensuring pod availability
  - **Baremetal Operations**: Critical for on-premises clusters where downtime is expensive

### k8s_memory_pressure_analyzer.py
```
python3 k8s_memory_pressure_analyzer.py [options]
  -n, --namespace: Analyze specific namespace (default: all namespaces)
  --nodes-only: Only show node memory pressure information
  --pods-only: Only show pod memory usage information
  -h, --help: Show help message
```

Examples:
```bash
# Check memory pressure in all namespaces
python3 k8s_memory_pressure_analyzer.py

# Check memory pressure in production namespace
python3 k8s_memory_pressure_analyzer.py -n production

# Show only node memory status
python3 k8s_memory_pressure_analyzer.py --nodes-only

# Show only pod memory usage
python3 k8s_memory_pressure_analyzer.py --pods-only

# Check specific namespace pod memory
python3 k8s_memory_pressure_analyzer.py -n kube-system --pods-only
```

Use Cases:
  - **Memory Pressure Detection**: Identify nodes experiencing memory pressure before OOMKill events
  - **Pod Memory Audit**: Find pods without memory limits that could destabilize the cluster
  - **Capacity Planning**: Analyze memory allocation across namespaces for resource forecasting
  - **Performance Troubleshooting**: Detect memory contention causing pod evictions
  - **Baremetal Optimization**: Critical for on-premises clusters where memory is limited and evictions are expensive
  - **Proactive Scaling**: Identify when clusters need memory upgrades or node additions
  - **Compliance**: Ensure all pods have proper memory limits for SLA adherence

### k8s_pod_eviction_risk_analyzer.py
```
python3 k8s_pod_eviction_risk_analyzer.py [options]
  -n, --namespace: Analyze specific namespace (default: all namespaces)
  -f, --format: Output format - 'plain', 'table', or 'json' (default: table)
  -w, --warn-only: Only show pods at medium/high/critical risk
  -h, --help: Show help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No pods at risk of eviction
  - 1: One or more pods at risk of eviction detected
  - 2: Usage error or kubectl not available

Features:
  - Detects pods on nodes with memory/disk/PID pressure
  - Analyzes QoS class (BestEffort evicted first, then Burstable, then Guaranteed)
  - Identifies pods without memory limits on pressure nodes
  - Tracks pod restart counts and OOMKill history
  - Flags containers without resource requests or limits
  - Monitors node condition changes that trigger eviction
  - Categorizes risk levels: NONE, LOW, MEDIUM, HIGH, CRITICAL

Risk Assessment Criteria:
  - **CRITICAL**: Pod on node with MemoryPressure, or container was OOMKilled
  - **HIGH**: BestEffort QoS pod, or Burstable pod without memory limits
  - **MEDIUM**: Pod on pressure node, or containers without memory limits
  - **LOW**: Stable pod with resource constraints in place
  - **NONE**: Healthy pod with no risk factors

Examples:
```bash
# Check all pods for eviction risk
k8s_pod_eviction_risk_analyzer.py

# Check pods in production namespace only
k8s_pod_eviction_risk_analyzer.py -n production

# Show only high-risk pods (MEDIUM, HIGH, CRITICAL)
k8s_pod_eviction_risk_analyzer.py --warn-only

# Get table output for human review
k8s_pod_eviction_risk_analyzer.py --format table

# Get JSON output for monitoring integration
k8s_pod_eviction_risk_analyzer.py --format json

# Combine options: production namespace, warn-only, JSON format
k8s_pod_eviction_risk_analyzer.py -n production -w -f json
```

Use Cases:
  - **Proactive Eviction Prevention**: Identify pods likely to be evicted before disruptions occur
  - **QoS Optimization**: Audit pod QoS classes and find BestEffort workloads in production
  - **Resource Planning**: Understand which pods are vulnerable to resource pressure
  - **Cluster Health**: Monitor pod stability during high-load periods
  - **Baremetal Deployments**: Critical for on-premises clusters where evictions cause expensive downtime
  - **SLA Compliance**: Ensure production workloads have Guaranteed QoS and proper resource limits
  - **Capacity Planning**: Identify when nodes are approaching resource exhaustion
  - **Monitoring Integration**: Export eviction risk via JSON for alerting systems

### k8s_node_restart_monitor.py
```
python3 k8s_node_restart_monitor.py [options]
  --format, -f: Output format - 'plain', 'table', or 'json' (default: table)
  --warn-only, -w: Only show nodes with excessive restarts or issues
  -h, --help: Show help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No restart issues detected
  - 1: Nodes with excessive restarts or recent crashes detected
  - 2: Usage error or kubectl not available

Features:
  - Monitors node uptime and identifies recently booted nodes
  - Tracks pod restart counts per node
  - Detects nodes with excessive pod restarts (potential hardware/software issues)
  - Monitors node conditions (MemoryPressure, DiskPressure, PIDPressure)
  - Identifies nodes not in Ready state
  - Generates alerts for stability issues
  - Multiple output formats for integration with monitoring systems

Output Formats:
  - **table**: Human-readable columnar format with node status, uptime, and restart counts (default)
  - **plain**: Space-separated values for scripting/shell integration
  - **json**: Machine-parseable JSON with detailed restart information per pod

Examples:
```bash
# Check all nodes with default table output
k8s_node_restart_monitor.py

# Show only nodes with issues
k8s_node_restart_monitor.py --warn-only

# Monitor for recent reboots with JSON output
k8s_node_restart_monitor.py -f json

# Integrate with monitoring: show problems in plain format
k8s_node_restart_monitor.py -w -f plain

# Get detailed restart information in JSON
k8s_node_restart_monitor.py --format json
```

Use Cases:
  - **Hardware Failure Detection**: Identify nodes with excessive restarts indicating hardware problems
  - **Kernel Panic Monitoring**: Detect cluster-wide instability from kernel issues
  - **Infrastructure Health**: Monitor baremetal hardware for reliability issues
  - **Incident Response**: Quickly identify problematic nodes during cluster issues
  - **Maintenance Tracking**: Monitor impact of updates and patches on node stability
  - **Capacity Planning**: Identify aging hardware with increasing restart rates
  - **Baremetal Operations**: Critical for on-premises clusters where hardware monitoring is essential
  - **Monitoring Integration**: Export node stability metrics for dashboards and alerting

### k8s_pod_count_analyzer.py
```
python3 k8s_pod_count_analyzer.py [options]
  -n, --namespace: Analyze specific namespace only (default: all namespaces)
  --format, -f: Output format - 'table', 'plain', or 'json' (default: table)
  --warn-only, -w: Only show resources with issues
  --deployments-only: Only analyze Deployments
  --statefulsets-only: Only analyze StatefulSets
  -h, --help: Show help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No scaling issues detected
  - 1: Scaling issues found (warnings)
  - 2: Usage error or kubectl not available

Features:
  - Analyzes Deployment and StatefulSet scaling configuration
  - Identifies deployments/statefulsets scaled to 0 replicas
  - Detects replica mismatches (desired vs. ready/available)
  - Warns about excessive replica counts (>50 replicas)
  - Tracks HPA configuration and correlation with replicas
  - Monitors resource quota usage and pod limits
  - Multiple output formats for integration with monitoring systems

Examples:
```bash
# Analyze all pod scaling across cluster
k8s_pod_count_analyzer.py

# Show only resources with issues (table format)
k8s_pod_count_analyzer.py --warn-only

# Analyze specific namespace
k8s_pod_count_analyzer.py -n production

# Get JSON output for monitoring integration
k8s_pod_count_analyzer.py --format json

# Only check Deployments (exclude StatefulSets)
k8s_pod_count_analyzer.py --deployments-only

# Combine options: production namespace, only problematic, plain format
k8s_pod_count_analyzer.py -n production -w -f plain
```

Use Cases:
  - **Scaling Configuration Audit**: Verify all deployments have correct replica configurations
  - **Capacity Planning**: Identify under-scaled or over-scaled workloads in baremetal clusters
  - **Resource Quota Monitoring**: Track namespace-level pod quotas to prevent quota exhaustion
  - **Deployment Health**: Detect deployments with replicas not becoming ready (potential issues)
  - **HPA Correlation**: Identify HPAs without proper minimum replica configuration
  - **Cluster Consolidation**: Find deployments with excessive replicas for consolidation opportunities
  - **Baremetal Operations**: Critical for on-premises clusters where pod density directly impacts resource utilization
  - **Incident Prevention**: Catch scaling misconfigurations before they impact availability

### k8s_orphaned_resources_finder.py
```
python3 k8s_orphaned_resources_finder.py [--namespace NAMESPACE] [--format FORMAT] [options]
  --namespace, -n: Check specific namespace only (default: all namespaces)
  --format, -f: Output format - 'plain' or 'json' (default: plain)
  --skip-empty-namespaces: Skip checking for empty namespaces
  --skip-configmaps: Skip checking for orphaned ConfigMaps
  --skip-secrets: Skip checking for orphaned Secrets
  --skip-pvcs: Skip checking for orphaned PersistentVolumeClaims
  --skip-services: Skip checking for unused Services with no endpoints
  --skip-service-accounts: Skip checking for unused ServiceAccounts
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No orphaned resources found
  - 1: Orphaned or unused resources detected
  - 2: Usage error or kubectl not available

Features:
  - Identifies empty namespaces (no pods or workloads)
  - Finds orphaned ConfigMaps not referenced by any pod
  - Detects orphaned Secrets not used by pod volumes or env variables
  - Identifies unused PersistentVolumeClaims not mounted by pods
  - Discovers Services with no endpoints (no backing pod replicas)
  - Finds unused ServiceAccounts not referenced by pods
  - Skips system namespaces (kube-*, olm*) automatically unless explicitly requested
  - Skips default-token Secrets (automatically managed by Kubernetes)
  - Multiple output formats for scripting and monitoring integration

Examples:
```bash
# Find all orphaned resources cluster-wide
k8s_orphaned_resources_finder.py

# Check specific namespace
k8s_orphaned_resources_finder.py -n production

# Show only ConfigMaps and Secrets
k8s_orphaned_resources_finder.py --skip-pvcs --skip-services --skip-service-accounts

# Get JSON output for processing
k8s_orphaned_resources_finder.py --format json

# Find only empty namespaces
k8s_orphaned_resources_finder.py --skip-configmaps --skip-secrets --skip-pvcs --skip-services --skip-service-accounts

# Combine namespace and format options
k8s_orphaned_resources_finder.py -n production -f json --skip-empty-namespaces
```

Use Cases:
  - **Resource Cleanup**: Identify and remove unused resources to reduce cluster overhead
  - **Cost Optimization**: Find and delete orphaned resources consuming storage/memory in baremetal clusters
  - **Cluster Health Auditing**: Regularly audit for orphaned configurations indicating stale deployments
  - **Storage Management**: Identify unused PVCs consuming storage space
  - **Configuration Cleanup**: Find orphaned ConfigMaps and Secrets from deleted workloads
  - **Security Hardening**: Identify and remove unused ServiceAccounts
  - **Operational Efficiency**: Catch configuration mistakes before they accumulate
  - **Baremetal Operations**: Critical for on-premises clusters where resources are limited and expensive

### k8s_container_restart_analyzer.py
```
python3 k8s_container_restart_analyzer.py [--namespace NAMESPACE] [--timeframe MINUTES] [options]
  --namespace, -n: Analyze restarts in specific namespace (default: all namespaces)
  --timeframe MINUTES: Only analyze restarts within last N minutes
  --verbose, -v: Show detailed analysis with remediation suggestions
  --warn-only: Only show warnings (flapping containers with 5+ restarts)
  --output: Output format - 'plain' or 'json' (default: plain)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No restarts or only informational findings
  - 1: Restarts detected with warnings
  - 2: Usage error or kubectl not available

Features:
  - Analyzes container restart patterns across all pods in the cluster
  - Categorizes restart causes (OOMKilled, CrashLoopBackOff, ApplicationError, ProbeFailure, Evicted, SIGTERM, SIGKILL)
  - Identifies "flapping" containers with excessive restarts (5+ restarts)
  - Provides actionable remediation suggestions based on restart category
  - Checks resource limits for containers experiencing OOMKills
  - Shows restart distribution by namespace and category
  - Detects containers without memory limits that may be causing issues
  - Time-based filtering to focus on recent restart activity
  - Multiple output formats for scripting and monitoring integration

Examples:
```bash
# Analyze all container restarts
k8s_container_restart_analyzer.py

# Analyze restarts in specific namespace
k8s_container_restart_analyzer.py -n kube-system

# Show verbose output with remediation suggestions
k8s_container_restart_analyzer.py --verbose

# Only show flapping containers (5+ restarts)
k8s_container_restart_analyzer.py --warn-only

# Analyze restarts in last 24 hours
k8s_container_restart_analyzer.py --timeframe 1440

# Output as JSON for monitoring integration
k8s_container_restart_analyzer.py --output json

# Combine filters: production namespace, verbose, only flapping
k8s_container_restart_analyzer.py -n production --verbose --warn-only

# Recent restarts in JSON for alerting
k8s_container_restart_analyzer.py --timeframe 60 --output json
```

Use Cases:
  - **Incident Response**: Quickly identify root causes of container restarts during incidents
  - **Proactive Monitoring**: Detect chronic restart issues before they impact availability
  - **Resource Right-Sizing**: Identify OOMKills and adjust memory limits accordingly
  - **Application Debugging**: Categorize restart reasons to prioritize troubleshooting efforts
  - **Pattern Detection**: Find flapping containers that may indicate configuration issues
  - **Capacity Planning**: Identify resource pressure patterns causing evictions
  - **MTTR Reduction**: Get immediate remediation suggestions to reduce mean time to resolution
  - **Health Probe Tuning**: Detect probe failures and tune liveness/readiness probe configurations
  - **Baremetal Operations**: Critical for large-scale environments where restart patterns indicate hardware or network issues
  - **Production Stability**: Regular analysis prevents cascading failures from unstable containers

### k8s_network_policy_audit.py
```
python3 k8s_network_policy_audit.py [--namespace NAMESPACE] [--format FORMAT] [--warn-only]
  --namespace, -n: Audit specific namespace (default: all namespaces)
  --format, -f: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show issues and warnings
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: Network policies properly configured
  - 1: Security issues or missing policies detected
  - 2: Usage error or kubectl not available

Features:
  - Identifies namespaces without network policies (default allow-all behavior)
  - Detects pods not covered by any network policy
  - Flags overly permissive policies (allowing all ingress/egress)
  - Finds deny-all policies that may block legitimate traffic
  - Validates network policy configuration and syntax
  - Analyzes pod label matching against policy selectors
  - Multiple output formats for monitoring integration

Examples:
```bash
# Audit all namespaces
k8s_network_policy_audit.py

# Audit specific namespace
k8s_network_policy_audit.py -n production

# Show only issues
k8s_network_policy_audit.py --warn-only

# JSON output for monitoring systems
k8s_network_policy_audit.py --format json

# Table format for overview
k8s_network_policy_audit.py --format table

# Combine options: production namespace, only issues, JSON format
k8s_network_policy_audit.py -n production -w -f json
```

Use Cases:
  - **Security Auditing**: Identify namespaces and pods without network policy protection
  - **Zero Trust Networking**: Validate that all workloads have appropriate network restrictions
  - **Compliance**: Ensure network policies meet security requirements and best practices
  - **Troubleshooting**: Identify overly restrictive policies blocking legitimate traffic
  - **Migration Planning**: Audit existing policies before implementing zero-trust architecture
  - **Multi-tenant Security**: Verify namespace isolation in shared clusters
  - **Policy Validation**: Detect misconfigured policies that don't match any pods
  - **Baremetal Deployments**: Critical for on-premises clusters where network segmentation is required
  - **Incident Prevention**: Catch security gaps before they're exploited
