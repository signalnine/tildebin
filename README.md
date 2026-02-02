# boxctl

A unified CLI for 300+ baremetal and Kubernetes monitoring scripts.

## Overview

boxctl provides a single interface to discover, run, and manage diagnostic scripts for system administration. Scripts are organized by category and tagged for easy discovery.

**Features:**
- 315 monitoring scripts (216 baremetal, 93 Kubernetes)
- Script discovery with search and filtering
- Consistent output formats (plain, JSON)
- Automatic privilege escalation for root-required scripts
- 2400+ unit tests with integration test suite
- Testable design with dependency injection

## Quick Start

```bash
# Install
pip install -e /path/to/boxctl

# List all scripts
boxctl list

# List scripts by category
boxctl list --category baremetal/disk

# Search for scripts
boxctl search "memory leak"

# Run a script
boxctl run disk_health

# Run with JSON output
boxctl run disk_health --format json

# Show script details
boxctl show disk_health
```

## Commands

| Command | Description |
|---------|-------------|
| `list` | List available scripts with optional filtering |
| `run` | Execute a script by name |
| `show` | Display script metadata and documentation |
| `search` | Find scripts by keyword in name, tags, or description |
| `doctor` | Check script health (missing dependencies, syntax errors) |
| `lint` | Validate script metadata format |

### list

List available scripts with filtering options.

```bash
# List all scripts
boxctl list

# Filter by category
boxctl list --category baremetal/disk
boxctl list --category k8s/pods

# Filter by tag
boxctl list --tag health
boxctl list --tag scheduling

# Show only scripts requiring root
boxctl list --privilege root

# Combine filters
boxctl list --category baremetal --tag network
```

### run

Execute a script by name.

```bash
# Basic execution
boxctl run disk_health

# Pass arguments to script
boxctl run disk_health -- --device /dev/sda

# Change output format
boxctl run disk_health --format json
boxctl run disk_health --format table

# Verbose output
boxctl run disk_health -v
```

### show

Display detailed information about a script.

```bash
boxctl show disk_health
```

Output includes:
- Category and tags
- Required tools
- Privilege level
- Related scripts
- Full docstring

### search

Find scripts by keyword.

```bash
# Search in script names, tags, and descriptions
boxctl search "cpu"
boxctl search "kubernetes node"
boxctl search "raid"
```

### doctor

Check for issues with scripts.

```bash
# Check all scripts
boxctl doctor

# Check specific category
boxctl doctor --category baremetal
```

Reports:
- Missing required tools
- Syntax errors
- Invalid metadata

### lint

Validate script metadata format.

```bash
# Lint all scripts
boxctl lint

# Lint specific script
boxctl lint disk_health
```

## Script Categories

### Baremetal (216 scripts)

| Category | Count | Examples |
|----------|-------|----------|
| `baremetal/network` | 30 | tcp_connection_monitor, arp_table_monitor, ethtool_audit |
| `baremetal/disk` | 29 | disk_health, disk_io_latency, nvme_health, zfs_health |
| `baremetal/security` | 25 | kernel_hardening_audit, ssh_host_key_audit, auditd_health |
| `baremetal/memory` | 16 | memory_fragmentation, oom_risk_analyzer, hugepage_monitor |
| `baremetal/kernel` | 14 | kernel_taint, kernel_module_audit, dmesg_analyzer |
| `baremetal/process` | 14 | process_tree, defunct_parent_analyzer, fd_exhaustion_monitor |
| `baremetal/storage` | 13 | lvm_health, btrfs_health, multipath_health |
| `baremetal/hardware` | 12 | ipmi_sensor, hardware_temperature, pci_health |
| `baremetal/cpu` | 10 | cpu_usage, cpu_steal_monitor, context_switch_monitor |
| `baremetal/systemd` | 9 | systemd_service_monitor, systemd_timer_monitor |
| `baremetal/system` | 10 | uptime, load_average, entropy_monitor |
| `baremetal/boot` | 6 | boot_perf, efi_secure_boot, initramfs_health |

### Kubernetes (93 scripts)

| Category | Count | Examples |
|----------|-------|----------|
| `k8s/workloads` | 10 | deployment_status, statefulset_health, daemonset_health |
| `k8s/security` | 10 | pod_security_audit, rbac_analyzer, secret_audit |
| `k8s/nodes` | 9 | node_health, node_capacity, node_pressure |
| `k8s/resources` | 9 | resource_quota_auditor, limit_range_audit |
| `k8s/networking` | 8 | service_health, ingress_health, network_policy_analyzer |
| `k8s/cluster` | 8 | api_latency, etcd_health, control_plane_health |
| `k8s/storage` | 8 | pv_health, pvc_analyzer, storage_class_audit |
| `k8s/pods` | 5 | pending_pod_analyzer, pod_disruption_budget |

## Exit Codes

All scripts follow a consistent exit code convention:

| Code | Meaning |
|------|---------|
| 0 | Success / healthy / no issues found |
| 1 | Warnings or issues detected |
| 2 | Usage error or missing dependency |

## Output Formats

Scripts support multiple output formats via `--format`:

**plain** (default): Human-readable text output
```
Disk /dev/sda: HEALTHY
  Temperature: 32C
  Power-on hours: 12,345
```

**json**: Machine-parseable JSON
```json
{
  "disk": "/dev/sda",
  "status": "healthy",
  "temperature_c": 32,
  "power_on_hours": 12345
}
```

**table**: Aligned columns for terminal display
```
DISK       STATUS   TEMP   HOURS
/dev/sda   HEALTHY  32C    12,345
/dev/sdb   HEALTHY  34C    8,901
```

## Installation

```bash
# Clone the repository
git clone https://github.com/signalnine/boxctl.git
cd boxctl

# Install in development mode
pip install -e .

# Or just run directly
PYTHONPATH=/path/to/boxctl python3 -m boxctl doctor
```

## Testing

```bash
# Run all unit tests (2400+)
make test

# Run integration tests (requires real hardware/cluster)
make test-integration

# Run specific test category
make test-baremetal
make test-k8s
```

## Required Tools

The `doctor` command shows which tools are available:

```bash
boxctl doctor
```

Common tools by category:
- **Disk**: smartctl, nvme, lsblk, btrfs, zpool
- **Network**: ss, ip, ethtool, iptables
- **Hardware**: ipmitool, sensors, dmidecode
- **Kubernetes**: kubectl
- **Security**: auditctl, openssl

## Requirements

- Python 3.10+
- Scripts check for required tools and exit with code 2 if missing

## License

MIT
