# boxctl

A unified CLI for 181+ baremetal and Kubernetes monitoring scripts.

## Overview

boxctl provides a single interface to discover, run, and manage diagnostic scripts for system administration. Scripts are organized by category and tagged for easy discovery.

**Features:**
- Unified CLI for all monitoring scripts
- Script discovery with search and filtering
- Consistent output formats (plain, JSON, table)
- Testable design with dependency injection
- Comprehensive script metadata

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

### Baremetal (142 scripts)

| Category | Examples |
|----------|----------|
| `baremetal/disk` | disk_health, disk_space_forecaster, disk_io_latency |
| `baremetal/memory` | memory_pressure_monitor, oom_killer_tracker |
| `baremetal/cpu` | cpu_steal_monitor, scheduler_latency |
| `baremetal/network` | network_connection_tracker, packet_loss_monitor |
| `baremetal/process` | process_ancestry_tree, zombie_process_hunter |
| `baremetal/security` | setuid_scanner, open_port_audit |

### Kubernetes (39 scripts)

| Category | Examples |
|----------|----------|
| `k8s/pods` | pod_resource_analyzer, pending_pod_debugger |
| `k8s/nodes` | node_capacity, node_resource_fragmentation |
| `k8s/resources` | resource_quota_analyzer, limit_range_audit |
| `k8s/network` | network_policy_analyzer, service_endpoint_health |

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

## Documentation

- [CLI Reference](docs/cli-reference.md) - Complete command documentation
- [Writing Scripts](docs/writing-scripts.md) - Guide for adding new scripts
- [Architecture](docs/architecture.md) - System design overview

## Requirements

- Python 3.10+
- Scripts may require additional tools (smartctl, kubectl, etc.)

## License

MIT
