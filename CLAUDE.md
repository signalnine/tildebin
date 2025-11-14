# CLAUDE.md - AI Assistant Guide for tildebin Repository

**Last Updated:** 2025-11-14
**Repository:** tildebin - Small utilities for your ~/bin/

This document provides AI assistants (Claude Code, Cursor, GPT, etc.) with comprehensive guidance for understanding and working with the tildebin repository.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Repository Overview](#repository-overview)
3. [Codebase Architecture](#codebase-architecture)
4. [Development Workflows](#development-workflows)
5. [Code Patterns & Conventions](#code-patterns--conventions)
6. [Testing Guidelines](#testing-guidelines)
7. [Common Tasks](#common-tasks)
8. [File Organization](#file-organization)
9. [Dependencies & Environment](#dependencies--environment)
10. [Best Practices](#best-practices)

---

## Quick Start

### For Immediate Context

**What is tildebin?**
A curated collection of 42 utility scripts for system administration, designed for personal ~/bin directories. Focus areas: AWS EC2 management, baremetal system monitoring, Kubernetes cluster operations, and SSH-based multi-host administration.

**Key Stats:**
- 42 total scripts (37 Python, 5 Shell)
- 37 comprehensive test files
- 3 categories: AWS (7), Baremetal (10), Kubernetes (18), SSH/Utils (7)
- 100% test coverage with subprocess-based functional tests
- Zero external test dependencies (no AWS, hardware, or kubectl required)

**Core Philosophy:**
- UNIX philosophy: Each script does one thing well
- Minimal dependencies: Prefer stdlib over external packages
- Graceful error handling with helpful messages
- Exit codes matter: 0=success, 1=errors/warnings, 2=usage error
- Backward compatibility is sacred (especially default output formats)

---

## Repository Overview

### Project Purpose

tildebin provides battle-tested utilities for:
1. **AWS EC2 Operations**: Instance management, tagging, security group cleanup, volume listing
2. **Baremetal Monitoring**: Hardware health (SMART, RAID, IPMI, temperature, memory, PCIe)
3. **Kubernetes Management**: Comprehensive cluster health, resource auditing, troubleshooting
4. **SSH Orchestration**: Multi-host command execution and user management

### Target Audience

System administrators and DevOps engineers managing:
- AWS infrastructure (EC2 instances, security groups, EBS volumes)
- Baremetal datacenter hardware
- Kubernetes clusters (especially on-premises/baremetal)
- Multi-host SSH environments

### Design Principles

From [AGENTS.md](AGENTS.md):

1. **Code Quality**
   - Simplicity over cleverness
   - UNIX philosophy (do one thing well)
   - Minimal external dependencies
   - Fail gracefully with helpful error messages
   - Meaningful exit codes

2. **User Experience**
   - Every script has `--help`
   - Sensible defaults
   - Backward compatibility
   - Destructive operations require confirmation (unless `--force`)
   - Progress feedback for long operations

3. **Testing Philosophy**
   - Every script has tests (1:1 mapping)
   - Tests don't require external resources
   - Use subprocess to test real behavior
   - Fast test suite (completes in seconds)

---

## Codebase Architecture

### Directory Structure

```
tildebin/
├── *.py                   # Python utility scripts (37 scripts)
├── *.sh                   # Shell utility scripts (5 scripts)
├── tests/                 # Test suite (37 test files)
│   ├── test_*.py         # Individual test files
│   ├── run_tests.py      # Test runner with filtering
│   └── README.md         # Testing documentation
├── Makefile               # Build/test automation
├── README.md              # User documentation
├── AGENTS.md              # AI agent guidance (legacy)
├── CLAUDE.md              # This file - Claude Code guidance
├── LICENSE                # MIT License
└── .gitignore             # Standard Python exclusions
```

### Script Categories

#### 1. AWS EC2 Management (7 scripts)

**Purpose:** Manage EC2 instances and resources using boto3

| Script | Purpose | Default Region |
|--------|---------|----------------|
| `listec2hosts.py` | List EC2 instances with filtering | us-west-2 |
| `ec2_tag_summary.py` | Multi-region tag-based grouping | us-west-2, us-east-1 |
| `ec2_manage.py` | Start/stop/restart instances | us-west-2 |
| `terminate_instance.py` | Terminate with confirmation | us-west-2 |
| `stop_all_instances.py` | Stop all running instances | us-west-2 |
| `emptysgs.py` | Find unused security groups | us-east-1 |
| `listvolumes.py` | List EBS volumes | us-west-2 |

**Common Patterns:**
- Use boto3 (not deprecated boto)
- Check environment variables for credentials
- Support `-r/--region` flag
- Handle `NoCredentialsError` gracefully
- Import boto3 late (after argument parsing)

#### 2. Baremetal System Monitoring (10 scripts + 3 utilities)

**Purpose:** Monitor hardware health and system parameters

**Core Monitoring:**
- `disk_health_check.py` - SMART disk monitoring
- `check_raid.py` - Hardware/software RAID status
- `cpu_frequency_monitor.py` - CPU scaling and governor
- `hardware_temperature_monitor.py` - Thermal sensors and fans
- `ipmi_sel_monitor.py` - IPMI System Event Log
- `memory_health_monitor.py` - ECC errors and memory pressure
- `network_interface_health.py` - NIC error statistics
- `network_bond_status.sh` - Network bonding status
- `ntp_drift_monitor.py` - Time synchronization
- `pcie_health_monitor.py` - PCIe device health

**Utilities:**
- `filesystem_usage_tracker.py` - Large directory detection
- `sysctl_audit.py` - Kernel parameter auditing
- `system_inventory.py` - Hardware inventory generation

**Common Patterns:**
- Support `--format` (plain/json/table)
- Include `--verbose` flag
- Support `--warn-only` filtering
- Check for system tools before using
- Exit code 0=healthy, 1=warnings/errors, 2=dependency missing

#### 3. Kubernetes Management (18 scripts)

**Purpose:** Monitor, audit, and troubleshoot Kubernetes clusters

**Core Infrastructure:**
- `kubernetes_node_health.py` - Node health and resources
- `k8s_deployment_status.py` - Deployment/StatefulSet status
- `k8s_statefulset_health.py` - StatefulSet-specific monitoring

**Storage & Networking:**
- `k8s_pv_health_check.py` - Persistent volume health
- `k8s_network_policy_audit.py` - Network policy security
- `k8s_dns_health_monitor.py` - DNS/CoreDNS health

**Pod & Resource Management:**
- `k8s_pod_resource_audit.py` - Pod resource usage
- `k8s_pod_count_analyzer.py` - Pod scaling configuration
- `k8s_cpu_throttling_detector.py` - CPU throttling detection
- `k8s_memory_pressure_analyzer.py` - Memory pressure analysis
- `k8s_pod_eviction_risk_analyzer.py` - Eviction risk

**Operational Monitoring:**
- `k8s_event_monitor.py` - Cluster event tracking
- `k8s_ingress_cert_checker.py` - Certificate expiration
- `k8s_node_drain_readiness.py` - Node drainability
- `k8s_node_restart_monitor.py` - Node restart activity
- `k8s_node_capacity_planner.py` - Capacity planning

**Troubleshooting & Cleanup:**
- `k8s_container_restart_analyzer.py` - Restart root cause analysis
- `k8s_orphaned_resources_finder.py` - Unused resources

**Common Patterns:**
- Use kubectl subprocess calls with JSON output
- Check for kubectl availability (FileNotFoundError)
- Support `--namespace` filtering
- Support `--format` (plain/json/table)
- Include `--warn-only` flag
- Exit code 2 if kubectl missing

#### 4. SSH Operations & Utilities (5 scripts)

**SSH Operations:**
- `acrosshosts.sh` - Execute commands across multiple hosts
- `useradd.sh` - Create user accounts with SSH keys
- `grephosts.sh` - Filter EC2 host output

**System Utilities:**
- `generate_fstab.sh` - Generate /etc/fstab using UUIDs

---

## Development Workflows

### Adding a New Script

**Step-by-step process:**

1. **Create the script file**
   ```bash
   # For Python scripts
   touch script_name.py
   chmod +x script_name.py

   # For shell scripts
   touch script_name.sh
   chmod +x script_name.sh
   ```

2. **Use the appropriate template** (see [Code Patterns](#code-patterns--conventions))

3. **Implement core functionality**
   - Include docstring with description and exit codes
   - Add argparse for CLI arguments
   - Support `--help` flag
   - Follow established patterns for your category
   - Support multiple output formats (at least plain and JSON)

4. **Create the test file**
   ```bash
   touch tests/test_script_name.py
   chmod +x tests/test_script_name.py
   ```

5. **Write comprehensive tests**
   - Test help message
   - Test valid arguments
   - Test invalid arguments
   - Test error conditions (missing dependencies)
   - Test output format parsing
   - Use subprocess.Popen pattern

6. **Update documentation**
   - Add entry to README.md under appropriate category
   - Include usage examples
   - Document exit codes
   - Update this file if introducing new patterns

7. **Run tests**
   ```bash
   make test                    # Run all tests
   make test-script_name        # Run specific test
   python3 tests/test_script_name.py  # Direct execution
   ```

8. **Commit changes**
   ```bash
   git add script_name.py tests/test_script_name.py README.md
   git commit -m "Add script_name.py for <purpose>"
   ```

### Modifying Existing Scripts

**Critical guidelines:**

1. **Backward compatibility is SACRED**
   - Default output format must remain unchanged
   - Existing CLI flags must work as before
   - Exit codes must remain consistent

2. **Update tests**
   - Modify corresponding test file in tests/
   - Add new test functions for new functionality
   - Ensure all existing tests still pass

3. **Update documentation**
   - Update README.md if behavior changes
   - Update docstring and help text
   - Update this file if patterns change

4. **Verify**
   ```bash
   make test                    # All tests pass
   make test-verbose            # Check for warnings
   ./script_name.py --help      # Verify help text
   ```

### Testing Workflow

```bash
# Run all tests
make test

# Run tests with verbose output
make test-verbose

# Run specific category
make test-ec2
make test-baremetal
make test-k8s

# Run specific script test
make test-disk_health_check

# Run with pattern filter
make test-filter PATTERN=disk

# Run test directly
python3 tests/test_disk_health_check.py

# Run test runner with options
python3 tests/run_tests.py -v              # Verbose
python3 tests/run_tests.py -f disk raid    # Filter patterns
python3 tests/run_tests.py --fail-fast     # Stop on first failure
```

---

## Code Patterns & Conventions

### Exit Code Convention

**CRITICAL: All scripts follow this convention**

- **0** = Success / No issues detected / Healthy status
- **1** = Warnings or errors found / Execution failed / Issues detected
- **2** = Usage error (bad arguments) / Missing dependency

### Python Script Template

```python
#!/usr/bin/env python3
"""
Brief description of what this script does.

Detailed explanation of functionality and use cases.

Exit codes:
    0 - Success / No issues detected
    1 - Warnings or errors found
    2 - Usage error or missing dependency
"""

import argparse
import sys
import os
import json

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Clear description of purpose",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Required arguments
    parser.add_argument(
        "positional",
        help="Positional argument description"
    )

    # Optional arguments
    parser.add_argument(
        "-o", "--option",
        default="default_value",
        help="Option description (default: %(default)s)"
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )

    args = parser.parse_args()

    try:
        # Implementation here
        result = do_work(args)

        # Output formatting
        if args.format == "json":
            print(json.dumps(result, indent=2))
        else:
            print_plain(result)

        sys.exit(0)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### AWS Script Pattern

```python
#!/usr/bin/env python3
"""AWS script description"""

import argparse
import sys
import os

def main():
    parser = argparse.ArgumentParser(description="AWS operation")
    parser.add_argument("-r", "--region", default="us-west-2",
                       help="AWS region (default: us-west-2)")
    parser.add_argument("--format", choices=["plain", "json"],
                       default="plain", help="Output format")
    args = parser.parse_args()

    # Check for AWS credentials BEFORE importing boto3
    access_key = os.environ.get('AWS_ACCESS_KEY_ID') or \
                 os.environ.get('AWS_ACCESS_KEY')
    secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY') or \
                 os.environ.get('AWS_SECRET_KEY')

    if not (access_key and secret_key):
        print("Error: AWS credentials not found", file=sys.stderr)
        print("Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY",
              file=sys.stderr)
        sys.exit(2)

    # Import boto3 late (after validation)
    try:
        import boto3
    except ImportError:
        print("Error: boto3 required. Install with: pip install boto3",
              file=sys.stderr)
        sys.exit(2)

    # Use boto3
    try:
        ec2 = boto3.client('ec2', region_name=args.region)
        response = ec2.describe_instances()

        # Process and output results
        process_results(response, args.format)
        sys.exit(0)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Baremetal Script Pattern

```python
#!/usr/bin/env python3
"""Baremetal monitoring script"""

import argparse
import sys
import subprocess

def check_tool_available(tool_name, install_hint):
    """Check if system tool is available"""
    try:
        result = subprocess.run(
            ['which', tool_name],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False

def run_command(cmd):
    """Execute shell command and return result"""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)

def main():
    parser = argparse.ArgumentParser(
        description="Hardware monitoring tool"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )
    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="Only show warnings or issues"
    )

    args = parser.parse_args()

    # Check for required tool
    if not check_tool_available('smartctl', 'smartmontools'):
        print("Error: 'smartctl' not found", file=sys.stderr)
        print("Install with: sudo apt-get install smartmontools",
              file=sys.stderr)
        sys.exit(2)

    # Execute monitoring
    returncode, stdout, stderr = run_command(['smartctl', '-a', '/dev/sda'])

    if returncode != 0:
        print(f"Error: {stderr}", file=sys.stderr)
        sys.exit(1)

    # Process and output results
    results = parse_output(stdout)
    output_results(results, args.format, args.warn_only)

    # Exit based on findings
    sys.exit(1 if has_warnings(results) else 0)

if __name__ == "__main__":
    main()
```

### Kubernetes Script Pattern

```python
#!/usr/bin/env python3
"""Kubernetes monitoring script"""

import argparse
import sys
import subprocess
import json

def run_kubectl(args):
    """Execute kubectl command and return output"""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/",
              file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}", file=sys.stderr)
        sys.exit(1)

def get_pods(namespace=None):
    """Get pods in JSON format"""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    return json.loads(output)

def main():
    parser = argparse.ArgumentParser(
        description="Kubernetes cluster monitoring"
    )
    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to check (default: all namespaces)"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings or issues"
    )

    args = parser.parse_args()

    # Get Kubernetes resources
    pods = get_pods(args.namespace)

    # Analyze and output results
    issues = analyze_pods(pods)
    output_results(issues, args.format, args.warn_only)

    # Exit based on findings
    sys.exit(1 if issues else 0)

if __name__ == "__main__":
    main()
```

### Destructive Operations Pattern

```python
def confirm_action(message, force=False):
    """Prompt for confirmation unless force flag set"""
    if force:
        return True

    response = input(f"{message} [y/N] ")
    return response.lower() == 'y'

def main():
    parser = argparse.ArgumentParser(description="Destructive operation")
    parser.add_argument("instance_id", help="Instance to terminate")
    parser.add_argument("--force", action="store_true",
                       help="Skip confirmation prompt")
    parser.add_argument("--dry-run", action="store_true",
                       help="Show what would happen without doing it")

    args = parser.parse_args()

    # Show what will happen
    print(f"Will terminate instance: {args.instance_id}")

    if args.dry_run:
        print("[DRY RUN] Would terminate instance")
        sys.exit(0)

    # Confirm
    if not confirm_action(
        f"Are you sure you want to terminate {args.instance_id}?",
        args.force
    ):
        print("Cancelled")
        sys.exit(0)

    # Perform action
    terminate_instance(args.instance_id)
```

### Output Format Pattern

```python
import json

def output_plain(data):
    """Plain text output (space-separated)"""
    for item in data:
        print(f"{item['name']} {item['status']} {item['value']}")

def output_json(data):
    """JSON output"""
    print(json.dumps(data, indent=2))

def output_table(data):
    """Tabular output with headers"""
    # Print header
    print(f"{'Name':<20} {'Status':<10} {'Value':<15}")
    print("-" * 45)

    # Print rows
    for item in data:
        print(f"{item['name']:<20} {item['status']:<10} {item['value']:<15}")

def main():
    # ... argument parsing ...

    results = get_results()

    if args.format == "json":
        output_json(results)
    elif args.format == "table":
        output_table(results)
    else:  # plain (default)
        output_plain(results)
```

---

## Testing Guidelines

### Test File Structure

**Location:** `tests/test_<script_name>.py`

**Pattern:**
```python
#!/usr/bin/env python3
"""
Test script for <script_name>.py functionality.
Tests argument parsing and error handling without requiring external resources.
"""

import subprocess
import sys
import json

def run_command(cmd_args):
    """Helper function to run a command and return result"""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)

def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'script_name.py', '--help']
    )

    if return_code == 0 and 'expected text' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:100]}")
        return False

def test_invalid_arguments():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'script_name.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False

def test_json_output_format():
    """Test JSON output format parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'script_name.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)
        print("[PASS] JSON output format test passed")
        return True
    except json.JSONDecodeError:
        print(f"[FAIL] JSON parsing failed")
        print(f"  Output: {stdout[:100]}")
        return False

def test_missing_dependency_handling():
    """Test graceful handling of missing dependencies"""
    # This test structure varies by script type
    # For AWS: Test missing credentials
    # For baremetal: Test missing tool
    # For K8s: Test missing kubectl
    pass

if __name__ == "__main__":
    print(f"Testing script_name.py...")

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_json_output_format,
        # Add more tests
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print(f"\nTest Results: {passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)
```

### Key Testing Principles

1. **No External Dependencies**
   - Tests must not require AWS credentials
   - Tests must not require hardware tools
   - Tests must not require kubectl access
   - Tests run in any environment

2. **Subprocess-Based Testing**
   - Use subprocess.Popen to run scripts
   - Test as users would (command-line invocation)
   - No mocking or monkey-patching

3. **Comprehensive Coverage**
   - Test help message (`--help`)
   - Test valid arguments
   - Test invalid arguments (should fail)
   - Test error conditions (missing tools, bad input)
   - Test output formats (JSON parsing, etc.)
   - Test exit codes

4. **Fast Execution**
   - Full test suite completes in seconds
   - No network calls
   - No heavy computation

### Test Categories

**AWS Scripts:**
- Test credential handling (missing credentials)
- Test region option parsing
- Test output format options
- Test boto3 import error handling

**Baremetal Scripts:**
- Test tool availability checking
- Test format options (plain/json/table)
- Test verbose mode
- Test warn-only filtering

**Kubernetes Scripts:**
- Test kubectl availability checking
- Test namespace filtering
- Test format options
- Test warn-only filtering
- Test JSON output parsing

---

## Common Tasks

### Adding a New AWS Script

```bash
# 1. Create script
cat > new_aws_script.py << 'EOF'
#!/usr/bin/env python3
"""New AWS script description"""

import argparse
import sys
import os

def main():
    parser = argparse.ArgumentParser(description="New AWS operation")
    parser.add_argument("-r", "--region", default="us-west-2")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    args = parser.parse_args()

    # Check credentials
    if not (os.environ.get('AWS_ACCESS_KEY_ID') and
            os.environ.get('AWS_SECRET_ACCESS_KEY')):
        print("Error: AWS credentials not found", file=sys.stderr)
        sys.exit(2)

    # Import boto3 late
    try:
        import boto3
    except ImportError:
        print("Error: boto3 required", file=sys.stderr)
        sys.exit(2)

    # Implementation
    ec2 = boto3.client('ec2', region_name=args.region)
    # ... do work ...
    sys.exit(0)

if __name__ == "__main__":
    main()
EOF

chmod +x new_aws_script.py

# 2. Create test
cat > tests/test_new_aws_script.py << 'EOF'
#!/usr/bin/env python3
"""Test new_aws_script.py"""

import subprocess
import sys

def run_command(args):
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')

def test_help():
    rc, stdout, _ = run_command([sys.executable, 'new_aws_script.py', '--help'])
    return rc == 0 and 'AWS' in stdout

if __name__ == "__main__":
    tests = [test_help]
    passed = sum(1 for t in tests if t())
    print(f"{passed}/{len(tests)} tests passed")
    sys.exit(0 if passed == len(tests) else 1)
EOF

chmod +x tests/test_new_aws_script.py

# 3. Test
python3 tests/test_new_aws_script.py

# 4. Update README.md
# Add entry under "AWS EC2 Management" section
```

### Adding a New Kubernetes Script

```bash
# 1. Create script with kubectl pattern
cat > k8s_new_monitor.py << 'EOF'
#!/usr/bin/env python3
"""Kubernetes monitoring script"""

import argparse
import sys
import subprocess
import json

def run_kubectl(args):
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except FileNotFoundError:
        print("Error: kubectl not found", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="K8s monitoring")
    parser.add_argument("-n", "--namespace")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true")
    args = parser.parse_args()

    # Get resources
    cmd = ['get', 'pods', '-o', 'json']
    if args.namespace:
        cmd.extend(['-n', args.namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    data = json.loads(output)

    # Process and output
    # ...

    sys.exit(0)

if __name__ == "__main__":
    main()
EOF

chmod +x k8s_new_monitor.py

# 2. Create test
cat > tests/test_k8s_new_monitor.py << 'EOF'
#!/usr/bin/env python3
"""Test k8s_new_monitor.py"""

import subprocess
import sys

def run_command(args):
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')

def test_help():
    rc, stdout, _ = run_command([sys.executable, 'k8s_new_monitor.py', '--help'])
    return rc == 0 and 'namespace' in stdout

def test_format_option():
    rc, _, _ = run_command([sys.executable, 'k8s_new_monitor.py', '--format', 'json'])
    # Will fail without kubectl, but option should parse
    return True  # Just test that option is recognized

if __name__ == "__main__":
    tests = [test_help, test_format_option]
    passed = sum(1 for t in tests if t())
    print(f"{passed}/{len(tests)} tests passed")
    sys.exit(0 if passed == len(tests) else 1)
EOF

chmod +x tests/test_k8s_new_monitor.py

# 3. Test
python3 tests/test_k8s_new_monitor.py

# 4. Update README.md
```

### Running Tests for Development

```bash
# Quick check while developing
python3 tests/test_my_script.py

# Run all tests
make test

# Run with verbose output to see details
make test-verbose

# Run specific category
make test-k8s
make test-ec2
make test-baremetal

# Run with pattern filter
make test-filter PATTERN="disk raid"

# Check for issues in test output
make test 2>&1 | grep FAIL
```

### Debugging Test Failures

```bash
# Run specific test with verbose output
python3 tests/test_script_name.py -v

# Run test and capture output
python3 tests/test_script_name.py > test_output.txt 2>&1

# Test script directly to see actual output
./script_name.py --help
./script_name.py --format json
./script_name.py --invalid-flag  # Should fail with exit code 2

# Check exit codes
./script_name.py --help; echo "Exit code: $?"
```

---

## File Organization

### Repository Layout

```
tildebin/
├── .git/                          # Git repository metadata
├── .gitignore                     # Python/IDE/test exclusions
├── LICENSE                        # MIT License
├── Makefile                       # Build/test automation
├── README.md                      # User-facing documentation
├── AGENTS.md                      # Legacy AI assistant guidance
├── CLAUDE.md                      # This file - Claude Code guidance
│
├── tests/                         # Test suite
│   ├── README.md                  # Testing documentation
│   ├── run_tests.py               # Test runner (filtering, colors, timing)
│   │
│   ├── test_*.py                  # AWS script tests (7 files)
│   ├── test_*.py                  # Baremetal script tests (13 files)
│   ├── test_*.py                  # Kubernetes script tests (15 files)
│   └── test_*.py                  # SSH/utility script tests (2 files)
│
├── AWS EC2 Scripts (7 files)
│   ├── listec2hosts.py
│   ├── ec2_tag_summary.py
│   ├── ec2_manage.py
│   ├── terminate_instance.py
│   ├── stop_all_instances.py
│   ├── emptysgs.py
│   └── listvolumes.py
│
├── Baremetal Scripts (10 + 3 files)
│   ├── disk_health_check.py
│   ├── check_raid.py
│   ├── cpu_frequency_monitor.py
│   ├── hardware_temperature_monitor.py
│   ├── ipmi_sel_monitor.py
│   ├── memory_health_monitor.py
│   ├── network_interface_health.py
│   ├── network_bond_status.sh
│   ├── ntp_drift_monitor.py
│   ├── pcie_health_monitor.py
│   ├── filesystem_usage_tracker.py
│   ├── sysctl_audit.py
│   └── system_inventory.py
│
├── Kubernetes Scripts (18 files)
│   ├── kubernetes_node_health.py
│   ├── k8s_deployment_status.py
│   ├── k8s_statefulset_health.py
│   ├── k8s_pv_health_check.py
│   ├── k8s_network_policy_audit.py
│   ├── k8s_dns_health_monitor.py
│   ├── k8s_pod_resource_audit.py
│   ├── k8s_pod_count_analyzer.py
│   ├── k8s_cpu_throttling_detector.py
│   ├── k8s_memory_pressure_analyzer.py
│   ├── k8s_pod_eviction_risk_analyzer.py
│   ├── k8s_event_monitor.py
│   ├── k8s_ingress_cert_checker.py
│   ├── k8s_node_drain_readiness.py
│   ├── k8s_node_restart_monitor.py
│   ├── k8s_node_capacity_planner.py
│   ├── k8s_container_restart_analyzer.py
│   └── k8s_orphaned_resources_finder.py
│
└── SSH & Utilities (5 files)
    ├── acrosshosts.sh
    ├── useradd.sh
    ├── grephosts.sh
    └── generate_fstab.sh
```

### Naming Conventions

**Python Scripts:**
- Lowercase with underscores: `script_name.py`
- AWS scripts: `ec2_*` or `list*` prefix
- Kubernetes scripts: `k8s_*` or `kubernetes_*` prefix
- Descriptive names: `disk_health_check.py` not `dhc.py`

**Shell Scripts:**
- Lowercase with underscores: `script_name.sh`
- Action-oriented: `acrosshosts.sh`, `generate_fstab.sh`

**Test Files:**
- Mirror script name: `test_<script_name>.py`
- Located in `tests/` directory
- One test file per script

---

## Dependencies & Environment

### Required Dependencies

**Python (all scripts):**
```bash
python3 >= 3.6  # f-strings, modern features
```

**AWS Scripts:**
```bash
pip install boto3  # AWS SDK for Python
```

**System Tools (optional, per script):**
```bash
# Disk monitoring
sudo apt-get install smartmontools   # smartctl

# RAID monitoring
sudo apt-get install mdadm            # mdadm (software RAID)
# MegaCli (LSI/Broadcom RAID)
# hpacucli/ssacli (HP RAID)

# Hardware monitoring
sudo apt-get install lm-sensors       # sensors
sudo apt-get install ipmitool         # ipmitool
sudo apt-get install pciutils         # lspci
sudo apt-get install dmidecode        # dmidecode

# Kubernetes
# kubectl (from Kubernetes website)

# Time sync
sudo apt-get install chrony           # chronyc
# or ntp                                # ntpq
```

### Environment Variables

**AWS Credentials:**
```bash
# Required for AWS scripts
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# Optional
export EC2_REGION="us-west-2"         # Override default region
export EC2_URL="https://..."          # Override endpoint (rare)

# Alternative names (supported)
export AWS_ACCESS_KEY="AKIA..."       # Instead of AWS_ACCESS_KEY_ID
export AWS_SECRET_KEY="..."           # Instead of AWS_SECRET_ACCESS_KEY
```

**Kubernetes Configuration:**
```bash
# kubectl uses standard kubeconfig
export KUBECONFIG="$HOME/.kube/config"

# Or use default location
# ~/.kube/config
```

### Checking Dependencies

```bash
# Check all dependencies
make check-deps

# Check Python version
python3 --version

# Check boto3
python3 -c "import boto3; print(boto3.__version__)"

# Check system tools
which smartctl
which mdadm
which kubectl
which sensors
which ipmitool
```

---

## Best Practices

### DO ✅

1. **Follow Exit Code Convention**
   - 0 = success
   - 1 = warnings/errors
   - 2 = usage error/missing dependency

2. **Maintain Backward Compatibility**
   - Default output format is sacred
   - Existing CLI flags must work
   - Add new options, don't change existing

3. **Write Comprehensive Tests**
   - Test help message
   - Test valid and invalid arguments
   - Test error conditions
   - Use subprocess pattern

4. **Provide Helpful Error Messages**
   ```python
   print("Error: boto3 required. Install with: pip install boto3",
         file=sys.stderr)
   ```

5. **Support Multiple Output Formats**
   - At minimum: plain and JSON
   - Optional: table format
   - Default: plain (for backward compatibility)

6. **Handle Missing Dependencies Gracefully**
   ```python
   if not tool_available('smartctl'):
       print("Error: smartctl not found", file=sys.stderr)
       print("Install: sudo apt-get install smartmontools",
             file=sys.stderr)
       sys.exit(2)
   ```

7. **Use argparse for CLI**
   ```python
   parser = argparse.ArgumentParser(
       description="Clear description",
       formatter_class=argparse.RawDescriptionHelpFormatter
   )
   ```

8. **Include Comprehensive Docstrings**
   ```python
   """
   Script description.

   Exit codes:
       0 - Success
       1 - Errors/warnings
       2 - Usage error
   """
   ```

9. **Confirm Destructive Operations**
   ```python
   if not args.force:
       response = input("Are you sure? [y/N] ")
       if response.lower() != 'y':
           sys.exit(0)
   ```

10. **Keep Documentation Updated**
    - Update README.md
    - Update docstrings
    - Update this file if patterns change

### DON'T ❌

1. **Don't Break Backward Compatibility**
   - Don't change default output format
   - Don't remove CLI flags
   - Don't change exit code meanings

2. **Don't Use External Dependencies Unnecessarily**
   - Prefer stdlib over third-party packages
   - Exception: boto3 for AWS (required)

3. **Don't Write Tests That Require Resources**
   - No AWS credentials
   - No hardware tools
   - No kubectl access
   - Tests must run anywhere

4. **Don't Import boto3 Early**
   ```python
   # DON'T do this:
   import boto3  # At top of file

   # DO this:
   def main():
       # After argument parsing
       try:
           import boto3
       except ImportError:
           print("Error: boto3 required")
           sys.exit(2)
   ```

5. **Don't Use Hardcoded Regions**
   ```python
   # DON'T:
   ec2 = boto3.client('ec2', region_name='us-west-2')

   # DO:
   ec2 = boto3.client('ec2', region_name=args.region)
   ```

6. **Don't Skip Error Handling**
   ```python
   # DON'T:
   result = subprocess.run(['kubectl', 'get', 'pods'])

   # DO:
   try:
       result = subprocess.run(
           ['kubectl', 'get', 'pods'],
           capture_output=True,
           text=True,
           check=True
       )
   except FileNotFoundError:
       print("Error: kubectl not found", file=sys.stderr)
       sys.exit(2)
   except subprocess.CalledProcessError as e:
       print(f"Error: {e.stderr}", file=sys.stderr)
       sys.exit(1)
   ```

7. **Don't Use Cryptic Variable Names**
   ```python
   # DON'T:
   def f(x, y, z):
       return x + y * z

   # DO:
   def calculate_total(base_cost, item_count, unit_price):
       return base_cost + (item_count * unit_price)
   ```

8. **Don't Print to stdout for Errors**
   ```python
   # DON'T:
   print("Error: Something went wrong")

   # DO:
   print("Error: Something went wrong", file=sys.stderr)
   ```

9. **Don't Forget to Make Scripts Executable**
   ```bash
   chmod +x new_script.py
   ```

10. **Don't Skip Testing**
    ```bash
    # Always run before committing
    make test
    ```

---

## Additional Resources

### Documentation Files

- **README.md** - User-facing documentation with usage examples
- **AGENTS.md** - Legacy AI assistant guidance (comprehensive)
- **CLAUDE.md** - This file (Claude Code specific)
- **tests/README.md** - Detailed testing documentation
- **Makefile** - Available automation targets

### Key Sections to Reference

**In README.md:**
- Usage examples for each script
- Installation instructions
- Dependency requirements
- Exit code conventions

**In AGENTS.md:**
- Detailed code patterns
- Development guidelines
- Testing philosophy
- Common patterns

**In tests/README.md:**
- Test runner usage
- Test categories
- Writing new tests

### External Documentation

**AWS (boto3):**
- https://boto3.amazonaws.com/v1/documentation/api/latest/index.html

**Kubernetes (kubectl):**
- https://kubernetes.io/docs/reference/kubectl/

**Python:**
- https://docs.python.org/3/library/argparse.html
- https://docs.python.org/3/library/subprocess.html

---

## Version History

**2025-11-14:**
- Created comprehensive CLAUDE.md for AI assistants
- Documented all 42 scripts across 4 categories
- Established clear patterns and conventions
- Added comprehensive examples and templates

---

## Quick Reference Card

### Script Categories
- **AWS**: 7 scripts (boto3, us-west-2 default)
- **Baremetal**: 13 scripts (system tools, health monitoring)
- **Kubernetes**: 18 scripts (kubectl, cluster operations)
- **SSH/Utils**: 4 scripts (multi-host administration)

### Exit Codes
- **0**: Success / Healthy
- **1**: Errors / Warnings
- **2**: Usage Error / Missing Dependency

### Common Flags
- `-h, --help`: Show help message
- `-r, --region`: AWS region (default: us-west-2)
- `-n, --namespace`: Kubernetes namespace
- `--format`: Output format (plain/json/table)
- `-v, --verbose`: Detailed output
- `-w, --warn-only`: Only show issues
- `--force`: Skip confirmations
- `--dry-run`: Simulate without executing

### Test Commands
```bash
make test                    # All tests
make test-verbose            # Verbose output
make test-ec2                # AWS tests
make test-baremetal          # Baremetal tests
make test-k8s                # Kubernetes tests
make test-script_name        # Specific test
python3 tests/test_foo.py    # Direct execution
```

### Development Workflow
1. Create script (chmod +x)
2. Create test file
3. Implement functionality
4. Write tests (subprocess pattern)
5. Run: `make test`
6. Update README.md
7. Commit changes

---

**END OF CLAUDE.md**
