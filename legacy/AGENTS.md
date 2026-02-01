# AGENTS.md

This file provides guidance to AI coding agents (Claude Code, Qwen, Cursor, etc.) when working with code in this repository.

## General Principles

### Code Quality
- **Simplicity over cleverness**: Write clear, maintainable code that's easy to understand
- **UNIX philosophy**: Each script should do one thing well
- **Minimal dependencies**: Keep external dependencies to a minimum; prefer stdlib when possible
- **Fail gracefully**: Handle errors with helpful messages, not cryptic stack traces
- **Exit codes matter**: 0 for success, 1 for errors/warnings, 2 for usage errors

### User Experience
- **Always include `--help`**: Every script must have a help message explaining usage
- **Sensible defaults**: Scripts should work with minimal configuration
- **Backward compatibility**: Don't break existing behavior; default output formats are sacred
- **No surprises**: Destructive operations require confirmation (unless `--force` is used)
- **Progress feedback**: For long-running operations, show what's happening

### Testing Philosophy
- **Every script has tests**: Each `foo.py` must have `tests/test_foo.py`
- **Tests don't require resources**: No AWS credentials, no hardware, no network calls
- **Test real behavior**: Use subprocess to run scripts as users would
- **Fast tests**: Full test suite should complete in seconds, not minutes
- **Validate, don't mock excessively**: Test argument parsing and error handling paths

### Documentation
- **Self-documenting code**: Good variable names and clear structure reduce need for comments
- **Document the why, not the what**: Comments should explain reasoning, not restate code
- **Keep docs in sync**: When you change behavior, update README.md and AGENTS.md
- **Examples over explanations**: Show usage examples in help messages and docs

## Project Overview

`tildebin` is a collection of small utility scripts (Python and shell) designed for personal ~/bin directories. The scripts focus on:
- AWS EC2 management and monitoring
- SSH-based system administration across multiple hosts
- Baremetal server monitoring (disks, RAID, network, hardware inventory)
- System utilities for Linux administration

## Testing

All tests are located in the `tests/` directory. Use the test runner or Makefile for convenient test execution:

```bash
# Run all tests
make test
python3 tests/run_tests.py

# Run tests with verbose output
make test-verbose
python3 tests/run_tests.py -v

# Run specific test categories
make test-ec2              # EC2-related tests only
make test-baremetal        # Baremetal monitoring tests only

# Run tests matching a pattern
make test-filter PATTERN=disk
python3 tests/run_tests.py -f disk raid

# Run a specific test file
make test-ec2_manage
python3 tests/test_ec2_manage.py
```

### Test Pattern

Each Python script `foo.py` has a corresponding `tests/test_foo.py` that validates:
- Argument parsing (all flags and options recognized)
- Help message generation (`--help` works)
- Error handling for missing AWS credentials or dependencies
- Invalid input rejection (bad arguments fail appropriately)
- Output format validation (plain/json/table as applicable)

Tests use subprocess to run scripts and validate exit codes and output without requiring actual AWS credentials, hardware, or API calls. This ensures tests are fast, reliable, and can run anywhere.

## Dependencies

**Python scripts** require `boto3` for AWS operations:
```bash
pip install boto3
```

**Baremetal scripts** have optional system dependencies:
- `disk_health_check.py`: smartmontools (`smartctl`)
- `check_raid.py`: mdadm (software RAID), MegaCli (LSI), hpacucli/ssacli (HP)
- `system_inventory.py`: dmidecode (for detailed hardware info)

All dependency checks are graceful with helpful error messages pointing to installation instructions.

Note: The codebase has fully migrated from deprecated `boto` (v2) to `boto3`. All AWS scripts now use boto3 exclusively.

## Code Architecture

### Script Categories

**AWS EC2 Management** (Python, boto3):
- Instance lifecycle: ec2_manage.py (start/stop/restart), terminate_instance.py, stop_all_instances.py
- Instance discovery: listec2hosts.py (single region listing), ec2_tag_summary.py (multi-region tag-based summary)
- Resource management: emptysgs.py (unused security groups), listvolumes.py (EBS volumes)

**SSH Orchestration** (Shell):
- acrosshosts.sh: Execute commands across multiple hosts from a file
- useradd.sh: Create users with SSH keys and sudo access on multiple hosts
- grephosts.sh: Filter listec2hosts.py output by search term

**Baremetal System Monitoring** (Python and shell):
- disk_health_check.py: Monitor disk health using SMART attributes
- check_raid.py: Check status of hardware and software RAID arrays (mdadm, MegaCli, hpacucli)
- network_bond_status.sh: Check status of network bonded interfaces
- system_inventory.py: Generate comprehensive hardware inventory

**Kubernetes Management** (Python, kubectl):
- kubernetes_node_health.py: Check Kubernetes node health and resource availability

**System Utilities** (Shell):
- generate_fstab.sh: Generate /etc/fstab from /proc/mounts using UUIDs

### AWS Credential Handling Pattern

All AWS scripts follow a consistent pattern for credentials:

1. **Check environment variables** for AWS credentials (in order of preference):
   - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`
   - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`
   - `EC2_REGION` (for region override)
   - `EC2_URL` (for endpoint override, less common)

2. **Import boto3 late**: Only after argument parsing and credential validation
3. **Handle import errors gracefully**: With helpful install messages
4. **Use boto3.client()**: Pattern is `boto3.client('ec2', region_name=region)`

Example from emptysgs.py:18-39 and ec2_manage.py:28-39

### Common Output Patterns

Scripts support multiple output formats (specified via `--format` flag):
- `plain`: Space-separated values (default for backward compatibility)
- `table`: Columnar output with headers (human-readable)
- `json`: JSON output (machine-parseable)

Not all scripts support all formats. At minimum, new scripts should support plain and json.

### Regional Defaults

- **Most scripts default to `us-west-2`**: ec2_manage.py, listec2hosts.py, listvolumes.py, terminate_instance.py, stop_all_instances.py
- **Exception**: emptysgs.py defaults to `us-east-1`
- **Multi-region**: ec2_tag_summary.py scans multiple regions by default: `us-west-2 us-east-1`

All scripts accept `-r/--region` to override defaults and respect the `EC2_REGION` environment variable.

### User Confirmation Pattern

Destructive operations (terminate_instance.py, stop_all_instances.py) follow this pattern:
1. Display affected resources before action
2. Interactive confirmation prompt (y/n)
3. Can be bypassed with `--force` flag
4. Support dry-run mode via `--dry-run` flag (show what would happen)

This prevents accidents while still allowing automation when needed.

## Development Guidelines

### When Adding New AWS Scripts

1. **Follow the credential handling pattern**: Check env vars, import boto3 late, handle errors gracefully
2. **Support `-r/--region` flag**: With a sensible default region
3. **Add comprehensive tests**: Create `tests/test_*.py` that validates argument parsing without AWS API calls
4. **Use boto3**: Not deprecated boto or boto2
5. **Add confirmation for destructive ops**: With `--force` and `--dry-run` support
6. **Match existing output patterns**: Support at minimum plain and json formats

### When Adding New Baremetal Scripts

1. **Support multiple output formats**: At minimum plain and json
2. **Include `--verbose` flag**: For detailed information when needed
3. **Support filtering**: `--warn-only` or similar for monitoring use cases
4. **Handle missing dependencies gracefully**: With helpful error messages pointing to installation
5. **Add corresponding test file**: In `tests/` directory
6. **Exit code indicates status**: 0 for healthy/success, 1 for warnings/errors

### When Adding New Kubernetes Scripts

1. **Use kubectl subprocess calls**: Run kubectl commands via subprocess.run() with JSON output
2. **Check for kubectl availability**: Handle FileNotFoundError gracefully
3. **Support multiple output formats**: At minimum plain and json
4. **Include `--warn-only` flag**: For filtering healthy resources in monitoring scenarios
5. **Parse kubectl JSON output**: Use json.loads() to parse structured output from kubectl
6. **Handle missing metrics-server**: Not all clusters have metrics-server; degrade gracefully
7. **Add corresponding test file**: In `tests/` directory
8. **Exit code indicates status**: 0 for healthy, 1 for warnings/errors, 2 for kubectl missing

### When Modifying Existing Scripts

1. **Maintain backward compatibility**: Especially for default output formats
2. **Preserve environment variable support**: Don't remove existing env var handling
3. **Update corresponding test file**: In `tests/` directory
4. **Keep exit codes consistent**: 0 for success, 1 for errors or warnings
5. **Update documentation**: README.md and this file if behavior changes

### Shell Script Guidelines

- Use `#!/bin/bash` or `#!/bin/sh` as appropriate
- Check for required commands before using them
- Quote variables: Use `"$var"` not `$var`
- Use `set -e` if you want to exit on first error (but understand implications)
- Provide usage message on invalid input
- Exit with status codes (0 success, 1 error, 2 usage error)

### Python Script Guidelines

- Use `#!/usr/bin/env python3` shebang
- Use argparse for argument parsing
- Import standard library first, then third-party, then local
- Use f-strings for formatting (Python 3.6+)
- Keep it simple: stdlib solutions over external dependencies when possible
- Make scripts executable: `chmod +x script.py`

## Common Patterns

### Script Template (Python)

```python
#!/usr/bin/env python3
# Brief description of what this script does

import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Description here")
    parser.add_argument("positional", help="Positional arg help")
    parser.add_argument("-o", "--option", default="default", help="Option help")

    args = parser.parse_args()

    # Do the work
    # ...

    sys.exit(0)

if __name__ == "__main__":
    main()
```

### Test Template (Python)

```python
#!/usr/bin/env python3
"""
Test script for foo.py functionality.
Tests argument parsing and error handling without requiring external resources.
"""

import subprocess
import sys

def run_command(cmd_args):
    """Helper function to run a command and return result"""
    try:
        proc = subprocess.Popen(cmd_args,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)

def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command([sys.executable, 'foo.py', '--help'])

    if return_code == 0 and 'expected text' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed")
        return False

if __name__ == "__main__":
    print("Testing foo.py...")

    tests = [
        test_help_message,
        # Add more tests here
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print(f"\nTest Results: {passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)
```

## File Organization

```
tildebin/
├── *.py                   # Python utility scripts
├── *.sh                   # Shell utility scripts
├── tests/                 # All test files
│   ├── test_*.py         # Individual test files
│   ├── run_tests.py      # Test runner
│   └── README.md         # Testing documentation
├── Makefile               # Build/test automation
├── README.md              # User documentation
├── AGENTS.md              # This file - AI agent guidance
└── .gitignore             # Git ignore patterns
```

## Resources

- See `tests/README.md` for detailed testing documentation
- See `README.md` for user-facing documentation and usage examples
- Check `Makefile` for available automation targets
- Run `make test` before committing changes
