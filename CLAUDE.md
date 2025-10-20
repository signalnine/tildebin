# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`tildebin` is a collection of small utility scripts (Python and shell) designed for personal ~/bin directories. The scripts primarily focus on AWS EC2 management and SSH-based system administration tasks across multiple hosts.

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

Test pattern: Each Python script `foo.py` has a corresponding `tests/test_foo.py` that validates:
- Argument parsing
- Help message generation
- Error handling for missing AWS credentials or dependencies
- Option/flag recognition
- Output format validation (plain/json)

Tests use subprocess to run scripts and validate exit codes and output without requiring actual AWS credentials, hardware, or API calls.

## Dependencies

Python scripts require `boto3` for AWS operations:
```bash
pip install boto3
```

Note: The codebase is actively migrating from deprecated `boto` (v2) to `boto3`. All scripts now use boto3 exclusively.

## Code Architecture

### AWS Credential Handling Pattern

All AWS scripts follow a consistent pattern for credentials:

1. Check environment variables for AWS credentials (in order of preference):
   - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`
   - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`
   - `EC2_REGION` (for region override)
   - `EC2_URL` (for endpoint override, less common)

2. Import boto3 only after argument parsing and credential validation
3. Handle boto3 import errors with helpful install messages
4. Use boto3.client('ec2', region_name=region) for EC2 operations

Example from emptysgs.py:46-62 and ec2_manage.py:28-39

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

**System Utilities** (Shell):
- generate_fstab.sh: Generate /etc/fstab from /proc/mounts using UUIDs

### Common Output Patterns

Scripts support multiple output formats:
- `--format plain`: Space-separated values (default for backward compatibility)
- `--format table`: Columnar output with headers
- `--format json`: JSON output (where applicable, e.g., ec2_tag_summary.py, listvolumes.py)

### Regional Defaults

- Most scripts default to `us-west-2` (ec2_manage.py, listec2hosts.py, listvolumes.py, terminate_instance.py, stop_all_instances.py)
- Exception: emptysgs.py defaults to `us-east-1`
- ec2_tag_summary.py scans multiple regions by default: `us-west-2 us-east-1`

All scripts accept `-r/--region` to override defaults and respect the `EC2_REGION` environment variable.

### User Confirmation Pattern

Destructive operations (terminate_instance.py, stop_all_instances.py) require:
- Display of affected resources before action
- Interactive confirmation prompt (can be bypassed with `--force`)
- Dry-run mode support (via `--dry-run` flag)

## Development Guidelines

When adding new AWS scripts:
- Follow the credential handling pattern (check env vars, import boto3 late, handle errors)
- Support `-r/--region` flag with sensible default
- Add corresponding test_*.py that validates argument parsing without AWS API calls
- Use boto3 (not deprecated boto)
- For destructive operations, add confirmation prompts and dry-run support
- Match existing output format patterns (plain/table/json as appropriate)

When adding new baremetal scripts:
- Support multiple output formats (plain/json at minimum)
- Include `--verbose` flag for detailed information
- Support `--warn-only` or similar filtering for monitoring use cases
- Handle missing dependencies gracefully with helpful error messages
- Add corresponding test file in `tests/` directory

When modifying existing scripts:
- Maintain backward compatibility for default output formats
- Preserve environment variable support
- Update corresponding test file in `tests/` directory
- Keep exit codes consistent: 0 for success, 1 for errors or warnings
