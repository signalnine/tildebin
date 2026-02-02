# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

tildebin is a collection of standalone utility scripts for system administrators. Scripts are placed directly in ~/bin and run independently. Focus areas: AWS EC2 management (boto3), baremetal system monitoring, Kubernetes cluster operations (kubectl), and SSH orchestration.

## Build & Test Commands

```bash
# Run all tests
make test

# Run tests with verbose output
make test-verbose

# Run specific category
make test-ec2          # AWS tests
make test-baremetal    # Baremetal tests
make test-k8s          # Kubernetes tests

# Run single test (two ways)
make test-disk_health_check
python3 tests/test_disk_health_check.py

# Run tests matching pattern
make test-filter PATTERN=disk
python3 tests/run_tests.py -f disk raid

# Check dependencies
make check-deps
```

## Exit Code Convention

All scripts follow this convention:
- **0** = Success / healthy / no issues
- **1** = Warnings or errors found
- **2** = Usage error (bad arguments) or missing dependency

## Architecture

### Directory Structure
```
tildebin/
├── *.py, *.sh          # Utility scripts (flat, no nesting)
├── tests/
│   ├── test_*.py       # One test file per script
│   └── run_tests.py    # Test runner with filtering
└── Makefile            # Test automation
```

### Script Categories

**AWS Scripts** (boto3): `listec2hosts.py`, `ec2_manage.py`, `ec2_tag_summary.py`, `terminate_instance.py`, `stop_all_instances.py`, `emptysgs.py`, `listvolumes.py`
- Default region: us-west-2 (except emptysgs.py: us-east-1)
- Support `-r/--region` flag
- Import boto3 late (after credential validation)
- Check `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars

**Kubernetes Scripts** (kubectl): `k8s_*.py`, `kubernetes_node_health.py`
- Use kubectl subprocess with JSON output
- Support `-n/--namespace` filtering
- Exit code 2 if kubectl not found

**Baremetal Scripts**: `baremetal_*.py`, `disk_health_check.py`, `check_raid.py`, etc.
- Check for system tools before using (smartctl, mdadm, etc.)
- Exit code 2 if required tool missing

### Common Flags

Most scripts support:
- `--format {plain,json,table}` - Output format (default: plain)
- `-v/--verbose` - Detailed output
- `-w/--warn-only` - Only show issues
- `--force` - Skip confirmation (destructive ops)
- `--dry-run` - Simulate without executing

## Testing Philosophy

Tests use subprocess to run scripts as users would. Tests must NOT require:
- AWS credentials
- Hardware tools (smartctl, etc.)
- kubectl access
- Network connectivity

Tests validate: argument parsing, help message, error handling, JSON output parsing, exit codes.

## Key Patterns

### AWS Script Pattern
```python
# Check credentials BEFORE importing boto3
if not (os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY')):
    print("Error: AWS credentials not found", file=sys.stderr)
    sys.exit(2)

# Import late
try:
    import boto3
except ImportError:
    print("Error: boto3 required", file=sys.stderr)
    sys.exit(2)
```

### Subprocess Tool Pattern (baremetal/k8s)
```python
try:
    result = subprocess.run(['kubectl', 'get', 'pods', '-o', 'json'],
                          capture_output=True, text=True, check=True)
except FileNotFoundError:
    print("Error: kubectl not found", file=sys.stderr)
    sys.exit(2)
except subprocess.CalledProcessError as e:
    print(f"Error: {e.stderr}", file=sys.stderr)
    sys.exit(1)
```

### Destructive Operations
```python
parser.add_argument("--force", action="store_true", help="Skip confirmation")
parser.add_argument("--dry-run", action="store_true", help="Show what would happen")

if not args.force:
    response = input("Are you sure? [y/N] ")
    if response.lower() != 'y':
        sys.exit(0)
```

## Critical Rules

1. **Backward compatibility is sacred** - Never change default output format or remove CLI flags
2. **Errors to stderr** - Use `print(..., file=sys.stderr)` for errors
3. **Test file per script** - Every `foo.py` has `tests/test_foo.py`
4. **Minimal dependencies** - Prefer stdlib; boto3 is the exception for AWS
5. **Scripts must be executable** - `chmod +x script.py`
