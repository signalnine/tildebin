# Tests

This directory contains all tests for tildebin utilities.

## Running Tests

### Quick Start

```bash
# From the repository root
make test
```

### Using the Test Runner

The `run_tests.py` script provides a comprehensive test runner with filtering and output options:

```bash
# Run all tests
python3 tests/run_tests.py

# Run with verbose output
python3 tests/run_tests.py -v

# Run tests matching a pattern
python3 tests/run_tests.py -f disk
python3 tests/run_tests.py -f disk raid network

# Stop on first failure
python3 tests/run_tests.py --fail-fast

# Disable colored output
python3 tests/run_tests.py --no-color
```

### Using Make

The Makefile provides convenient shortcuts:

```bash
# Run all tests
make test

# Run with verbose output
make test-verbose

# Run EC2-related tests
make test-ec2

# Run baremetal-related tests
make test-baremetal

# Run tests matching a pattern
make test-filter PATTERN=disk
make test-filter PATTERN="disk raid"

# Run a specific test file
make test-ec2_manage
make test-disk_health_check
```

### Running Individual Tests

Each test file can be run independently:

```bash
python3 tests/test_ec2_manage.py
python3 tests/test_disk_health_check.py
```

## Test Structure

Each test file follows a consistent pattern:

1. **File naming**: `test_<script_name>.py` for testing `<script_name>.py`
2. **Test functions**: Named `test_<feature>()` describing what is being tested
3. **Subprocess execution**: Tests run scripts as subprocesses to validate real-world behavior
4. **No dependencies**: Tests don't require AWS credentials, hardware, or special permissions
5. **Output parsing**: Tests validate exit codes and parse output to verify correct behavior

### Example Test Structure

```python
def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command([sys.executable, 'script.py', '--help'])
    if return_code == 0 and 'expected text' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed")
        return False
```

## What Tests Validate

### For All Scripts
- Help message (`--help` flag works)
- Argument parsing (flags are recognized)
- Invalid input rejection (bad arguments fail appropriately)

### For AWS Scripts
- Credential handling (graceful failure when credentials missing)
- Region option support
- Output format options (plain/table/json)

### For Baremetal Scripts
- Dependency checking (graceful failure when tools missing)
- Output format options (plain/json)
- Verbose mode support
- Filter options (--warn-only, etc.)

## Adding New Tests

When creating a new script, add a corresponding test file:

1. Create `tests/test_<script_name>.py`
2. Implement test functions for key features
3. Run the test to verify it works: `python3 tests/test_<script_name>.py`
4. Run the full test suite: `make test`

### Test Template

```python
#!/usr/bin/env python3
"""
Test script for <script_name>.py functionality.
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
    return_code, stdout, stderr = run_command([sys.executable, 'script.py', '--help'])

    if return_code == 0:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed")
        return False


if __name__ == "__main__":
    print("Testing <script_name>.py...")

    tests = [
        test_help_message,
        # Add more test functions here
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print(f"\nTest Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
```

## Continuous Integration

Tests are designed to run in CI/CD environments:
- No external dependencies required (AWS, hardware, etc.)
- Exit code 0 on success, 1 on failure
- Can run in parallel
- Fast execution (all tests complete in seconds)

## Troubleshooting

### Tests fail with "No such file or directory"

Make sure you're running tests from the repository root or using the correct path to test files.

### Tests hang or timeout

Check if a script is waiting for user input. Tests should not prompt for interactive input.

### Tests pass locally but fail in CI

Ensure tests don't depend on:
- Specific file paths (use relative paths)
- Environment variables (or mock them in tests)
- System tools being installed (tests should handle missing tools gracefully)
