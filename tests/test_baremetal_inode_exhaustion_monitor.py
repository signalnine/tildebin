#!/usr/bin/env python3
"""
Test script for baremetal_inode_exhaustion_monitor.py functionality.
Tests argument parsing and output formats without requiring special access.
"""

import subprocess
import sys
import json


def run_command(cmd_args):
    """Helper function to run a command and return result."""
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
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--help']
    )

    if return_code == 0 and 'inode' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_recognized():
    """Test that format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--format', 'invalid']
    )

    # Should fail with usage error (invalid choice)
    if return_code != 0 and ('invalid choice' in stderr or 'invalid' in stderr.lower()):
        print("[PASS] Format option recognition test passed")
        return True
    else:
        print(f"[FAIL] Format option recognition test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_threshold_out_of_range():
    """Test that out-of-range threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--warn', '150']
    )

    if return_code == 2 and 'between 0 and 100' in stderr:
        print("[PASS] Invalid threshold (out of range) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (out of range) test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_threshold_negative():
    """Test that negative threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--warn', '-10']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold (negative) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (negative) test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_crit_le_warn():
    """Test that crit <= warn is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--warn', '90', '--crit', '80']
    )

    if return_code == 2 and 'must be greater than' in stderr:
        print("[PASS] Invalid threshold (crit <= warn) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (crit <= warn) test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py']
    )

    # Exit code 0 or 1 = success (healthy or warnings)
    if return_code in [0, 1]:
        if 'Inode' in stdout or 'inode' in stdout.lower():
            print("[PASS] Plain output format test passed")
            return True
        else:
            print(f"[FAIL] Plain output missing expected content")
            print(f"  Output: {stdout[:300]}")
            return False
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON output format returned unexpected code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'filesystems' not in data or 'issues' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify summary structure
        if 'summary' not in data:
            print("[FAIL] JSON output missing summary")
            return False

        summary = data['summary']
        required_keys = ['total_filesystems', 'critical_count', 'warning_count', 'healthy']
        if not all(key in summary for key in required_keys):
            print("[FAIL] JSON summary missing required keys")
            print(f"  Summary keys: {list(summary.keys())}")
            return False

        print("[PASS] JSON output format test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1] and 'INODE USAGE STATUS' in stdout:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode includes detailed info."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--verbose']
    )

    if return_code in [0, 1] and ('Filesystem:' in stdout or 'Available:' in stdout):
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:300]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on system state)
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_thresholds():
    """Test custom threshold arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--warn', '70', '--crit', '85']
    )

    if return_code in [0, 1]:
        print("[PASS] Custom thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_mountpoint_filter():
    """Test mountpoint filter option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--mountpoint', '/']
    )

    if return_code in [0, 1]:
        print("[PASS] Mountpoint filter test passed")
        return True
    else:
        # Mountpoint / should exist on any Linux system
        print(f"[FAIL] Mountpoint filter test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_mountpoint():
    """Test invalid mountpoint is handled."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py',
         '--mountpoint', '/nonexistent/path/12345']
    )

    if return_code == 2 and 'not found' in stderr:
        print("[PASS] Invalid mountpoint test passed")
        return True
    else:
        print(f"[FAIL] Invalid mountpoint test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_filesystem_structure():
    """Test JSON filesystem entries have correct structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON filesystem structure test returned unexpected code: {return_code}")
        return False

    try:
        data = json.loads(stdout)

        # Check filesystem structure if any exist
        if data['filesystems']:
            fs = data['filesystems'][0]
            required_keys = ['mountpoint', 'filesystem', 'total', 'used', 'available', 'usage_percent']
            if not all(key in fs for key in required_keys):
                print("[FAIL] Filesystem entry missing required keys")
                print(f"  Keys: {list(fs.keys())}")
                return False

        print("[PASS] JSON filesystem structure test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] JSON filesystem structure test failed: {e}")
        return False


def test_json_values_are_numeric():
    """Test that filesystem values in JSON are numeric."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] Numeric values test returned unexpected code: {return_code}")
        return False

    try:
        data = json.loads(stdout)

        # Check filesystem values if any exist
        if data['filesystems']:
            fs = data['filesystems'][0]

            if not isinstance(fs['total'], int):
                print("[FAIL] filesystem.total is not an integer")
                return False
            if not isinstance(fs['used'], int):
                print("[FAIL] filesystem.used is not an integer")
                return False
            if not isinstance(fs['available'], int):
                print("[FAIL] filesystem.available is not an integer")
                return False
            if not isinstance(fs['usage_percent'], (int, float)):
                print("[FAIL] filesystem.usage_percent is not numeric")
                return False

        print("[PASS] JSON values are numeric test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] Numeric values test failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py']
    )

    if return_code in [0, 1]:
        print(f"[PASS] Exit code test passed (got {return_code})")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_help_contains_remediation():
    """Test that help includes remediation guidance."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--help']
    )

    if return_code == 0 and 'find' in stdout and 'remediation' in stdout.lower():
        print("[PASS] Help contains remediation guidance test passed")
        return True
    else:
        print(f"[FAIL] Help should contain remediation guidance")
        print(f"  Output: {stdout[:300]}")
        return False


def test_help_contains_exit_codes():
    """Test that help documents exit codes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--help']
    )

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Help contains exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_json_summary_counts():
    """Test that JSON summary has correct count types."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_exhaustion_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON summary counts test returned unexpected code: {return_code}")
        return False

    try:
        data = json.loads(stdout)
        summary = data['summary']

        if not isinstance(summary['total_filesystems'], int):
            print("[FAIL] summary.total_filesystems is not an integer")
            return False
        if not isinstance(summary['critical_count'], int):
            print("[FAIL] summary.critical_count is not an integer")
            return False
        if not isinstance(summary['warning_count'], int):
            print("[FAIL] summary.warning_count is not an integer")
            return False
        if not isinstance(summary['healthy'], bool):
            print("[FAIL] summary.healthy is not a boolean")
            return False

        print("[PASS] JSON summary counts test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] JSON summary counts test failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_inode_exhaustion_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_recognized,
        test_invalid_threshold_out_of_range,
        test_invalid_threshold_negative,
        test_invalid_threshold_crit_le_warn,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_custom_thresholds,
        test_mountpoint_filter,
        test_invalid_mountpoint,
        test_json_filesystem_structure,
        test_json_values_are_numeric,
        test_exit_codes,
        test_help_contains_remediation,
        test_help_contains_exit_codes,
        test_json_summary_counts,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"{total - passed} test(s) failed")
        sys.exit(1)
