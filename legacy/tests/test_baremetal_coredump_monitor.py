#!/usr/bin/env python3
"""
Test script for baremetal_coredump_monitor.py functionality.
Tests argument parsing and output formats without requiring specific coredump conditions.
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
        [sys.executable, 'baremetal_coredump_monitor.py', '--help']
    )

    if return_code == 0 and 'coredump' in stdout.lower():
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
        [sys.executable, 'baremetal_coredump_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_coredump_monitor.py']
    )

    # Should succeed (exit 0 or 1 depending on configuration)
    if return_code in [0, 1] and ('Core Pattern' in stdout or 'coredump' in stdout.lower()):
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_coredump_monitor.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['core_pattern', 'ulimit', 'systemd_coredump', 'issues']
        missing_keys = [k for k in required_keys if k not in data]

        if missing_keys:
            print(f"[FAIL] JSON output missing expected keys: {missing_keys}")
            print(f"  Keys found: {list(data.keys())}")
            return False

        # Verify core_pattern is a string
        if not isinstance(data['core_pattern'], str):
            print("[FAIL] core_pattern is not a string")
            return False

        # Verify ulimit structure
        ulimit = data['ulimit']
        if 'soft_limit' not in ulimit or 'hard_limit' not in ulimit:
            print("[FAIL] ulimit missing required keys")
            return False

        # Verify issues is a list
        if not isinstance(data['issues'], list):
            print("[FAIL] issues is not a list")
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
        [sys.executable, 'baremetal_coredump_monitor.py', '--format', 'table']
    )

    # Should succeed and contain table structure
    if return_code in [0, 1] and ('COREDUMP' in stdout or 'Core Pattern' in stdout):
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_coredump_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on configuration)
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_mode():
    """Test verbose mode shows additional details."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_coredump_monitor.py', '--verbose']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_storage_threshold_options():
    """Test storage threshold options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_coredump_monitor.py',
         '--storage-warn', '70', '--storage-crit', '85']
    )

    # Should succeed with valid thresholds
    if return_code in [0, 1]:
        print("[PASS] Storage threshold options test passed")
        return True
    else:
        print(f"[FAIL] Storage threshold options test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_storage_thresholds():
    """Test that invalid storage thresholds are rejected."""
    # Test crit <= warn
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_coredump_monitor.py',
         '--storage-warn', '80', '--storage-crit', '70']
    )

    if return_code == 2:
        print("[PASS] Invalid storage thresholds test passed (crit <= warn)")
        return True
    else:
        print(f"[FAIL] Invalid storage thresholds test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_storage_threshold_range():
    """Test that storage thresholds must be 0-100."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_coredump_monitor.py',
         '--storage-warn', '150']
    )

    if return_code == 2:
        print("[PASS] Storage threshold range test passed")
        return True
    else:
        print(f"[FAIL] Storage threshold range test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_contains_systemd_info():
    """Test JSON output includes systemd-coredump information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_coredump_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'systemd_coredump' not in data:
            print("[FAIL] JSON output missing systemd_coredump")
            return False

        systemd = data['systemd_coredump']
        if 'enabled' not in systemd:
            print("[FAIL] systemd_coredump missing 'enabled' key")
            return False

        print("[PASS] JSON systemd info test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_contains_ulimit_info():
    """Test JSON output includes ulimit information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_coredump_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'ulimit' not in data:
            print("[FAIL] JSON output missing ulimit")
            return False

        ulimit = data['ulimit']
        required_keys = ['soft_limit', 'hard_limit', 'enabled']
        missing = [k for k in required_keys if k not in ulimit]

        if missing:
            print(f"[FAIL] ulimit missing keys: {missing}")
            return False

        print("[PASS] JSON ulimit info test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_coredump_monitor.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_format_option_choices():
    """Test that only valid format options are accepted."""
    # Test invalid format
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_coredump_monitor.py', '--format', 'xml']
    )

    if return_code == 2:
        print("[PASS] Format option choices test passed")
        return True
    else:
        print(f"[FAIL] Format option choices test failed")
        print(f"  Return code: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_coredump_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_warn_only_mode,
        test_verbose_mode,
        test_storage_threshold_options,
        test_invalid_storage_thresholds,
        test_storage_threshold_range,
        test_json_contains_systemd_info,
        test_json_contains_ulimit_info,
        test_exit_codes,
        test_format_option_choices,
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
