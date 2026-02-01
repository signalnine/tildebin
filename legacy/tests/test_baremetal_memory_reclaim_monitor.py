#!/usr/bin/env python3
"""
Test script for baremetal_memory_reclaim_monitor.py functionality.
Tests argument parsing and output formats without requiring specific memory conditions.
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
        [sys.executable, 'baremetal_memory_reclaim_monitor.py', '--help']
    )

    if return_code == 0 and 'memory reclaim' in stdout.lower():
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
        [sys.executable, 'baremetal_memory_reclaim_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_memory_reclaim_monitor.py']
    )

    # Should succeed (exit 0 or 1 depending on memory state)
    if return_code in [0, 1] and 'kswapd' in stdout.lower():
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
        [sys.executable, 'baremetal_memory_reclaim_monitor.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'reclaim' not in data or 'memory' not in data or 'issues' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify reclaim data structure
        reclaim = data['reclaim']
        required_reclaim_keys = ['kswapd_scan', 'kswapd_steal', 'direct_scan',
                                  'direct_steal', 'efficiency_percent']
        if not all(key in reclaim for key in required_reclaim_keys):
            print("[FAIL] JSON reclaim data missing required keys")
            print(f"  Reclaim keys: {list(reclaim.keys())}")
            return False

        # Verify memory data structure
        memory = data['memory']
        required_memory_keys = ['total_kb', 'available_kb', 'available_percent']
        if not all(key in memory for key in required_memory_keys):
            print("[FAIL] JSON memory data missing required keys")
            print(f"  Memory keys: {list(memory.keys())}")
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
        [sys.executable, 'baremetal_memory_reclaim_monitor.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and 'MEMORY RECLAIM' in stdout:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode includes additional information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_reclaim_monitor.py', '--verbose']
    )

    # Should succeed and contain additional details
    if return_code in [0, 1] and ('Allocation stalls' in stdout or 'allocstall' in stdout.lower()):
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_reclaim_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on memory state)
    # Output might be empty if no warnings
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
        [sys.executable, 'baremetal_memory_reclaim_monitor.py',
         '--direct-reclaim', '200000',
         '--allocstall', '5000',
         '--efficiency', '5',
         '--compact-stall', '20000']
    )

    # Should succeed with custom thresholds
    if return_code in [0, 1]:
        print("[PASS] Custom thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thresholds test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_efficiency_threshold():
    """Test that invalid efficiency threshold is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_reclaim_monitor.py', '--efficiency', '150']
    )

    if return_code == 2:
        print("[PASS] Invalid efficiency threshold test passed")
        return True
    else:
        print(f"[FAIL] Invalid efficiency threshold should fail with exit code 2")
        print(f"  Return code: {return_code}")
        return False


def test_negative_threshold():
    """Test that negative threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_reclaim_monitor.py', '--direct-reclaim', '-100']
    )

    if return_code == 2:
        print("[PASS] Negative threshold test passed")
        return True
    else:
        print(f"[FAIL] Negative threshold should fail with exit code 2")
        print(f"  Return code: {return_code}")
        return False


def test_json_verbose_includes_additional():
    """Test JSON verbose output includes additional metrics."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_reclaim_monitor.py', '--format', 'json', '--verbose']
    )

    try:
        data = json.loads(stdout)

        # Verify additional metrics are included in verbose mode
        if 'additional' not in data:
            print("[FAIL] JSON verbose missing 'additional' section")
            return False

        additional = data['additional']
        required_keys = ['allocstall', 'compact_stall', 'compact_fail',
                         'compact_success', 'oom_kill', 'pswpin', 'pswpout']

        if not all(key in additional for key in required_keys):
            print("[FAIL] JSON additional data missing required keys")
            print(f"  Additional keys: {list(additional.keys())}")
            return False

        print("[PASS] JSON verbose includes additional test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON verbose parsing failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_reclaim_monitor.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_reclaim_efficiency_in_output():
    """Test that reclaim efficiency is calculated and shown."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_reclaim_monitor.py']
    )

    if return_code in [0, 1] and 'efficiency' in stdout.lower():
        print("[PASS] Reclaim efficiency in output test passed")
        return True
    else:
        print(f"[FAIL] Reclaim efficiency in output test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_has_issues_field():
    """Test JSON output has has_issues boolean field."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_reclaim_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'has_issues' not in data:
            print("[FAIL] JSON missing 'has_issues' field")
            return False

        if not isinstance(data['has_issues'], bool):
            print("[FAIL] 'has_issues' should be boolean")
            return False

        print("[PASS] JSON has_issues field test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_memory_reclaim_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_custom_thresholds,
        test_invalid_efficiency_threshold,
        test_negative_threshold,
        test_json_verbose_includes_additional,
        test_exit_codes,
        test_reclaim_efficiency_in_output,
        test_json_has_issues_field,
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
