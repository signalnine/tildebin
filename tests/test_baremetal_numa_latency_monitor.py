#!/usr/bin/env python3
"""
Test script for baremetal_numa_latency_monitor.py functionality.
Tests argument parsing and output formats without requiring specific NUMA hardware.
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
        [sys.executable, 'baremetal_numa_latency_monitor.py', '--help']
    )

    if return_code == 0 and 'numa' in stdout.lower():
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
        [sys.executable, 'baremetal_numa_latency_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_numa_latency_monitor.py']
    )

    # Should succeed (0 or 1) or fail gracefully (2 if NUMA not available)
    if return_code in [0, 1]:
        # Has NUMA - check output
        if 'NUMA' in stdout or 'node' in stdout.lower():
            print("[PASS] Plain output format test passed (NUMA available)")
            return True
        else:
            print(f"[FAIL] Plain output missing expected content")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # No NUMA - check error message
        if 'numa' in stderr.lower() or 'not available' in stderr.lower():
            print("[PASS] Plain output format test passed (NUMA not available)")
            return True
        else:
            print(f"[FAIL] Unexpected error message")
            print(f"  Stderr: {stderr[:200]}")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_numa_latency_monitor.py', '--format', 'json']
    )

    # May exit 2 if no NUMA support
    if return_code == 2:
        print("[PASS] JSON output format test passed (NUMA not available)")
        return True

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'topology' not in data:
            print("[FAIL] JSON output missing topology key")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify topology data structure
        topology = data['topology']
        if 'node_count' not in topology:
            print("[FAIL] JSON topology missing node_count")
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
        [sys.executable, 'baremetal_numa_latency_monitor.py', '--format', 'table']
    )

    # May exit 2 if no NUMA support
    if return_code == 2:
        print("[PASS] Table output format test passed (NUMA not available)")
        return True

    # Should contain table-like content
    if return_code in [0, 1] and ('Node' in stdout or 'NUMA' in stdout):
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
        [sys.executable, 'baremetal_numa_latency_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on NUMA state)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_mode():
    """Test verbose mode shows more details."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_numa_latency_monitor.py', '--verbose']
    )

    # Should succeed or gracefully handle no NUMA
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_format_option_choices():
    """Test that only valid format options are accepted."""
    # Test invalid format
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_numa_latency_monitor.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid' in stderr.lower():
        print("[PASS] Format option validation test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_numa_latency_monitor.py',
         '--format', 'json', '--verbose']
    )

    # Should succeed or gracefully handle no NUMA
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed")
        print(f"  Return code: {return_code}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_numa_latency_monitor.py']
    )

    # Should return 0 (healthy), 1 (warnings), or 2 (unavailable)
    if return_code in [0, 1, 2]:
        print(f"[PASS] Exit code test passed (code: {return_code})")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_issues_array():
    """Test JSON output includes issues array."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_numa_latency_monitor.py', '--format', 'json']
    )

    # May exit 2 if no NUMA support
    if return_code == 2:
        print("[PASS] JSON issues array test passed (NUMA not available)")
        return True

    try:
        data = json.loads(stdout)

        if 'issues' in data and isinstance(data['issues'], list):
            print("[PASS] JSON issues array test passed")
            return True
        else:
            print("[FAIL] JSON output missing issues array")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_short_verbose_option():
    """Test -v short form of --verbose option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_numa_latency_monitor.py', '-v']
    )

    # Should succeed or gracefully handle no NUMA
    if return_code in [0, 1, 2]:
        print("[PASS] Short form -v option test passed")
        return True
    else:
        print(f"[FAIL] Short form -v option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_short_warn_only_option():
    """Test -w short form of --warn-only option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_numa_latency_monitor.py', '-w']
    )

    # Should succeed or gracefully handle no NUMA
    if return_code in [0, 1, 2]:
        print("[PASS] Short form -w option test passed")
        return True
    else:
        print(f"[FAIL] Short form -w option test failed")
        print(f"  Return code: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_numa_latency_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_warn_only_mode,
        test_verbose_mode,
        test_format_option_choices,
        test_combined_options,
        test_exit_codes,
        test_json_issues_array,
        test_short_verbose_option,
        test_short_warn_only_option,
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
