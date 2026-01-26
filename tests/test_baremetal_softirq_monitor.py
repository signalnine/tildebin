#!/usr/bin/env python3
"""
Test script for baremetal_softirq_monitor.py functionality.
Tests argument parsing and output formats without requiring specific system conditions.
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
        [sys.executable, 'baremetal_softirq_monitor.py', '--help']
    )

    if return_code == 0 and 'softirq' in stdout.lower():
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
        [sys.executable, 'baremetal_softirq_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_softirq_monitor.py']
    )

    # Should succeed (exit 0 or 1 depending on findings)
    if return_code in [0, 1] and 'CPU Count:' in stdout:
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
        [sys.executable, 'baremetal_softirq_monitor.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'summary' not in data or 'totals' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify summary structure
        summary = data['summary']
        required_keys = ['cpu_count', 'softirq_types', 'issue_count', 'warning_count']
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
        [sys.executable, 'baremetal_softirq_monitor.py', '--format', 'table',
         '--interval', '0.1']
    )

    # Should succeed and contain table elements
    if return_code in [0, 1] and ('SOFTIRQ' in stdout or 'No softirq issues' in stdout
                                   or '===' in stdout):
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
        [sys.executable, 'baremetal_softirq_monitor.py', '--verbose']
    )

    # Should succeed and contain detailed info
    if return_code in [0, 1] and 'Softirq Totals:' in stdout:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output when no warnings."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softirq_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on system state)
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_interval_option():
    """Test interval option for rate calculation."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softirq_monitor.py', '--interval', '0.1',
         '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # With interval, should have rates data
        if 'rates' not in data:
            print("[FAIL] Interval mode missing 'rates' in JSON")
            return False

        if 'rate_totals' not in data:
            print("[FAIL] Interval mode missing 'rate_totals' in JSON")
            return False

        print("[PASS] Interval option test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] Interval option JSON parsing failed: {e}")
        return False


def test_imbalance_threshold_option():
    """Test custom imbalance threshold option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softirq_monitor.py', '--imbalance', '5.0']
    )

    # Should succeed with custom threshold
    if return_code in [0, 1]:
        print("[PASS] Imbalance threshold option test passed")
        return True
    else:
        print(f"[FAIL] Imbalance threshold option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_rate_threshold_option():
    """Test custom rate threshold option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softirq_monitor.py', '--rate-threshold', '200000']
    )

    # Should succeed with custom threshold
    if return_code in [0, 1]:
        print("[PASS] Rate threshold option test passed")
        return True
    else:
        print(f"[FAIL] Rate threshold option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_imbalance_threshold():
    """Test that invalid imbalance threshold is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softirq_monitor.py', '--imbalance', '0.5']
    )

    if return_code == 2:
        print("[PASS] Invalid imbalance threshold test passed")
        return True
    else:
        print(f"[FAIL] Invalid imbalance threshold test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_rate_threshold():
    """Test that invalid rate threshold is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softirq_monitor.py', '--rate-threshold', '-100']
    )

    if return_code == 2:
        print("[PASS] Invalid rate threshold test passed")
        return True
    else:
        print(f"[FAIL] Invalid rate threshold test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_interval():
    """Test that negative interval is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softirq_monitor.py', '--interval', '-1']
    )

    if return_code == 2:
        print("[PASS] Invalid interval test passed")
        return True
    else:
        print(f"[FAIL] Invalid interval test failed")
        print(f"  Return code: {return_code}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softirq_monitor.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_totals_structure():
    """Test that JSON totals have expected softirq types."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softirq_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        totals = data.get('totals', {})

        # Common softirq types that should exist on Linux
        expected_types = ['TIMER', 'SCHED', 'RCU']
        found_types = [t for t in expected_types if t in totals]

        if len(found_types) >= 2:
            print("[PASS] JSON totals structure test passed")
            return True
        else:
            print(f"[FAIL] JSON totals missing expected types")
            print(f"  Found types: {list(totals.keys())}")
            return False
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] JSON totals test failed: {e}")
        return False


def test_json_summary_values_numeric():
    """Test that JSON summary values are numeric."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softirq_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        summary = data['summary']

        # Check that values are numeric
        if not isinstance(summary['cpu_count'], int):
            print("[FAIL] summary.cpu_count is not an integer")
            return False
        if not isinstance(summary['softirq_types'], int):
            print("[FAIL] summary.softirq_types is not an integer")
            return False
        if not isinstance(summary['issue_count'], int):
            print("[FAIL] summary.issue_count is not an integer")
            return False
        if not isinstance(summary['warning_count'], int):
            print("[FAIL] summary.warning_count is not an integer")
            return False

        print("[PASS] JSON summary values are numeric test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] JSON summary values test failed: {e}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softirq_monitor.py',
         '--format', 'json', '--verbose', '--interval', '0.1',
         '--imbalance', '3.0', '--rate-threshold', '50000']
    )

    try:
        data = json.loads(stdout)

        # Should have all expected fields
        if 'summary' in data and 'totals' in data and 'rates' in data:
            print("[PASS] Combined options test passed")
            return True
        else:
            print("[FAIL] Combined options missing expected fields")
            print(f"  Keys: {list(data.keys())}")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] Combined options test failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_softirq_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_interval_option,
        test_imbalance_threshold_option,
        test_rate_threshold_option,
        test_invalid_imbalance_threshold,
        test_invalid_rate_threshold,
        test_invalid_interval,
        test_exit_codes,
        test_json_totals_structure,
        test_json_summary_values_numeric,
        test_combined_options,
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
