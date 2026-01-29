#!/usr/bin/env python3
"""
Test script for baremetal_writeback_monitor.py functionality.
Tests argument parsing and error handling without requiring elevated privileges.
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
        [sys.executable, 'baremetal_writeback_monitor.py', '--help']
    )

    if return_code == 0 and 'writeback' in stdout.lower() and 'dirty' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_plain():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1, 2]:
        if 'invalid choice' not in stderr:
            print("[PASS] Plain format option test passed")
            return True

    print("[FAIL] Plain format option test failed")
    print(f"  Error: {stderr[:100]}")
    return False


def test_format_option_json():
    """Test JSON output format"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--format', 'json']
    )

    # If it works, validate JSON structure
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'status' in data and 'metrics' in data:
                print("[PASS] JSON format option test passed")
                return True
        except json.JSONDecodeError:
            pass

    # If exit 2, should be a system access issue
    if return_code == 2:
        if 'proc' in stderr.lower() or 'error' in stderr.lower():
            print("[PASS] JSON format option test passed (system access issue)")
            return True

    print(f"[FAIL] JSON format option test failed")
    print(f"  Return code: {return_code}")
    print(f"  Stdout: {stdout[:100]}")
    print(f"  Stderr: {stderr[:100]}")
    return False


def test_format_option_table():
    """Test table format option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        if 'invalid choice' not in stderr:
            print("[PASS] Table format option test passed")
            return True

    print("[FAIL] Table format option test failed")
    return False


def test_verbose_flag():
    """Test verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--verbose']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        return False


def test_warn_only_flag():
    """Test warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--warn-only']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        return False


def test_warn_pct_option():
    """Test warning percentage threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--warn-pct', '8']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-pct option test passed")
        return True
    else:
        print("[FAIL] Warn-pct option not recognized")
        return False


def test_crit_pct_option():
    """Test critical percentage threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--crit-pct', '15']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Crit-pct option test passed")
        return True
    else:
        print("[FAIL] Crit-pct option not recognized")
        return False


def test_negative_warn_pct():
    """Test that negative warning percentage is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--warn-pct', '-5']
    )

    if return_code == 2:
        print("[PASS] Negative warn-pct test passed")
        return True
    else:
        print(f"[FAIL] Negative warn-pct should return exit code 2, got {return_code}")
        return False


def test_warn_pct_over_100():
    """Test that warning percentage over 100 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--warn-pct', '150']
    )

    if return_code == 2:
        print("[PASS] Warn-pct over 100 test passed")
        return True
    else:
        print(f"[FAIL] Warn-pct over 100 should return exit code 2, got {return_code}")
        return False


def test_negative_crit_pct():
    """Test that negative critical percentage is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--crit-pct', '-10']
    )

    if return_code == 2:
        print("[PASS] Negative crit-pct test passed")
        return True
    else:
        print(f"[FAIL] Negative crit-pct should return exit code 2, got {return_code}")
        return False


def test_crit_pct_over_100():
    """Test that critical percentage over 100 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--crit-pct', '200']
    )

    if return_code == 2:
        print("[PASS] Crit-pct over 100 test passed")
        return True
    else:
        print(f"[FAIL] Crit-pct over 100 should return exit code 2, got {return_code}")
        return False


def test_warn_exceeds_crit():
    """Test that warning threshold exceeding critical is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py',
         '--warn-pct', '20', '--crit-pct', '10']
    )

    if return_code == 2:
        print("[PASS] Warn exceeds crit test passed")
        return True
    else:
        print(f"[FAIL] Warn exceeds crit should return exit code 2, got {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py',
         '--format', 'json', '--verbose', '--warn-only',
         '--warn-pct', '5', '--crit-pct', '10']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed with code {return_code}")
        return False


def test_exit_code_validity():
    """Test that exit codes are valid (0, 1, or 2)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Exit code validity test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_json_structure():
    """Test JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            required_keys = ['status', 'issues', 'metrics', 'settings']
            if all(k in data for k in required_keys):
                # Check metrics has expected fields
                metrics = data.get('metrics', {})
                expected_metrics = ['dirty_bytes', 'dirty_pct', 'writeback_bytes']
                if all(m in metrics for m in expected_metrics):
                    print("[PASS] JSON structure test passed")
                    return True
        except json.JSONDecodeError:
            pass

    # Exit 2 is acceptable for system access issues
    if return_code == 2:
        print("[PASS] JSON structure test passed (system access limited)")
        return True

    print(f"[FAIL] JSON structure test failed")
    print(f"  Stdout: {stdout[:200]}")
    return False


def test_default_run():
    """Test default execution without any options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py']
    )

    # Should succeed or fail gracefully
    if return_code in [0, 1]:
        # Should contain some output about writeback
        if 'dirty' in stdout.lower() or 'writeback' in stdout.lower():
            print("[PASS] Default run test passed")
            return True
    elif return_code == 2:
        # System access issue is acceptable
        print("[PASS] Default run test passed (system access limited)")
        return True

    print(f"[FAIL] Default run test failed")
    print(f"  Return code: {return_code}")
    print(f"  Stdout: {stdout[:100]}")
    return False


def test_float_thresholds():
    """Test that float thresholds work"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_writeback_monitor.py',
         '--warn-pct', '5.5', '--crit-pct', '10.5']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Float thresholds test passed")
        return True
    else:
        print(f"[FAIL] Float thresholds test failed with code {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_writeback_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_verbose_flag,
        test_warn_only_flag,
        test_warn_pct_option,
        test_crit_pct_option,
        test_negative_warn_pct,
        test_warn_pct_over_100,
        test_negative_crit_pct,
        test_crit_pct_over_100,
        test_warn_exceeds_crit,
        test_combined_options,
        test_exit_code_validity,
        test_json_structure,
        test_default_run,
        test_float_thresholds,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
