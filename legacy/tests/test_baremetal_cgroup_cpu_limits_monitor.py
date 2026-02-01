#!/usr/bin/env python3
"""
Test script for baremetal_cgroup_cpu_limits_monitor.py functionality.
Tests argument parsing and error handling without requiring cgroup v2.
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
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--help']
    )

    if return_code == 0 and 'cpu' in stdout.lower() and 'cgroup' in stdout.lower():
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
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_throttle_warn_threshold():
    """Test that invalid throttle warn threshold values are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--throttle-warn', '150']
    )

    if return_code == 2:
        print("[PASS] Invalid throttle warn threshold (>100) test passed")
        return True
    else:
        print(f"[FAIL] Invalid throttle warn threshold should return exit code 2, got {return_code}")
        return False


def test_invalid_throttle_warn_threshold_negative():
    """Test that negative throttle warn threshold values are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--throttle-warn', '-10']
    )

    if return_code == 2:
        print("[PASS] Invalid throttle warn threshold (negative) test passed")
        return True
    else:
        print(f"[FAIL] Negative throttle warn threshold should return exit code 2, got {return_code}")
        return False


def test_invalid_throttle_crit_threshold():
    """Test that invalid throttle crit threshold values are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--throttle-crit', '200']
    )

    if return_code == 2:
        print("[PASS] Invalid throttle crit threshold (>100) test passed")
        return True
    else:
        print(f"[FAIL] Invalid throttle crit threshold should return exit code 2, got {return_code}")
        return False


def test_warn_greater_than_crit():
    """Test that warn >= crit is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py',
         '--throttle-warn', '30', '--throttle-crit', '20']
    )

    if return_code == 2:
        print("[PASS] Warn >= crit validation test passed")
        return True
    else:
        print(f"[FAIL] Warn >= crit should return exit code 2, got {return_code}")
        return False


def test_invalid_low_weight():
    """Test that invalid low-weight values are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--low-weight', '0']
    )

    if return_code == 2:
        print("[PASS] Invalid low-weight threshold (0) test passed")
        return True
    else:
        print(f"[FAIL] Invalid low-weight should return exit code 2, got {return_code}")
        return False


def test_invalid_low_weight_too_high():
    """Test that low-weight > 10000 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--low-weight', '10001']
    )

    if return_code == 2:
        print("[PASS] Invalid low-weight threshold (>10000) test passed")
        return True
    else:
        print(f"[FAIL] Invalid low-weight >10000 should return exit code 2, got {return_code}")
        return False


def test_format_option():
    """Test that format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--format', 'json']
    )

    # Should not fail with "invalid choice" error
    if 'invalid choice' not in stderr:
        print("[PASS] Format option test passed")
        return True
    else:
        print("[FAIL] Format option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing (if cgroup v2 is available)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--format', 'json']
    )

    # If no cgroup v2, expected to fail with exit code 2
    if return_code == 2:
        if 'cgroup' in stderr.lower():
            print("[PASS] JSON output format test passed (no cgroup v2 available)")
            return True
        else:
            print(f"[FAIL] Expected cgroup-related error, got: {stderr[:100]}")
            return False

    # If it succeeds, validate JSON
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Validate expected fields
            if 'cgroups' in data and 'issues' in data and 'summary' in data:
                print("[PASS] JSON output format test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected fields")
                print(f"  Data keys: {list(data.keys())}")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON parsing failed")
            print(f"  Output: {stdout[:100]}")
            return False

    print(f"[FAIL] Unexpected return code: {return_code}")
    print(f"  Stderr: {stderr[:100]}")
    return False


def test_table_format():
    """Test table format option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--format', 'table']
    )

    # Should either work or fail with no cgroup v2
    if return_code == 2:
        if 'cgroup' in stderr.lower():
            print("[PASS] Table format test passed (no cgroup v2 available)")
            return True

    # If succeeds, check for table headers
    if return_code in [0, 1]:
        if 'Cgroup' in stdout or 'Limit' in stdout or 'Weight' in stdout:
            print("[PASS] Table format test passed")
            return True
        else:
            print("[FAIL] Table format missing expected headers")
            print(f"  Output: {stdout[:200]}")
            return False

    print(f"[FAIL] Table format test failed with code {return_code}")
    return False


def test_verbose_flag():
    """Test verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--verbose']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_warn_only_flag():
    """Test warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--warn-only']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py',
         '--format', 'json', '--verbose', '--warn-only',
         '--throttle-warn', '5', '--throttle-crit', '15']
    )

    # Should not fail due to option conflicts
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:100]}")
        return False


def test_exit_code_validity():
    """Test that exit codes are valid (0, 1, or 2)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py']
    )

    # Valid exit codes: 0 (no issues), 1 (issues), 2 (no cgroup v2/usage error)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_throttle_warn_option():
    """Test that --throttle-warn option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--throttle-warn', '8']
    )

    if 'unrecognized' not in stderr and 'invalid' not in stderr.lower():
        print("[PASS] Throttle warn option test passed")
        return True
    else:
        print("[FAIL] Throttle warn option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_throttle_crit_option():
    """Test that --throttle-crit option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--throttle-crit', '30']
    )

    if 'unrecognized' not in stderr and 'invalid' not in stderr.lower():
        print("[PASS] Throttle crit option test passed")
        return True
    else:
        print("[FAIL] Throttle crit option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_cgroup_option():
    """Test that --cgroup option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--cgroup', 'system.slice']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Cgroup option test passed")
        return True
    else:
        print("[FAIL] Cgroup option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_top_option():
    """Test that --top option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--top', '20']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Top option test passed")
        return True
    else:
        print("[FAIL] Top option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_low_weight_option():
    """Test that --low-weight option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py', '--low-weight', '25']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Low-weight option test passed")
        return True
    else:
        print("[FAIL] Low-weight option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_nonexistent_cgroup():
    """Test handling of nonexistent cgroup path"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_cpu_limits_monitor.py',
         '--cgroup', 'nonexistent_cgroup_path_12345']
    )

    # Should fail gracefully with exit code 2
    if return_code == 2:
        print("[PASS] Nonexistent cgroup test passed")
        return True
    else:
        # If cgroup v2 not available, that's also fine
        if 'cgroup' in stderr.lower():
            print("[PASS] Nonexistent cgroup test passed (no cgroup v2)")
            return True
        print(f"[FAIL] Nonexistent cgroup should return exit code 2, got {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_cgroup_cpu_limits_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_invalid_throttle_warn_threshold,
        test_invalid_throttle_warn_threshold_negative,
        test_invalid_throttle_crit_threshold,
        test_warn_greater_than_crit,
        test_invalid_low_weight,
        test_invalid_low_weight_too_high,
        test_format_option,
        test_json_output_format,
        test_table_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_combined_options,
        test_exit_code_validity,
        test_throttle_warn_option,
        test_throttle_crit_option,
        test_cgroup_option,
        test_top_option,
        test_low_weight_option,
        test_nonexistent_cgroup,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
