#!/usr/bin/env python3
"""
Test script for baremetal_cgroup_pressure_monitor.py functionality.
Tests argument parsing and error handling without requiring cgroup v2/PSI.
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
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--help']
    )

    if return_code == 0 and 'PSI' in stdout and 'pressure' in stdout.lower():
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
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_warn_threshold():
    """Test that invalid warn threshold values are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--warn', '150']
    )

    if return_code == 2:
        print("[PASS] Invalid warn threshold (>100) test passed")
        return True
    else:
        print(f"[FAIL] Invalid warn threshold should return exit code 2, got {return_code}")
        return False


def test_invalid_warn_threshold_negative():
    """Test that negative warn threshold values are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--warn', '-10']
    )

    if return_code == 2:
        print("[PASS] Invalid warn threshold (negative) test passed")
        return True
    else:
        print(f"[FAIL] Negative warn threshold should return exit code 2, got {return_code}")
        return False


def test_invalid_crit_threshold():
    """Test that invalid crit threshold values are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--crit', '200']
    )

    if return_code == 2:
        print("[PASS] Invalid crit threshold (>100) test passed")
        return True
    else:
        print(f"[FAIL] Invalid crit threshold should return exit code 2, got {return_code}")
        return False


def test_warn_greater_than_crit():
    """Test that warn >= crit is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--warn', '50', '--crit', '25']
    )

    if return_code == 2:
        print("[PASS] Warn >= crit validation test passed")
        return True
    else:
        print(f"[FAIL] Warn >= crit should return exit code 2, got {return_code}")
        return False


def test_format_option():
    """Test that format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--format', 'json']
    )

    # Should either succeed (0), find issues (1), or fail with no cgroup v2/PSI (2)
    # Should NOT fail with "invalid choice" error
    if 'invalid choice' not in stderr:
        print("[PASS] Format option test passed")
        return True
    else:
        print("[FAIL] Format option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing (if PSI is available)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--format', 'json']
    )

    # If no cgroup v2/PSI, expected to fail with exit code 2
    if return_code == 2:
        if 'cgroup' in stderr.lower() or 'psi' in stderr.lower():
            print("[PASS] JSON output format test passed (no cgroup v2/PSI available)")
            return True
        else:
            print(f"[FAIL] Expected cgroup/PSI-related error, got: {stderr[:100]}")
            return False

    # If it succeeds, validate JSON
    if return_code in [0, 1]:  # 0 = no issues, 1 = issues found
        try:
            data = json.loads(stdout)
            # Validate expected fields
            if 'system_pressure' in data and 'issues' in data and 'summary' in data:
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
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--format', 'table']
    )

    # Should either work or fail with no cgroup v2/PSI
    if return_code == 2:
        if 'cgroup' in stderr.lower() or 'psi' in stderr.lower():
            print("[PASS] Table format test passed (no cgroup v2/PSI available)")
            return True

    # If succeeds, check for table headers
    if return_code in [0, 1]:
        if 'Resource' in stdout or 'Level' in stdout:
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
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--verbose']
    )

    # Should not fail due to unrecognized option
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
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--warn-only']
    )

    # Should not fail due to unrecognized option
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
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py',
         '--format', 'json', '--verbose', '--warn-only',
         '--warn', '5', '--crit', '20']
    )

    # Should not fail due to option conflicts
    if return_code in [0, 1, 2]:  # Any valid exit code
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
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py']
    )

    # Valid exit codes: 0 (no issues), 1 (issues), 2 (no cgroup v2/PSI/usage error)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_warn_threshold_option():
    """Test that --warn option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--warn', '15']
    )

    # Should not fail due to unrecognized option or invalid value
    if 'unrecognized' not in stderr and 'invalid' not in stderr.lower():
        print("[PASS] Warn threshold option test passed")
        return True
    else:
        print("[FAIL] Warn threshold option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_crit_threshold_option():
    """Test that --crit option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--crit', '30']
    )

    # Should not fail due to unrecognized option or invalid value
    if 'unrecognized' not in stderr and 'invalid' not in stderr.lower():
        print("[PASS] Crit threshold option test passed")
        return True
    else:
        print("[FAIL] Crit threshold option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_cgroup_option():
    """Test that --cgroup option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cgroup_pressure_monitor.py', '--cgroup', '/sys/fs/cgroup']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Cgroup option test passed")
        return True
    else:
        print("[FAIL] Cgroup option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_cgroup_pressure_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_invalid_warn_threshold,
        test_invalid_warn_threshold_negative,
        test_invalid_crit_threshold,
        test_warn_greater_than_crit,
        test_format_option,
        test_json_output_format,
        test_table_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_combined_options,
        test_exit_code_validity,
        test_warn_threshold_option,
        test_crit_threshold_option,
        test_cgroup_option,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
