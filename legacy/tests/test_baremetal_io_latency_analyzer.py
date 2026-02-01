#!/usr/bin/env python3
"""
Test script for baremetal_io_latency_analyzer.py functionality.
Tests argument parsing and error handling without requiring specific hardware.
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
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--help']
    )

    if return_code == 0 and 'latency' in stdout.lower() and 'I/O' in stdout:
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
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_interval_zero():
    """Test that zero interval is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--interval', '0']
    )

    if return_code == 2:
        print("[PASS] Zero interval test passed")
        return True
    else:
        print(f"[FAIL] Zero interval should return exit code 2, got {return_code}")
        return False


def test_invalid_interval_negative():
    """Test that negative interval is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--interval', '-1']
    )

    if return_code == 2:
        print("[PASS] Negative interval test passed")
        return True
    else:
        print(f"[FAIL] Negative interval should return exit code 2, got {return_code}")
        return False


def test_invalid_interval_too_large():
    """Test that interval > 60 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--interval', '120']
    )

    if return_code == 2:
        print("[PASS] Large interval test passed")
        return True
    else:
        print(f"[FAIL] Interval > 60 should return exit code 2, got {return_code}")
        return False


def test_invalid_warn_latency():
    """Test that zero warn-latency is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--warn-latency', '0']
    )

    if return_code == 2:
        print("[PASS] Zero warn-latency test passed")
        return True
    else:
        print(f"[FAIL] Zero warn-latency should return exit code 2, got {return_code}")
        return False


def test_invalid_crit_latency():
    """Test that zero crit-latency is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--crit-latency', '0']
    )

    if return_code == 2:
        print("[PASS] Zero crit-latency test passed")
        return True
    else:
        print(f"[FAIL] Zero crit-latency should return exit code 2, got {return_code}")
        return False


def test_warn_greater_than_crit():
    """Test that warn-latency >= crit-latency is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py',
         '--warn-latency', '100', '--crit-latency', '50']
    )

    if return_code == 2:
        print("[PASS] Warn >= crit validation test passed")
        return True
    else:
        print(f"[FAIL] Warn >= crit should return exit code 2, got {return_code}")
        return False


def test_invalid_warn_util():
    """Test that warn-util outside 0-100 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--warn-util', '150']
    )

    if return_code == 2:
        print("[PASS] Invalid warn-util test passed")
        return True
    else:
        print(f"[FAIL] warn-util > 100 should return exit code 2, got {return_code}")
        return False


def test_format_option():
    """Test that format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--format', 'json', '--interval', '0.1']
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
    """Test JSON output format parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--format', 'json', '--interval', '0.1']
    )

    # If no devices found, expected to fail with exit code 2
    if return_code == 2:
        if 'device' in stderr.lower() or 'diskstats' in stderr.lower():
            print("[PASS] JSON output format test passed (no devices or access issue)")
            return True
        else:
            print(f"[FAIL] Expected device/diskstats-related error, got: {stderr[:100]}")
            return False

    # If it succeeds, validate JSON
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Validate expected fields
            if 'devices' in data and 'issues' in data and 'summary' in data:
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
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--format', 'table', '--interval', '0.1']
    )

    # Should either work or fail with no devices
    if return_code == 2:
        if 'device' in stderr.lower() or 'diskstats' in stderr.lower():
            print("[PASS] Table format test passed (no devices or access issue)")
            return True

    # If succeeds, check for table headers
    if return_code in [0, 1]:
        if 'Device' in stdout or 'Avg Lat' in stdout:
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
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--verbose', '--interval', '0.1']
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
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--warn-only', '--interval', '0.1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_device_option():
    """Test --device option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--device', 'sda', '--interval', '0.1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Device option test passed")
        return True
    else:
        print("[FAIL] Device option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py',
         '--format', 'json', '--verbose', '--warn-only',
         '--interval', '0.1', '--warn-latency', '20', '--crit-latency', '50']
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
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--interval', '0.1']
    )

    # Valid exit codes: 0 (no issues), 1 (issues), 2 (no devices/access/usage error)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_interval_option():
    """Test that --interval option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py', '--interval', '0.5']
    )

    # Should not fail due to unrecognized option or invalid value
    if 'unrecognized' not in stderr and 'invalid' not in stderr.lower():
        print("[PASS] Interval option test passed")
        return True
    else:
        print("[FAIL] Interval option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_warn_latency_option():
    """Test that --warn-latency option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py',
         '--warn-latency', '30', '--interval', '0.1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Warn-latency option test passed")
        return True
    else:
        print("[FAIL] Warn-latency option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_crit_latency_option():
    """Test that --crit-latency option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py',
         '--crit-latency', '150', '--interval', '0.1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Crit-latency option test passed")
        return True
    else:
        print("[FAIL] Crit-latency option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_warn_util_option():
    """Test that --warn-util option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_io_latency_analyzer.py',
         '--warn-util', '90', '--interval', '0.1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Warn-util option test passed")
        return True
    else:
        print("[FAIL] Warn-util option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_io_latency_analyzer.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_invalid_interval_zero,
        test_invalid_interval_negative,
        test_invalid_interval_too_large,
        test_invalid_warn_latency,
        test_invalid_crit_latency,
        test_warn_greater_than_crit,
        test_invalid_warn_util,
        test_format_option,
        test_json_output_format,
        test_table_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_device_option,
        test_combined_options,
        test_exit_code_validity,
        test_interval_option,
        test_warn_latency_option,
        test_crit_latency_option,
        test_warn_util_option,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
