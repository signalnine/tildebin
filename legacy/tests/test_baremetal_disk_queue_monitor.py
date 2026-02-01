#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_disk_queue_monitor.py functionality.
Tests argument parsing and error handling without requiring specific hardware.
"""

import subprocess
import sys
import json
import os


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
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '--help']
    )

    if return_code == 0 and 'queue' in stdout.lower() and 'disk' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_format_option_plain():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '--format', 'plain']
    )

    # Should succeed (0), have warnings (1), or fail due to no devices (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print("[FAIL] Format plain option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_format_option_json():
    """Test that JSON format option produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1, 2]:
        try:
            data = json.loads(stdout)
            # Should be a dict with expected keys or error message
            if isinstance(data, dict):
                if 'devices' in data or 'error' in data:
                    print("[PASS] Format JSON option test passed")
                    return True
                else:
                    print("[FAIL] Format JSON option test failed - missing expected keys")
                    return False
            else:
                print("[FAIL] Format JSON option test failed - expected dict")
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] Format JSON option test failed - invalid JSON output")
            print("Error: " + str(e))
            print("stdout: " + stdout[:200])
            return False
    else:
        print("[FAIL] Format JSON option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_format_option_table():
    """Test that table format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        # Table output should have header or error message
        if 'Device' in stdout or 'No block devices' in stdout or 'No issues' in stdout or 'Error' in stderr:
            print("[PASS] Format table option test passed")
            return True
        else:
            print("[FAIL] Format table option test failed - unexpected output")
            return False
    else:
        print("[FAIL] Format table option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '--format', 'invalid']
    )

    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '-w']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_warn_threshold_option():
    """Test that the warn threshold option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '--warn', '8']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn threshold option test passed")
        return True
    else:
        print("[FAIL] Warn threshold option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_crit_threshold_option():
    """Test that the crit threshold option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '--crit', '64']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Crit threshold option test passed")
        return True
    else:
        print("[FAIL] Crit threshold option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_invalid_thresholds():
    """Test that warn >= crit thresholds are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '--warn', '32', '--crit', '16']
    )

    if return_code == 2:
        print("[PASS] Invalid thresholds test passed")
        return True
    else:
        print("[FAIL] Invalid thresholds test failed - should have rejected warn >= crit")
        return False


def test_samples_option():
    """Test that the samples option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '--samples', '3']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Samples option test passed")
        return True
    else:
        print("[FAIL] Samples option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_interval_option():
    """Test that the interval option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '--interval', '0.1']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Interval option test passed")
        return True
    else:
        print("[FAIL] Interval option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_queue_monitor.py',
        '-v',
        '-w',
        '--warn', '8',
        '--crit', '32',
        '--samples', '3',
        '--format', 'plain'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_json_structure():
    """Test that JSON output has correct structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1, 2]:
        try:
            data = json.loads(stdout)

            # If error, just check it's valid JSON
            if 'error' in data:
                print("[PASS] JSON structure test passed (no devices)")
                return True

            # Check expected keys
            if 'devices' in data and 'summary' in data:
                summary = data['summary']
                if all(k in summary for k in ['total_devices', 'critical', 'warning', 'ok']):
                    print("[PASS] JSON structure test passed")
                    return True
                else:
                    print("[FAIL] JSON structure test failed - summary missing keys")
                    return False
            else:
                print("[FAIL] JSON structure test failed - missing devices/summary")
                return False

        except json.JSONDecodeError:
            print("[FAIL] JSON structure test failed - invalid JSON")
            return False
    else:
        print("[FAIL] JSON structure test failed with return code: " + str(return_code))
        return False


def test_unknown_option():
    """Test that unknown options are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_queue_monitor.py', '--unknown-option']
    )

    if return_code != 0:
        print("[PASS] Unknown option test passed")
        return True
    else:
        print("[FAIL] Unknown option test failed - should have rejected unknown option")
        return False


def test_quick_execution():
    """Test that script executes quickly with minimal samples"""
    import time
    start = time.time()

    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_queue_monitor.py',
        '--samples', '2',
        '--interval', '0.1',
        '--format', 'json'
    ])

    elapsed = time.time() - start

    # Should complete in under 5 seconds even with sampling
    if elapsed < 5 and return_code in [0, 1, 2]:
        print("[PASS] Quick execution test passed (%.2fs)" % elapsed)
        return True
    else:
        print("[FAIL] Quick execution test failed - took %.2fs" % elapsed)
        return False


def test_real_devices():
    """Test with real block devices if available"""
    # Check if /sys/block exists and has devices
    if not os.path.exists('/sys/block'):
        print("[SKIP] Real devices test skipped - /sys/block not found")
        return True

    devices = [d for d in os.listdir('/sys/block')
               if not d.startswith('loop') and not d.startswith('ram')]

    if not devices:
        print("[SKIP] Real devices test skipped - no block devices found")
        return True

    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_queue_monitor.py',
        '--format', 'json',
        '--samples', '2'
    ])

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'devices' in data and len(data['devices']) > 0:
                print("[PASS] Real devices test passed (%d devices)" % len(data['devices']))
                return True
        except json.JSONDecodeError:
            pass

    # May fail with exit 2 if devices present but not readable
    if return_code == 2:
        print("[PASS] Real devices test passed (permission issue expected)")
        return True

    print("[FAIL] Real devices test failed")
    return False


if __name__ == "__main__":
    print("Testing baremetal_disk_queue_monitor.py...")

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_option,
        test_warn_only_option,
        test_warn_threshold_option,
        test_crit_threshold_option,
        test_invalid_thresholds,
        test_samples_option,
        test_interval_option,
        test_combined_options,
        test_json_structure,
        test_unknown_option,
        test_quick_execution,
        test_real_devices,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print("\nTest Results: " + str(passed) + "/" + str(total) + " tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
