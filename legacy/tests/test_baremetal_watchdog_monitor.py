#!/usr/bin/env python3
"""
Test script for baremetal_watchdog_monitor.py functionality.
Tests argument parsing and error handling without requiring actual watchdog hardware.
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
        [sys.executable, 'baremetal_watchdog_monitor.py', '--help']
    )

    if return_code == 0 and 'watchdog' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        print("  stdout: " + stdout[:200])
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout:
        print("[PASS] Help contains examples")
        return True
    else:
        print("[FAIL] Help should contain examples")
        return False


def test_help_describes_healthy_config():
    """Test that help describes healthy watchdog configuration"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--help']
    )

    if return_code == 0 and 'healthy watchdog' in stdout.lower():
        print("[PASS] Help describes healthy configuration")
        return True
    else:
        print("[FAIL] Help should describe healthy watchdog configuration")
        return False


def test_verbose_option():
    """Test that the -v/--verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '-v']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_warn_only_option():
    """Test that the -w/--warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '-w']
    )

    # Should not fail at argument parsing level (may exit 0 if no issues)
    if return_code in [0, 1]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_format_plain():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print("[FAIL] Plain format option test failed with return code: " + str(return_code))
        return False


def test_format_json():
    """Test that JSON format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        print("[PASS] JSON format option test passed")
        return True
    else:
        print("[FAIL] JSON format option test failed with return code: " + str(return_code))
        return False


def test_format_table():
    """Test that table format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        print("[PASS] Table format option test passed")
        return True
    else:
        print("[FAIL] Table format option test failed with return code: " + str(return_code))
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'invalid']
    )

    # Should fail with argument error (exit code 2)
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_watchdog_monitor.py',
        '-v',
        '--format', 'json'
    ])

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_unknown_option_rejected():
    """Test that unknown options are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--unknown-option']
    )

    if return_code == 2 and 'unrecognized arguments' in stderr:
        print("[PASS] Unknown option rejected test passed")
        return True
    else:
        print("[FAIL] Unknown option should be rejected")
        return False


def test_json_output_structure():
    """Test JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'json']
    )

    # Output should be valid JSON with expected fields
    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            required_fields = ['devices', 'modules', 'daemons', 'health', 'summary']
            if isinstance(data, dict) and all(f in data for f in required_fields):
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected fields")
                print("  Fields present: " + str(list(data.keys())))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON output is not valid JSON")
            print("  Error: " + str(e))
            print("  stdout: " + stdout[:200])
            return False
    else:
        print("[FAIL] JSON output structure test failed")
        return False


def test_json_health_fields():
    """Test that JSON health section has expected fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            health = data.get('health', {})
            required_health = ['status', 'issues', 'warnings', 'info']
            if all(f in health for f in required_health):
                print("[PASS] JSON health fields test passed")
                return True
            else:
                print("[FAIL] JSON health missing expected fields")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print("[FAIL] JSON health fields test failed")
        return False


def test_json_summary_fields():
    """Test that JSON summary has expected fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            required_summary = ['devices_found', 'modules_loaded', 'daemons_active', 'status']
            if all(f in summary for f in required_summary):
                print("[PASS] JSON summary fields test passed")
                return True
            else:
                print("[FAIL] JSON summary missing expected fields")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print("[FAIL] JSON summary fields test failed")
        return False


def test_json_devices_array():
    """Test that JSON output has devices array"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            if 'devices' in data and isinstance(data['devices'], list):
                print("[PASS] JSON devices array test passed")
                return True
            else:
                print("[FAIL] JSON output missing devices array")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print("[FAIL] JSON devices array test failed")
        return False


def test_json_uptime_present():
    """Test that JSON output includes uptime"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            if 'uptime' in data and 'seconds' in data['uptime']:
                print("[PASS] JSON uptime test passed")
                return True
            else:
                print("[FAIL] JSON output missing uptime")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print("[FAIL] JSON uptime test failed")
        return False


def test_plain_output_has_header():
    """Test that plain output has a header"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1] and 'Watchdog Timer Status Report' in stdout:
        print("[PASS] Plain output header test passed")
        return True
    else:
        print("[FAIL] Plain output should have header")
        return False


def test_plain_output_shows_uptime():
    """Test that plain output shows system uptime"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1] and 'Uptime:' in stdout:
        print("[PASS] Plain output uptime test passed")
        return True
    else:
        print("[FAIL] Plain output should show uptime")
        return False


def test_plain_output_shows_status():
    """Test that plain output shows overall status"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1] and 'Status:' in stdout:
        print("[PASS] Plain output status test passed")
        return True
    else:
        print("[FAIL] Plain output should show status")
        return False


def test_plain_output_shows_devices_section():
    """Test that plain output shows devices section"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1] and 'Watchdog Devices:' in stdout:
        print("[PASS] Plain output devices section test passed")
        return True
    else:
        print("[FAIL] Plain output should show devices section")
        return False


def test_plain_output_shows_daemons_section():
    """Test that plain output shows daemons section"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1] and 'Watchdog Daemons:' in stdout:
        print("[PASS] Plain output daemons section test passed")
        return True
    else:
        print("[FAIL] Plain output should show daemons section")
        return False


def test_table_output_has_columns():
    """Test that table output has column headers"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1] and 'Device' in stdout and 'State' in stdout:
        print("[PASS] Table output columns test passed")
        return True
    else:
        print("[FAIL] Table output should have column headers")
        return False


def test_exit_code_0_or_1():
    """Test that script exits with 0 (configured) or 1 (not configured/issues)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (returned {})".format(return_code))
        return True
    else:
        print("[FAIL] Exit code should be 0 or 1, got {}".format(return_code))
        return False


def test_health_status_valid():
    """Test that health status is one of expected values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_watchdog_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            status = data.get('health', {}).get('status', '')
            if status in ['healthy', 'warning', 'critical']:
                print("[PASS] Health status valid test passed (status: {})".format(status))
                return True
            else:
                print("[FAIL] Health status should be healthy/warning/critical, got: " + status)
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print("[FAIL] Health status valid test failed")
        return False


if __name__ == "__main__":
    print("Testing baremetal_watchdog_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_help_contains_examples,
        test_help_describes_healthy_config,
        test_verbose_option,
        test_warn_only_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_combined_options,
        test_unknown_option_rejected,
        test_json_output_structure,
        test_json_health_fields,
        test_json_summary_fields,
        test_json_devices_array,
        test_json_uptime_present,
        test_plain_output_has_header,
        test_plain_output_shows_uptime,
        test_plain_output_shows_status,
        test_plain_output_shows_devices_section,
        test_plain_output_shows_daemons_section,
        test_table_output_has_columns,
        test_exit_code_0_or_1,
        test_health_status_valid,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print()
    print("Test Results: {}/{} tests passed".format(passed, total))

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
