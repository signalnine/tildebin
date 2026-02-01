#!/usr/bin/env python3
"""
Test script for baremetal_systemd_service_monitor.py functionality.
Tests argument parsing and error handling without requiring root access.
"""

import json
import subprocess
import sys


def run_command(cmd_args):
    """Helper function to run a command and return result."""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=10)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '--help']
    )

    if return_code == 0 and 'systemd' in stdout and 'service' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: {}".format(return_code))
        print("stdout: {}".format(stdout[:200]))
        return False


def test_verbose_option():
    """Test that the verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '-v']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_plain():
    """Test that plain format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print("[FAIL] Plain format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_json():
    """Test that JSON format option is recognized and produces valid JSON."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '--format', 'json']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        # If we got output and systemctl is available, verify it's valid JSON
        if stdout.strip() and return_code != 2:
            try:
                data = json.loads(stdout)
                if 'system_state' in data and 'summary' in data:
                    print("[PASS] JSON format option test passed (valid JSON with expected fields)")
                    return True
                else:
                    print("[FAIL] JSON output missing expected fields")
                    return False
            except json.JSONDecodeError:
                print("[FAIL] JSON format test failed - invalid JSON output")
                print("Output: {}".format(stdout[:200]))
                return False
        print("[PASS] JSON format option test passed")
        return True
    else:
        print("[FAIL] JSON format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_table():
    """Test that table format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Table format option test passed")
        return True
    else:
        print("[FAIL] Table format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_invalid_format():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '--format', 'invalid']
    )

    # Should fail with argument error
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        print("return_code: {}, stderr: {}".format(return_code, stderr))
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_critical_services_option():
    """Test that the critical services option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '--critical', 'sshd,docker']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Critical services option test passed")
        return True
    else:
        print("[FAIL] Critical services option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_restart_threshold_option():
    """Test that the restart threshold option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '--restart-threshold', '5']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Restart threshold option test passed")
        return True
    else:
        print("[FAIL] Restart threshold option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_show_masked_option():
    """Test that the show-masked option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '--show-masked']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Show-masked option test passed")
        return True
    else:
        print("[FAIL] Show-masked option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_combined_options():
    """Test that multiple options can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_systemd_service_monitor.py',
        '-v',
        '--format', 'json',
        '--critical', 'sshd',
        '--restart-threshold', '10',
        '--show-masked'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_exit_code_documentation():
    """Test that exit codes are documented in help."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '--help']
    )

    if return_code == 0:
        # Check for exit code documentation
        if 'Exit codes' in stdout or 'exit code' in stdout.lower():
            print("[PASS] Exit code documentation test passed")
            return True
        else:
            print("[FAIL] Exit codes not documented in help")
            return False
    else:
        print("[FAIL] Could not check exit code documentation")
        return False


def test_json_output_structure():
    """Test that JSON output has the expected structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # systemctl not available - skip this test
        print("[SKIP] JSON structure test - systemctl not available")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            expected_keys = ['system_state', 'failed_units', 'critical_issues',
                           'restart_warnings', 'summary', 'timestamp']
            missing_keys = [k for k in expected_keys if k not in data]

            if not missing_keys:
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print("[FAIL] JSON output missing keys: {}".format(missing_keys))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON parsing failed: {}".format(e))
            return False
    else:
        print("[FAIL] Unexpected return code: {}".format(return_code))
        return False


def test_summary_fields():
    """Test that JSON summary has expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_service_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # systemctl not available - skip this test
        print("[SKIP] Summary fields test - systemctl not available")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            expected_summary_keys = ['failed_count', 'critical_issues_count',
                                    'restart_warnings_count', 'has_issues']
            missing_keys = [k for k in expected_summary_keys if k not in summary]

            if not missing_keys:
                print("[PASS] Summary fields test passed")
                return True
            else:
                print("[FAIL] Summary missing keys: {}".format(missing_keys))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON parsing failed: {}".format(e))
            return False
    else:
        print("[FAIL] Unexpected return code: {}".format(return_code))
        return False


if __name__ == "__main__":
    print("Testing baremetal_systemd_service_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_verbose_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_warn_only_option,
        test_critical_services_option,
        test_restart_threshold_option,
        test_show_masked_option,
        test_combined_options,
        test_exit_code_documentation,
        test_json_output_structure,
        test_summary_fields,
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
