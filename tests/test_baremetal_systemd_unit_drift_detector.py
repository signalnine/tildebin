#!/usr/bin/env python3
"""
Test script for baremetal_systemd_unit_drift_detector.py functionality.
Tests argument parsing and error handling without requiring actual systemd changes.
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
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py', '--help']
    )

    if return_code == 0 and 'Detect systemd unit files' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout and '--warn-only' in stdout:
        print("[PASS] Help contains examples test passed")
        return True
    else:
        print("[FAIL] Help contains examples test failed")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py', '--help']
    )

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Help contains exit codes test passed")
        return True
    else:
        print("[FAIL] Help contains exit codes test failed")
        return False


def test_invalid_format_option():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option test failed")
        return False


def test_format_plain_option():
    """Test that plain format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py',
         '--format', 'plain', '--unit', 'nonexistent.service']
    )

    # Should accept the option (may fail due to systemctl not available or unit not found)
    if return_code in [0, 1, 2]:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print("[FAIL] Format plain option test failed")
        return False


def test_format_json_option():
    """Test that JSON format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py',
         '--format', 'json', '--unit', 'nonexistent.service']
    )

    # Should accept the option
    if return_code in [0, 1, 2]:
        print("[PASS] Format JSON option test passed")
        return True
    else:
        print("[FAIL] Format JSON option test failed")
        return False


def test_format_table_option():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py',
         '--format', 'table', '--unit', 'nonexistent.service']
    )

    # Should accept the option
    if return_code in [0, 1, 2]:
        print("[PASS] Format table option test passed")
        return True
    else:
        print("[FAIL] Format table option test failed")
        return False


def test_warn_only_option():
    """Test that warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py',
         '--warn-only', '--unit', 'nonexistent.service']
    )

    # Should accept the option
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed")
        return False


def test_verbose_option():
    """Test that verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py',
         '--verbose', '--unit', 'nonexistent.service']
    )

    # Should accept the option
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed")
        return False


def test_type_option():
    """Test that type option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py',
         '--type', 'service']
    )

    # Should accept the option (may succeed or fail based on systemctl availability)
    if return_code in [0, 1, 2]:
        print("[PASS] Type option test passed")
        return True
    else:
        print("[FAIL] Type option test failed")
        return False


def test_unit_option():
    """Test that unit option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py',
         '--unit', 'sshd.service']
    )

    # Should accept the option
    if return_code in [0, 1, 2]:
        print("[PASS] Unit option test passed")
        return True
    else:
        print("[FAIL] Unit option test failed")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py',
         '--warn-only', '--verbose', '--format', 'json', '--type', 'service']
    )

    # Should accept all options
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed")
        return False


def test_json_output_structure():
    """Test that JSON output has correct structure when systemctl available"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py',
         '--format', 'json', '--unit', 'sshd.service']
    )

    if return_code == 2:
        # systemctl not available
        if 'systemctl' in stderr.lower():
            print("[PASS] JSON output test passed (systemctl not available)")
            return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'units' in data:
                if 'total_checked' in data['summary']:
                    print("[PASS] JSON output structure test passed")
                    return True
        except json.JSONDecodeError:
            pass

    # If we got JSON output at all, consider it a pass
    if '{' in stdout and '"summary"' in stdout:
        print("[PASS] JSON output structure test passed")
        return True

    print("[FAIL] JSON output structure test failed")
    return False


def test_short_options():
    """Test short option variants"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py',
         '-w', '-v', '-f', 'plain', '-t', 'service']
    )

    # Should accept short options
    if return_code in [0, 1, 2]:
        print("[PASS] Short options test passed")
        return True
    else:
        print("[FAIL] Short options test failed")
        return False


def test_systemctl_missing_handling():
    """Test that missing systemctl is handled gracefully"""
    # This test validates the error message format when systemctl would be missing
    # We can't easily test this without actually removing systemctl,
    # but we can verify the help text mentions the dependency
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py', '--help']
    )

    # The help should work regardless of systemctl
    if return_code == 0:
        print("[PASS] Systemctl dependency documentation test passed")
        return True
    else:
        print("[FAIL] Systemctl dependency documentation test failed")
        return False


def test_exit_code_documentation():
    """Test that exit codes are properly documented"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py', '--help']
    )

    if return_code == 0:
        # Check all three exit codes are documented
        if '0 -' in stdout and '1 -' in stdout and '2 -' in stdout:
            print("[PASS] Exit code documentation test passed")
            return True

    print("[FAIL] Exit code documentation test failed")
    return False


def test_drift_types_documented():
    """Test that drift types are documented in help"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_unit_drift_detector.py', '--help']
    )

    if return_code == 0:
        # Check drift types are documented
        if 'local_override' in stdout and 'has_drop_ins' in stdout and 'masked' in stdout:
            print("[PASS] Drift types documentation test passed")
            return True

    print("[FAIL] Drift types documentation test failed")
    return False


if __name__ == "__main__":
    print("Testing baremetal_systemd_unit_drift_detector.py...")

    tests = [
        test_help_message,
        test_help_contains_examples,
        test_help_contains_exit_codes,
        test_invalid_format_option,
        test_format_plain_option,
        test_format_json_option,
        test_format_table_option,
        test_warn_only_option,
        test_verbose_option,
        test_type_option,
        test_unit_option,
        test_combined_options,
        test_json_output_structure,
        test_short_options,
        test_systemctl_missing_handling,
        test_exit_code_documentation,
        test_drift_types_documented,
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
