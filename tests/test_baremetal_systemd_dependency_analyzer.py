#!/usr/bin/env python3
"""
Test script for baremetal_systemd_dependency_analyzer.py functionality.
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
        stdout, stderr = proc.communicate(timeout=30)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--help']
    )

    if return_code == 0 and 'dependency' in stdout.lower() and 'systemd' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: {}".format(return_code))
        print("stdout: {}".format(stdout[:200]))
        return False


def test_verbose_option():
    """Test that the verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '-v']
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
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--format', 'plain']
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
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--format', 'json']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        # If we got output and systemctl is available, verify it's valid JSON
        if stdout.strip() and return_code != 2:
            try:
                data = json.loads(stdout)
                if 'summary' in data and 'units' in data:
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
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--format', 'table']
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
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_unit_option():
    """Test that the unit option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--unit', 'sshd.service']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Unit option test passed")
        return True
    else:
        print("[FAIL] Unit option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_type_option():
    """Test that the type option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--type', 'service']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Type option test passed")
        return True
    else:
        print("[FAIL] Type option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_all_option():
    """Test that the all option is recognized with type filter to limit scope."""
    # Use --type timer to limit scope and avoid timeout
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--all', '--type', 'timer', '--format', 'json']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] All option test passed")
        return True
    else:
        print("[FAIL] All option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_check_depth_option():
    """Test that the check-depth option is recognized with specific unit to avoid timeout."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--check-depth', '--unit', 'systemd-journald.service']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Check-depth option test passed")
        return True
    else:
        print("[FAIL] Check-depth option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_max_depth_warn_option():
    """Test that the max-depth-warn option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--max-depth-warn', '5']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Max-depth-warn option test passed")
        return True
    else:
        print("[FAIL] Max-depth-warn option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_combined_options():
    """Test that multiple options can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_systemd_dependency_analyzer.py',
        '-v',
        '--format', 'json',
        '--unit', 'sshd.service',
        '--check-depth',
        '--max-depth-warn', '10'
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
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--help']
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
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--format', 'json']
    )

    if return_code == 2:
        # systemctl not available - skip this test
        print("[SKIP] JSON structure test - systemctl not available")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            expected_keys = ['summary', 'units']
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
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--format', 'json']
    )

    if return_code == 2:
        # systemctl not available - skip this test
        print("[SKIP] Summary fields test - systemctl not available")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            expected_summary_keys = ['total_units', 'units_with_issues', 'error_count', 'warning_count']
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


def test_unit_info_structure():
    """Test that each unit in JSON output has expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_dependency_analyzer.py', '--format', 'json',
         '--unit', 'systemd-journald.service']
    )

    if return_code == 2:
        # systemctl not available - skip this test
        print("[SKIP] Unit info structure test - systemctl not available")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            units = data.get('units', [])

            if not units:
                print("[PASS] Unit info structure test passed (no units to check)")
                return True

            unit = units[0]
            expected_keys = ['unit', 'state', 'issues']
            missing_keys = [k for k in expected_keys if k not in unit]

            if not missing_keys:
                # Also check state structure
                state = unit.get('state', {})
                state_keys = ['load_state', 'active_state', 'sub_state']
                missing_state_keys = [k for k in state_keys if k not in state]
                if not missing_state_keys:
                    print("[PASS] Unit info structure test passed")
                    return True
                else:
                    print("[FAIL] Unit state missing keys: {}".format(missing_state_keys))
                    return False
            else:
                print("[FAIL] Unit info missing keys: {}".format(missing_keys))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON parsing failed: {}".format(e))
            return False
    else:
        print("[FAIL] Unexpected return code: {}".format(return_code))
        return False


def test_short_option_aliases():
    """Test that short option aliases work."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_systemd_dependency_analyzer.py',
        '-u', 'sshd.service',
        '-t', 'service',
        '-w',
        '-v'
    ])

    # -u and -t together might conflict, but each individually should work
    if return_code in [0, 1, 2]:
        print("[PASS] Short option aliases test passed")
        return True
    else:
        print("[FAIL] Short option aliases test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


if __name__ == "__main__":
    print("Testing baremetal_systemd_dependency_analyzer.py...")
    print()

    tests = [
        test_help_message,
        test_verbose_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_warn_only_option,
        test_unit_option,
        test_type_option,
        test_all_option,
        test_check_depth_option,
        test_max_depth_warn_option,
        test_combined_options,
        test_exit_code_documentation,
        test_json_output_structure,
        test_summary_fields,
        test_unit_info_structure,
        test_short_option_aliases,
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
