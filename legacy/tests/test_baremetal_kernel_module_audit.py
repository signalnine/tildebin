#!/usr/bin/env python3
"""
Test script for baremetal_kernel_module_audit.py functionality.
Tests argument parsing and error handling without requiring specific kernel modules.
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
        [sys.executable, 'baremetal_kernel_module_audit.py', '--help']
    )

    if return_code == 0 and 'kernel modules' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        print("  stdout: " + stdout[:200])
        return False


def test_help_contains_flags_documentation():
    """Test that help message documents module flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py', '--help']
    )

    if return_code == 0 and 'proprietary' in stdout and 'unsigned' in stdout:
        print("[PASS] Help contains flags documentation")
        return True
    else:
        print("[FAIL] Help should document module flags")
        return False


def test_verbose_option():
    """Test that the -v/--verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py', '-v']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_all_option():
    """Test that the -a/--all option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py', '-a']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] All option test passed")
        return True
    else:
        print("[FAIL] All option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_warn_only_option():
    """Test that the -w/--warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py', '-w']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_no_signature_check_option():
    """Test that the --no-signature-check option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py', '--no-signature-check']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] No-signature-check option test passed")
        return True
    else:
        print("[FAIL] No-signature-check option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_format_plain():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py', '--format', 'plain']
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
        [sys.executable, 'baremetal_kernel_module_audit.py', '--format', 'json']
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
        [sys.executable, 'baremetal_kernel_module_audit.py', '--format', 'table']
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
        [sys.executable, 'baremetal_kernel_module_audit.py', '--format', 'invalid']
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
        sys.executable, 'baremetal_kernel_module_audit.py',
        '-v',
        '-a',
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
        [sys.executable, 'baremetal_kernel_module_audit.py', '--unknown-option']
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
        [sys.executable, 'baremetal_kernel_module_audit.py', '--format', 'json']
    )

    # Output should be valid JSON with expected fields
    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            required_fields = ['kernel_version', 'taint_value', 'modules', 'summary']
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


def test_json_summary_fields():
    """Test that JSON summary has expected fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            required_summary = ['total', 'unsigned', 'out_of_tree', 'proprietary']
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


def test_json_modules_array():
    """Test that JSON output has modules array"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py', '--format', 'json', '-a']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            if 'modules' in data and isinstance(data['modules'], list):
                # Check module structure if any modules present
                if data['modules']:
                    module = data['modules'][0]
                    required = ['name', 'size', 'flags', 'issues']
                    if all(f in module for f in required):
                        print("[PASS] JSON modules array test passed")
                        return True
                    else:
                        print("[FAIL] Module missing required fields")
                        return False
                else:
                    print("[PASS] JSON modules array test passed (empty array)")
                    return True
            else:
                print("[FAIL] JSON output missing modules array")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print("[FAIL] JSON modules array test failed")
        return False


def test_plain_output_has_header():
    """Test that plain output has a header"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py', '--format', 'plain']
    )

    if return_code in [0, 1] and 'Kernel Module Audit Report' in stdout:
        print("[PASS] Plain output header test passed")
        return True
    else:
        print("[FAIL] Plain output should have header")
        return False


def test_plain_output_shows_kernel_version():
    """Test that plain output shows kernel version"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py', '--format', 'plain']
    )

    if return_code in [0, 1] and 'Kernel Version:' in stdout:
        print("[PASS] Plain output kernel version test passed")
        return True
    else:
        print("[FAIL] Plain output should show kernel version")
        return False


def test_plain_output_shows_taint_status():
    """Test that plain output shows taint status"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py', '--format', 'plain']
    )

    if return_code in [0, 1] and 'Kernel Taint:' in stdout:
        print("[PASS] Plain output taint status test passed")
        return True
    else:
        print("[FAIL] Plain output should show taint status")
        return False


def test_table_output_has_columns():
    """Test that table output has column headers"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py', '--format', 'table', '-a']
    )

    if return_code in [0, 1] and 'Module' in stdout and 'Size' in stdout:
        print("[PASS] Table output columns test passed")
        return True
    else:
        print("[FAIL] Table output should have column headers")
        return False


def test_exit_code_0_or_1():
    """Test that script exits with 0 (clean) or 1 (issues)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_module_audit.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (returned {})".format(return_code))
        return True
    else:
        print("[FAIL] Exit code should be 0 or 1, got {}".format(return_code))
        return False


if __name__ == "__main__":
    print("Testing baremetal_kernel_module_audit.py...")
    print()

    tests = [
        test_help_message,
        test_help_contains_flags_documentation,
        test_verbose_option,
        test_all_option,
        test_warn_only_option,
        test_no_signature_check_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_combined_options,
        test_unknown_option_rejected,
        test_json_output_structure,
        test_json_summary_fields,
        test_json_modules_array,
        test_plain_output_has_header,
        test_plain_output_shows_kernel_version,
        test_plain_output_shows_taint_status,
        test_table_output_has_columns,
        test_exit_code_0_or_1,
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
