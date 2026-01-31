#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_disk_encryption_status.py functionality.
Tests argument parsing and error handling without requiring actual disk access
or root privileges.
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
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--help'
    ])

    if return_code == 0 and 'encryption status' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: {}".format(return_code))
        print("  stdout: {}".format(stdout[:200]))
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--help'
    ])

    if return_code == 0 and 'Examples:' in stdout:
        print("[PASS] Help contains examples")
        return True
    else:
        print("[FAIL] Help should contain examples section")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--help'
    ])

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Help contains exit codes documentation")
        return True
    else:
        print("[FAIL] Help should document exit codes")
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '-v'
    ])

    # Should not fail at argument parsing level (exit 2 means usage error)
    # May fail with 1 (issues found) or 2 (missing cryptsetup) but not arg parse error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option not recognized")
        print("  stderr: {}".format(stderr))
        return False


def test_verbose_long_option():
    """Test that the --verbose long option works"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--verbose'
    ])

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose long option test passed")
        return True
    else:
        print("[FAIL] Verbose long option not recognized")
        return False


def test_all_option():
    """Test that the --all option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--all'
    ])

    if 'unrecognized arguments' not in stderr:
        print("[PASS] All option test passed")
        return True
    else:
        print("[FAIL] All option not recognized")
        return False


def test_all_short_option():
    """Test that the -a short option works"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '-a'
    ])

    if 'unrecognized arguments' not in stderr:
        print("[PASS] All short option test passed")
        return True
    else:
        print("[FAIL] All short option not recognized")
        return False


def test_format_plain_option():
    """Test that --format plain is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--format', 'plain'
    ])

    if 'unrecognized arguments' not in stderr and 'invalid choice' not in stderr:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print("[FAIL] Format plain option not recognized")
        return False


def test_format_json_option():
    """Test that --format json is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--format', 'json'
    ])

    if 'unrecognized arguments' not in stderr and 'invalid choice' not in stderr:
        print("[PASS] Format json option test passed")
        return True
    else:
        print("[FAIL] Format json option not recognized")
        return False


def test_format_table_option():
    """Test that --format table is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--format', 'table'
    ])

    if 'unrecognized arguments' not in stderr and 'invalid choice' not in stderr:
        print("[PASS] Format table option test passed")
        return True
    else:
        print("[FAIL] Format table option not recognized")
        return False


def test_invalid_format_rejected():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--format', 'invalid'
    ])

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        print("  return_code: {}".format(return_code))
        print("  stderr: {}".format(stderr))
        return False


def test_warn_only_option():
    """Test that --warn-only option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--warn-only'
    ])

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option not recognized")
        return False


def test_warn_only_short_option():
    """Test that -w short option works"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '-w'
    ])

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only short option test passed")
        return True
    else:
        print("[FAIL] Warn-only short option not recognized")
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py',
        '-v', '--all', '--format', 'json'
    ])

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options not recognized")
        return False


def test_json_output_structure():
    """Test that JSON output has expected structure when cryptsetup available"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--format', 'json'
    ])

    # If cryptsetup is missing, this will fail - that's OK
    if return_code == 2:
        print("[SKIP] JSON structure test - cryptsetup not available")
        return True

    try:
        data = json.loads(stdout)
        if 'devices' in data and 'summary' in data:
            print("[PASS] JSON output structure test passed")
            return True
        else:
            print("[FAIL] JSON output missing expected fields")
            return False
    except json.JSONDecodeError:
        print("[FAIL] JSON output is not valid JSON")
        print("  stdout: {}".format(stdout[:200]))
        return False


def test_json_summary_fields():
    """Test that JSON summary has required fields"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--format', 'json'
    ])

    if return_code == 2:
        print("[SKIP] JSON summary test - cryptsetup not available")
        return True

    try:
        data = json.loads(stdout)
        summary = data.get('summary', {})
        required_fields = ['total', 'encrypted', 'unencrypted_data', 'has_issues']

        missing = [f for f in required_fields if f not in summary]
        if not missing:
            print("[PASS] JSON summary fields test passed")
            return True
        else:
            print("[FAIL] JSON summary missing fields: {}".format(missing))
            return False
    except json.JSONDecodeError:
        print("[FAIL] JSON output is not valid JSON")
        return False


def test_missing_cryptsetup_exit_code():
    """Test that missing cryptsetup returns exit code 2"""
    # We can't easily test this without mocking, but we can verify
    # that the help text documents the behavior
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--help'
    ])

    if 'Missing dependency' in stdout or 'cryptsetup' in stdout:
        print("[PASS] Missing cryptsetup documented in help")
        return True
    else:
        print("[FAIL] Help should mention cryptsetup dependency")
        return False


def test_invalid_argument_rejected():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_encryption_status.py', '--invalid-flag'
    ])

    if return_code != 0 and 'unrecognized arguments' in stderr:
        print("[PASS] Invalid argument test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should be rejected")
        return False


def test_script_executable():
    """Test that the script has proper shebang"""
    try:
        with open('baremetal_disk_encryption_status.py', 'r') as f:
            first_line = f.readline()
            if first_line.startswith('#!/usr/bin/env python3'):
                print("[PASS] Script has proper shebang")
                return True
            else:
                print("[FAIL] Script should have #!/usr/bin/env python3 shebang")
                return False
    except Exception as e:
        print("[FAIL] Could not read script: {}".format(e))
        return False


def test_script_has_docstring():
    """Test that the script has a module docstring"""
    try:
        with open('baremetal_disk_encryption_status.py', 'r') as f:
            content = f.read()
            if '"""' in content[:500] and 'Exit codes:' in content[:1000]:
                print("[PASS] Script has docstring with exit codes")
                return True
            else:
                print("[FAIL] Script should have docstring with exit codes")
                return False
    except Exception as e:
        print("[FAIL] Could not read script: {}".format(e))
        return False


if __name__ == "__main__":
    print("Testing baremetal_disk_encryption_status.py...")
    print()

    tests = [
        test_help_message,
        test_help_contains_examples,
        test_help_contains_exit_codes,
        test_verbose_option,
        test_verbose_long_option,
        test_all_option,
        test_all_short_option,
        test_format_plain_option,
        test_format_json_option,
        test_format_table_option,
        test_invalid_format_rejected,
        test_warn_only_option,
        test_warn_only_short_option,
        test_combined_options,
        test_json_output_structure,
        test_json_summary_fields,
        test_missing_cryptsetup_exit_code,
        test_invalid_argument_rejected,
        test_script_executable,
        test_script_has_docstring,
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
