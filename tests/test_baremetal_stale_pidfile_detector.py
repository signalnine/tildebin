#!/usr/bin/env python3
"""
Test script for baremetal_stale_pidfile_detector.py functionality.
Tests argument parsing and error handling without requiring root access.
"""

import json
import os
import subprocess
import sys
import tempfile


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
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '--help']
    )

    if return_code == 0 and 'PID' in stdout and 'stale' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: {}".format(return_code))
        print("stdout: {}".format(stdout[:200]))
        return False


def test_verbose_option():
    """Test that the verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '-v', '-d', '/nonexistent']
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
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '--format', 'plain', '-d', '/nonexistent']
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
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '--format', 'json', '-d', '/nonexistent']
    )

    if return_code in [0, 1, 2]:
        if stdout.strip():
            try:
                data = json.loads(stdout)
                if 'summary' in data and 'has_issues' in data:
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
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '--format', 'table', '-d', '/nonexistent']
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
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '--warn-only', '-d', '/nonexistent']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_directories_option():
    """Test that the directories option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '-d', '/var/run', '/tmp']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Directories option test passed")
        return True
    else:
        print("[FAIL] Directories option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_recursive_option():
    """Test that the recursive option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '-r', '-d', '/nonexistent']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Recursive option test passed")
        return True
    else:
        print("[FAIL] Recursive option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_check_name_option():
    """Test that the check-name option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '--check-name', '-d', '/nonexistent']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Check-name option test passed")
        return True
    else:
        print("[FAIL] Check-name option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_min_age_option():
    """Test that the min-age option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '--min-age', '60', '-d', '/nonexistent']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Min-age option test passed")
        return True
    else:
        print("[FAIL] Min-age option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_combined_options():
    """Test that multiple options can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_stale_pidfile_detector.py',
        '-v',
        '--format', 'json',
        '-d', '/var/run', '/tmp',
        '-r',
        '--check-name',
        '--min-age', '30'
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
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '--help']
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
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '--format', 'json', '-d', '/nonexistent']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            expected_keys = ['pidfiles', 'summary', 'has_issues', 'timestamp']
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
        [sys.executable, 'baremetal_stale_pidfile_detector.py', '--format', 'json', '-d', '/nonexistent']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            expected_summary_keys = ['total', 'valid', 'stale', 'mismatch', 'invalid']
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


def test_stale_pidfile_detection():
    """Test detection of a stale PID file with a non-existent process."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a PID file with a very high PID that shouldn't exist
        pidfile = os.path.join(tmpdir, 'test_stale.pid')
        with open(pidfile, 'w') as f:
            f.write('999999999\n')

        return_code, stdout, stderr = run_command([
            sys.executable, 'baremetal_stale_pidfile_detector.py',
            '--format', 'json',
            '-d', tmpdir
        ])

        if return_code == 1:  # Should exit with 1 when stale files found
            try:
                data = json.loads(stdout)
                if data['summary']['stale'] >= 1:
                    print("[PASS] Stale PID file detection test passed")
                    return True
                else:
                    print("[FAIL] Stale file not detected")
                    return False
            except json.JSONDecodeError as e:
                print("[FAIL] JSON parsing failed: {}".format(e))
                return False
        else:
            print("[FAIL] Expected return code 1 for stale file, got: {}".format(return_code))
            return False


def test_valid_pidfile_detection():
    """Test that valid PID files (current process) are recognized."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a PID file with current process PID (should be valid)
        pidfile = os.path.join(tmpdir, 'test_valid.pid')
        with open(pidfile, 'w') as f:
            f.write('{}\n'.format(os.getpid()))

        return_code, stdout, stderr = run_command([
            sys.executable, 'baremetal_stale_pidfile_detector.py',
            '--format', 'json',
            '-d', tmpdir
        ])

        if return_code == 0:  # Should exit with 0 when no stale files
            try:
                data = json.loads(stdout)
                if data['summary']['valid'] >= 1 and data['summary']['stale'] == 0:
                    print("[PASS] Valid PID file detection test passed")
                    return True
                else:
                    print("[FAIL] Valid file not properly detected")
                    print("Data: {}".format(data))
                    return False
            except json.JSONDecodeError as e:
                print("[FAIL] JSON parsing failed: {}".format(e))
                return False
        else:
            print("[FAIL] Expected return code 0 for valid file, got: {}".format(return_code))
            print("stdout: {}".format(stdout))
            return False


def test_invalid_pidfile():
    """Test handling of invalid PID file contents."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a PID file with invalid content
        pidfile = os.path.join(tmpdir, 'test_invalid.pid')
        with open(pidfile, 'w') as f:
            f.write('not_a_pid\n')

        return_code, stdout, stderr = run_command([
            sys.executable, 'baremetal_stale_pidfile_detector.py',
            '--format', 'json',
            '-d', tmpdir
        ])

        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                if data['summary']['invalid'] >= 1:
                    print("[PASS] Invalid PID file handling test passed")
                    return True
                else:
                    print("[FAIL] Invalid file not properly detected")
                    return False
            except json.JSONDecodeError as e:
                print("[FAIL] JSON parsing failed: {}".format(e))
                return False
        else:
            print("[FAIL] Unexpected return code: {}".format(return_code))
            return False


def test_empty_directory():
    """Test behavior with empty directory (no PID files)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        return_code, stdout, stderr = run_command([
            sys.executable, 'baremetal_stale_pidfile_detector.py',
            '--format', 'json',
            '-d', tmpdir
        ])

        if return_code == 0:
            try:
                data = json.loads(stdout)
                if data['summary']['total'] == 0:
                    print("[PASS] Empty directory test passed")
                    return True
                else:
                    print("[FAIL] Expected 0 total files")
                    return False
            except json.JSONDecodeError as e:
                print("[FAIL] JSON parsing failed: {}".format(e))
                return False
        else:
            print("[FAIL] Unexpected return code: {}".format(return_code))
            return False


def test_nonexistent_directory():
    """Test behavior with nonexistent directory."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_stale_pidfile_detector.py',
        '--format', 'json',
        '-d', '/this/directory/does/not/exist/hopefully'
    ])

    if return_code == 0:
        try:
            data = json.loads(stdout)
            if data['summary']['total'] == 0:
                print("[PASS] Nonexistent directory test passed")
                return True
            else:
                print("[FAIL] Expected 0 total files for nonexistent dir")
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON parsing failed: {}".format(e))
            return False
    else:
        print("[FAIL] Unexpected return code: {}".format(return_code))
        return False


if __name__ == "__main__":
    print("Testing baremetal_stale_pidfile_detector.py...")
    print()

    tests = [
        test_help_message,
        test_verbose_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_warn_only_option,
        test_directories_option,
        test_recursive_option,
        test_check_name_option,
        test_min_age_option,
        test_combined_options,
        test_exit_code_documentation,
        test_json_output_structure,
        test_summary_fields,
        test_stale_pidfile_detection,
        test_valid_pidfile_detection,
        test_invalid_pidfile,
        test_empty_directory,
        test_nonexistent_directory,
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
