#!/usr/bin/env python3
"""
Tests for systemd_service_monitor.py

These tests verify the script's basic functionality without requiring
actual systemd services or root access.
"""

import subprocess
import sys
import os

# Get the directory containing this test file
test_dir = os.path.dirname(os.path.abspath(__file__))
# The script is in the parent directory
script_path = os.path.join(os.path.dirname(test_dir), 'systemd_service_monitor.py')


def run_command(args):
    """
    Run the systemd_service_monitor.py script with given arguments.

    Args:
        args: List of command-line arguments

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    cmd = [sys.executable, script_path] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def test_help_message():
    """Test that help message is displayed correctly."""
    print("Testing help message...")
    rc, stdout, stderr = run_command(['--help'])

    if rc == 0 and 'systemd' in stdout.lower() and 'usage' in stdout.lower():
        print("[PASS] Help message displayed correctly")
        return True
    else:
        print(f"[FAIL] Help message test failed (rc={rc})")
        print(f"stdout: {stdout[:200]}")
        print(f"stderr: {stderr[:200]}")
        return False


def test_short_help():
    """Test short help flag."""
    print("Testing short help flag...")
    rc, stdout, stderr = run_command(['-h'])

    if rc == 0 and 'systemd' in stdout.lower():
        print("[PASS] Short help flag works")
        return True
    else:
        print(f"[FAIL] Short help flag test failed (rc={rc})")
        return False


def test_format_options():
    """Test that all format options are accepted."""
    print("Testing format options...")
    formats = ['plain', 'json', 'table']
    all_passed = True

    for fmt in formats:
        rc, stdout, stderr = run_command(['--format', fmt])
        # rc can be 0, 1 (problems found), or 2 (systemctl not available)
        # We just want to make sure the argument is recognized
        if rc in [0, 1, 2]:
            if rc == 2 and 'systemctl' in stderr:
                # systemctl not available, but argument was accepted
                print(f"[PASS] Format '{fmt}' argument accepted (systemctl not available)")
            elif 'unrecognized arguments' not in stderr and 'invalid choice' not in stderr:
                print(f"[PASS] Format '{fmt}' works")
            else:
                print(f"[FAIL] Format '{fmt}' not recognized")
                print(f"stderr: {stderr[:200]}")
                all_passed = False
        else:
            print(f"[FAIL] Format '{fmt}' failed with unexpected rc={rc}")
            all_passed = False

    return all_passed


def test_warn_only_flag():
    """Test warn-only flag."""
    print("Testing warn-only flag...")
    rc, stdout, stderr = run_command(['--warn-only'])

    # Should accept the argument (rc 0, 1, or 2)
    if rc in [0, 1, 2] and 'unrecognized arguments' not in stderr:
        print("[PASS] --warn-only flag accepted")
        return True
    else:
        print(f"[FAIL] --warn-only flag test failed (rc={rc})")
        print(f"stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test verbose flag."""
    print("Testing verbose flag...")
    rc, stdout, stderr = run_command(['-v'])

    if rc in [0, 1, 2] and 'unrecognized arguments' not in stderr:
        print("[PASS] -v flag accepted")
        return True
    else:
        print(f"[FAIL] -v flag test failed (rc={rc})")
        return False


def test_type_filter():
    """Test type filter option."""
    print("Testing type filter...")
    rc, stdout, stderr = run_command(['--type', 'service'])

    if rc in [0, 1, 2] and 'unrecognized arguments' not in stderr:
        print("[PASS] --type filter accepted")
        return True
    else:
        print(f"[FAIL] --type filter test failed (rc={rc})")
        return False


def test_pattern_filter():
    """Test pattern filter option."""
    print("Testing pattern filter...")
    rc, stdout, stderr = run_command(['--filter', 'ssh*'])

    if rc in [0, 1, 2] and 'unrecognized arguments' not in stderr:
        print("[PASS] --filter option accepted")
        return True
    else:
        print(f"[FAIL] --filter option test failed (rc={rc})")
        return False


def test_combined_options():
    """Test combining multiple options."""
    print("Testing combined options...")
    rc, stdout, stderr = run_command([
        '--format', 'json',
        '--warn-only',
        '--type', 'service'
    ])

    if rc in [0, 1, 2] and 'unrecognized arguments' not in stderr:
        print("[PASS] Combined options work")
        return True
    else:
        print(f"[FAIL] Combined options test failed (rc={rc})")
        print(f"stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test that JSON output is valid JSON."""
    print("Testing JSON output format...")
    rc, stdout, stderr = run_command(['--format', 'json'])

    if rc == 2:
        # systemctl not available, skip this test
        print("[SKIP] JSON format test (systemctl not available)")
        return True

    if rc in [0, 1]:
        try:
            import json
            data = json.loads(stdout)
            if 'summary' in data or 'units' in data or len(data) == 0:
                print("[PASS] JSON output is valid")
                return True
            else:
                print("[FAIL] JSON output missing expected fields")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON output is not valid JSON: {e}")
            print(f"stdout: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {rc}")
        return False


def test_exit_code_on_systemctl_missing():
    """Test that script exits with code 2 when systemctl is not available."""
    print("Testing exit code when systemctl is missing...")
    # This test can only verify behavior when systemctl is actually missing
    # On systems with systemctl, we just verify the script runs
    rc, stdout, stderr = run_command([])

    if rc in [0, 1, 2]:
        print(f"[PASS] Script returns valid exit code ({rc})")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {rc}")
        return False


def main():
    """Run all tests."""
    print("=" * 70)
    print("Running tests for systemd_service_monitor.py")
    print("=" * 70)

    tests = [
        test_help_message,
        test_short_help,
        test_format_options,
        test_warn_only_flag,
        test_verbose_flag,
        test_type_filter,
        test_pattern_filter,
        test_combined_options,
        test_json_output_format,
        test_exit_code_on_systemctl_missing,
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"[ERROR] Test {test.__name__} raised exception: {e}")
            results.append(False)
        print()

    # Summary
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Test Results: {passed}/{total} passed")
    print("=" * 70)

    # Exit with appropriate code
    sys.exit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
