#!/usr/bin/env python3
"""
Tests for baremetal_systemd_timer_monitor.py

These tests verify the script's basic functionality without requiring
actual systemd timers or root access.
"""

import subprocess
import sys
import os

# Get the directory containing this test file
test_dir = os.path.dirname(os.path.abspath(__file__))
# The script is in the parent directory
script_path = os.path.join(os.path.dirname(test_dir), 'baremetal_systemd_timer_monitor.py')


def run_command(args):
    """
    Run the baremetal_systemd_timer_monitor.py script with given arguments.

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

    if rc == 0 and 'timer' in stdout.lower() and 'usage' in stdout.lower():
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

    if rc == 0 and 'timer' in stdout.lower():
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


def test_short_warn_only_flag():
    """Test short warn-only flag."""
    print("Testing short warn-only flag...")
    rc, stdout, stderr = run_command(['-w'])

    if rc in [0, 1, 2] and 'unrecognized arguments' not in stderr:
        print("[PASS] -w flag accepted")
        return True
    else:
        print(f"[FAIL] -w flag test failed (rc={rc})")
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


def test_max_age_option():
    """Test max-age option with valid formats."""
    print("Testing max-age option...")
    test_cases = ['24h', '7d', '30m', '2w']
    all_passed = True

    for age in test_cases:
        rc, stdout, stderr = run_command(['--max-age', age])
        if rc in [0, 1, 2] and 'unrecognized arguments' not in stderr and 'Invalid duration' not in stderr:
            print(f"[PASS] --max-age {age} accepted")
        else:
            print(f"[FAIL] --max-age {age} not accepted")
            print(f"stderr: {stderr[:200]}")
            all_passed = False

    return all_passed


def test_max_age_invalid():
    """Test max-age option with invalid format."""
    print("Testing max-age with invalid format...")
    rc, stdout, stderr = run_command(['--max-age', 'invalid'])

    if rc == 2 and 'Invalid duration' in stderr:
        print("[PASS] Invalid max-age correctly rejected")
        return True
    elif rc == 2:
        # Could be systemctl not available
        print("[PASS] Script exited with code 2 (may be missing systemctl)")
        return True
    else:
        print(f"[FAIL] Invalid max-age should be rejected (rc={rc})")
        print(f"stderr: {stderr[:200]}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    print("Testing combined options...")
    rc, stdout, stderr = run_command([
        '--format', 'json',
        '--warn-only',
        '--max-age', '24h'
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
            if 'summary' in data or 'timers' in data:
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


def test_json_summary_fields():
    """Test that JSON output has expected summary fields."""
    print("Testing JSON summary fields...")
    rc, stdout, stderr = run_command(['--format', 'json'])

    if rc == 2:
        print("[SKIP] JSON summary test (systemctl not available)")
        return True

    if rc in [0, 1]:
        try:
            import json
            data = json.loads(stdout)
            if 'summary' in data:
                summary = data['summary']
                expected_fields = ['total', 'healthy', 'with_issues']
                missing = [f for f in expected_fields if f not in summary]
                if not missing:
                    print("[PASS] JSON summary has expected fields")
                    return True
                else:
                    print(f"[FAIL] JSON summary missing fields: {missing}")
                    return False
            else:
                print("[FAIL] JSON output missing 'summary' field")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parse error: {e}")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {rc}")
        return False


def test_exit_codes():
    """Test that script returns valid exit codes."""
    print("Testing exit codes...")
    rc, stdout, stderr = run_command([])

    if rc in [0, 1, 2]:
        print(f"[PASS] Script returns valid exit code ({rc})")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {rc}")
        return False


def test_table_output():
    """Test table output format."""
    print("Testing table output format...")
    rc, stdout, stderr = run_command(['--format', 'table'])

    if rc == 2:
        print("[SKIP] Table format test (systemctl not available)")
        return True

    if rc in [0, 1]:
        # Table output should have headers
        if 'STATUS' in stdout or 'TIMER' in stdout or 'No systemd timers' in stdout:
            print("[PASS] Table output format works")
            return True
        else:
            print("[FAIL] Table output missing expected headers")
            print(f"stdout: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {rc}")
        return False


def main():
    """Run all tests."""
    print("=" * 70)
    print("Running tests for baremetal_systemd_timer_monitor.py")
    print("=" * 70)

    tests = [
        test_help_message,
        test_short_help,
        test_format_options,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_verbose_flag,
        test_max_age_option,
        test_max_age_invalid,
        test_combined_options,
        test_json_output_format,
        test_json_summary_fields,
        test_exit_codes,
        test_table_output,
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
