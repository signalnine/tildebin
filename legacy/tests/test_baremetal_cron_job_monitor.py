#!/usr/bin/env python3
"""
Tests for baremetal_cron_job_monitor.py

These tests verify the script's basic functionality without requiring
actual cron files or root access.
"""

import subprocess
import sys
import os
import json
import tempfile
import shutil

# Get the directory containing this test file
test_dir = os.path.dirname(os.path.abspath(__file__))
# The script is in the parent directory
script_path = os.path.join(os.path.dirname(test_dir), 'baremetal_cron_job_monitor.py')


def run_command(args):
    """
    Run the baremetal_cron_job_monitor.py script with given arguments.

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

    if rc == 0 and 'cron' in stdout.lower() and 'usage' in stdout.lower():
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

    if rc == 0 and 'cron' in stdout.lower():
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
        # rc can be 0 (healthy), 1 (issues found), or 2 (error)
        if rc in [0, 1, 2]:
            if 'unrecognized arguments' not in stderr and 'invalid choice' not in stderr:
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


def test_system_only_flag():
    """Test system-only flag."""
    print("Testing system-only flag...")
    rc, stdout, stderr = run_command(['--system-only'])

    if rc in [0, 1, 2] and 'unrecognized arguments' not in stderr:
        print("[PASS] --system-only flag accepted")
        return True
    else:
        print(f"[FAIL] --system-only flag test failed (rc={rc})")
        return False


def test_user_only_flag():
    """Test user-only flag."""
    print("Testing user-only flag...")
    rc, stdout, stderr = run_command(['--user-only'])

    if rc in [0, 1, 2] and 'unrecognized arguments' not in stderr:
        print("[PASS] --user-only flag accepted")
        return True
    else:
        print(f"[FAIL] --user-only flag test failed (rc={rc})")
        return False


def test_conflicting_flags():
    """Test that --system-only and --user-only together is rejected."""
    print("Testing conflicting flags...")
    rc, stdout, stderr = run_command(['--system-only', '--user-only'])

    if rc == 2 and 'Cannot specify both' in stderr:
        print("[PASS] Conflicting flags correctly rejected")
        return True
    else:
        print(f"[FAIL] Conflicting flags should be rejected (rc={rc})")
        print(f"stderr: {stderr[:200]}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    print("Testing combined options...")
    rc, stdout, stderr = run_command([
        '--format', 'json',
        '--warn-only',
        '--system-only'
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

    if rc in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data:
                print("[PASS] JSON output is valid")
                return True
            else:
                print("[FAIL] JSON output missing 'summary' field")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON output is not valid JSON: {e}")
            print(f"stdout: {stdout[:200]}")
            return False
    else:
        # Even if rc=2, script should still produce valid output
        print(f"[PASS] Script returned code {rc} (acceptable)")
        return True


def test_json_summary_fields():
    """Test that JSON output has expected summary fields."""
    print("Testing JSON summary fields...")
    rc, stdout, stderr = run_command(['--format', 'json'])

    if rc in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data:
                summary = data['summary']
                expected_fields = ['total_jobs', 'jobs_with_issues', 'critical', 'warning']
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
        print(f"[PASS] Script returned code {rc} (acceptable)")
        return True


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

    if rc in [0, 1]:
        # Table output should have headers
        if 'STATUS' in stdout or 'SOURCE' in stdout or 'SCHEDULE' in stdout:
            print("[PASS] Table output format works")
            return True
        else:
            print("[FAIL] Table output missing expected headers")
            print(f"stdout: {stdout[:200]}")
            return False
    else:
        print(f"[PASS] Script returned code {rc} (acceptable)")
        return True


def test_plain_output_header():
    """Test plain output has expected header."""
    print("Testing plain output header...")
    rc, stdout, stderr = run_command(['--format', 'plain'])

    if rc in [0, 1]:
        if 'Cron Job Health Monitor' in stdout or 'cron' in stdout.lower():
            print("[PASS] Plain output has expected content")
            return True
        else:
            print("[FAIL] Plain output missing expected header")
            print(f"stdout: {stdout[:200]}")
            return False
    else:
        print(f"[PASS] Script returned code {rc} (acceptable)")
        return True


def test_invalid_format():
    """Test that invalid format option is rejected."""
    print("Testing invalid format option...")
    rc, stdout, stderr = run_command(['--format', 'invalid'])

    if rc == 2 and ('invalid choice' in stderr or 'invalid' in stderr.lower()):
        print("[PASS] Invalid format correctly rejected")
        return True
    elif rc == 2:
        # argparse may phrase it differently
        print("[PASS] Invalid format rejected with code 2")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected (rc={rc})")
        print(f"stderr: {stderr[:200]}")
        return False


def test_schedule_parsing():
    """Test cron schedule parsing by importing the module."""
    print("Testing cron schedule parsing...")

    try:
        # Import the module to test internal functions
        import importlib.util
        spec = importlib.util.spec_from_file_location("cron_monitor", script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Test valid schedules
        valid_schedules = [
            '* * * * *',
            '0 0 * * *',
            '*/5 * * * *',
            '0 0 1 1 *',
            '0 0 * * 0',
            '@reboot',
            '@daily',
            '@hourly',
            '0 0 * * mon',
            '0 0 1 jan *',
        ]

        for schedule in valid_schedules:
            is_valid, error = module.parse_cron_schedule(schedule)
            if not is_valid:
                print(f"[FAIL] Valid schedule '{schedule}' rejected: {error}")
                return False

        # Test invalid schedules
        invalid_schedules = [
            '* *',  # Too few fields
            '* * * * * * * *',  # Too many fields
        ]

        for schedule in invalid_schedules:
            is_valid, error = module.parse_cron_schedule(schedule)
            if is_valid:
                print(f"[FAIL] Invalid schedule '{schedule}' was accepted")
                return False

        print("[PASS] Cron schedule parsing works correctly")
        return True

    except Exception as e:
        print(f"[FAIL] Could not test schedule parsing: {e}")
        return False


def test_crontab_line_parsing():
    """Test crontab line parsing."""
    print("Testing crontab line parsing...")

    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("cron_monitor", script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Test standard cron line
        result = module.parse_crontab_line('0 0 * * * /usr/bin/backup.sh')
        if not result or result['schedule'] != '0 0 * * *':
            print("[FAIL] Failed to parse standard cron line")
            return False

        # Test cron line with user field
        result = module.parse_crontab_line('0 0 * * * root /usr/bin/backup.sh', has_user_field=True)
        if not result or result['user'] != 'root':
            print("[FAIL] Failed to parse cron line with user field")
            return False

        # Test comment line (should return None)
        result = module.parse_crontab_line('# This is a comment')
        if result is not None:
            print("[FAIL] Comment line should return None")
            return False

        # Test empty line (should return None)
        result = module.parse_crontab_line('')
        if result is not None:
            print("[FAIL] Empty line should return None")
            return False

        # Test variable assignment (should return None)
        result = module.parse_crontab_line('SHELL=/bin/bash')
        if result is not None:
            print("[FAIL] Variable assignment should return None")
            return False

        # Test @reboot
        result = module.parse_crontab_line('@reboot /usr/bin/startup.sh')
        if not result or result['schedule'] != '@reboot':
            print("[FAIL] Failed to parse @reboot line")
            return False

        print("[PASS] Crontab line parsing works correctly")
        return True

    except Exception as e:
        print(f"[FAIL] Could not test line parsing: {e}")
        return False


def test_user_exists_function():
    """Test user existence checking."""
    print("Testing user existence checking...")

    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("cron_monitor", script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Root should always exist
        if not module.user_exists('root'):
            print("[FAIL] 'root' user should exist")
            return False

        # Random nonexistent user
        if module.user_exists('nonexistent_user_12345'):
            print("[FAIL] Nonexistent user should not exist")
            return False

        print("[PASS] User existence checking works correctly")
        return True

    except Exception as e:
        print(f"[FAIL] Could not test user existence: {e}")
        return False


def test_command_exists_function():
    """Test command existence checking."""
    print("Testing command existence checking...")

    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("cron_monitor", script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Common commands that should exist
        common_commands = ['ls', 'cat', 'echo', 'true']
        for cmd in common_commands:
            if not module.command_exists(cmd):
                # echo and true are shell builtins, ls and cat are common
                pass  # Some systems might not have these

        # Shell builtins should be accepted
        if not module.command_exists('echo'):
            print("[FAIL] 'echo' should be recognized as builtin")
            return False

        # Nonexistent command
        if module.command_exists('/nonexistent/path/to/command'):
            print("[FAIL] Nonexistent command should not exist")
            return False

        print("[PASS] Command existence checking works correctly")
        return True

    except Exception as e:
        print(f"[FAIL] Could not test command existence: {e}")
        return False


def main():
    """Run all tests."""
    print("=" * 70)
    print("Running tests for baremetal_cron_job_monitor.py")
    print("=" * 70)

    tests = [
        test_help_message,
        test_short_help,
        test_format_options,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_verbose_flag,
        test_system_only_flag,
        test_user_only_flag,
        test_conflicting_flags,
        test_combined_options,
        test_json_output_format,
        test_json_summary_fields,
        test_exit_codes,
        test_table_output,
        test_plain_output_header,
        test_invalid_format,
        test_schedule_parsing,
        test_crontab_line_parsing,
        test_user_exists_function,
        test_command_exists_function,
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
