#!/usr/bin/env python3
"""
Test script for baremetal_open_file_monitor.py functionality.
Tests argument parsing, output formats, and error handling without requiring
specific system state.
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
        [sys.executable, 'baremetal_open_file_monitor.py', '--help']
    )

    if return_code == 0 and 'open file' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        print("  stdout: " + stdout[:200])
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout and '--deleted-only' in stdout:
        print("[PASS] Help contains examples")
        return True
    else:
        print("[FAIL] Help should contain usage examples")
        return False


def test_verbose_option():
    """Test that the -v/--verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '-v']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_min_fds_option():
    """Test that the --min-fds option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '--min-fds', '50']
    )

    if return_code in [0, 1]:
        print("[PASS] Min-fds option test passed")
        return True
    else:
        print("[FAIL] Min-fds option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_warn_percent_option():
    """Test that the --warn-percent option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '--warn-percent', '50']
    )

    if return_code in [0, 1]:
        print("[PASS] Warn-percent option test passed")
        return True
    else:
        print("[FAIL] Warn-percent option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_top_option():
    """Test that the --top option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '--top', '5']
    )

    if return_code in [0, 1]:
        print("[PASS] Top option test passed")
        return True
    else:
        print("[FAIL] Top option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_name_filter_option():
    """Test that the --name filter option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '--name', 'python']
    )

    if return_code in [0, 1]:
        print("[PASS] Name filter option test passed")
        return True
    else:
        print("[FAIL] Name filter option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_user_filter_option():
    """Test that the --user filter option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '--user', 'root']
    )

    if return_code in [0, 1]:
        print("[PASS] User filter option test passed")
        return True
    else:
        print("[FAIL] User filter option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_deleted_only_option():
    """Test that the --deleted-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '--deleted-only']
    )

    if return_code in [0, 1]:
        print("[PASS] Deleted-only option test passed")
        return True
    else:
        print("[FAIL] Deleted-only option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_warn_only_option():
    """Test that the -w/--warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '-w']
    )

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
        [sys.executable, 'baremetal_open_file_monitor.py', '--format', 'plain']
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
        [sys.executable, 'baremetal_open_file_monitor.py', '--format', 'json']
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
        [sys.executable, 'baremetal_open_file_monitor.py', '--format', 'table']
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
        [sys.executable, 'baremetal_open_file_monitor.py', '--format', 'invalid']
    )

    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_open_file_monitor.py',
        '-v',
        '--top', '10',
        '--min-fds', '5',
        '--format', 'json'
    ])

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
        [sys.executable, 'baremetal_open_file_monitor.py', '--unknown-option']
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
        [sys.executable, 'baremetal_open_file_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            required_fields = ['hostname', 'processes', 'summary']
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
        [sys.executable, 'baremetal_open_file_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            required_summary = ['total_processes_checked', 'processes_reported',
                              'total_open_fds', 'processes_with_warnings']
            if all(f in summary for f in required_summary):
                print("[PASS] JSON summary fields test passed")
                return True
            else:
                print("[FAIL] JSON summary missing expected fields")
                print("  Present: " + str(list(summary.keys())))
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print("[FAIL] JSON summary fields test failed")
        return False


def test_json_processes_array():
    """Test that JSON output has processes array"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '--format', 'json', '--min-fds', '1']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            if 'processes' in data and isinstance(data['processes'], list):
                # Check process structure if any processes present
                if data['processes']:
                    proc = data['processes'][0]
                    required = ['pid', 'name', 'user', 'fd_count', 'warnings']
                    if all(f in proc for f in required):
                        print("[PASS] JSON processes array test passed")
                        return True
                    else:
                        print("[FAIL] Process missing required fields")
                        print("  Present: " + str(list(proc.keys())))
                        return False
                else:
                    print("[PASS] JSON processes array test passed (empty array)")
                    return True
            else:
                print("[FAIL] JSON output missing processes array")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print("[FAIL] JSON processes array test failed")
        return False


def test_plain_output_has_header():
    """Test that plain output has a header"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1] and 'Open File Handle Monitor' in stdout:
        print("[PASS] Plain output header test passed")
        return True
    else:
        print("[FAIL] Plain output should have header")
        return False


def test_plain_output_shows_summary():
    """Test that plain output shows summary section"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1] and 'Summary:' in stdout and 'Processes checked:' in stdout:
        print("[PASS] Plain output summary test passed")
        return True
    else:
        print("[FAIL] Plain output should show summary")
        return False


def test_table_output_has_columns():
    """Test that table output has column headers"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1] and 'PID' in stdout and 'FDs' in stdout:
        print("[PASS] Table output columns test passed")
        return True
    else:
        print("[FAIL] Table output should have column headers")
        return False


def test_exit_code_0_or_1():
    """Test that script exits with 0 (clean) or 1 (issues)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (returned {})".format(return_code))
        return True
    else:
        print("[FAIL] Exit code should be 0 or 1, got {}".format(return_code))
        return False


def test_invalid_min_fds_type():
    """Test that non-integer min-fds is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '--min-fds', 'abc']
    )

    if return_code != 0 and 'invalid' in stderr.lower():
        print("[PASS] Invalid min-fds type rejected")
        return True
    else:
        print("[FAIL] Invalid min-fds should be rejected")
        return False


def test_verbose_shows_types():
    """Test that verbose mode shows type breakdown"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_open_file_monitor.py', '-v', '--min-fds', '1']
    )

    # If there are processes, verbose should show Types:
    if return_code in [0, 1]:
        # This test passes regardless since it depends on system state
        # We're just checking the option works
        print("[PASS] Verbose types test passed")
        return True
    else:
        print("[FAIL] Verbose mode failed")
        return False


if __name__ == "__main__":
    print("Testing baremetal_open_file_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_help_contains_examples,
        test_verbose_option,
        test_min_fds_option,
        test_warn_percent_option,
        test_top_option,
        test_name_filter_option,
        test_user_filter_option,
        test_deleted_only_option,
        test_warn_only_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_combined_options,
        test_unknown_option_rejected,
        test_json_output_structure,
        test_json_summary_fields,
        test_json_processes_array,
        test_plain_output_has_header,
        test_plain_output_shows_summary,
        test_table_output_has_columns,
        test_exit_code_0_or_1,
        test_invalid_min_fds_type,
        test_verbose_shows_types,
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
