#!/usr/bin/env python3
"""
Test script for baremetal_process_priority_monitor.py functionality.
Tests argument parsing and output formats without requiring root privileges
or specific system state.
"""

import subprocess
import sys
import json


def run_command(cmd_args):
    """Helper function to run a command and return result."""
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
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py', '--help']
    )

    if return_code == 0 and 'priority' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py']
    )

    # Should succeed (exit 0 or 1 depending on system state)
    if return_code in [0, 1] and 'Process Priority Monitor' in stdout:
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['summary', 'processes']
        if not all(key in data for key in required_keys):
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify summary structure
        summary = data['summary']
        expected_summary_keys = ['total_analyzed', 'elevated_nice_count',
                                  'degraded_nice_count', 'realtime_io_count',
                                  'idle_io_count', 'total_issues']
        if not all(key in summary for key in expected_summary_keys):
            print("[FAIL] JSON summary missing required keys")
            print(f"  Summary keys: {list(summary.keys())}")
            return False

        # Verify processes is a list
        if not isinstance(data['processes'], list):
            print("[FAIL] JSON 'processes' should be an array")
            return False

        print("[PASS] JSON output format test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and 'PROCESS PRIORITY REPORT' in stdout:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode includes additional information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py', '--verbose', '--all']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on system state)
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py']
    )

    # Exit code should be 0 (no issues) or 1 (issues found), never 2 for normal runs
    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_all_option():
    """Test --all option to include all processes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py', '--all', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # With --all, we should see more processes than without
        if 'processes' not in data:
            print("[FAIL] JSON output missing 'processes' key")
            return False

        print("[PASS] All processes option test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_user_filter():
    """Test --user filter option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py',
         '--user', 'root', '--all', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Verify all returned processes are owned by root
        for proc in data.get('processes', []):
            if proc.get('user') and proc.get('user') != 'root':
                print(f"[FAIL] Found process not owned by root: {proc}")
                return False

        print("[PASS] User filter test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_comm_filter():
    """Test --comm filter option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py',
         '--comm', 'python', '--all', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Verify all returned processes match the comm filter
        for proc in data.get('processes', []):
            if 'python' not in proc.get('comm', '').lower():
                print(f"[FAIL] Found process not matching filter: {proc['comm']}")
                return False

        print("[PASS] Comm filter test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_format_option_values():
    """Test all valid format option values."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_process_priority_monitor.py', '--format', fmt]
        )

        if return_code not in [0, 1]:
            print(f"[FAIL] Format '{fmt}' returned error code {return_code}")
            return False

    print("[PASS] All format options test passed")
    return True


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py',
         '--format', 'json', '--verbose', '--all']
    )

    try:
        data = json.loads(stdout)
        if return_code in [0, 1] and 'summary' in data:
            print("[PASS] Combined options test passed")
            return True
        else:
            print(f"[FAIL] Combined options test failed")
            return False
    except json.JSONDecodeError:
        print("[FAIL] Combined options JSON parsing failed")
        return False


def test_json_summary_structure():
    """Test JSON summary structure has expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        summary = data.get('summary', {})

        expected_keys = ['total_analyzed', 'elevated_nice_count',
                         'degraded_nice_count', 'realtime_io_count',
                         'idle_io_count', 'total_issues']
        for key in expected_keys:
            if key not in summary:
                print(f"[FAIL] Summary missing key: {key}")
                return False

        # All should be integers
        for key in expected_keys:
            if not isinstance(summary[key], int):
                print(f"[FAIL] summary.{key} should be an integer")
                return False

        print("[PASS] JSON summary structure test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_process_structure():
    """Test JSON process structure has expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py',
         '--format', 'json', '--all']
    )

    try:
        data = json.loads(stdout)
        processes = data.get('processes', [])

        # If we have any processes, check their structure
        if processes:
            proc = processes[0]
            expected_keys = ['pid', 'comm', 'nice', 'ioprio_class',
                             'ioprio_class_name', 'issues']
            for key in expected_keys:
                if key not in proc:
                    print(f"[FAIL] Process missing key: {key}")
                    return False

            # pid should be an integer
            if not isinstance(proc['pid'], int):
                print("[FAIL] process.pid should be an integer")
                return False

            # issues should be a list
            if not isinstance(proc['issues'], list):
                print("[FAIL] process.issues should be a list")
                return False

        print("[PASS] JSON process structure test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_nice_threshold_options():
    """Test nice threshold options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_priority_monitor.py',
         '--nice-elevated', '-10', '--nice-degraded', '15']
    )

    if return_code in [0, 1]:
        print("[PASS] Nice threshold options test passed")
        return True
    else:
        print(f"[FAIL] Nice threshold options test failed: {return_code}")
        return False


def test_script_metadata():
    """Test script has proper shebang and docstring."""
    try:
        with open('baremetal_process_priority_monitor.py', 'r') as f:
            content = f.read()

        # Check shebang
        if not content.startswith('#!/usr/bin/env python3'):
            print("[FAIL] Script missing proper shebang")
            return False

        # Check for docstring with exit codes
        if 'Exit codes:' not in content:
            print("[FAIL] Script missing exit codes documentation")
            return False

        # Check for argparse import
        if 'import argparse' not in content:
            print("[FAIL] Script missing argparse import")
            return False

        print("[PASS] Script metadata test passed")
        return True
    except FileNotFoundError:
        print("[FAIL] Script file not found")
        return False


if __name__ == "__main__":
    print("Testing baremetal_process_priority_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_exit_codes,
        test_all_option,
        test_user_filter,
        test_comm_filter,
        test_format_option_values,
        test_combined_options,
        test_json_summary_structure,
        test_json_process_structure,
        test_nice_threshold_options,
        test_script_metadata,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"{total - passed} test(s) failed")
        sys.exit(1)
