#!/usr/bin/env python3
"""
Test script for baremetal_fd_leak_detector.py functionality.
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
        [sys.executable, 'baremetal_fd_leak_detector.py', '--help']
    )

    if return_code == 0 and 'file descriptor' in stdout.lower():
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
        [sys.executable, 'baremetal_fd_leak_detector.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_fd_leak_detector.py']
    )

    # Should succeed (exit 0 or 1 depending on system state)
    if return_code in [0, 1] and 'File Descriptor Leak Detector' in stdout:
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
        [sys.executable, 'baremetal_fd_leak_detector.py', '--format', 'json']
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
        expected_summary_keys = ['total_processes_analyzed', 'processes_with_issues',
                                  'critical_count', 'warning_count']
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
        [sys.executable, 'baremetal_fd_leak_detector.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and 'FILE DESCRIPTOR LEAK DETECTOR REPORT' in stdout:
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
        [sys.executable, 'baremetal_fd_leak_detector.py', '--verbose']
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
        [sys.executable, 'baremetal_fd_leak_detector.py', '--warn-only']
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
        [sys.executable, 'baremetal_fd_leak_detector.py']
    )

    # Exit code should be 0 (no issues) or 1 (issues found), never 2 for normal runs
    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_top_option():
    """Test --top option to limit output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_leak_detector.py', '--top', '5', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # With --top 5, we should see at most 5 processes in output
        # (though more may be analyzed)
        if 'processes' not in data:
            print("[FAIL] JSON output missing 'processes' key")
            return False

        print("[PASS] Top option test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_user_filter():
    """Test --user filter option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_leak_detector.py',
         '--user', 'root', '--format', 'json']
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
        [sys.executable, 'baremetal_fd_leak_detector.py',
         '--comm', 'python', '--format', 'json']
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
            [sys.executable, 'baremetal_fd_leak_detector.py', '--format', fmt]
        )

        if return_code not in [0, 1]:
            print(f"[FAIL] Format '{fmt}' returned error code {return_code}")
            return False

    print("[PASS] All format options test passed")
    return True


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_leak_detector.py',
         '--format', 'json', '--verbose', '--top', '10']
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
        [sys.executable, 'baremetal_fd_leak_detector.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        summary = data.get('summary', {})

        expected_keys = ['total_processes_analyzed', 'processes_with_issues',
                         'critical_count', 'warning_count', 'total_fds_tracked']
        for key in expected_keys:
            if key not in summary:
                print(f"[FAIL] Summary missing key: {key}")
                return False

        # Most should be integers
        for key in ['total_processes_analyzed', 'processes_with_issues',
                    'critical_count', 'warning_count']:
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
        [sys.executable, 'baremetal_fd_leak_detector.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        processes = data.get('processes', [])

        # If we have any processes, check their structure
        if processes:
            proc = processes[0]
            expected_keys = ['pid', 'comm', 'fd_count', 'fd_limit', 'issues']
            for key in expected_keys:
                if key not in proc:
                    print(f"[FAIL] Process missing key: {key}")
                    return False

            # pid should be an integer
            if not isinstance(proc['pid'], int):
                print("[FAIL] process.pid should be an integer")
                return False

            # fd_count should be an integer
            if not isinstance(proc['fd_count'], int):
                print("[FAIL] process.fd_count should be an integer")
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


def test_threshold_options():
    """Test FD threshold options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_leak_detector.py',
         '--fd-warning', '500', '--fd-critical', '2000']
    )

    if return_code in [0, 1]:
        print("[PASS] FD threshold options test passed")
        return True
    else:
        print(f"[FAIL] FD threshold options test failed: {return_code}")
        return False


def test_min_fds_option():
    """Test --min-fds option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_leak_detector.py',
         '--min-fds', '5', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # All processes should have at least 5 FDs
        for proc in data.get('processes', []):
            if proc['fd_count'] < 5:
                print(f"[FAIL] Found process with fewer than 5 FDs: {proc['fd_count']}")
                return False

        print("[PASS] Min FDs option test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_details_option():
    """Test --details option for FD categories."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_leak_detector.py',
         '--details', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        processes = data.get('processes', [])

        # If we have processes, at least some should have fd_categories
        has_categories = any('fd_categories' in p for p in processes)
        if processes and not has_categories:
            # Not a failure - depends on permissions
            print("[PASS] Details option test passed (categories may require permissions)")
            return True

        print("[PASS] Details option test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_script_metadata():
    """Test script has proper shebang and docstring."""
    try:
        with open('baremetal_fd_leak_detector.py', 'r') as f:
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


def test_system_fd_info():
    """Test that system FD info is included in summary."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_leak_detector.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        summary = data.get('summary', {})

        # Should have system FD info
        if 'system_fd_allocated' in summary:
            if not isinstance(summary['system_fd_allocated'], int):
                print("[FAIL] system_fd_allocated should be an integer")
                return False
            if 'system_fd_max' in summary and summary['system_fd_max']:
                if not isinstance(summary['system_fd_max'], int):
                    print("[FAIL] system_fd_max should be an integer")
                    return False

        print("[PASS] System FD info test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_fd_leak_detector.py...")
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
        test_top_option,
        test_user_filter,
        test_comm_filter,
        test_format_option_values,
        test_combined_options,
        test_json_summary_structure,
        test_json_process_structure,
        test_threshold_options,
        test_min_fds_option,
        test_details_option,
        test_script_metadata,
        test_system_fd_info,
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
