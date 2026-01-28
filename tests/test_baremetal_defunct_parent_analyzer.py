#!/usr/bin/env python3
"""
Test script for baremetal_defunct_parent_analyzer.py functionality.
Tests argument parsing and output formats without requiring specific system state.
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
        [sys.executable, 'baremetal_defunct_parent_analyzer.py', '--help']
    )

    if return_code == 0 and 'orphan' in stdout.lower():
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
        [sys.executable, 'baremetal_defunct_parent_analyzer.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_defunct_parent_analyzer.py']
    )

    # Should succeed (exit 0 or 1 depending on system state)
    if return_code in [0, 1] and 'Defunct Parent Analyzer' in stdout:
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
        [sys.executable, 'baremetal_defunct_parent_analyzer.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['summary', 'orphans']
        if not all(key in data for key in required_keys):
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify summary structure
        summary = data['summary']
        expected_summary_keys = ['total_orphans', 'with_issues', 'long_running',
                                  'init_like', 'by_user', 'by_process']
        if not all(key in summary for key in expected_summary_keys):
            print("[FAIL] JSON summary missing required keys")
            print(f"  Summary keys: {list(summary.keys())}")
            return False

        # Verify orphans is a list
        if not isinstance(data['orphans'], list):
            print("[FAIL] JSON 'orphans' should be an array")
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
        [sys.executable, 'baremetal_defunct_parent_analyzer.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and 'ORPHANED PROCESS REPORT' in stdout:
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
        [sys.executable, 'baremetal_defunct_parent_analyzer.py', '--verbose', '--all']
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
        [sys.executable, 'baremetal_defunct_parent_analyzer.py', '--warn-only']
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
        [sys.executable, 'baremetal_defunct_parent_analyzer.py']
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
    """Test --all option to include all orphaned processes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_defunct_parent_analyzer.py', '--all', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # With --all, we should have the orphans key
        if 'orphans' not in data:
            print("[FAIL] JSON output missing 'orphans' key")
            return False

        print("[PASS] All orphans option test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_user_filter():
    """Test --user filter option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_defunct_parent_analyzer.py',
         '--user', 'root', '--all', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Verify all returned orphans are owned by root
        for orphan in data.get('orphans', []):
            if orphan.get('user') and orphan.get('user') != 'root':
                print(f"[FAIL] Found process not owned by root: {orphan}")
                return False

        print("[PASS] User filter test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_min_age_option():
    """Test --min-age filter option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_defunct_parent_analyzer.py',
         '--min-age', '3600', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Verify all returned orphans are old enough
        for orphan in data.get('orphans', []):
            if orphan.get('age_seconds') and orphan.get('age_seconds') < 3600:
                print(f"[FAIL] Found process younger than min-age: {orphan}")
                return False

        print("[PASS] Min-age filter test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_format_option_values():
    """Test all valid format option values."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_defunct_parent_analyzer.py', '--format', fmt]
        )

        if return_code not in [0, 1]:
            print(f"[FAIL] Format '{fmt}' returned error code {return_code}")
            return False

    print("[PASS] All format options test passed")
    return True


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_defunct_parent_analyzer.py',
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
        [sys.executable, 'baremetal_defunct_parent_analyzer.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        summary = data.get('summary', {})

        expected_keys = ['total_orphans', 'with_issues', 'long_running',
                         'init_like', 'by_user', 'by_process']
        for key in expected_keys:
            if key not in summary:
                print(f"[FAIL] Summary missing key: {key}")
                return False

        # Numeric fields should be integers
        for key in ['total_orphans', 'with_issues', 'long_running', 'init_like']:
            if not isinstance(summary[key], int):
                print(f"[FAIL] summary.{key} should be an integer")
                return False

        # by_user and by_process should be dicts
        if not isinstance(summary['by_user'], dict):
            print("[FAIL] summary.by_user should be a dict")
            return False
        if not isinstance(summary['by_process'], dict):
            print("[FAIL] summary.by_process should be a dict")
            return False

        print("[PASS] JSON summary structure test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_orphan_structure():
    """Test JSON orphan structure has expected fields when orphans exist."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_defunct_parent_analyzer.py',
         '--format', 'json', '--all']
    )

    try:
        data = json.loads(stdout)
        orphans = data.get('orphans', [])

        # If we have any orphans, check their structure
        if orphans:
            orphan = orphans[0]
            expected_keys = ['pid', 'comm', 'state', 'user', 'age_seconds',
                             'age_human', 'is_init_like', 'issues']
            for key in expected_keys:
                if key not in orphan:
                    print(f"[FAIL] Orphan missing key: {key}")
                    return False

            # pid should be an integer
            if not isinstance(orphan['pid'], int):
                print("[FAIL] orphan.pid should be an integer")
                return False

            # issues should be a list
            if not isinstance(orphan['issues'], list):
                print("[FAIL] orphan.issues should be a list")
                return False

        print("[PASS] JSON orphan structure test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_script_metadata():
    """Test script has proper shebang and docstring."""
    try:
        with open('baremetal_defunct_parent_analyzer.py', 'r') as f:
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


def test_invalid_min_age():
    """Test that invalid min-age values are handled."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_defunct_parent_analyzer.py',
         '--min-age', 'invalid']
    )

    # Should fail with usage error
    if return_code != 0:
        print("[PASS] Invalid min-age test passed")
        return True
    else:
        print("[FAIL] Invalid min-age should fail")
        return False


if __name__ == "__main__":
    print("Testing baremetal_defunct_parent_analyzer.py...")
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
        test_min_age_option,
        test_format_option_values,
        test_combined_options,
        test_json_summary_structure,
        test_json_orphan_structure,
        test_script_metadata,
        test_invalid_min_age,
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
