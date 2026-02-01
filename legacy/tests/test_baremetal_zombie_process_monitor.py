#!/usr/bin/env python3
"""
Test script for baremetal_zombie_process_monitor.py functionality.
Tests argument parsing, output formats, and error handling without requiring
specific system state or actual zombie processes.
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
        [sys.executable, 'baremetal_zombie_process_monitor.py', '--help']
    )

    if return_code == 0 and 'zombie' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_basic_execution():
    """Test basic execution without arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py']
    )

    # Should succeed (0 = no zombies) or have warnings (1 = zombies found)
    # Should not be usage error (2)
    if return_code in [0, 1]:
        print("[PASS] Basic execution test passed")
        return True
    else:
        print(f"[FAIL] Basic execution test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format and parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON format test failed - wrong return code: {return_code}")
        return False

    try:
        data = json.loads(stdout)
        # Check expected structure
        if 'total_zombies' in data and 'zombies' in data and 'by_parent' in data:
            if isinstance(data['zombies'], list):
                print("[PASS] JSON output format test passed")
                return True
            else:
                print(f"[FAIL] JSON zombies field is not a list")
                return False
        else:
            print(f"[FAIL] JSON missing expected fields")
            print(f"  Keys found: {list(data.keys())}")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py', '--format', 'table']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        # Check for table formatting characters or zombie-related content
        if '─' in stdout or '│' in stdout or 'zombie' in stdout.lower():
            print("[PASS] Table output format test passed")
            return True
        else:
            print(f"[FAIL] Table format missing expected formatting")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Table format test failed - wrong return code: {return_code}")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py', '--format', 'plain']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        # Should have zombie-related output
        if 'zombie' in stdout.lower():
            print("[PASS] Plain output format test passed")
            return True
        else:
            print(f"[FAIL] Plain format missing expected content")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Plain format test failed - wrong return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py', '--format', 'invalid']
    )

    # Should fail with usage error (exit code 2)
    if return_code == 2:
        print("[PASS] Invalid format rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should return exit code 2, got {return_code}")
        return False


def test_group_flag():
    """Test --group flag to group by parent process."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py', '--group']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --group flag test passed")
        return True
    else:
        print(f"[FAIL] --group flag test failed - return code: {return_code}")
        return False


def test_verbose_flag():
    """Test verbose output flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py', '--verbose']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed - return code: {return_code}")
        return False


def test_min_age_option():
    """Test --min-age option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py', '--min-age', '3600']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --min-age option test passed")
        return True
    else:
        print(f"[FAIL] --min-age option test failed - return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_warn_only_flag():
    """Test --warn-only flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py', '--warn-only']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] --warn-only flag test failed - return code: {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py',
         '--format', 'json', '--group', '--verbose']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] Combined options test failed - return code: {return_code}")
        return False

    try:
        data = json.loads(stdout)
        print("[PASS] Combined options test passed")
        return True
    except json.JSONDecodeError:
        print(f"[FAIL] Combined options produced invalid JSON")
        return False


def test_json_structure_complete():
    """Test that JSON output has all expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON structure test failed - wrong return code")
        return False

    try:
        data = json.loads(stdout)
        required_fields = ['total_zombies', 'parent_count', 'zombies', 'by_parent']
        missing = [f for f in required_fields if f not in data]

        if missing:
            print(f"[FAIL] JSON structure missing fields: {missing}")
            return False

        # Verify types
        if not isinstance(data['total_zombies'], int):
            print("[FAIL] total_zombies should be int")
            return False
        if not isinstance(data['parent_count'], int):
            print("[FAIL] parent_count should be int")
            return False
        if not isinstance(data['zombies'], list):
            print("[FAIL] zombies should be list")
            return False
        if not isinstance(data['by_parent'], dict):
            print("[FAIL] by_parent should be dict")
            return False

        print("[PASS] JSON structure complete test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_short_flags():
    """Test short flag versions."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py', '-g', '-v']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] Short flags test passed")
        return True
    else:
        print(f"[FAIL] Short flags test failed - return code: {return_code}")
        return False


def test_invalid_min_age():
    """Test that non-numeric min-age is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_zombie_process_monitor.py', '--min-age', 'abc']
    )

    # Should fail with usage error (exit code 2)
    if return_code == 2:
        print("[PASS] Invalid min-age rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid min-age should return exit code 2, got {return_code}")
        return False


if __name__ == '__main__':
    print("Testing baremetal_zombie_process_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_basic_execution,
        test_json_output_format,
        test_table_output_format,
        test_plain_output_format,
        test_invalid_format,
        test_group_flag,
        test_verbose_flag,
        test_min_age_option,
        test_warn_only_flag,
        test_combined_options,
        test_json_structure_complete,
        test_short_flags,
        test_invalid_min_age,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    print("=" * 60)

    sys.exit(0 if passed == total else 1)
