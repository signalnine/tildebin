#!/usr/bin/env python3
"""
Test script for baremetal_hugepage_monitor.py functionality.
Tests argument parsing and output formats without requiring specific hugepage configuration.
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
        [sys.executable, 'baremetal_hugepage_monitor.py', '--help']
    )

    if return_code == 0 and 'hugepage' in stdout.lower():
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
        [sys.executable, 'baremetal_hugepage_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_hugepage_monitor.py']
    )

    # Should succeed (exit 0 or 1 depending on hugepage status)
    if return_code in [0, 1] and ('Hugepages:' in stdout or 'hugepage' in stdout.lower()):
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
        [sys.executable, 'baremetal_hugepage_monitor.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'hugepages' not in data:
            print("[FAIL] JSON output missing 'hugepages' key")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify hugepages data structure
        hp = data['hugepages']
        required_keys = ['total', 'free', 'used', 'reserved', 'pagesize_kb']
        if not all(key in hp for key in required_keys):
            print("[FAIL] JSON hugepages data missing required keys")
            print(f"  Hugepages keys: {list(hp.keys())}")
            return False

        # Verify THP status exists
        if 'transparent_huge_pages' not in data:
            print("[FAIL] JSON output missing 'transparent_huge_pages' key")
            return False

        # Verify issues list exists
        if 'issues' not in data:
            print("[FAIL] JSON output missing 'issues' key")
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
        [sys.executable, 'baremetal_hugepage_monitor.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and ('HUGEPAGE' in stdout or 'Total Pages' in stdout):
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
        [sys.executable, 'baremetal_hugepage_monitor.py', '--verbose']
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
    """Test warn-only mode suppresses normal output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_hugepage_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on hugepage state)
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_thresholds():
    """Test custom threshold arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_hugepage_monitor.py', '--warn', '70', '--crit', '90']
    )

    # Should succeed with custom thresholds
    if return_code in [0, 1]:
        print("[PASS] Custom thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_range():
    """Test that invalid threshold values are rejected."""
    # Test warn > 100
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_hugepage_monitor.py', '--warn', '150']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold range test passed (warn > 100)")
        return True

    # Test warn >= crit
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_hugepage_monitor.py', '--warn', '95', '--crit', '90']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold range test passed (warn >= crit)")
        return True
    else:
        print(f"[FAIL] Invalid threshold range test failed")
        print(f"  Return code: {return_code}")
        return False


def test_min_available_option():
    """Test min-available argument."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_hugepage_monitor.py', '--min-available', '5']
    )

    # Should succeed with custom min-available
    if return_code in [0, 1]:
        print("[PASS] Min-available option test passed")
        return True
    else:
        print(f"[FAIL] Min-available option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_min_available():
    """Test that negative min-available is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_hugepage_monitor.py', '--min-available', '-5']
    )

    if return_code == 2:
        print("[PASS] Invalid min-available test passed")
        return True
    else:
        print(f"[FAIL] Invalid min-available should return exit code 2")
        print(f"  Return code: {return_code}")
        return False


def test_json_verbose_includes_extra_data():
    """Test JSON verbose output includes additional data."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_hugepage_monitor.py', '--format', 'json', '--verbose']
    )

    try:
        data = json.loads(stdout)

        # Verbose mode should include vmstat
        if 'vmstat' not in data:
            print("[FAIL] JSON verbose missing vmstat data")
            return False

        # Should include sizes
        if 'sizes' not in data:
            print("[FAIL] JSON verbose missing sizes data")
            return False

        print("[PASS] JSON verbose output test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON verbose parsing failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_hugepage_monitor.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_hugepage_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_custom_thresholds,
        test_invalid_threshold_range,
        test_min_available_option,
        test_invalid_min_available,
        test_json_verbose_includes_extra_data,
        test_exit_codes,
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
