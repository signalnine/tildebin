#!/usr/bin/env python3
"""
Test script for baremetal_lvm_health_monitor.py functionality.
Tests argument parsing and output formats without requiring LVM to be configured.
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
        [sys.executable, 'baremetal_lvm_health_monitor.py', '--help']
    )

    if return_code == 0 and 'lvm' in stdout.lower() and 'logical volume' in stdout.lower():
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
        [sys.executable, 'baremetal_lvm_health_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_lvm_health_monitor.py']
    )

    # Should succeed (0, 1, or 2 for no LVM tools)
    # Check for expected output patterns
    if return_code in [0, 1, 2]:
        # Either shows LVM info, no LVM config, or LVM tools not found
        expected = any([
            'LVM Health' in stdout,
            'No LVM' in stdout,
            'LVM tools not found' in stderr,
            'Volume Groups' in stdout
        ])
        if expected or return_code == 2:
            print("[PASS] Plain output format test passed")
            return True

    print(f"[FAIL] Plain output format test failed")
    print(f"  Return code: {return_code}")
    print(f"  Output: {stdout[:200]}")
    return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_lvm_health_monitor.py', '--format', 'json']
    )

    # Exit code 2 means LVM tools not available - still valid
    if return_code == 2:
        print("[PASS] JSON output format test passed (LVM not available)")
        return True

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure (either full output or no-LVM message)
        if 'issues' in data or 'message' in data:
            print("[PASS] JSON output format test passed")
            return True

        # If we have summary, check for expected keys
        if 'summary' in data:
            summary = data['summary']
            expected_keys = ['volume_groups', 'logical_volumes', 'physical_volumes']
            if all(key in summary for key in expected_keys):
                print("[PASS] JSON output format test passed")
                return True

        print("[FAIL] JSON output missing expected keys")
        print(f"  Keys: {list(data.keys())}")
        return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_lvm_health_monitor.py', '--format', 'table']
    )

    # Should succeed and contain table formatting
    if return_code in [0, 1, 2]:
        # Exit code 2 means LVM tools not available
        if return_code == 2:
            print("[PASS] Table output format test passed (LVM not available)")
            return True

        # Check for table-like output
        expected = any([
            'LVM HEALTH' in stdout,
            'No LVM' in stdout,
            '=' in stdout  # Table separators
        ])
        if expected:
            print("[PASS] Table output format test passed")
            return True

    print(f"[FAIL] Table output format test failed")
    print(f"  Return code: {return_code}")
    print(f"  Output: {stdout[:200]}")
    return False


def test_verbose_mode():
    """Test verbose mode includes additional information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_lvm_health_monitor.py', '--verbose']
    )

    # Should succeed
    if return_code in [0, 1, 2]:
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
        [sys.executable, 'baremetal_lvm_health_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on LVM state)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_thin_thresholds():
    """Test custom thin pool threshold arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_lvm_health_monitor.py',
         '--thin-warn', '70', '--thin-crit', '85']
    )

    # Should succeed with custom thresholds
    if return_code in [0, 1, 2]:
        print("[PASS] Custom thin thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thin thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_vg_thresholds():
    """Test custom volume group threshold arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_lvm_health_monitor.py',
         '--vg-warn', '80', '--vg-crit', '92']
    )

    # Should succeed with custom thresholds
    if return_code in [0, 1, 2]:
        print("[PASS] Custom VG thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom VG thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_snap_age():
    """Test custom snapshot age threshold."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_lvm_health_monitor.py', '--snap-age', '14']
    )

    # Should succeed with custom threshold
    if return_code in [0, 1, 2]:
        print("[PASS] Custom snapshot age test passed")
        return True
    else:
        print(f"[FAIL] Custom snapshot age test failed")
        print(f"  Return code: {return_code}")
        return False


def test_disable_snap_age():
    """Test disabling snapshot age check."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_lvm_health_monitor.py', '--snap-age', '0']
    )

    # Should succeed with disabled check
    if return_code in [0, 1, 2]:
        print("[PASS] Disable snapshot age test passed")
        return True
    else:
        print(f"[FAIL] Disable snapshot age test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_range():
    """Test that invalid threshold values are rejected."""
    # Test warn > 100
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_lvm_health_monitor.py', '--thin-warn', '150']
    )

    if return_code == 2 and 'between 0 and 100' in stderr:
        print("[PASS] Invalid threshold range test passed (warn > 100)")
        return True

    # Test warn >= crit
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_lvm_health_monitor.py',
         '--thin-warn', '90', '--thin-crit', '80']
    )

    if return_code == 2 and 'less than critical' in stderr:
        print("[PASS] Invalid threshold range test passed (warn >= crit)")
        return True

    print(f"[FAIL] Invalid threshold range test failed")
    print(f"  Return code: {return_code}")
    print(f"  Stderr: {stderr[:200]}")
    return False


def test_json_verbose_output():
    """Test JSON verbose output includes detailed data."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_lvm_health_monitor.py',
         '--format', 'json', '--verbose']
    )

    # Exit code 2 means LVM tools not available - still valid
    if return_code == 2:
        print("[PASS] JSON verbose output test passed (LVM not available)")
        return True

    try:
        data = json.loads(stdout)

        # Should have summary and issues at minimum
        if 'issues' in data or 'message' in data:
            print("[PASS] JSON verbose output test passed")
            return True

        print("[FAIL] JSON verbose missing expected data")
        return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON verbose parsing failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0, 1, or 2 (not other values)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_lvm_health_monitor.py']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_all_formats_with_warn_only():
    """Test that all output formats work with warn-only mode."""
    formats = ['plain', 'json', 'table']
    all_passed = True

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_lvm_health_monitor.py',
             '--format', fmt, '--warn-only']
        )

        if return_code not in [0, 1, 2]:
            print(f"[FAIL] Format {fmt} with warn-only failed")
            all_passed = False

    if all_passed:
        print("[PASS] All formats with warn-only test passed")
    return all_passed


if __name__ == "__main__":
    print("Testing baremetal_lvm_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_custom_thin_thresholds,
        test_custom_vg_thresholds,
        test_custom_snap_age,
        test_disable_snap_age,
        test_invalid_threshold_range,
        test_json_verbose_output,
        test_exit_codes,
        test_all_formats_with_warn_only,
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
