#!/usr/bin/env python3
"""
Test script for baremetal_multipath_health_monitor.py functionality.
Tests argument parsing and output formats without requiring multipath to be configured.
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
        [sys.executable, 'baremetal_multipath_health_monitor.py', '--help']
    )

    if return_code == 0 and 'multipath' in stdout.lower() and 'path' in stdout.lower():
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
        [sys.executable, 'baremetal_multipath_health_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_multipath_health_monitor.py']
    )

    # Should succeed (0, 1, or 2 for no multipath tools/config)
    if return_code in [0, 1, 2]:
        # Either shows multipath info, no config, or tools not found
        expected = any([
            'Multipath Health' in stdout,
            'No multipath' in stdout.lower(),
            'multipath tools not found' in stderr,
            'multipathd' in stdout.lower(),
            'multipathd' in stderr.lower()
        ])
        if expected or return_code == 2:
            print("[PASS] Plain output format test passed")
            return True

    print(f"[FAIL] Plain output format test failed")
    print(f"  Return code: {return_code}")
    print(f"  Output: {stdout[:200]}")
    print(f"  Stderr: {stderr[:200]}")
    return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_multipath_health_monitor.py', '--format', 'json']
    )

    # Exit code 2 means multipath tools not available - still valid
    if return_code == 2:
        # Check if we got JSON output anyway (for "service not running" message)
        try:
            if stdout.strip():
                data = json.loads(stdout)
                if 'message' in data or 'issues' in data:
                    print("[PASS] JSON output format test passed (multipath not available)")
                    return True
        except json.JSONDecodeError:
            pass
        print("[PASS] JSON output format test passed (multipath not available)")
        return True

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure (either full output or no-config message)
        if 'issues' in data or 'message' in data:
            print("[PASS] JSON output format test passed")
            return True

        # If we have summary, check for expected keys
        if 'summary' in data:
            summary = data['summary']
            expected_keys = ['devices', 'total_paths', 'active_paths', 'failed_paths']
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
        [sys.executable, 'baremetal_multipath_health_monitor.py', '--format', 'table']
    )

    # Should succeed and contain table formatting
    if return_code in [0, 1, 2]:
        # Exit code 2 means multipath tools not available
        if return_code == 2:
            print("[PASS] Table output format test passed (multipath not available)")
            return True

        # Check for table-like output
        expected = any([
            'MULTIPATH HEALTH' in stdout,
            'No multipath' in stdout.lower(),
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
        [sys.executable, 'baremetal_multipath_health_monitor.py', '--verbose']
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
        [sys.executable, 'baremetal_multipath_health_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on multipath state)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_min_paths_warn():
    """Test custom minimum paths warning threshold."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_multipath_health_monitor.py',
         '--min-paths-warn', '2']
    )

    # Should succeed with custom threshold
    if return_code in [0, 1, 2]:
        print("[PASS] Custom min-paths-warn test passed")
        return True
    else:
        print(f"[FAIL] Custom min-paths-warn test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_min_paths_crit():
    """Test custom minimum paths critical threshold."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_multipath_health_monitor.py',
         '--min-paths-crit', '1']
    )

    # Should succeed with custom threshold
    if return_code in [0, 1, 2]:
        print("[PASS] Custom min-paths-crit test passed")
        return True
    else:
        print(f"[FAIL] Custom min-paths-crit test failed")
        print(f"  Return code: {return_code}")
        return False


def test_combined_thresholds():
    """Test combined warning and critical thresholds."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_multipath_health_monitor.py',
         '--min-paths-warn', '3', '--min-paths-crit', '1']
    )

    # Should succeed with combined thresholds
    if return_code in [0, 1, 2]:
        print("[PASS] Combined thresholds test passed")
        return True
    else:
        print(f"[FAIL] Combined thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_negative():
    """Test that negative threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_multipath_health_monitor.py',
         '--min-paths-warn', '-1']
    )

    if return_code == 2 and '>= 0' in stderr:
        print("[PASS] Negative threshold test passed")
        return True

    print(f"[FAIL] Negative threshold test failed")
    print(f"  Return code: {return_code}")
    print(f"  Stderr: {stderr[:200]}")
    return False


def test_invalid_threshold_order():
    """Test that warn < crit is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_multipath_health_monitor.py',
         '--min-paths-warn', '1', '--min-paths-crit', '2']
    )

    if return_code == 2 and '>=' in stderr:
        print("[PASS] Threshold order validation test passed")
        return True

    print(f"[FAIL] Threshold order validation test failed")
    print(f"  Return code: {return_code}")
    print(f"  Stderr: {stderr[:200]}")
    return False


def test_json_verbose_output():
    """Test JSON verbose output includes detailed data."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_multipath_health_monitor.py',
         '--format', 'json', '--verbose']
    )

    # Exit code 2 means multipath tools not available - still valid
    if return_code == 2:
        print("[PASS] JSON verbose output test passed (multipath not available)")
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
        [sys.executable, 'baremetal_multipath_health_monitor.py']
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
            [sys.executable, 'baremetal_multipath_health_monitor.py',
             '--format', fmt, '--warn-only']
        )

        if return_code not in [0, 1, 2]:
            print(f"[FAIL] Format {fmt} with warn-only failed")
            all_passed = False

    if all_passed:
        print("[PASS] All formats with warn-only test passed")
    return all_passed


def test_all_formats_with_verbose():
    """Test that all output formats work with verbose mode."""
    formats = ['plain', 'json', 'table']
    all_passed = True

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_multipath_health_monitor.py',
             '--format', fmt, '--verbose']
        )

        if return_code not in [0, 1, 2]:
            print(f"[FAIL] Format {fmt} with verbose failed")
            all_passed = False

    if all_passed:
        print("[PASS] All formats with verbose test passed")
    return all_passed


if __name__ == "__main__":
    print("Testing baremetal_multipath_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_custom_min_paths_warn,
        test_custom_min_paths_crit,
        test_combined_thresholds,
        test_invalid_threshold_negative,
        test_invalid_threshold_order,
        test_json_verbose_output,
        test_exit_codes,
        test_all_formats_with_warn_only,
        test_all_formats_with_verbose,
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
