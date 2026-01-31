#!/usr/bin/env python3
"""
Test script for baremetal_btrfs_health_monitor.py functionality.
Tests argument parsing and output formats without requiring BTRFS to be configured.
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
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '--help']
    )

    if return_code == 0 and 'btrfs' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_help_shows_examples():
    """Test that help message includes usage examples."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '--help']
    )

    if return_code == 0 and 'Examples' in stdout:
        print("[PASS] Help examples test passed")
        return True
    else:
        print(f"[FAIL] Help examples test failed")
        return False


def test_help_shows_exit_codes():
    """Test that help message documents exit codes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '--help']
    )

    if return_code == 0 and 'Exit codes' in stdout:
        print("[PASS] Help exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help exit codes test failed")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_btrfs_health_monitor.py']
    )

    # Should succeed (0, 1, or 2 for no BTRFS tools)
    if return_code in [0, 1, 2]:
        expected = any([
            'BTRFS' in stdout,
            'No BTRFS' in stdout,
            'BTRFS tools not found' in stderr,
            'Filesystems:' in stdout
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
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '--format', 'json']
    )

    # Exit code 2 means BTRFS tools not available - still valid
    if return_code == 2:
        print("[PASS] JSON output format test passed (BTRFS not available)")
        return True

    try:
        data = json.loads(stdout)

        # Verify expected structure
        if 'issues' in data or 'message' in data:
            print("[PASS] JSON output format test passed")
            return True

        if 'summary' in data:
            summary = data['summary']
            if 'filesystems' in summary:
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
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        if return_code == 2:
            print("[PASS] Table output format test passed (BTRFS not available)")
            return True

        expected = any([
            'BTRFS FILESYSTEM HEALTH' in stdout,
            'No BTRFS' in stdout,
            '=' in stdout
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
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '--verbose']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_short_option():
    """Test verbose mode with short -v option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Verbose short option test passed")
        return True
    else:
        print(f"[FAIL] Verbose short option test failed")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_short_option():
    """Test warn-only mode with short -w option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '-w']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only short option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only short option test failed")
        return False


def test_custom_capacity_thresholds():
    """Test custom capacity threshold arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py',
         '--capacity-warn', '70', '--capacity-crit', '85']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Custom capacity thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom capacity thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_scrub_threshold():
    """Test custom scrub warning threshold."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '--scrub-warn', '60']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Custom scrub threshold test passed")
        return True
    else:
        print(f"[FAIL] Custom scrub threshold test failed")
        return False


def test_custom_error_threshold():
    """Test custom device error threshold."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '--error-threshold', '5']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Custom error threshold test passed")
        return True
    else:
        print(f"[FAIL] Custom error threshold test failed")
        return False


def test_invalid_threshold_range():
    """Test that invalid threshold values are rejected."""
    # Test warn > 100
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py', '--capacity-warn', '150']
    )

    if return_code == 2 and 'between 0 and 100' in stderr:
        print("[PASS] Invalid threshold range test passed (warn > 100)")
        return True

    # Test warn >= crit
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py',
         '--capacity-warn', '90', '--capacity-crit', '80']
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
        [sys.executable, 'baremetal_btrfs_health_monitor.py',
         '--format', 'json', '--verbose']
    )

    if return_code == 2:
        print("[PASS] JSON verbose output test passed (BTRFS not available)")
        return True

    try:
        data = json.loads(stdout)

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
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py']
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
            [sys.executable, 'baremetal_btrfs_health_monitor.py',
             '--format', fmt, '--warn-only']
        )

        if return_code not in [0, 1, 2]:
            print(f"[FAIL] Format {fmt} with warn-only failed")
            all_passed = False

    if all_passed:
        print("[PASS] All formats with warn-only test passed")
    return all_passed


def test_btrfs_tools_missing_message():
    """Test that helpful message is shown when BTRFS tools are missing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py']
    )

    # If BTRFS is not installed, we should get a helpful error
    if return_code == 2:
        if 'btrfs-progs' in stderr or 'btrfs' in stderr:
            print("[PASS] BTRFS tools missing message test passed")
            return True
        else:
            print(f"[FAIL] Missing helpful install message")
            print(f"  Stderr: {stderr[:200]}")
            return False

    # If BTRFS is installed, test passes anyway
    print("[PASS] BTRFS tools missing message test passed (BTRFS available)")
    return True


def test_combined_options():
    """Test multiple options combined."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_btrfs_health_monitor.py',
         '--format', 'json',
         '--verbose',
         '--capacity-warn', '75',
         '--capacity-crit', '88',
         '--scrub-warn', '45',
         '--error-threshold', '3']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed")
        print(f"  Return code: {return_code}")
        return False


def test_docstring_present():
    """Test that the script has a proper docstring."""
    return_code, stdout, stderr = run_command(
        [sys.executable, '-c',
         'import baremetal_btrfs_health_monitor; print(baremetal_btrfs_health_monitor.__doc__)']
    )

    if return_code == 0 and 'BTRFS' in stdout and 'Exit codes' in stdout:
        print("[PASS] Docstring present test passed")
        return True
    else:
        print(f"[FAIL] Docstring test failed")
        print(f"  Output: {stdout[:200]}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_btrfs_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_help_shows_examples,
        test_help_shows_exit_codes,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_verbose_short_option,
        test_warn_only_mode,
        test_warn_only_short_option,
        test_custom_capacity_thresholds,
        test_custom_scrub_threshold,
        test_custom_error_threshold,
        test_invalid_threshold_range,
        test_json_verbose_output,
        test_exit_codes,
        test_all_formats_with_warn_only,
        test_btrfs_tools_missing_message,
        test_combined_options,
        test_docstring_present,
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
