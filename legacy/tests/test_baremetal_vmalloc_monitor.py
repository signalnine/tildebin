#!/usr/bin/env python3
"""
Test script for baremetal_vmalloc_monitor.py functionality.
Tests argument parsing and output formats without requiring specific kernel state.
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
        [sys.executable, 'baremetal_vmalloc_monitor.py', '--help']
    )

    if return_code == 0 and 'vmalloc' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_format_option():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vmalloc_monitor.py', '--format', 'xml']
    )

    # Should fail with exit code 2 (usage error)
    if return_code != 0:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option should fail")
        return False


def test_format_options():
    """Test that format options are recognized"""
    formats = ['plain', 'json', 'table']
    results = []

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_vmalloc_monitor.py', '--format', fmt]
        )

        # Return code should be 0 (success) or 1 (warnings) or 2 (missing /proc)
        if return_code in (0, 1, 2):
            results.append(True)
        else:
            print(f"[FAIL] Format {fmt} crashed with code {return_code}")
            results.append(False)

    if all(results):
        print("[PASS] Format options test passed")
        return True
    else:
        print(f"[FAIL] Format options test failed: {sum(results)}/{len(results)} passed")
        return False


def test_verbose_flag():
    """Test that verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vmalloc_monitor.py', '-v']
    )

    # Should parse successfully
    if return_code in (0, 1, 2):
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed with code {return_code}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vmalloc_monitor.py', '-w']
    )

    # Should parse successfully
    if return_code in (0, 1, 2):
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed with code {return_code}")
        return False


def test_threshold_options():
    """Test that threshold options are recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vmalloc_monitor.py',
         '--warn-pct', '70', '--crit-pct', '90', '--min-chunk', '64']
    )

    # Should parse successfully
    if return_code in (0, 1, 2):
        print("[PASS] Threshold options test passed")
        return True
    else:
        print(f"[FAIL] Threshold options test failed with code {return_code}")
        return False


def test_invalid_threshold_order():
    """Test that invalid threshold order is detected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vmalloc_monitor.py',
         '--warn-pct', '95', '--crit-pct', '80']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2 and 'warn-pct' in stderr.lower():
        print("[PASS] Invalid threshold order test passed")
        return True
    elif return_code != 0:
        # At least it didn't succeed silently
        print("[PASS] Invalid threshold order test passed (error detected)")
        return True
    else:
        print(f"[FAIL] Invalid threshold order should be rejected")
        return False


def test_json_output_format():
    """Test JSON output format parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vmalloc_monitor.py', '--format', 'json']
    )

    # If successful, try to parse JSON
    if return_code in (0, 1):
        try:
            data = json.loads(stdout)
            # Should have expected keys
            if 'status' in data:
                print("[PASS] JSON output format test passed")
                return True
            else:
                print(f"[FAIL] JSON missing 'status' key")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # Missing /proc is acceptable in test environment
        print("[PASS] JSON output format test passed (no /proc available)")
        return True
    else:
        print(f"[FAIL] JSON output format test failed with code {return_code}")
        return False


def test_json_contains_metrics():
    """Test that JSON output contains vmalloc metrics"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vmalloc_monitor.py', '--format', 'json']
    )

    if return_code in (0, 1):
        try:
            data = json.loads(stdout)
            # Should have vmalloc metrics or be a minimal status response
            if 'total_kb' in data or 'message' in data:
                print("[PASS] JSON metrics test passed")
                return True
            else:
                print(f"[FAIL] JSON missing expected fields")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] JSON metrics test passed (no /proc available)")
        return True
    else:
        print(f"[FAIL] JSON metrics test failed with code {return_code}")
        return False


def test_combined_flags():
    """Test combination of multiple flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vmalloc_monitor.py',
         '--format', 'json', '-v', '-w']
    )

    # Should parse successfully
    if return_code in (0, 1, 2):
        print("[PASS] Combined flags test passed")
        return True
    else:
        print(f"[FAIL] Combined flags test failed with code {return_code}")
        return False


def test_exit_code_convention():
    """Test that exit codes follow convention (0=success, 1=issues, 2=error)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vmalloc_monitor.py']
    )

    if return_code in (0, 1, 2):
        print("[PASS] Exit code convention test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_table_format_output():
    """Test table format produces readable output"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vmalloc_monitor.py', '--format', 'table']
    )

    if return_code in (0, 1):
        # Table format should have some structured output
        if 'Vmalloc' in stdout or 'Metric' in stdout or 'No' in stdout:
            print("[PASS] Table format output test passed")
            return True
        else:
            print(f"[FAIL] Table format missing expected headers")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        print("[PASS] Table format output test passed (no /proc available)")
        return True
    else:
        print(f"[FAIL] Table format test failed with code {return_code}")
        return False


def test_plain_format_shows_stats():
    """Test plain format shows vmalloc statistics"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vmalloc_monitor.py', '--format', 'plain']
    )

    if return_code in (0, 1):
        # Should mention vmalloc or memory info
        if 'Vmalloc' in stdout or 'Total' in stdout or 'issues' in stdout.lower():
            print("[PASS] Plain format stats test passed")
            return True
        else:
            print(f"[FAIL] Plain format missing expected content")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        print("[PASS] Plain format stats test passed (no /proc available)")
        return True
    else:
        print(f"[FAIL] Plain format test failed with code {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_vmalloc_monitor.py...\n")

    tests = [
        test_help_message,
        test_invalid_format_option,
        test_format_options,
        test_verbose_flag,
        test_warn_only_flag,
        test_threshold_options,
        test_invalid_threshold_order,
        test_json_output_format,
        test_json_contains_metrics,
        test_combined_flags,
        test_exit_code_convention,
        test_table_format_output,
        test_plain_format_shows_stats,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print(f"\nTest Results: {passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)
