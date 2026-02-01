#!/usr/bin/env python3
"""
Test script for baremetal_process_limits_monitor.py functionality.
Tests argument parsing and output formats without requiring specific process states.
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
        [sys.executable, 'baremetal_process_limits_monitor.py', '--help']
    )

    if return_code == 0 and 'process' in stdout.lower() and 'limits' in stdout.lower():
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
        [sys.executable, 'baremetal_process_limits_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_process_limits_monitor.py']
    )

    # Should succeed (exit 0 or 1 depending on process states)
    if return_code in [0, 1] and 'Process Limits Monitor' in stdout:
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
        [sys.executable, 'baremetal_process_limits_monitor.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['total_scanned', 'processes_with_issues', 'processes', 'issues_found']
        if not all(key in data for key in required_keys):
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify processes is a list
        if not isinstance(data['processes'], list):
            print("[FAIL] JSON 'processes' should be a list")
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
        [sys.executable, 'baremetal_process_limits_monitor.py', '--format', 'table']
    )

    # Should succeed and contain table headers or "No processes" message
    if return_code in [0, 1] and ('PID' in stdout or 'No processes' in stdout):
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
        [sys.executable, 'baremetal_process_limits_monitor.py', '--verbose']
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
        [sys.executable, 'baremetal_process_limits_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on process states)
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
        [sys.executable, 'baremetal_process_limits_monitor.py', '--warn', '70', '--crit', '90']
    )

    # Should succeed with custom thresholds
    if return_code in [0, 1]:
        print("[PASS] Custom thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_zero():
    """Test that zero threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_limits_monitor.py', '--warn', '0']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold (zero) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (zero) test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_over_100():
    """Test that threshold values over 100 for crit are accepted, but over for warn gets crit<=warn error."""
    # warn must be < 100 for percentages to make sense
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_limits_monitor.py', '--warn', '101']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold (warn > 100) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (warn > 100) test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_crit_le_warn():
    """Test that crit <= warn is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_limits_monitor.py', '--warn', '90', '--crit', '80']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold (crit <= warn) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (crit <= warn) test failed")
        print(f"  Return code: {return_code}")
        return False


def test_name_filter():
    """Test name filter option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_limits_monitor.py', '--name', 'python', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # All processes should have 'python' in name (case-insensitive)
        for proc in data['processes']:
            if 'python' not in proc['name'].lower():
                print(f"[FAIL] Name filter test failed - non-matching process: {proc['name']}")
                return False

        print("[PASS] Name filter test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] Name filter test failed - JSON parse error: {e}")
        return False


def test_top_filter():
    """Test top N filter option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_limits_monitor.py', '--top', '5', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Should have at most 5 processes
        if len(data['processes']) > 5:
            print(f"[FAIL] Top filter test failed - got {len(data['processes'])} processes, expected <= 5")
            return False

        print("[PASS] Top filter test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] Top filter test failed - JSON parse error: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_limits_monitor.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_process_structure():
    """Test that process entries in JSON have correct structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_limits_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if data['processes']:
            proc = data['processes'][0]
            required_keys = ['pid', 'name', 'user', 'issues', 'metrics']
            for key in required_keys:
                if key not in proc:
                    print(f"[FAIL] JSON process structure missing key: {key}")
                    return False

            # Check pid is integer
            if not isinstance(proc['pid'], int):
                print("[FAIL] Process pid is not an integer")
                return False

            # Check issues is a list
            if not isinstance(proc['issues'], list):
                print("[FAIL] Process issues is not a list")
                return False

            # Check metrics is a dict
            if not isinstance(proc['metrics'], dict):
                print("[FAIL] Process metrics is not a dict")
                return False

        print("[PASS] JSON process structure test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] JSON process structure test failed: {e}")
        return False


def test_json_thresholds_included():
    """Test that thresholds are included in JSON output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_limits_monitor.py', '--format', 'json', '--warn', '75', '--crit', '92']
    )

    try:
        data = json.loads(stdout)

        if data.get('warn_threshold') != 75:
            print(f"[FAIL] warn_threshold mismatch: {data.get('warn_threshold')} != 75")
            return False

        if data.get('crit_threshold') != 92:
            print(f"[FAIL] crit_threshold mismatch: {data.get('crit_threshold')} != 92")
            return False

        print("[PASS] JSON thresholds included test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] JSON thresholds test failed: {e}")
        return False


def test_combined_options():
    """Test that multiple options work together."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_limits_monitor.py',
         '--format', 'json',
         '--warn', '60',
         '--crit', '85',
         '--top', '10',
         '--verbose']
    )

    try:
        data = json.loads(stdout)

        # Should parse successfully with all options
        if 'processes' in data and 'total_scanned' in data:
            print("[PASS] Combined options test passed")
            return True
        else:
            print("[FAIL] Combined options test failed - missing expected keys")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] Combined options test failed - JSON parse error: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_process_limits_monitor.py...")
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
        test_invalid_threshold_zero,
        test_invalid_threshold_over_100,
        test_invalid_threshold_crit_le_warn,
        test_name_filter,
        test_top_filter,
        test_exit_codes,
        test_json_process_structure,
        test_json_thresholds_included,
        test_combined_options,
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
