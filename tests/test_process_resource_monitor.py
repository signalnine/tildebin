#!/usr/bin/env python3
"""
Test script for process_resource_monitor.py functionality.
Tests argument parsing and error handling without requiring specific processes.
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
        [sys.executable, 'process_resource_monitor.py', '--help']
    )

    if return_code == 0 and 'Monitor process resource consumption' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_plain_output():
    """Test plain text output format (default)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py']
    )

    # Should succeed and show process info
    if 'Total processes:' in stdout and 'Memory Consumers' in stdout:
        print("[PASS] Plain output test passed")
        return True
    else:
        print(f"[FAIL] Plain output test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_output():
    """Test JSON output format"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py', '--format', 'json']
    )

    # Should succeed and output valid JSON
    try:
        data = json.loads(stdout)
        if 'total_processes' in data and 'top_cpu' in data and 'top_memory' in data:
            print("[PASS] JSON output test passed")
            return True
        else:
            print(f"[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON output test failed - invalid JSON")
        print(f"  Error: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output():
    """Test table output format"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py', '--format', 'table']
    )

    # Should succeed and show table headers
    if 'PROCESS RESOURCE MONITOR' in stdout and 'Total Processes:' in stdout:
        print("[PASS] Table output test passed")
        return True
    else:
        print(f"[FAIL] Table output test failed")
        print(f"  Output: {stdout[:200]}")
        return False


def test_top_n_option():
    """Test --top-n option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py', '--top-n', '5', '--format', 'json']
    )

    if return_code in [0, 1]:  # 0 or 1 both valid (depends on system state)
        try:
            data = json.loads(stdout)
            # Check that we got at most 5 entries (could be fewer if system has fewer processes)
            if len(data['top_cpu']) <= 5 and len(data['top_memory']) <= 5:
                print("[PASS] Top-n option test passed")
                return True
            else:
                print(f"[FAIL] Top-n returned more than requested")
                print(f"  CPU: {len(data['top_cpu'])}, Mem: {len(data['top_memory'])}")
                return False
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[FAIL] Top-n option test failed - JSON error: {e}")
            return False
    else:
        print(f"[FAIL] Top-n option test failed - unexpected return code: {return_code}")
        return False


def test_invalid_top_n():
    """Test that invalid --top-n is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py', '--top-n', '0']
    )

    if return_code == 2 and 'must be at least 1' in stderr:
        print("[PASS] Invalid top-n test passed")
        return True
    else:
        print(f"[FAIL] Invalid top-n should return exit code 2")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr}")
        return False


def test_mem_threshold_option():
    """Test --mem-threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py', '--mem-threshold', '50', '--format', 'json']
    )

    if return_code in [0, 1]:  # Valid return codes
        try:
            data = json.loads(stdout)
            if 'thresholds_exceeded' in data and 'mem_exceeded' in data['thresholds_exceeded']:
                print("[PASS] Memory threshold option test passed")
                return True
            else:
                print(f"[FAIL] Memory threshold output missing expected data")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] Memory threshold test failed - JSON error: {e}")
            return False
    else:
        print(f"[FAIL] Memory threshold test failed - return code: {return_code}")
        return False


def test_invalid_mem_threshold():
    """Test that invalid --mem-threshold is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py', '--mem-threshold', '150']
    )

    if return_code == 2 and 'must be between 0 and 100' in stderr:
        print("[PASS] Invalid memory threshold test passed")
        return True
    else:
        print(f"[FAIL] Invalid memory threshold should return exit code 2")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr}")
        return False


def test_by_user_option():
    """Test --by-user option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py', '--by-user', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'process_count_by_user' in data and isinstance(data['process_count_by_user'], dict):
                print("[PASS] By-user option test passed")
                return True
            else:
                print(f"[FAIL] By-user output missing expected data")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] By-user test failed - JSON error: {e}")
            return False
    else:
        print(f"[FAIL] By-user test failed - return code: {return_code}")
        return False


def test_warn_only_option():
    """Test --warn-only option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py', '--warn-only']
    )

    # Should run successfully, output may be empty if no warnings
    if return_code in [0, 1]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py', '--format', 'xml']
    )

    # argparse should reject invalid choice
    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_option():
    """Test --verbose option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py', '--verbose']
    )

    # Should run successfully
    if return_code in [0, 1]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_combined_options():
    """Test combination of multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py',
         '--format', 'json',
         '--top-n', '3',
         '--mem-threshold', '10',
         '--by-user']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check all expected keys are present
            expected_keys = ['total_processes', 'top_cpu', 'top_memory',
                           'thresholds_exceeded', 'process_count_by_user']
            if all(key in data for key in expected_keys):
                print("[PASS] Combined options test passed")
                return True
            else:
                missing = [k for k in expected_keys if k not in data]
                print(f"[FAIL] Combined options missing keys: {missing}")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] Combined options test failed - JSON error: {e}")
            return False
    else:
        print(f"[FAIL] Combined options test failed - return code: {return_code}")
        return False


def test_exit_codes():
    """Test that exit codes are correct"""
    # Test successful execution (no issues)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'process_resource_monitor.py', '--mem-threshold', '99']
    )

    # Should return 0 (no processes using >99% memory) or 1 (some edge case)
    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (normal execution)")
        return True
    else:
        print(f"[FAIL] Exit code test failed - unexpected code: {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing process_resource_monitor.py...")
    print("=" * 70)

    tests = [
        test_help_message,
        test_plain_output,
        test_json_output,
        test_table_output,
        test_top_n_option,
        test_invalid_top_n,
        test_mem_threshold_option,
        test_invalid_mem_threshold,
        test_by_user_option,
        test_warn_only_option,
        test_invalid_format,
        test_verbose_option,
        test_combined_options,
        test_exit_codes,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("=" * 70)
    print(f"\nTest Results: {passed}/{total} tests passed")

    if passed == total:
        print("✓ All tests passed!")
        sys.exit(0)
    else:
        print(f"✗ {total - passed} test(s) failed")
        sys.exit(1)
