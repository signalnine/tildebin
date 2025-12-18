#!/usr/bin/env python3
"""
Test script for baremetal_oom_risk_analyzer.py functionality.
Tests argument parsing and output formats without requiring specific OOM conditions.
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
        [sys.executable, 'baremetal_oom_risk_analyzer.py', '--help']
    )

    if return_code == 0 and 'oom' in stdout.lower():
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
        [sys.executable, 'baremetal_oom_risk_analyzer.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_oom_risk_analyzer.py']
    )

    # Should succeed (exit 0 or 1 depending on OOM scores)
    if return_code in [0, 1] and ('System memory:' in stdout or 'Top' in stdout):
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
        [sys.executable, 'baremetal_oom_risk_analyzer.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'system' not in data or 'top_processes' not in data or 'issues' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify system data structure
        system = data['system']
        required_system_keys = ['mem_total_kb', 'processes_analyzed']
        if not all(key in system for key in required_system_keys):
            print("[FAIL] JSON system data missing required keys")
            print(f"  System keys: {list(system.keys())}")
            return False

        # Verify top_processes is a list
        if not isinstance(data['top_processes'], list):
            print("[FAIL] top_processes is not a list")
            return False

        # Verify process structure if there are any
        if len(data['top_processes']) > 0:
            proc = data['top_processes'][0]
            required_proc_keys = ['pid', 'name', 'oom_score', 'rss_kb', 'risk_level']
            if not all(key in proc for key in required_proc_keys):
                print("[FAIL] Process data missing required keys")
                print(f"  Process keys: {list(proc.keys())}")
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
        [sys.executable, 'baremetal_oom_risk_analyzer.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and ('OOM RISK' in stdout or 'Risk' in stdout):
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_risk_analyzer.py', '--warn-only']
    )

    # Should succeed (exit code depends on OOM state)
    # Output might be empty if no warnings
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
        [sys.executable, 'baremetal_oom_risk_analyzer.py', '--warn', '400', '--crit', '700']
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
    # Test warn >= crit
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_risk_analyzer.py', '--warn', '800', '--crit', '700']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold range test passed (warn >= crit)")
        return True
    else:
        print(f"[FAIL] Invalid threshold range test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_top_n_option():
    """Test --top option for limiting output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_risk_analyzer.py', '--top', '5']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Top N option test passed")
        return True
    else:
        print(f"[FAIL] Top N option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_top_n():
    """Test that invalid --top value is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_risk_analyzer.py', '--top', '0']
    )

    if return_code == 2:
        print("[PASS] Invalid top N test passed")
        return True
    else:
        print(f"[FAIL] Invalid top N test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_contains_thresholds():
    """Test JSON output includes threshold settings."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_risk_analyzer.py', '--format', 'json',
         '--warn', '300', '--crit', '600']
    )

    try:
        data = json.loads(stdout)

        if 'thresholds' not in data:
            print("[FAIL] JSON output missing thresholds")
            return False

        thresholds = data['thresholds']
        if thresholds.get('warn') == 300 and thresholds.get('crit') == 600:
            print("[PASS] JSON thresholds test passed")
            return True
        else:
            print(f"[FAIL] Thresholds not as expected: {thresholds}")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_risk_analyzer.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_short_top_option():
    """Test -n short form of --top option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_risk_analyzer.py', '-n', '10']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Short form -n option test passed")
        return True
    else:
        print(f"[FAIL] Short form -n option test failed")
        print(f"  Return code: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_oom_risk_analyzer.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_warn_only_mode,
        test_custom_thresholds,
        test_invalid_threshold_range,
        test_top_n_option,
        test_invalid_top_n,
        test_json_contains_thresholds,
        test_exit_codes,
        test_short_top_option,
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
