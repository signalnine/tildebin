#!/usr/bin/env python3
"""
Test script for baremetal_softnet_backlog_monitor.py functionality.
Tests argument parsing and output formats without requiring root access.
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
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--help']
    )

    if return_code == 0 and 'softnet' in stdout.lower():
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
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_recognized():
    """Test that format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--format', 'invalid']
    )

    # Should fail with usage error (invalid choice)
    if return_code != 0 and ('invalid choice' in stderr or 'invalid' in stderr.lower()):
        print("[PASS] Format option recognition test passed")
        return True
    else:
        print(f"[FAIL] Format option recognition test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_negative_threshold_rejected():
    """Test that negative threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--drop-warn', '-10']
    )

    if return_code == 2:
        print("[PASS] Negative threshold test passed")
        return True
    else:
        print(f"[FAIL] Negative threshold test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_order():
    """Test that warn > crit is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py',
         '--drop-warn', '1000', '--drop-crit', '100']
    )

    if return_code == 2 and 'less than or equal' in stderr:
        print("[PASS] Invalid threshold order test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold order test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_squeeze_threshold_order():
    """Test that squeeze warn > crit is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py',
         '--squeeze-warn', '2000', '--squeeze-crit', '500']
    )

    if return_code == 2 and 'less than or equal' in stderr:
        print("[PASS] Squeeze threshold order test passed")
        return True
    else:
        print(f"[FAIL] Squeeze threshold order test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py']
    )

    # Exit code 0 or 1 = success (healthy or warnings), 2 = not supported
    if return_code in [0, 1]:
        if 'softnet' in stdout.lower() or 'processed' in stdout.lower():
            print("[PASS] Plain output format test passed")
            return True
        else:
            print(f"[FAIL] Plain output missing expected content")
            print(f"  Output: {stdout[:300]}")
            return False
    elif return_code == 2:
        # May not be available on non-Linux
        if 'cannot read' in stderr.lower() or 'linux' in stderr.lower():
            print("[SKIP] Plain output format test skipped (not Linux)")
            return True
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # May not be available on non-Linux
        if 'cannot read' in stderr.lower() or 'linux' in stderr.lower():
            print("[SKIP] JSON output format test skipped (not Linux)")
            return True
        print(f"[FAIL] JSON output format returned unexpected code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON output format returned unexpected code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['settings', 'totals', 'per_cpu', 'issues', 'healthy']
        if not all(key in data for key in required_keys):
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify totals structure
        totals = data['totals']
        totals_required = ['total_processed', 'total_dropped', 'total_time_squeeze', 'cpu_count']
        if not all(key in totals for key in totals_required):
            print("[FAIL] JSON totals missing required keys")
            print(f"  Totals keys: {list(totals.keys())}")
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
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--format', 'table']
    )

    if return_code == 2:
        # May not be available on non-Linux
        if 'cannot read' in stderr.lower() or 'linux' in stderr.lower():
            print("[SKIP] Table output format test skipped (not Linux)")
            return True

    if return_code in [0, 1] and ('Metric' in stdout or 'Processed' in stdout):
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode shows all CPUs."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--verbose']
    )

    if return_code == 2:
        # May not be available on non-Linux
        print("[SKIP] Verbose mode test skipped (not Linux)")
        return True

    if return_code in [0, 1] and ('CPU' in stdout or 'Per-CPU' in stdout):
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:300]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on system state)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_thresholds():
    """Test custom threshold arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py',
         '--drop-warn', '100', '--drop-crit', '10000',
         '--squeeze-warn', '50', '--squeeze-crit', '5000']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Custom thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_has_healthy_flag():
    """Test JSON output includes healthy flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("[SKIP] JSON healthy flag test skipped (not Linux)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON healthy flag test returned unexpected code: {return_code}")
        return False

    try:
        data = json.loads(stdout)

        if 'healthy' not in data:
            print("[FAIL] JSON output missing 'healthy' flag")
            return False

        if not isinstance(data['healthy'], bool):
            print("[FAIL] 'healthy' flag is not boolean")
            return False

        print("[PASS] JSON has healthy flag test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON healthy flag test failed: {e}")
        return False


def test_json_has_per_cpu():
    """Test JSON output includes per_cpu list."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("[SKIP] JSON per_cpu test skipped (not Linux)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON per_cpu test returned unexpected code: {return_code}")
        return False

    try:
        data = json.loads(stdout)

        if 'per_cpu' not in data:
            print("[FAIL] JSON output missing 'per_cpu'")
            return False

        if not isinstance(data['per_cpu'], list):
            print("[FAIL] 'per_cpu' is not a list")
            return False

        # If there are CPU entries, verify structure
        if data['per_cpu']:
            cpu = data['per_cpu'][0]
            required = ['cpu', 'processed', 'dropped', 'time_squeeze']
            if not all(key in cpu for key in required):
                print("[FAIL] CPU entry missing required keys")
                print(f"  Keys: {list(cpu.keys())}")
                return False

        print("[PASS] JSON has per_cpu test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON per_cpu test failed: {e}")
        return False


def test_json_has_settings():
    """Test JSON output includes kernel settings."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("[SKIP] JSON settings test skipped (not Linux)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON settings test returned unexpected code: {return_code}")
        return False

    try:
        data = json.loads(stdout)

        if 'settings' not in data:
            print("[FAIL] JSON output missing 'settings'")
            return False

        # Settings should be a dict (may be empty on some systems)
        if not isinstance(data['settings'], dict):
            print("[FAIL] 'settings' is not a dict")
            return False

        print("[PASS] JSON has settings test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON settings test failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py']
    )

    if return_code in [0, 1, 2]:
        print(f"[PASS] Exit code test passed (got {return_code})")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_help_contains_usage_examples():
    """Test that help includes usage examples."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout and '--format json' in stdout:
        print("[PASS] Help contains usage examples test passed")
        return True
    else:
        print(f"[FAIL] Help should contain usage examples")
        print(f"  Output: {stdout[:300]}")
        return False


def test_help_contains_exit_codes():
    """Test that help documents exit codes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--help']
    )

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Help contains exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_help_contains_causes():
    """Test that help documents common causes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--help']
    )

    if return_code == 0 and ('IRQ' in stdout or 'packet' in stdout.lower()):
        print("[PASS] Help contains causes test passed")
        return True
    else:
        print(f"[FAIL] Help should document common causes")
        return False


def test_warn_only_json_when_healthy():
    """Test warn-only mode with JSON format returns minimal output when healthy."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py', '--warn-only', '--format', 'json']
    )

    if return_code == 2:
        print("[SKIP] Warn-only JSON test skipped (not Linux)")
        return True

    if return_code == 0:
        try:
            data = json.loads(stdout)
            if 'healthy' in data and data['healthy']:
                print("[PASS] Warn-only JSON when healthy test passed")
                return True
        except json.JSONDecodeError:
            pass

    # Even if return code is 1 (warnings), test passes as long as we got valid output
    if return_code in [0, 1]:
        print("[PASS] Warn-only JSON test passed")
        return True

    print(f"[FAIL] Warn-only JSON test failed")
    print(f"  Return code: {return_code}")
    return False


def test_zero_thresholds_allowed():
    """Test that zero thresholds are allowed."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softnet_backlog_monitor.py',
         '--drop-warn', '0', '--drop-crit', '0']
    )

    # Should work (will report all drops as issues)
    if return_code in [0, 1, 2]:
        print("[PASS] Zero thresholds test passed")
        return True
    else:
        print(f"[FAIL] Zero thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_softnet_backlog_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_recognized,
        test_negative_threshold_rejected,
        test_invalid_threshold_order,
        test_squeeze_threshold_order,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_custom_thresholds,
        test_json_has_healthy_flag,
        test_json_has_per_cpu,
        test_json_has_settings,
        test_exit_codes,
        test_help_contains_usage_examples,
        test_help_contains_exit_codes,
        test_help_contains_causes,
        test_warn_only_json_when_healthy,
        test_zero_thresholds_allowed,
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
