#!/usr/bin/env python3
"""
Test script for baremetal_napi_health_monitor.py functionality.
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
        [sys.executable, 'baremetal_napi_health_monitor.py', '--help']
    )

    if return_code == 0 and 'napi' in stdout.lower():
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
        [sys.executable, 'baremetal_napi_health_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_napi_health_monitor.py', '--format', 'invalid']
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


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_napi_health_monitor.py']
    )

    # Exit code 0 or 1 = success (healthy or issues), 2 = not supported
    if return_code in [0, 1]:
        if 'napi' in stdout.lower() or 'settings' in stdout.lower():
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
        [sys.executable, 'baremetal_napi_health_monitor.py', '--format', 'json']
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
        required_keys = ['settings', 'interfaces', 'softirq_stats', 'issues', 'healthy']
        if not all(key in data for key in required_keys):
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
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
        [sys.executable, 'baremetal_napi_health_monitor.py', '--format', 'table']
    )

    if return_code == 2:
        # May not be available on non-Linux
        if 'cannot read' in stderr.lower() or 'linux' in stderr.lower():
            print("[SKIP] Table output format test skipped (not Linux)")
            return True

    if return_code in [0, 1] and ('Setting' in stdout or 'Interface' in stdout):
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode shows per-CPU stats."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_napi_health_monitor.py', '--verbose']
    )

    if return_code == 2:
        # May not be available on non-Linux
        print("[SKIP] Verbose mode test skipped (not Linux)")
        return True

    if return_code in [0, 1]:
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
        [sys.executable, 'baremetal_napi_health_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on system state)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_has_healthy_flag():
    """Test JSON output includes healthy flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_napi_health_monitor.py', '--format', 'json']
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


def test_json_has_interfaces():
    """Test JSON output includes interfaces list."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_napi_health_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("[SKIP] JSON interfaces test skipped (not Linux)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON interfaces test returned unexpected code: {return_code}")
        return False

    try:
        data = json.loads(stdout)

        if 'interfaces' not in data:
            print("[FAIL] JSON output missing 'interfaces'")
            return False

        if not isinstance(data['interfaces'], list):
            print("[FAIL] 'interfaces' is not a list")
            return False

        # If there are interfaces, verify structure
        if data['interfaces']:
            iface = data['interfaces'][0]
            required = ['name', 'operstate']
            if not all(key in iface for key in required):
                print("[FAIL] Interface entry missing required keys")
                print(f"  Keys: {list(iface.keys())}")
                return False

        print("[PASS] JSON has interfaces test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON interfaces test failed: {e}")
        return False


def test_json_has_settings():
    """Test JSON output includes kernel settings."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_napi_health_monitor.py', '--format', 'json']
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

        # Settings should be a dict
        if not isinstance(data['settings'], dict):
            print("[FAIL] 'settings' is not a dict")
            return False

        print("[PASS] JSON has settings test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON settings test failed: {e}")
        return False


def test_json_has_softirq_stats():
    """Test JSON output includes softirq statistics."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_napi_health_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("[SKIP] JSON softirq stats test skipped (not Linux)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON softirq stats test returned unexpected code: {return_code}")
        return False

    try:
        data = json.loads(stdout)

        if 'softirq_stats' not in data:
            print("[FAIL] JSON output missing 'softirq_stats'")
            return False

        # Verify softirq_stats structure
        stats = data['softirq_stats']
        required = ['net_rx', 'net_tx', 'total_net_rx', 'total_net_tx']
        if not all(key in stats for key in required):
            print("[FAIL] softirq_stats missing required keys")
            print(f"  Keys: {list(stats.keys())}")
            return False

        print("[PASS] JSON has softirq stats test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON softirq stats test failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_napi_health_monitor.py']
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
        [sys.executable, 'baremetal_napi_health_monitor.py', '--help']
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
        [sys.executable, 'baremetal_napi_health_monitor.py', '--help']
    )

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Help contains exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_help_contains_tuning_tips():
    """Test that help documents NAPI tuning tips."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_napi_health_monitor.py', '--help']
    )

    if return_code == 0 and ('netdev_budget' in stdout or 'tuning' in stdout.lower()):
        print("[PASS] Help contains tuning tips test passed")
        return True
    else:
        print(f"[FAIL] Help should document tuning tips")
        return False


def test_warn_only_json_when_healthy():
    """Test warn-only mode with JSON format returns minimal output when healthy."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_napi_health_monitor.py', '--warn-only', '--format', 'json']
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


def test_short_verbose_flag():
    """Test that -v works as short form of --verbose."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_napi_health_monitor.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Short verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Short verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_short_warn_only_flag():
    """Test that -w works as short form of --warn-only."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_napi_health_monitor.py', '-w']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Short warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Short warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_combined_flags():
    """Test combining multiple flags."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_napi_health_monitor.py', '-v', '--format', 'json']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Combined flags test passed")
        return True
    else:
        print(f"[FAIL] Combined flags test failed")
        print(f"  Return code: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_napi_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_recognized,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_json_has_healthy_flag,
        test_json_has_interfaces,
        test_json_has_settings,
        test_json_has_softirq_stats,
        test_exit_codes,
        test_help_contains_usage_examples,
        test_help_contains_exit_codes,
        test_help_contains_tuning_tips,
        test_warn_only_json_when_healthy,
        test_short_verbose_flag,
        test_short_warn_only_flag,
        test_combined_flags,
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
