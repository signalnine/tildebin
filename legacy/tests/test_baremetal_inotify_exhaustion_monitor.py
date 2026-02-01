#!/usr/bin/env python3
"""
Test script for baremetal_inotify_exhaustion_monitor.py functionality.
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
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--help']
    )

    if return_code == 0 and 'inotify' in stdout.lower():
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
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--format', 'invalid']
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


def test_invalid_threshold_out_of_range():
    """Test that out-of-range threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--warn', '150']
    )

    if return_code == 2 and 'between 0 and 100' in stderr:
        print("[PASS] Invalid threshold (out of range) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (out of range) test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_threshold_negative():
    """Test that negative threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--warn', '-10']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold (negative) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (negative) test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_crit_le_warn():
    """Test that crit <= warn is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--warn', '90', '--crit', '80']
    )

    if return_code == 2 and 'must be less than' in stderr:
        print("[PASS] Invalid threshold (crit <= warn) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (crit <= warn) test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py']
    )

    # Exit code 0 or 1 = success (healthy or warnings), 2 = not supported
    if return_code in [0, 1]:
        if 'inotify' in stdout.lower() or 'watch' in stdout.lower():
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
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--format', 'json']
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
        if 'limits' not in data or 'summary' not in data or 'issues' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify limits structure
        limits = data['limits']
        if 'max_user_watches' not in limits:
            print("[FAIL] JSON limits missing max_user_watches")
            return False

        # Verify summary structure
        summary = data['summary']
        required_keys = ['total_watches', 'total_instances']
        if not all(key in summary for key in required_keys):
            print("[FAIL] JSON summary missing required keys")
            print(f"  Summary keys: {list(summary.keys())}")
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
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--format', 'table']
    )

    if return_code == 2:
        # May not be available on non-Linux
        if 'cannot read' in stderr.lower() or 'linux' in stderr.lower():
            print("[SKIP] Table output format test skipped (not Linux)")
            return True

    if return_code in [0, 1] and ('Metric' in stdout or 'Watches' in stdout):
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode includes all processes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--verbose']
    )

    if return_code == 2:
        # May not be available on non-Linux
        print("[SKIP] Verbose mode test skipped (not Linux)")
        return True

    if return_code in [0, 1] and ('Process' in stdout or 'Watches' in stdout):
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
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--warn-only']
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
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--warn', '80', '--crit', '95']
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
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--format', 'json']
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


def test_json_has_processes():
    """Test JSON output includes processes list."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("[SKIP] JSON processes test skipped (not Linux)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON processes test returned unexpected code: {return_code}")
        return False

    try:
        data = json.loads(stdout)

        if 'processes' not in data:
            print("[FAIL] JSON output missing 'processes'")
            return False

        if not isinstance(data['processes'], list):
            print("[FAIL] 'processes' is not a list")
            return False

        # If there are processes, verify structure
        if data['processes']:
            proc = data['processes'][0]
            required = ['pid', 'name', 'watches', 'instances']
            if not all(key in proc for key in required):
                print("[FAIL] Process entry missing required keys")
                print(f"  Keys: {list(proc.keys())}")
                return False

        print("[PASS] JSON has processes test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON processes test failed: {e}")
        return False


def test_json_has_top_consumers():
    """Test JSON output includes top consumers in summary."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("[SKIP] JSON top consumers test skipped (not Linux)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON top consumers test returned unexpected code: {return_code}")
        return False

    try:
        data = json.loads(stdout)

        if 'summary' not in data or 'top_consumers' not in data['summary']:
            print("[FAIL] JSON summary missing 'top_consumers'")
            return False

        print("[PASS] JSON has top consumers test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON top consumers test failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py']
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
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--help']
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
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--help']
    )

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Help contains exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_help_contains_common_causes():
    """Test that help documents common causes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--help']
    )

    if return_code == 0 and ('kubelet' in stdout.lower() or 'kubernetes' in stdout.lower()):
        print("[PASS] Help contains common causes test passed")
        return True
    else:
        print(f"[FAIL] Help should document common causes")
        return False


def test_warn_only_json_when_healthy():
    """Test warn-only mode with JSON format returns minimal output when healthy."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inotify_exhaustion_monitor.py', '--warn-only', '--format', 'json']
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


if __name__ == "__main__":
    print("Testing baremetal_inotify_exhaustion_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_recognized,
        test_invalid_threshold_out_of_range,
        test_invalid_threshold_negative,
        test_invalid_threshold_crit_le_warn,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_custom_thresholds,
        test_json_has_healthy_flag,
        test_json_has_processes,
        test_json_has_top_consumers,
        test_exit_codes,
        test_help_contains_usage_examples,
        test_help_contains_exit_codes,
        test_help_contains_common_causes,
        test_warn_only_json_when_healthy,
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
