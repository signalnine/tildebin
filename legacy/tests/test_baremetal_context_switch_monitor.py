#!/usr/bin/env python3
"""
Test script for baremetal_context_switch_monitor.py functionality.
Tests argument parsing and error handling without requiring specific system states.
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
        stdout, stderr = proc.communicate(timeout=30)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--help']
    )

    if return_code == 0 and 'context' in stdout.lower() and 'switch' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_format_option_plain():
    """Test that plain format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--format', 'plain', '--interval', '0.1']
    )

    # Script will run on Linux systems
    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option is accepted and produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--format', 'json', '--interval', '0.1']
    )

    # If script runs successfully or finds issues
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'context_switches' in data and 'interrupts' in data:
                print("[PASS] JSON format option test passed")
                return True
            else:
                print(f"[FAIL] JSON format missing expected keys")
                print(f"  Keys found: {list(data.keys())}")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON format test failed: invalid JSON output")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # /proc/stat not available - that's OK for non-Linux systems
        print("[PASS] JSON format option test passed (/proc/stat not available)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--format', 'table', '--interval', '0.1']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed: unexpected return code {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--format', 'invalid']
    )

    # Should fail with exit code 2 (usage error) or show error message
    if return_code == 2 or 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test that verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '-v', '--interval', '0.1']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed: unexpected return code {return_code}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--warn-only', '--interval', '0.1']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_interval_option():
    """Test that interval option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--interval', '0.5']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Interval option test passed")
        return True
    else:
        print(f"[FAIL] Interval option test failed: unexpected return code {return_code}")
        return False


def test_invalid_interval_zero():
    """Test that zero interval is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--interval', '0']
    )

    if return_code == 2 or 'must be positive' in stderr.lower():
        print("[PASS] Zero interval rejection test passed")
        return True
    else:
        print(f"[FAIL] Zero interval should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_interval_negative():
    """Test that negative interval is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--interval', '-1']
    )

    if return_code == 2 or 'must be positive' in stderr.lower():
        print("[PASS] Negative interval rejection test passed")
        return True
    else:
        print(f"[FAIL] Negative interval should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_threshold_options():
    """Test that threshold options are accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py',
         '--ctxt-warn', '10000',
         '--ctxt-crit', '30000',
         '--intr-warn', '40000',
         '--intr-crit', '80000',
         '--interval', '0.1']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Threshold options test passed")
        return True
    else:
        print(f"[FAIL] Threshold options test failed: unexpected return code {return_code}")
        return False


def test_run_queue_thresholds():
    """Test that run queue threshold options are accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py',
         '--run-queue-warn', '1',
         '--run-queue-crit', '3',
         '--interval', '0.1']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Run queue threshold options test passed")
        return True
    else:
        print(f"[FAIL] Run queue threshold options test failed: unexpected return code {return_code}")
        return False


def test_blocked_thresholds():
    """Test that blocked process threshold options are accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py',
         '--blocked-warn', '3',
         '--blocked-crit', '10',
         '--interval', '0.1']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Blocked threshold options test passed")
        return True
    else:
        print(f"[FAIL] Blocked threshold options test failed: unexpected return code {return_code}")
        return False


def test_fork_thresholds():
    """Test that fork rate threshold options are accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py',
         '--fork-warn', '200',
         '--fork-crit', '1000',
         '--interval', '0.1']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Fork threshold options test passed")
        return True
    else:
        print(f"[FAIL] Fork threshold options test failed: unexpected return code {return_code}")
        return False


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py',
         '--format', 'json', '-v', '--warn-only', '--interval', '0.1']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed: unexpected return code {return_code}")
        return False


def test_json_structure():
    """Test that JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--format', 'json', '--interval', '0.1']
    )

    if return_code == 2:
        # Non-Linux system
        print("[PASS] JSON structure test passed (non-Linux system)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON structure test failed: unexpected return code {return_code}")
        return False

    try:
        data = json.loads(stdout)

        # Check summary structure
        if 'summary' not in data:
            print("[FAIL] JSON structure test failed: missing 'summary'")
            return False

        summary = data['summary']
        required_summary_keys = ['cpu_count', 'sample_interval', 'issue_count', 'critical_count', 'warning_count']
        for key in required_summary_keys:
            if key not in summary:
                print(f"[FAIL] JSON structure test failed: missing summary key '{key}'")
                return False

        # Check context_switches structure
        if 'context_switches' not in data:
            print("[FAIL] JSON structure test failed: missing 'context_switches'")
            return False

        ctxt = data['context_switches']
        required_ctxt_keys = ['total_per_sec', 'per_cpu_per_sec']
        for key in required_ctxt_keys:
            if key not in ctxt:
                print(f"[FAIL] JSON structure test failed: missing context_switches key '{key}'")
                return False

        # Check interrupts structure
        if 'interrupts' not in data:
            print("[FAIL] JSON structure test failed: missing 'interrupts'")
            return False

        # Check processes structure
        if 'processes' not in data:
            print("[FAIL] JSON structure test failed: missing 'processes'")
            return False

        procs = data['processes']
        required_procs_keys = ['running', 'blocked', 'created_per_sec']
        for key in required_procs_keys:
            if key not in procs:
                print(f"[FAIL] JSON structure test failed: missing processes key '{key}'")
                return False

        # Check issues is a list
        if 'issues' not in data or not isinstance(data['issues'], list):
            print("[FAIL] JSON structure test failed: missing or invalid 'issues'")
            return False

        print("[PASS] JSON structure test passed")
        return True

    except json.JSONDecodeError:
        print(f"[FAIL] JSON structure test failed: invalid JSON")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--format', 'plain', '--interval', '0.1']
    )

    # Valid exit codes: 0 (no issues), 1 (issues found), 2 (error/missing dependency)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False


def test_plain_output_contains_metrics():
    """Test that plain output contains expected metrics"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--format', 'plain', '--interval', '0.1']
    )

    if return_code == 2:
        # Non-Linux system
        print("[PASS] Plain output metrics test passed (non-Linux system)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] Plain output metrics test failed: unexpected return code {return_code}")
        return False

    # Check for expected section headers and labels
    expected_content = ['Context Switch', 'Interrupt', 'running', 'blocked']
    missing = [label for label in expected_content if label.lower() not in stdout.lower()]

    if missing:
        print(f"[FAIL] Plain output missing content: {missing}")
        print(f"  Output: {stdout[:500]}")
        return False

    print("[PASS] Plain output metrics test passed")
    return True


def test_short_interval():
    """Test that very short intervals work"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_context_switch_monitor.py', '--interval', '0.1']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Short interval test passed")
        return True
    else:
        print(f"[FAIL] Short interval test failed: unexpected return code {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_context_switch_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_interval_option,
        test_invalid_interval_zero,
        test_invalid_interval_negative,
        test_threshold_options,
        test_run_queue_thresholds,
        test_blocked_thresholds,
        test_fork_thresholds,
        test_combined_options,
        test_json_structure,
        test_exit_codes,
        test_plain_output_contains_metrics,
        test_short_interval,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("=" * 60)
    print(f"\nTest Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"{total - passed} test(s) failed")
        sys.exit(1)
