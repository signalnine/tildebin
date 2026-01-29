#!/usr/bin/env python3
"""
Test script for baremetal_memory_leak_detector.py functionality.
Tests argument parsing and error handling without requiring long monitoring periods.
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
        [sys.executable, 'baremetal_memory_leak_detector.py', '--help']
    )

    if return_code == 0 and 'memory' in stdout.lower() and 'leak' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_duration_zero():
    """Test that zero duration is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py', '--duration', '0']
    )

    if return_code == 2:
        print("[PASS] Zero duration test passed")
        return True
    else:
        print(f"[FAIL] Zero duration should return exit code 2, got {return_code}")
        return False


def test_invalid_duration_negative():
    """Test that negative duration is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py', '--duration', '-10']
    )

    if return_code == 2:
        print("[PASS] Negative duration test passed")
        return True
    else:
        print(f"[FAIL] Negative duration should return exit code 2, got {return_code}")
        return False


def test_invalid_duration_too_large():
    """Test that duration > 3600 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py', '--duration', '7200']
    )

    if return_code == 2:
        print("[PASS] Large duration test passed")
        return True
    else:
        print(f"[FAIL] Duration > 3600 should return exit code 2, got {return_code}")
        return False


def test_invalid_interval_zero():
    """Test that zero interval is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py', '--interval', '0']
    )

    if return_code == 2:
        print("[PASS] Zero interval test passed")
        return True
    else:
        print(f"[FAIL] Zero interval should return exit code 2, got {return_code}")
        return False


def test_invalid_interval_negative():
    """Test that negative interval is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py', '--interval', '-5']
    )

    if return_code == 2:
        print("[PASS] Negative interval test passed")
        return True
    else:
        print(f"[FAIL] Negative interval should return exit code 2, got {return_code}")
        return False


def test_interval_exceeds_duration():
    """Test that interval > duration is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--interval', '30', '--duration', '10']
    )

    if return_code == 2:
        print("[PASS] Interval > duration test passed")
        return True
    else:
        print(f"[FAIL] Interval > duration should return exit code 2, got {return_code}")
        return False


def test_invalid_min_rss_negative():
    """Test that negative min-rss is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py', '--min-rss', '-100']
    )

    if return_code == 2:
        print("[PASS] Negative min-rss test passed")
        return True
    else:
        print(f"[FAIL] Negative min-rss should return exit code 2, got {return_code}")
        return False


def test_invalid_min_growth_negative():
    """Test that negative min-growth is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py', '--min-growth', '-100']
    )

    if return_code == 2:
        print("[PASS] Negative min-growth test passed")
        return True
    else:
        print(f"[FAIL] Negative min-growth should return exit code 2, got {return_code}")
        return False


def test_invalid_min_rate_negative():
    """Test that negative min-rate is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py', '--min-rate', '-50']
    )

    if return_code == 2:
        print("[PASS] Negative min-rate test passed")
        return True
    else:
        print(f"[FAIL] Negative min-rate should return exit code 2, got {return_code}")
        return False


def test_invalid_pid_format():
    """Test that invalid PID format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py', '--pid', 'abc,def']
    )

    if return_code == 2:
        print("[PASS] Invalid PID format test passed")
        return True
    else:
        print(f"[FAIL] Invalid PID format should return exit code 2, got {return_code}")
        return False


def test_format_option():
    """Test that format option is recognized"""
    # Use very short duration to avoid long test times
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--format', 'json', '--duration', '2', '--interval', '1']
    )

    # Should not fail with "invalid choice" error
    if 'invalid choice' not in stderr:
        print("[PASS] Format option test passed")
        return True
    else:
        print("[FAIL] Format option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--format', 'json', '--duration', '2', '--interval', '1']
    )

    # If /proc not available, expected to fail with exit code 2
    if return_code == 2:
        if 'proc' in stderr.lower() or 'sample' in stderr.lower():
            print("[PASS] JSON output format test passed (no /proc access)")
            return True
        else:
            print(f"[FAIL] Expected proc-related error, got: {stderr[:100]}")
            return False

    # If it succeeds, validate JSON
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Validate expected fields
            if 'issues' in data and 'summary' in data:
                print("[PASS] JSON output format test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected fields")
                print(f"  Data keys: {list(data.keys())}")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON parsing failed")
            print(f"  Output: {stdout[:100]}")
            return False

    print(f"[FAIL] Unexpected return code: {return_code}")
    print(f"  Stderr: {stderr[:100]}")
    return False


def test_table_format():
    """Test table format option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--format', 'table', '--duration', '2', '--interval', '1']
    )

    # Should either work or fail with no /proc access
    if return_code == 2:
        if 'proc' in stderr.lower() or 'sample' in stderr.lower():
            print("[PASS] Table format test passed (no /proc access)")
            return True

    # If succeeds, check for table headers or no growth message
    if return_code in [0, 1]:
        if 'Process' in stdout or 'PID' in stdout or 'No significant' in stdout:
            print("[PASS] Table format test passed")
            return True
        else:
            print("[FAIL] Table format missing expected output")
            print(f"  Output: {stdout[:200]}")
            return False

    print(f"[FAIL] Table format test failed with code {return_code}")
    return False


def test_verbose_flag():
    """Test verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--verbose', '--duration', '2', '--interval', '1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_warn_only_flag():
    """Test warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--warn-only', '--duration', '2', '--interval', '1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_pid_option():
    """Test --pid option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--pid', '1', '--duration', '2', '--interval', '1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] PID option test passed")
        return True
    else:
        print("[FAIL] PID option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_multiple_pids():
    """Test comma-separated PIDs"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--pid', '1,2,3', '--duration', '2', '--interval', '1']
    )

    # Should not fail due to PID parsing
    if 'Invalid PID' not in stderr:
        print("[PASS] Multiple PIDs test passed")
        return True
    else:
        print("[FAIL] Multiple PIDs not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--format', 'json', '--verbose', '--warn-only',
         '--duration', '2', '--interval', '1',
         '--min-rss', '1024', '--min-growth', '1024', '--min-rate', '50']
    )

    # Should not fail due to option conflicts
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:100]}")
        return False


def test_exit_code_validity():
    """Test that exit codes are valid (0, 1, or 2)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--duration', '2', '--interval', '1']
    )

    # Valid exit codes: 0 (no growth), 1 (growth detected), 2 (error)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_duration_option():
    """Test that --duration option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py', '--duration', '5']
    )

    # Should not fail due to unrecognized option or invalid value
    if 'unrecognized' not in stderr and 'invalid' not in stderr.lower():
        print("[PASS] Duration option test passed")
        return True
    else:
        print("[FAIL] Duration option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_interval_option():
    """Test that --interval option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--interval', '2', '--duration', '4']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Interval option test passed")
        return True
    else:
        print("[FAIL] Interval option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_min_rss_option():
    """Test that --min-rss option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--min-rss', '5120', '--duration', '2', '--interval', '1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Min-rss option test passed")
        return True
    else:
        print("[FAIL] Min-rss option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_min_growth_option():
    """Test that --min-growth option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--min-growth', '10240', '--duration', '2', '--interval', '1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Min-growth option test passed")
        return True
    else:
        print("[FAIL] Min-growth option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_min_rate_option():
    """Test that --min-rate option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_leak_detector.py',
         '--min-rate', '200', '--duration', '2', '--interval', '1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Min-rate option test passed")
        return True
    else:
        print("[FAIL] Min-rate option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_memory_leak_detector.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_invalid_duration_zero,
        test_invalid_duration_negative,
        test_invalid_duration_too_large,
        test_invalid_interval_zero,
        test_invalid_interval_negative,
        test_interval_exceeds_duration,
        test_invalid_min_rss_negative,
        test_invalid_min_growth_negative,
        test_invalid_min_rate_negative,
        test_invalid_pid_format,
        test_format_option,
        test_json_output_format,
        test_table_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_pid_option,
        test_multiple_pids,
        test_combined_options,
        test_exit_code_validity,
        test_duration_option,
        test_interval_option,
        test_min_rss_option,
        test_min_growth_option,
        test_min_rate_option,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
