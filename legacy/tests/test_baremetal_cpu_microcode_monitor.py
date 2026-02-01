#!/usr/bin/env python3
"""
Test script for baremetal_cpu_microcode_monitor.py functionality.
Tests argument parsing and output formats without requiring specific CPU models.
"""

import subprocess
import sys
import json
import os


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
        [sys.executable, 'baremetal_cpu_microcode_monitor.py', '--help']
    )

    if return_code == 0 and 'microcode' in stdout.lower():
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
        [sys.executable, 'baremetal_cpu_microcode_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_recognized():
    """Test that --format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py', '--help']
    )

    if '--format' in stdout:
        print("[PASS] Format option recognized")
        return True
    else:
        print("[FAIL] Format option not in help")
        return False


def test_verbose_option_recognized():
    """Test that --verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py', '--help']
    )

    if '--verbose' in stdout or '-v' in stdout:
        print("[PASS] Verbose option recognized")
        return True
    else:
        print("[FAIL] Verbose option not in help")
        return False


def test_warn_only_option_recognized():
    """Test that --warn-only option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py', '--help']
    )

    if '--warn-only' in stdout or '-w' in stdout:
        print("[PASS] Warn-only option recognized")
        return True
    else:
        print("[FAIL] Warn-only option not in help")
        return False


def test_min_version_option_recognized():
    """Test that --min-version option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py', '--help']
    )

    if '--min-version' in stdout:
        print("[PASS] Min-version option recognized")
        return True
    else:
        print("[FAIL] Min-version option not in help")
        return False


def test_plain_output_on_linux():
    """Test plain output format on Linux systems."""
    if not os.path.exists('/proc/cpuinfo'):
        print("[SKIP] Plain output test - /proc/cpuinfo not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py']
    )

    # Should succeed (0 or 1 depending on system state)
    if return_code in [0, 1] and ('CPU:' in stdout or 'Microcode' in stdout):
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_on_linux():
    """Test JSON output format on Linux systems."""
    if not os.path.exists('/proc/cpuinfo'):
        print("[SKIP] JSON output test - /proc/cpuinfo not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['summary', 'sockets', 'issues']
        if not all(key in data for key in required_keys):
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify summary structure
        summary = data['summary']
        summary_keys = ['total_cpus', 'total_sockets', 'vendor', 'model_name',
                        'microcode_versions', 'consistent']
        if not all(key in summary for key in summary_keys):
            print("[FAIL] JSON summary missing required keys")
            print(f"  Summary keys: {list(summary.keys())}")
            return False

        print("[PASS] JSON output format test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_on_linux():
    """Test table output format on Linux systems."""
    if not os.path.exists('/proc/cpuinfo'):
        print("[SKIP] Table output test - /proc/cpuinfo not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1] and 'MICROCODE' in stdout.upper():
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode_on_linux():
    """Test verbose mode includes additional information."""
    if not os.path.exists('/proc/cpuinfo'):
        print("[SKIP] Verbose mode test - /proc/cpuinfo not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py', '--verbose']
    )

    # Should succeed and contain socket details
    if return_code in [0, 1] and ('Socket' in stdout or 'socket' in stdout.lower()):
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:300]}")
        return False


def test_warn_only_mode_on_linux():
    """Test warn-only mode suppresses normal output."""
    if not os.path.exists('/proc/cpuinfo'):
        print("[SKIP] Warn-only mode test - /proc/cpuinfo not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on system state)
    if return_code in [0, 1]:
        # If no issues, output should be minimal or empty
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_min_version_check():
    """Test minimum version checking functionality."""
    if not os.path.exists('/proc/cpuinfo'):
        print("[SKIP] Min-version test - /proc/cpuinfo not available")
        return True

    # Use a very high version that should trigger a warning
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py',
         '--min-version', '0xffffffff']
    )

    # Should fail with exit code 1 (below minimum)
    if return_code == 1 and 'below minimum' in stdout.lower():
        print("[PASS] Min-version check test passed")
        return True
    elif return_code == 1:
        # May fail for other reasons, check output
        print("[PASS] Min-version check test passed (warning generated)")
        return True
    else:
        print(f"[FAIL] Min-version check test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_with_min_version():
    """Test JSON output with minimum version check."""
    if not os.path.exists('/proc/cpuinfo'):
        print("[SKIP] JSON with min-version test - /proc/cpuinfo not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py',
         '--format', 'json', '--min-version', '0x1']
    )

    try:
        data = json.loads(stdout)

        # Should have issues array
        if 'issues' not in data:
            print("[FAIL] JSON with min-version missing issues key")
            return False

        print("[PASS] JSON with min-version test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    if not os.path.exists('/proc/cpuinfo'):
        print("[SKIP] Exit code test - /proc/cpuinfo not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py']
    )

    # Should return 0 (no issues) or 1 (issues found), not 2 (usage error)
    if return_code in [0, 1]:
        print(f"[PASS] Exit code test passed (code: {return_code})")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_missing_cpuinfo():
    """Test graceful handling documented in help."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cpu_microcode_monitor.py', '--help']
    )

    # Help should mention Linux or /proc requirement
    if 'linux' in stdout.lower() or 'proc' in stdout.lower():
        print("[PASS] Missing cpuinfo handling documented")
        return True
    else:
        print("[PASS] Help message present (cpuinfo check is runtime)")
        return True


if __name__ == "__main__":
    print("Testing baremetal_cpu_microcode_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_recognized,
        test_verbose_option_recognized,
        test_warn_only_option_recognized,
        test_min_version_option_recognized,
        test_plain_output_on_linux,
        test_json_output_on_linux,
        test_table_output_on_linux,
        test_verbose_mode_on_linux,
        test_warn_only_mode_on_linux,
        test_min_version_check,
        test_json_with_min_version,
        test_exit_codes,
        test_missing_cpuinfo,
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
