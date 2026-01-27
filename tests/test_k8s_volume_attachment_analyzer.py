#!/usr/bin/env python3
"""
Test script for k8s_volume_attachment_analyzer.py functionality.
Tests argument parsing and error handling without requiring kubectl access.
"""

import subprocess
import sys


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
        [sys.executable, 'k8s_volume_attachment_analyzer.py', '--help']
    )

    if return_code == 0 and 'VolumeAttachment' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_format_option():
    """Test that invalid format options are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_volume_attachment_analyzer.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_format_options_accepted():
    """Test that valid format options are accepted (will fail at kubectl stage)"""
    formats = ['plain', 'json', 'table']
    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_volume_attachment_analyzer.py', '--format', fmt]
        )

        # Script will fail because kubectl is not available or no cluster
        # Exit code 2 means kubectl not found (expected)
        # Exit code 1 means kubectl error (also acceptable for test)
        if return_code in [1, 2]:
            print(f"[PASS] Format option '{fmt}' accepted")
        else:
            print(f"[FAIL] Format option '{fmt}' not properly handled")
            print(f"  Return code: {return_code}")
            return False

    return True


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_volume_attachment_analyzer.py', '--warn-only']
    )

    # Will fail at kubectl stage, but should accept the flag
    if return_code in [1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not properly handled")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_flag():
    """Test that verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_volume_attachment_analyzer.py', '-v']
    )

    # Will fail at kubectl stage, but should accept the flag
    if return_code in [1, 2]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not properly handled")
        print(f"  Return code: {return_code}")
        return False


def test_stale_hours_option():
    """Test that stale-hours option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_volume_attachment_analyzer.py', '--stale-hours', '12']
    )

    # Will fail at kubectl stage, but should accept the option
    if return_code in [1, 2]:
        print("[PASS] Stale-hours option test passed")
        return True
    else:
        print("[FAIL] Stale-hours option not properly handled")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_stale_hours():
    """Test that invalid stale-hours values are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_volume_attachment_analyzer.py', '--stale-hours', 'invalid']
    )

    if return_code != 0:
        print("[PASS] Invalid stale-hours test passed")
        return True
    else:
        print("[FAIL] Invalid stale-hours should be rejected")
        return False


def test_kubectl_not_found_exit_code():
    """Test that missing kubectl returns exit code 2"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_volume_attachment_analyzer.py']
    )

    # Should exit with code 2 if kubectl not found, or 1 if kubectl fails
    if return_code in [1, 2]:
        if return_code == 2 and 'kubectl' in stderr.lower():
            print("[PASS] kubectl not found exit code test passed (exit code 2)")
        else:
            print("[PASS] Script handles kubectl errors appropriately (exit code 1)")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_short_options():
    """Test short option flags"""
    # Test -w (warn-only)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_volume_attachment_analyzer.py', '-w']
    )
    if return_code not in [1, 2]:
        print("[FAIL] Short option -w not working")
        return False

    # Test -v (verbose)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_volume_attachment_analyzer.py', '-v']
    )
    if return_code not in [1, 2]:
        print("[FAIL] Short option -v not working")
        return False

    print("[PASS] Short options test passed")
    return True


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_volume_attachment_analyzer.py',
         '--format', 'json', '--warn-only', '--stale-hours', '6']
    )

    # Will fail at kubectl stage, but should accept all options
    if return_code in [1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options not properly handled")
        print(f"  Return code: {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing k8s_volume_attachment_analyzer.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_format_option,
        test_format_options_accepted,
        test_warn_only_flag,
        test_verbose_flag,
        test_stale_hours_option,
        test_invalid_stale_hours,
        test_kubectl_not_found_exit_code,
        test_short_options,
        test_combined_options,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    print("=" * 60)

    sys.exit(0 if passed == total else 1)
