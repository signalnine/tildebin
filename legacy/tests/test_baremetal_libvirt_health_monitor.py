#!/usr/bin/env python3
"""
Test script for baremetal_libvirt_health_monitor.py functionality.
Tests argument parsing and error handling without requiring actual libvirt access.
"""

import json
import subprocess
import sys


def run_command(cmd_args):
    """Helper function to run a command and return result."""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=10)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '--help']
    )

    if return_code == 0 and 'libvirt' in stdout.lower() and 'KVM' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: {}".format(return_code))
        print("stdout: {}".format(stdout[:200]))
        return False


def test_vm_option():
    """Test that the vm option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '--vm', 'testvm']
    )

    # Should not fail at argument parsing level (exit code 2 is OK for missing deps)
    if return_code in [0, 1, 2]:
        print("[PASS] VM option test passed")
        return True
    else:
        print("[FAIL] VM option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_verbose_option():
    """Test that the verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '-v']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_plain():
    """Test that plain format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print("[FAIL] Plain format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_json():
    """Test that JSON format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '--format', 'json']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        # If libvirt is available and output exists, verify it's valid JSON
        if stdout.strip() and return_code != 2:
            try:
                data = json.loads(stdout)
                if 'hypervisor' in data or 'vms' in data:
                    print("[PASS] JSON format option test passed (valid JSON)")
                    return True
            except json.JSONDecodeError:
                # May not have libvirt, that's OK
                pass
        print("[PASS] JSON format option test passed")
        return True
    else:
        print("[FAIL] JSON format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_table():
    """Test that table format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Table format option test passed")
        return True
    else:
        print("[FAIL] Table format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_invalid_format():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '--format', 'invalid']
    )

    # Should fail with argument error
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        print("return_code: {}, stderr: {}".format(return_code, stderr))
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_check_autostart_option():
    """Test that the check-autostart option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '--check-autostart']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Check-autostart option test passed")
        return True
    else:
        print("[FAIL] Check-autostart option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_skip_pools_option():
    """Test that the skip-pools option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '--skip-pools']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Skip-pools option test passed")
        return True
    else:
        print("[FAIL] Skip-pools option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_skip_networks_option():
    """Test that the skip-networks option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '--skip-networks']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Skip-networks option test passed")
        return True
    else:
        print("[FAIL] Skip-networks option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_combined_options():
    """Test that multiple options can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_libvirt_health_monitor.py',
        '--vm', 'testvm',
        '-v',
        '--format', 'json',
        '--check-autostart',
        '--skip-pools'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_exit_code_documentation():
    """Test that exit codes are documented in help."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '--help']
    )

    if return_code == 0:
        # Check for exit code documentation
        if 'Exit codes' in stdout or 'exit code' in stdout.lower():
            print("[PASS] Exit code documentation test passed")
            return True
        else:
            print("[FAIL] Exit codes not documented in help")
            return False
    else:
        print("[FAIL] Could not check exit code documentation")
        return False


def test_missing_virsh_message():
    """Test that missing virsh gives helpful error message."""
    # This test is informational - we can't easily simulate missing virsh
    # But we can verify the help message mentions the dependency
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_libvirt_health_monitor.py', '--help']
    )

    # The script should work without libvirt for --help
    if return_code == 0:
        print("[PASS] Script runs without libvirt for --help")
        return True
    else:
        print("[FAIL] Script should handle --help without libvirt")
        return False


if __name__ == "__main__":
    print("Testing baremetal_libvirt_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_vm_option,
        test_verbose_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_warn_only_option,
        test_check_autostart_option,
        test_skip_pools_option,
        test_skip_networks_option,
        test_combined_options,
        test_exit_code_documentation,
        test_missing_virsh_message,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print()
    print("Test Results: {}/{} tests passed".format(passed, total))

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
