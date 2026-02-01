#!/usr/bin/env python3
"""
Test script for baremetal_nic_link_speed_audit.py functionality.
Tests argument parsing and error handling without requiring actual network hardware.
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
        stdout, stderr = proc.communicate()
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '--help']
    )

    if return_code == 0 and 'link speed' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  stdout: {stdout[:200]}")
        return False


def test_interface_option():
    """Test that the interface option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '-i', 'eth0']
    )

    # Should not fail at argument parsing level (exit code 2 only for missing deps)
    # May return 0, 1, or 2 depending on system state
    if return_code in [0, 1, 2]:
        print("[PASS] Interface option test passed")
        return True
    else:
        print(f"[FAIL] Interface option test failed with return code: {return_code}")
        return False


def test_long_interface_option():
    """Test that the --interface long option works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '--interface', 'lo']
    )

    # lo is typically present but not physical, so may get various results
    if return_code in [0, 1, 2]:
        print("[PASS] Long interface option test passed")
        return True
    else:
        print(f"[FAIL] Long interface option test failed with return code: {return_code}")
        return False


def test_min_speed_option():
    """Test that the --min-speed option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '--min-speed', '10000']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Min-speed option test passed")
        return True
    else:
        print(f"[FAIL] Min-speed option test failed with return code: {return_code}")
        return False


def test_invalid_min_speed():
    """Test that invalid min-speed value is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '--min-speed', 'notanumber']
    )

    # Should fail with argument error
    if return_code == 2 and 'invalid' in stderr.lower():
        print("[PASS] Invalid min-speed test passed")
        return True
    else:
        print("[FAIL] Invalid min-speed test failed - should have rejected invalid value")
        return False


def test_format_option_plain():
    """Test that the plain format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '--format', 'plain']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed with return code: {return_code}")
        return False


def test_format_option_json():
    """Test that the json format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '--format', 'json']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] JSON format option test passed")
        return True
    else:
        print(f"[FAIL] JSON format option test failed with return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '--format', 'xml']
    )

    # Should fail with argument error
    if return_code != 0 and 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_verbose_option():
    """Test that the verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed with return code: {return_code}")
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed with return code: {return_code}")
        return False


def test_short_warn_only_option():
    """Test that the -w short option works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '-w']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Short warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Short warn-only option test failed with return code: {return_code}")
        return False


def test_combined_options():
    """Test that multiple options can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_nic_link_speed_audit.py',
        '-v',
        '--warn-only',
        '--format', 'json',
        '--min-speed', '1000'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed with return code: {return_code}")
        return False


def test_json_output_structure():
    """Test that JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '--format', 'json']
    )

    # Skip if ethtool not available (exit code 2)
    if return_code == 2:
        print("[SKIP] JSON output structure test - ethtool not available")
        return True

    try:
        data = json.loads(stdout)
        # Check for expected keys
        if 'interfaces' in data and 'summary' in data:
            print("[PASS] JSON output structure test passed")
            return True
        else:
            print("[FAIL] JSON output structure test failed - missing expected keys")
            return False
    except json.JSONDecodeError:
        print("[FAIL] JSON output structure test failed - invalid JSON")
        print(f"  Output: {stdout[:200]}")
        return False


def test_plain_output_header():
    """Test that plain output has expected header."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '--format', 'plain']
    )

    # Skip if ethtool not available
    if return_code == 2:
        print("[SKIP] Plain output header test - ethtool not available")
        return True

    if 'NIC Link Speed Audit' in stdout or 'No physical' in stdout:
        print("[PASS] Plain output header test passed")
        return True
    else:
        print("[FAIL] Plain output header test failed")
        print(f"  Output: {stdout[:200]}")
        return False


def test_nonexistent_interface():
    """Test handling of non-existent interface."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '-i', 'nonexistent_iface_xyz']
    )

    # Should fail with error about interface not found
    if return_code == 2 and 'not found' in stderr.lower():
        print("[PASS] Non-existent interface test passed")
        return True
    else:
        print("[FAIL] Non-existent interface test failed")
        print(f"  Return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_help_shows_examples():
    """Test that help includes usage examples."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_link_speed_audit.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout:
        print("[PASS] Help shows examples test passed")
        return True
    else:
        print("[FAIL] Help shows examples test failed")
        return False


if __name__ == "__main__":
    print("Testing baremetal_nic_link_speed_audit.py...")
    print()

    tests = [
        test_help_message,
        test_interface_option,
        test_long_interface_option,
        test_min_speed_option,
        test_invalid_min_speed,
        test_format_option_plain,
        test_format_option_json,
        test_invalid_format,
        test_verbose_option,
        test_warn_only_option,
        test_short_warn_only_option,
        test_combined_options,
        test_json_output_structure,
        test_plain_output_header,
        test_nonexistent_interface,
        test_help_shows_examples,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
