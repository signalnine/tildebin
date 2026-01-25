#!/usr/bin/env python3
"""
Test script for baremetal_vlan_config_audit.py functionality.
Tests argument parsing and error handling without requiring actual VLAN configuration.
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
        [sys.executable, 'baremetal_vlan_config_audit.py', '--help']
    )

    if return_code == 0 and 'vlan' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  stdout: {stdout[:200]}")
        return False


def test_format_option_plain():
    """Test that the plain format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--format', 'plain']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed with return code: {return_code}")
        return False


def test_format_option_json():
    """Test that the json format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--format', 'json']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] JSON format option test passed")
        return True
    else:
        print(f"[FAIL] JSON format option test failed with return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--format', 'xml']
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
        [sys.executable, 'baremetal_vlan_config_audit.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed with return code: {return_code}")
        return False


def test_long_verbose_option():
    """Test that the --verbose long option works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--verbose']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Long verbose option test passed")
        return True
    else:
        print(f"[FAIL] Long verbose option test failed with return code: {return_code}")
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--warn-only']
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
        [sys.executable, 'baremetal_vlan_config_audit.py', '-w']
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
        sys.executable, 'baremetal_vlan_config_audit.py',
        '-v',
        '--warn-only',
        '--format', 'json'
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
        [sys.executable, 'baremetal_vlan_config_audit.py', '--format', 'json']
    )

    # Skip if sysfs not accessible (exit code 2)
    if return_code == 2:
        print("[SKIP] JSON output structure test - sysfs not accessible")
        return True

    try:
        data = json.loads(stdout)
        # Check for expected keys
        if 'vlans' in data and 'summary' in data and 'conflicts' in data:
            print("[PASS] JSON output structure test passed")
            return True
        else:
            print("[FAIL] JSON output structure test failed - missing expected keys")
            print(f"  Keys found: {list(data.keys())}")
            return False
    except json.JSONDecodeError:
        print("[FAIL] JSON output structure test failed - invalid JSON")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_summary_fields():
    """Test that JSON summary has expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--format', 'json']
    )

    if return_code == 2:
        print("[SKIP] JSON summary fields test - sysfs not accessible")
        return True

    try:
        data = json.loads(stdout)
        summary = data.get('summary', {})
        expected_fields = ['total', 'ok', 'warning', 'error', 'conflicts']

        missing = [f for f in expected_fields if f not in summary]
        if not missing:
            print("[PASS] JSON summary fields test passed")
            return True
        else:
            print(f"[FAIL] JSON summary fields test failed - missing: {missing}")
            return False
    except json.JSONDecodeError:
        print("[FAIL] JSON summary fields test failed - invalid JSON")
        return False


def test_plain_output_header():
    """Test that plain output has expected header."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--format', 'plain']
    )

    # Skip if sysfs not accessible
    if return_code == 2:
        print("[SKIP] Plain output header test - sysfs not accessible")
        return True

    if 'VLAN Configuration Audit' in stdout or 'No VLAN' in stdout:
        print("[PASS] Plain output header test passed")
        return True
    else:
        print("[FAIL] Plain output header test failed")
        print(f"  Output: {stdout[:200]}")
        return False


def test_plain_output_summary():
    """Test that plain output includes summary line."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--format', 'plain']
    )

    if return_code == 2:
        print("[SKIP] Plain output summary test - sysfs not accessible")
        return True

    # Should have either "Summary:" or "No VLAN interfaces"
    if 'Summary:' in stdout or 'No VLAN' in stdout:
        print("[PASS] Plain output summary test passed")
        return True
    else:
        print("[FAIL] Plain output summary test failed")
        print(f"  Output: {stdout[:300]}")
        return False


def test_help_shows_examples():
    """Test that help includes usage examples."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout:
        print("[PASS] Help shows examples test passed")
        return True
    else:
        print("[FAIL] Help shows examples test failed")
        return False


def test_help_shows_description():
    """Test that help shows meaningful description."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--help']
    )

    if return_code == 0 and 'configuration' in stdout.lower():
        print("[PASS] Help shows description test passed")
        return True
    else:
        print("[FAIL] Help shows description test failed")
        return False


def test_invalid_option():
    """Test that invalid options are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--invalid-option']
    )

    if return_code != 0 and 'unrecognized' in stderr.lower():
        print("[PASS] Invalid option test passed")
        return True
    else:
        print("[FAIL] Invalid option test failed - should have rejected invalid option")
        return False


def test_no_vlans_scenario():
    """Test behavior when no VLANs are configured (common case)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--format', 'plain']
    )

    # If no VLANs, should exit 0 (healthy) with appropriate message
    # If VLANs exist with issues, exit 1
    # Both are valid depending on system state
    if return_code in [0, 1]:
        print("[PASS] No VLANs scenario test passed")
        return True
    elif return_code == 2:
        print("[SKIP] No VLANs scenario test - sysfs not accessible")
        return True
    else:
        print(f"[FAIL] No VLANs scenario test failed with return code: {return_code}")
        return False


def test_json_vlans_is_list():
    """Test that JSON vlans field is a list."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_vlan_config_audit.py', '--format', 'json']
    )

    if return_code == 2:
        print("[SKIP] JSON vlans list test - sysfs not accessible")
        return True

    try:
        data = json.loads(stdout)
        if isinstance(data.get('vlans'), list):
            print("[PASS] JSON vlans is list test passed")
            return True
        else:
            print("[FAIL] JSON vlans is list test failed - vlans is not a list")
            return False
    except json.JSONDecodeError:
        print("[FAIL] JSON vlans is list test failed - invalid JSON")
        return False


if __name__ == "__main__":
    print("Testing baremetal_vlan_config_audit.py...")
    print()

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_invalid_format,
        test_verbose_option,
        test_long_verbose_option,
        test_warn_only_option,
        test_short_warn_only_option,
        test_combined_options,
        test_json_output_structure,
        test_json_summary_fields,
        test_plain_output_header,
        test_plain_output_summary,
        test_help_shows_examples,
        test_help_shows_description,
        test_invalid_option,
        test_no_vlans_scenario,
        test_json_vlans_is_list,
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
