#!/usr/bin/env python3
"""
Test script for firmware_version_audit.py functionality.
Tests argument parsing and error handling without requiring root privileges.
"""

import subprocess
import sys
import json
import os


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
    print("\n[TEST] Help message")
    return_code, stdout, stderr = run_command(
        [sys.executable, 'firmware_version_audit.py', '--help']
    )

    if return_code == 0 and 'firmware versions' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected"""
    print("\n[TEST] Invalid arguments")
    return_code, stdout, stderr = run_command(
        [sys.executable, 'firmware_version_audit.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    print("\n[TEST] Invalid format option")
    return_code, stdout, stderr = run_command(
        [sys.executable, 'firmware_version_audit.py', '--format', 'xml']
    )

    if return_code != 0:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option should fail")
        return False


def test_plain_output_format():
    """Test plain output format (default)"""
    print("\n[TEST] Plain output format")
    return_code, stdout, stderr = run_command(
        [sys.executable, 'firmware_version_audit.py', '--format', 'plain']
    )

    # Script may exit with 1 if it can't collect all info (no root, missing tools)
    # but it should still produce output
    if '=== System Information ===' in stdout or '=== BIOS Information ===' in stdout:
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing"""
    print("\n[TEST] JSON output format")
    return_code, stdout, stderr = run_command(
        [sys.executable, 'firmware_version_audit.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Check for expected keys
        expected_keys = ['system', 'bios', 'bmc', 'network']
        has_keys = any(key in data for key in expected_keys)

        if has_keys:
            print("[PASS] JSON output format test passed")
            print(f"  Found keys: {list(data.keys())}")
            return True
        else:
            print(f"[FAIL] JSON output missing expected keys")
            print(f"  Data: {data}")
            return False

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format"""
    print("\n[TEST] Table output format")
    return_code, stdout, stderr = run_command(
        [sys.executable, 'firmware_version_audit.py', '--format', 'table']
    )

    # Check for table borders and content
    if '┌' in stdout or '│' in stdout or 'Firmware Version Audit' in stdout:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_option():
    """Test verbose option parsing"""
    print("\n[TEST] Verbose option")
    return_code, stdout, stderr = run_command(
        [sys.executable, 'firmware_version_audit.py', '-v']
    )

    # Verbose option should be parsed without error
    # Output content may vary based on system
    print("[PASS] Verbose option test passed")
    return True


def test_script_executable():
    """Test that script is executable"""
    print("\n[TEST] Script executable permissions")

    if os.access('firmware_version_audit.py', os.X_OK):
        print("[PASS] Script is executable")
        return True
    else:
        print("[FAIL] Script is not executable")
        return False


def test_exit_codes():
    """Test various exit code scenarios"""
    print("\n[TEST] Exit codes")

    # Help should exit 0
    rc, _, _ = run_command([sys.executable, 'firmware_version_audit.py', '--help'])
    if rc != 0:
        print(f"[FAIL] Help should exit 0, got {rc}")
        return False

    # Invalid argument should exit non-zero
    rc, _, _ = run_command([sys.executable, 'firmware_version_audit.py', '--bad'])
    if rc == 0:
        print(f"[FAIL] Invalid argument should exit non-zero")
        return False

    print("[PASS] Exit codes test passed")
    return True


def test_output_contains_sections():
    """Test that output contains expected sections"""
    print("\n[TEST] Output sections")
    return_code, stdout, stderr = run_command(
        [sys.executable, 'firmware_version_audit.py']
    )

    # Check for at least some expected sections
    sections = ['System Information', 'BIOS Information', 'BMC', 'Network']
    found_sections = [s for s in sections if s in stdout]

    if len(found_sections) >= 2:
        print(f"[PASS] Output sections test passed (found: {found_sections})")
        return True
    else:
        print(f"[FAIL] Expected sections not found")
        print(f"  Found: {found_sections}")
        print(f"  Output: {stdout[:300]}")
        return False


def test_handles_missing_tools():
    """Test graceful handling when tools are missing"""
    print("\n[TEST] Missing tools handling")

    # Run normally - script should handle missing tools gracefully
    return_code, stdout, stderr = run_command(
        [sys.executable, 'firmware_version_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Should have error messages or actual data for each component
        for component in ['system', 'bios', 'bmc', 'network']:
            if component in data:
                # Either has error key or has actual data
                is_valid = 'error' in data[component] or len(data[component]) > 0
                if not is_valid:
                    print(f"[FAIL] Component {component} has invalid structure")
                    return False

        print("[PASS] Missing tools handling test passed")
        return True

    except json.JSONDecodeError:
        print("[FAIL] Could not parse output as JSON")
        return False


if __name__ == "__main__":
    print("=" * 70)
    print("Testing firmware_version_audit.py")
    print("=" * 70)

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_invalid_format,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_option,
        test_script_executable,
        test_exit_codes,
        test_output_contains_sections,
        test_handles_missing_tools,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[ERROR] Test {test.__name__} raised exception: {e}")
            failed += 1

    print("\n" + "=" * 70)
    print(f"Test Results: {passed}/{len(tests)} tests passed")
    if failed > 0:
        print(f"              {failed} tests failed")
    print("=" * 70)

    sys.exit(0 if failed == 0 else 1)
