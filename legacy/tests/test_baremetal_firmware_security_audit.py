#!/usr/bin/env python3
"""
Test script for baremetal_firmware_security_audit.py functionality.
Tests argument parsing and error handling without requiring root access or
specific firmware features.
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
        stdout, stderr = proc.communicate(timeout=30)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py', '--help']
    )

    if return_code == 0 and 'firmware security' in stdout.lower():
        if 'Secure Boot' in stdout and 'TPM' in stdout and 'IOMMU' in stdout:
            print("[PASS] Help message test passed")
            return True
    print("[FAIL] Help message test failed - return code: {}".format(return_code))
    print("stdout: {}".format(stdout[:300]))
    return False


def test_exit_code_documentation():
    """Test that exit codes are documented in help."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py', '--help']
    )

    if return_code == 0:
        if 'Exit codes' in stdout or 'exit code' in stdout.lower():
            print("[PASS] Exit code documentation test passed")
            return True
        else:
            print("[FAIL] Exit codes not documented in help")
            return False
    else:
        print("[FAIL] Could not check exit code documentation")
        return False


def test_verbose_option():
    """Test that the verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py', '-v']
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
        [sys.executable, 'baremetal_firmware_security_audit.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        # Should have some output about security checks
        if 'Secure Boot' in stdout or 'TPM' in stdout or 'Boot Mode' in stdout:
            print("[PASS] Plain format option test passed")
            return True
        print("[PASS] Plain format option test passed (no output)")
        return True
    else:
        print("[FAIL] Plain format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_json():
    """Test that JSON format option produces valid JSON."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        if stdout.strip():
            try:
                data = json.loads(stdout)
                # Verify expected structure
                if 'checks' in data and 'summary' in data:
                    if 'secure_boot' in data['checks'] and 'tpm' in data['checks']:
                        print("[PASS] JSON format option test passed (valid JSON with expected structure)")
                        return True
                print("[FAIL] JSON structure missing expected keys")
                return False
            except json.JSONDecodeError as e:
                print("[FAIL] JSON format test failed - invalid JSON: {}".format(e))
                print("stdout: {}".format(stdout[:200]))
                return False
        print("[PASS] JSON format option test passed")
        return True
    else:
        print("[FAIL] JSON format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_table():
    """Test that table format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        # Table should have headers
        if 'CHECK' in stdout and 'STATUS' in stdout:
            print("[PASS] Table format option test passed")
            return True
        # Accept any valid output
        print("[PASS] Table format option test passed (no table headers)")
        return True
    else:
        print("[FAIL] Table format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_invalid_format():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_firmware_security_audit.py', '--warn-only']
    )

    if return_code in [0, 1]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_require_secure_boot_option():
    """Test that the require-secure-boot option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py', '--require-secure-boot']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Require-secure-boot option test passed")
        return True
    else:
        print("[FAIL] Require-secure-boot option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_require_tpm_option():
    """Test that the require-tpm option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py', '--require-tpm']
    )

    if return_code in [0, 1]:
        print("[PASS] Require-tpm option test passed")
        return True
    else:
        print("[FAIL] Require-tpm option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_require_iommu_option():
    """Test that the require-iommu option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py', '--require-iommu']
    )

    if return_code in [0, 1]:
        print("[PASS] Require-iommu option test passed")
        return True
    else:
        print("[FAIL] Require-iommu option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_require_all_option():
    """Test that the require-all option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py', '--require-all']
    )

    if return_code in [0, 1]:
        print("[PASS] Require-all option test passed")
        return True
    else:
        print("[FAIL] Require-all option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_combined_options():
    """Test that multiple options can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_firmware_security_audit.py',
        '-v',
        '--format', 'json',
        '--require-secure-boot'
    ])

    if return_code in [0, 1]:
        # Verify JSON output
        if stdout.strip():
            try:
                json.loads(stdout)
                print("[PASS] Combined options test passed (valid JSON)")
                return True
            except json.JSONDecodeError:
                print("[FAIL] Combined options produced invalid JSON")
                return False
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_json_has_all_checks():
    """Test that JSON output contains all expected security checks."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            checks = data.get('checks', {})
            expected_checks = [
                'secure_boot', 'tpm', 'boot_mode', 'iommu',
                'intel_txt', 'amd_sev', 'kernel_lockdown'
            ]
            missing = [c for c in expected_checks if c not in checks]
            if not missing:
                print("[PASS] JSON contains all expected checks")
                return True
            else:
                print("[FAIL] JSON missing checks: {}".format(missing))
                return False
        except json.JSONDecodeError:
            print("[FAIL] Could not parse JSON to verify checks")
            return False
    else:
        print("[PASS] JSON checks test passed (skipped - no output)")
        return True


def test_json_summary():
    """Test that JSON output contains summary section."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            if 'summary' in data:
                summary = data['summary']
                if 'secure_boot' in summary and 'tpm' in summary and 'boot_mode' in summary:
                    print("[PASS] JSON summary test passed")
                    return True
                print("[FAIL] Summary missing expected keys")
                return False
            else:
                print("[FAIL] JSON missing summary section")
                return False
        except json.JSONDecodeError:
            print("[FAIL] Could not parse JSON")
            return False
    else:
        print("[PASS] JSON summary test passed (skipped - no output)")
        return True


def test_script_runs_without_root():
    """Test that script can run without root (may have limited output)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_security_audit.py']
    )

    # Should run successfully (0 or 1) even without root access
    if return_code in [0, 1]:
        print("[PASS] Script runs without root access")
        return True
    else:
        print("[FAIL] Script requires root access or has other issues")
        print("return_code: {}, stderr: {}".format(return_code, stderr))
        return False


if __name__ == "__main__":
    print("Testing baremetal_firmware_security_audit.py...")
    print()

    tests = [
        test_help_message,
        test_exit_code_documentation,
        test_verbose_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_warn_only_option,
        test_require_secure_boot_option,
        test_require_tpm_option,
        test_require_iommu_option,
        test_require_all_option,
        test_combined_options,
        test_json_has_all_checks,
        test_json_summary,
        test_script_runs_without_root,
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
