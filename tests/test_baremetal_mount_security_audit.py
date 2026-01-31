#!/usr/bin/env python3
"""
Test script for baremetal_mount_security_audit.py functionality.
Tests argument parsing and output without requiring root access.
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
        [sys.executable, 'baremetal_mount_security_audit.py', '--help']
    )

    if return_code == 0 and 'security compliance' in stdout and 'noexec' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_plain_output():
    """Test default plain output format"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py']
    )

    # Should succeed (exit 0 or 1) and produce output with audit info
    if return_code in [0, 1] and 'Mount Security Audit' in stdout:
        print("[PASS] Plain output test passed")
        return True
    else:
        print(f"[FAIL] Plain output test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stdout: {stdout[:200]}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Verify expected fields
        if 'summary' in data and 'findings' in data and 'timestamp' in data:
            print("[PASS] JSON output format test passed")
            return True
        else:
            print(f"[FAIL] JSON missing expected fields")
            print(f"  Keys: {list(data.keys())}")
            return False

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py', '--format', 'table']
    )

    # Should succeed and produce table-like output
    if return_code in [0, 1]:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output test failed")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_flag():
    """Test verbose flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py', '-v']
    )

    # Should succeed and show CIS references
    if return_code in [0, 1]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_flag():
    """Test warn-only flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py', '--warn-only']
    )

    # Should succeed (may have limited output if compliant)
    if return_code in [0, 1]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_strict_flag():
    """Test strict mode flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py', '--strict']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Strict flag test passed")
        return True
    else:
        print(f"[FAIL] Strict flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_no_removable_flag():
    """Test no-removable flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py', '--no-removable']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] No-removable flag test passed")
        return True
    else:
        print(f"[FAIL] No-removable flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_show_fixes_flag():
    """Test show-fixes flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py', '--show-fixes']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Show-fixes flag test passed")
        return True
    else:
        print(f"[FAIL] Show-fixes flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_structure():
    """Test JSON output structure in detail"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Check required fields
        required_fields = ['timestamp', 'total_mounts', 'checked', 'compliant',
                          'non_compliant', 'findings', 'summary']
        missing_fields = [field for field in required_fields if field not in data]

        if missing_fields:
            print(f"[FAIL] JSON structure missing fields: {missing_fields}")
            return False

        # Check summary structure
        summary = data.get('summary', {})
        summary_fields = ['total_checked', 'compliant', 'non_compliant', 'compliance_percentage']
        missing_summary = [field for field in summary_fields if field not in summary]

        if missing_summary:
            print(f"[FAIL] Summary missing fields: {missing_summary}")
            return False

        # Check findings is a list
        if not isinstance(data['findings'], list):
            print(f"[FAIL] 'findings' should be a list")
            return False

        print("[PASS] JSON structure test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_combined_flags():
    """Test combining multiple flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py',
         '--format', 'json', '-v', '--strict', '--show-fixes']
    )

    # Should work with combined flags
    if return_code in [0, 1]:
        try:
            json.loads(stdout)
            print("[PASS] Combined flags test passed")
            return True
        except json.JSONDecodeError:
            print(f"[FAIL] Combined flags produced invalid JSON")
            return False
    else:
        print(f"[FAIL] Combined flags test failed")
        print(f"  Return code: {return_code}")
        return False


def test_exit_code_semantics():
    """Test that exit codes follow convention"""
    # Run basic audit
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        non_compliant = data['summary']['non_compliant']

        # Exit 0 if compliant, exit 1 if non-compliant
        expected_code = 1 if non_compliant > 0 else 0

        if return_code == expected_code:
            print("[PASS] Exit code semantics test passed")
            return True
        else:
            print(f"[FAIL] Exit code mismatch: got {return_code}, expected {expected_code}")
            print(f"  Non-compliant count: {non_compliant}")
            return False

    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] Could not verify exit code semantics: {e}")
        return False


def test_findings_structure():
    """Test that individual findings have expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_security_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        findings = data.get('findings', [])

        if not findings:
            # No findings is acceptable (some systems have no matching mounts)
            print("[PASS] Findings structure test passed (no findings)")
            return True

        # Check first finding structure
        finding = findings[0]
        required_fields = ['mountpoint', 'device', 'fstype', 'current_options',
                          'missing_required', 'compliant']
        missing = [f for f in required_fields if f not in finding]

        if missing:
            print(f"[FAIL] Finding missing fields: {missing}")
            return False

        print("[PASS] Findings structure test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_mount_security_audit.py...")
    print()

    tests = [
        test_help_message,
        test_plain_output,
        test_json_output_format,
        test_table_output_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_strict_flag,
        test_no_removable_flag,
        test_show_fixes_flag,
        test_invalid_format,
        test_json_structure,
        test_combined_flags,
        test_exit_code_semantics,
        test_findings_structure,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
