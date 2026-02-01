#!/usr/bin/env python3
"""
Test script for baremetal_kernel_cmdline_audit.py functionality.
Tests argument parsing and output formats without requiring specific kernel parameters.
"""

import subprocess
import sys
import json
import os
import tempfile


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
        [sys.executable, 'baremetal_kernel_cmdline_audit.py', '--help']
    )

    if return_code == 0 and 'kernel' in stdout.lower() and 'cmdline' in stdout.lower():
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
        [sys.executable, 'baremetal_kernel_cmdline_audit.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_cmdline_audit.py']
    )

    # Should succeed (exit 0 or 1 depending on findings)
    if return_code in [0, 1] and 'Kernel Command Line Audit' in stdout:
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_cmdline_audit.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['cmdline', 'parameter_count', 'parameters', 'summary', 'findings']
        if not all(key in data for key in required_keys):
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify summary structure
        summary = data['summary']
        summary_keys = ['critical', 'warning', 'info', 'total']
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


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_cmdline_audit.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and 'SEVERITY' in stdout and 'PARAMETER' in stdout:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode includes recommendations."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_cmdline_audit.py', '--verbose']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses info output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_cmdline_audit.py', '--warn-only']
    )

    # Should succeed (exit code depends on findings)
    # Should not contain INFORMATIONAL section
    if return_code in [0, 1] and 'INFORMATIONAL' not in stdout:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_skip_security_flag():
    """Test --skip-security flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_cmdline_audit.py', '--skip-security', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Should have no security category findings
            security_findings = [f for f in data['findings'] if f.get('category') == 'security']
            if not security_findings:
                print("[PASS] Skip security flag test passed")
                return True
            else:
                print("[FAIL] Skip security flag should remove security findings")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print(f"[FAIL] Skip security flag test failed: {return_code}")
        return False


def test_skip_debug_flag():
    """Test --skip-debug flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_cmdline_audit.py', '--skip-debug', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Should have no debug category findings
            debug_findings = [f for f in data['findings'] if f.get('category') == 'debug']
            if not debug_findings:
                print("[PASS] Skip debug flag test passed")
                return True
            else:
                print("[FAIL] Skip debug flag should remove debug findings")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print(f"[FAIL] Skip debug flag test failed: {return_code}")
        return False


def test_save_baseline():
    """Test saving baseline to file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        temp_path = f.name

    try:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_kernel_cmdline_audit.py', '--save', temp_path]
        )

        if return_code == 0 and os.path.exists(temp_path):
            with open(temp_path, 'r') as f:
                content = f.read()
            # Should contain a comment header
            if '# Kernel cmdline baseline' in content:
                print("[PASS] Save baseline test passed")
                return True
            else:
                print("[FAIL] Baseline file missing expected header")
                return False
        else:
            print(f"[FAIL] Save baseline test failed: {return_code}")
            return False
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_load_baseline():
    """Test loading and comparing against baseline."""
    # Create a baseline file with a fake parameter
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write("# Test baseline\n")
        f.write("fake_test_param=testvalue\n")
        temp_path = f.name

    try:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_kernel_cmdline_audit.py', '--baseline', temp_path, '--format', 'json']
        )

        # Should detect the missing parameter
        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                baseline_findings = [f for f in data['findings'] if f.get('category') == 'baseline']
                # Should find the fake param as missing
                missing = [f for f in baseline_findings if f.get('parameter') == 'fake_test_param']
                if missing:
                    print("[PASS] Load baseline test passed")
                    return True
                else:
                    print("[FAIL] Baseline comparison should detect missing parameter")
                    return False
            except json.JSONDecodeError:
                print("[FAIL] JSON parsing failed")
                return False
        else:
            print(f"[FAIL] Load baseline test failed: {return_code}")
            return False
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_missing_baseline_file():
    """Test error handling for missing baseline file."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_cmdline_audit.py', '--baseline', '/nonexistent/file.conf']
    )

    if return_code == 2 and 'not found' in stderr.lower():
        print("[PASS] Missing baseline file test passed")
        return True
    else:
        print(f"[FAIL] Missing baseline should exit with code 2")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_cmdline_audit.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_has_cmdline():
    """Test that JSON output includes the actual cmdline."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_cmdline_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            cmdline = data.get('cmdline', '')
            # cmdline should be non-empty on a real Linux system
            if cmdline:
                print("[PASS] JSON cmdline test passed")
                return True
            else:
                print("[FAIL] JSON output should include cmdline")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print(f"[FAIL] JSON cmdline test failed: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_kernel_cmdline_audit.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_skip_security_flag,
        test_skip_debug_flag,
        test_save_baseline,
        test_load_baseline,
        test_missing_baseline_file,
        test_exit_codes,
        test_json_has_cmdline,
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
