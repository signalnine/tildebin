#!/usr/bin/env python3
"""
Test script for baremetal_grub_config_audit.py functionality.
Tests argument parsing and output formats without requiring GRUB to be installed.
"""

import subprocess
import sys
import json


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
        [sys.executable, 'baremetal_grub_config_audit.py', '--help']
    )

    if return_code == 0 and 'grub' in stdout.lower():
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
        [sys.executable, 'baremetal_grub_config_audit.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_grub_config_audit.py']
    )

    # Should succeed (exit 0 or 1 depending on configuration)
    if return_code in [0, 1] and ('GRUB' in stdout or 'grub' in stdout.lower()):
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_grub_config_audit.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['paths', 'defaults', 'password', 'issues']
        missing_keys = [k for k in required_keys if k not in data]

        if missing_keys:
            print(f"[FAIL] JSON output missing expected keys: {missing_keys}")
            print(f"  Keys found: {list(data.keys())}")
            return False

        # Verify paths structure
        paths = data['paths']
        if 'main_config' not in paths or 'default_config' not in paths:
            print("[FAIL] paths missing required keys")
            return False

        # Verify defaults structure
        defaults = data['defaults']
        if 'settings' not in defaults:
            print("[FAIL] defaults missing 'settings' key")
            return False

        # Verify issues is a list
        if not isinstance(data['issues'], list):
            print("[FAIL] issues is not a list")
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
        [sys.executable, 'baremetal_grub_config_audit.py', '--format', 'table']
    )

    # Should succeed and contain table structure
    if return_code in [0, 1] and ('GRUB' in stdout or 'Setting' in stdout):
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_grub_config_audit.py', '--warn-only']
    )

    # Should succeed (exit code depends on configuration)
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_mode():
    """Test verbose mode shows additional details."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_grub_config_audit.py', '--verbose']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_contains_paths_info():
    """Test JSON output includes paths information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_grub_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'paths' not in data:
            print("[FAIL] JSON output missing paths")
            return False

        paths = data['paths']
        required_keys = ['main_config', 'default_config', 'grub_dir']
        missing = [k for k in required_keys if k not in paths]

        if missing:
            print(f"[FAIL] paths missing keys: {missing}")
            return False

        print("[PASS] JSON paths info test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_contains_password_info():
    """Test JSON output includes password information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_grub_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'password' not in data:
            print("[FAIL] JSON output missing password")
            return False

        password = data['password']
        if 'enabled' not in password:
            print("[FAIL] password missing 'enabled' key")
            return False

        print("[PASS] JSON password info test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_contains_cmdline_analysis():
    """Test JSON output includes command line analysis."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_grub_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'cmdline_analysis' not in data:
            print("[FAIL] JSON output missing cmdline_analysis")
            return False

        cmdline = data['cmdline_analysis']
        required_keys = ['raw', 'parameters', 'security']
        missing = [k for k in required_keys if k not in cmdline]

        if missing:
            print(f"[FAIL] cmdline_analysis missing keys: {missing}")
            return False

        print("[PASS] JSON cmdline analysis test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_contains_grub_install():
    """Test JSON output includes grub install information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_grub_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'grub_install' not in data:
            print("[FAIL] JSON output missing grub_install")
            return False

        grub = data['grub_install']
        required_keys = ['version', 'installed', 'efi_mode']
        missing = [k for k in required_keys if k not in grub]

        if missing:
            print(f"[FAIL] grub_install missing keys: {missing}")
            return False

        print("[PASS] JSON grub install info test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_contains_kernels():
    """Test JSON output includes kernel information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_grub_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'kernels' not in data:
            print("[FAIL] JSON output missing kernels")
            return False

        kernels = data['kernels']
        if not isinstance(kernels, list):
            print("[FAIL] kernels is not a list")
            return False

        print("[PASS] JSON kernels info test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_grub_config_audit.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_format_option_choices():
    """Test that only valid format options are accepted."""
    # Test invalid format
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_grub_config_audit.py', '--format', 'xml']
    )

    if return_code == 2:
        print("[PASS] Format option choices test passed")
        return True
    else:
        print(f"[FAIL] Format option choices test failed")
        print(f"  Return code: {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_grub_config_audit.py',
         '--format', 'json', '--verbose']
    )

    try:
        data = json.loads(stdout)
        if return_code in [0, 1] and 'paths' in data:
            print("[PASS] Combined options test passed")
            return True
        else:
            print(f"[FAIL] Combined options test failed")
            return False
    except json.JSONDecodeError:
        print(f"[FAIL] Combined options test failed - invalid JSON")
        return False


def test_json_security_structure():
    """Test JSON security analysis structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_grub_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'cmdline_analysis' not in data:
            print("[FAIL] JSON output missing cmdline_analysis")
            return False

        security = data['cmdline_analysis'].get('security', {})
        required_keys = ['iommu_enabled', 'kaslr_disabled', 'mitigations_off']
        missing = [k for k in required_keys if k not in security]

        if missing:
            print(f"[FAIL] security missing keys: {missing}")
            return False

        print("[PASS] JSON security structure test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_grub_config_audit.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_warn_only_mode,
        test_verbose_mode,
        test_json_contains_paths_info,
        test_json_contains_password_info,
        test_json_contains_cmdline_analysis,
        test_json_contains_grub_install,
        test_json_contains_kernels,
        test_exit_codes,
        test_format_option_choices,
        test_combined_options,
        test_json_security_structure,
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
