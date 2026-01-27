#!/usr/bin/env python3
"""
Test script for baremetal_kdump_config_audit.py functionality.
Tests argument parsing and output formats without requiring kdump to be installed.
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
        [sys.executable, 'baremetal_kdump_config_audit.py', '--help']
    )

    if return_code == 0 and 'kdump' in stdout.lower():
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
        [sys.executable, 'baremetal_kdump_config_audit.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_kdump_config_audit.py']
    )

    # Should succeed (exit 0 or 1 depending on configuration)
    if return_code in [0, 1] and ('Kdump' in stdout or 'kdump' in stdout.lower() or 'Service' in stdout):
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
        [sys.executable, 'baremetal_kdump_config_audit.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['service', 'crashkernel', 'dump_target', 'issues']
        missing_keys = [k for k in required_keys if k not in data]

        if missing_keys:
            print(f"[FAIL] JSON output missing expected keys: {missing_keys}")
            print(f"  Keys found: {list(data.keys())}")
            return False

        # Verify service structure
        service = data['service']
        if 'installed' not in service or 'enabled' not in service:
            print("[FAIL] service missing required keys")
            return False

        # Verify crashkernel structure
        crashkernel = data['crashkernel']
        if 'reserved' not in crashkernel:
            print("[FAIL] crashkernel missing 'reserved' key")
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
        [sys.executable, 'baremetal_kdump_config_audit.py', '--format', 'table']
    )

    # Should succeed and contain table structure
    if return_code in [0, 1] and ('KDUMP' in stdout or 'Service' in stdout):
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
        [sys.executable, 'baremetal_kdump_config_audit.py', '--warn-only']
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
        [sys.executable, 'baremetal_kdump_config_audit.py', '--verbose']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_dump_path_option():
    """Test custom dump path option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kdump_config_audit.py',
         '--dump-path', '/tmp']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Dump path option test passed")
        return True
    else:
        print(f"[FAIL] Dump path option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_contains_service_info():
    """Test JSON output includes service information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kdump_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'service' not in data:
            print("[FAIL] JSON output missing service")
            return False

        service = data['service']
        required_keys = ['installed', 'enabled', 'active']
        missing = [k for k in required_keys if k not in service]

        if missing:
            print(f"[FAIL] service missing keys: {missing}")
            return False

        print("[PASS] JSON service info test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_contains_crashkernel_info():
    """Test JSON output includes crashkernel information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kdump_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'crashkernel' not in data:
            print("[FAIL] JSON output missing crashkernel")
            return False

        crashkernel = data['crashkernel']
        if 'reserved' not in crashkernel:
            print("[FAIL] crashkernel missing 'reserved' key")
            return False

        print("[PASS] JSON crashkernel info test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_contains_dump_target():
    """Test JSON output includes dump target information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kdump_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'dump_target' not in data:
            print("[FAIL] JSON output missing dump_target")
            return False

        target = data['dump_target']
        required_keys = ['type', 'path']
        missing = [k for k in required_keys if k not in target]

        if missing:
            print(f"[FAIL] dump_target missing keys: {missing}")
            return False

        print("[PASS] JSON dump target info test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_contains_kexec_info():
    """Test JSON output includes kexec information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kdump_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'kexec' not in data:
            print("[FAIL] JSON output missing kexec")
            return False

        kexec = data['kexec']
        if 'loaded' not in kexec:
            print("[FAIL] kexec missing 'loaded' key")
            return False

        print("[PASS] JSON kexec info test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_contains_memory_info():
    """Test JSON output includes memory information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kdump_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'memory' not in data:
            print("[FAIL] JSON output missing memory")
            return False

        memory = data['memory']
        required_keys = ['total_bytes', 'estimated_dump_size']
        missing = [k for k in required_keys if k not in memory]

        if missing:
            print(f"[FAIL] memory missing keys: {missing}")
            return False

        print("[PASS] JSON memory info test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kdump_config_audit.py']
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
        [sys.executable, 'baremetal_kdump_config_audit.py', '--format', 'xml']
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
        [sys.executable, 'baremetal_kdump_config_audit.py',
         '--format', 'json', '--verbose']
    )

    try:
        data = json.loads(stdout)
        if return_code in [0, 1] and 'service' in data:
            print("[PASS] Combined options test passed")
            return True
        else:
            print(f"[FAIL] Combined options test failed")
            return False
    except json.JSONDecodeError:
        print(f"[FAIL] Combined options test failed - invalid JSON")
        return False


if __name__ == "__main__":
    print("Testing baremetal_kdump_config_audit.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_warn_only_mode,
        test_verbose_mode,
        test_dump_path_option,
        test_json_contains_service_info,
        test_json_contains_crashkernel_info,
        test_json_contains_dump_target,
        test_json_contains_kexec_info,
        test_json_contains_memory_info,
        test_exit_codes,
        test_format_option_choices,
        test_combined_options,
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
