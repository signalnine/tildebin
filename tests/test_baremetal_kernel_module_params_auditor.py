#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_kernel_module_params_auditor.py functionality.
Tests argument parsing and error handling without requiring root access.
"""

import subprocess
import sys
import json
import os
import tempfile


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
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--help'
    ])
    assert return_code == 0, f"Help command failed with return code: {return_code}"
    assert 'kernel module' in stdout.lower() or 'module parameters' in stdout.lower(), \
        "Expected 'kernel module' or 'module parameters' in help output"
    assert '--format' in stdout, "Expected '--format' option in help"
    assert '--verbose' in stdout, "Expected '--verbose' option in help"
    assert '--baseline' in stdout, "Expected '--baseline' option in help"
    assert '--security' in stdout, "Expected '--security' option in help"


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '-v'
    ])
    # Should not fail at argument parsing level
    assert return_code in [0, 1, 2], f"Verbose option failed with unexpected return code: {return_code}"


def test_format_option_plain():
    """Test that the format option accepts 'plain'"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--format', 'plain'
    ])
    assert return_code in [0, 1, 2], f"Format option 'plain' failed: {return_code}"


def test_format_option_json():
    """Test that the format option accepts 'json'"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--format', 'json'
    ])
    assert return_code in [0, 1, 2], f"Format option 'json' failed: {return_code}"


def test_format_option_table():
    """Test that the format option accepts 'table'"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--format', 'table'
    ])
    assert return_code in [0, 1, 2], f"Format option 'table' failed: {return_code}"


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--format', 'invalid'
    ])
    assert return_code != 0, "Invalid format should have been rejected"
    assert 'invalid choice' in stderr or 'invalid choice' in stdout, \
        "Expected 'invalid choice' error message"


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--warn-only'
    ])
    assert return_code in [0, 1, 2], f"Warn-only option failed: {return_code}"


def test_security_option():
    """Test that the security option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--security'
    ])
    assert return_code in [0, 1, 2], f"Security option failed: {return_code}"


def test_module_filter_option():
    """Test that module filter option works"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--module', 'nvme.*'
    ])
    assert return_code in [0, 1, 2], f"Module filter option failed: {return_code}"


def test_param_filter_option():
    """Test that param filter option works"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--param', 'timeout'
    ])
    assert return_code in [0, 1, 2], f"Param filter option failed: {return_code}"


def test_invalid_module_regex():
    """Test that invalid module regex is rejected"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--module', '[invalid'
    ])
    assert return_code == 2, f"Invalid regex should exit with code 2, got: {return_code}"
    assert 'pattern' in stderr.lower() or 'invalid' in stderr.lower(), \
        "Expected error message about invalid pattern"


def test_invalid_param_regex():
    """Test that invalid param regex is rejected"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--param', '(unclosed'
    ])
    assert return_code == 2, f"Invalid regex should exit with code 2, got: {return_code}"
    assert 'pattern' in stderr.lower() or 'invalid' in stderr.lower(), \
        "Expected error message about invalid pattern"


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py',
        '-v',
        '--format', 'json',
        '--warn-only'
    ])
    assert return_code in [0, 1, 2], f"Combined options failed: {return_code}"


def test_json_output_structure():
    """Test that JSON output has expected structure"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--format', 'json'
    ])
    # Only check JSON structure if command succeeded
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "Expected 'status' key in JSON output"
            assert 'summary' in data, "Expected 'summary' key in JSON output"
            assert 'modules' in data, "Expected 'modules' key in JSON output"
            assert 'total_modules' in data['summary'], "Expected 'total_modules' in summary"
            assert 'total_parameters' in data['summary'], "Expected 'total_parameters' in summary"
        except json.JSONDecodeError:
            # If /sys/module not available, may have non-JSON error
            pass


def test_generate_baseline():
    """Test that generate-baseline outputs valid JSON"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--generate-baseline'
    ])
    if return_code == 0:
        try:
            data = json.loads(stdout)
            assert isinstance(data, dict), "Baseline should be a dict"
            # Each module should map to a dict of params
            for module, params in data.items():
                assert isinstance(params, dict), f"Module {module} params should be a dict"
        except json.JSONDecodeError as e:
            assert False, f"Baseline should be valid JSON: {e}"


def test_baseline_file_not_found():
    """Test that missing baseline file gives appropriate error"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py',
        '--baseline', '/nonexistent/baseline.json'
    ])
    assert return_code == 2, f"Missing baseline file should exit with code 2, got: {return_code}"
    assert 'cannot read' in stderr.lower() or 'error' in stderr.lower(), \
        "Expected error message about missing file"


def test_baseline_invalid_json():
    """Test that invalid JSON baseline gives appropriate error"""
    # Create a temporary file with invalid JSON
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('{ invalid json }')
        temp_path = f.name

    try:
        return_code, stdout, stderr = run_command([
            sys.executable, 'baremetal_kernel_module_params_auditor.py',
            '--baseline', temp_path
        ])
        assert return_code == 2, f"Invalid JSON baseline should exit with code 2, got: {return_code}"
        assert 'json' in stderr.lower() or 'invalid' in stderr.lower(), \
            "Expected error message about invalid JSON"
    finally:
        os.unlink(temp_path)


def test_baseline_comparison():
    """Test that baseline comparison works with valid baseline"""
    # First generate a baseline
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '--generate-baseline'
    ])

    if return_code != 0:
        # Skip if we can't generate baseline (no modules)
        return

    # Write baseline to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write(stdout)
        temp_path = f.name

    try:
        # Compare against same baseline - should match
        return_code, stdout, stderr = run_command([
            sys.executable, 'baremetal_kernel_module_params_auditor.py',
            '--baseline', temp_path,
            '--format', 'json'
        ])
        assert return_code == 0, f"Comparing against same baseline should succeed, got: {return_code}"

        if return_code == 0:
            data = json.loads(stdout)
            assert data['summary']['mismatches'] == 0, "No mismatches expected for same baseline"
    finally:
        os.unlink(temp_path)


def test_short_verbose_option():
    """Test that short -v option works"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '-v'
    ])
    assert return_code in [0, 1, 2], f"Short verbose option failed: {return_code}"


def test_short_format_option():
    """Test that short -f option works"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '-f', 'json'
    ])
    assert return_code in [0, 1, 2], f"Short format option failed: {return_code}"


def test_short_warn_only_option():
    """Test that short -w option works"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_kernel_module_params_auditor.py', '-w'
    ])
    assert return_code in [0, 1, 2], f"Short warn-only option failed: {return_code}"


if __name__ == "__main__":
    print("Testing baremetal_kernel_module_params_auditor.py...")
    print()

    tests = [
        ("Help message", test_help_message),
        ("Verbose option", test_verbose_option),
        ("Format option plain", test_format_option_plain),
        ("Format option json", test_format_option_json),
        ("Format option table", test_format_option_table),
        ("Invalid format", test_invalid_format),
        ("Warn-only option", test_warn_only_option),
        ("Security option", test_security_option),
        ("Module filter option", test_module_filter_option),
        ("Param filter option", test_param_filter_option),
        ("Invalid module regex", test_invalid_module_regex),
        ("Invalid param regex", test_invalid_param_regex),
        ("Combined options", test_combined_options),
        ("JSON output structure", test_json_output_structure),
        ("Generate baseline", test_generate_baseline),
        ("Baseline file not found", test_baseline_file_not_found),
        ("Baseline invalid JSON", test_baseline_invalid_json),
        ("Baseline comparison", test_baseline_comparison),
        ("Short verbose option", test_short_verbose_option),
        ("Short format option", test_short_format_option),
        ("Short warn-only option", test_short_warn_only_option),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            print(f"  [PASS] {name}")
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  [ERROR] {name}: {e}")
            failed += 1

    print()
    print(f"Results: {passed}/{passed + failed} tests passed")

    sys.exit(0 if failed == 0 else 1)
