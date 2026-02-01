#!/usr/bin/env python3
"""
Tests for k8s_init_container_analyzer.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and core functions.
"""

import subprocess
import sys
import json
import os

# Add parent directory to path to import the script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_command(cmd_args):
    """Run the script with given arguments and return result."""
    cmd = [sys.executable, 'k8s_init_container_analyzer.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )
    return result.returncode, result.stdout, result.stderr


def test_help_message():
    """Test that --help flag works and shows usage information."""
    returncode, stdout, stderr = run_command(['--help'])

    if returncode != 0:
        print(f"[FAIL] Help message test failed - exit code {returncode}")
        return False

    if 'init container' not in stdout.lower():
        print("[FAIL] Help message missing 'init container' description")
        return False

    if '--namespace' not in stdout:
        print("[FAIL] Help message missing --namespace option")
        return False

    if '--format' not in stdout:
        print("[FAIL] Help message missing --format option")
        return False

    if '--verbose' not in stdout:
        print("[FAIL] Help message missing --verbose option")
        return False

    if 'Examples:' not in stdout:
        print("[FAIL] Help message missing Examples section")
        return False

    print("[PASS] Help message test passed")
    return True


def test_help_short_flag():
    """Test that -h flag works."""
    returncode, stdout, stderr = run_command(['-h'])

    if returncode != 0:
        print(f"[FAIL] Short help flag test failed - exit code {returncode}")
        return False

    if 'init container' not in stdout.lower():
        print("[FAIL] Short help missing description")
        return False

    print("[PASS] Short help flag test passed")
    return True


def test_namespace_option():
    """Test --namespace option is accepted."""
    returncode, stdout, stderr = run_command(['--namespace', 'kube-system'])

    # Should accept option (may fail due to kubectl, but not usage error)
    if returncode == 2 and 'unrecognized' in stderr.lower():
        print("[FAIL] Namespace option not recognized")
        return False

    print("[PASS] Namespace option test passed")
    return True


def test_namespace_short_option():
    """Test -n short option works."""
    returncode, stdout, stderr = run_command(['-n', 'default'])

    if returncode == 2 and 'unrecognized' in stderr.lower():
        print("[FAIL] Short namespace option not recognized")
        return False

    print("[PASS] Short namespace option test passed")
    return True


def test_format_option_plain():
    """Test --format plain option is accepted."""
    returncode, stdout, stderr = run_command(['--format', 'plain'])

    if returncode == 2 and 'invalid choice' in stderr.lower():
        print("[FAIL] Plain format not accepted")
        return False

    print("[PASS] Plain format option test passed")
    return True


def test_format_option_json():
    """Test --format json option is accepted."""
    returncode, stdout, stderr = run_command(['--format', 'json'])

    if returncode == 2 and 'invalid choice' in stderr.lower():
        print("[FAIL] JSON format not accepted")
        return False

    print("[PASS] JSON format option test passed")
    return True


def test_format_option_table():
    """Test --format table option is accepted."""
    returncode, stdout, stderr = run_command(['--format', 'table'])

    if returncode == 2 and 'invalid choice' in stderr.lower():
        print("[FAIL] Table format not accepted")
        return False

    print("[PASS] Table format option test passed")
    return True


def test_invalid_format_option():
    """Test that invalid format is rejected."""
    returncode, stdout, stderr = run_command(['--format', 'invalid'])

    if returncode != 2:
        print(f"[FAIL] Invalid format should return exit code 2, got {returncode}")
        return False

    if 'invalid choice' not in stderr.lower():
        print("[FAIL] Invalid format should report invalid choice")
        return False

    print("[PASS] Invalid format option test passed")
    return True


def test_verbose_option():
    """Test --verbose option is accepted."""
    returncode, stdout, stderr = run_command(['--verbose'])

    if returncode == 2 and 'unrecognized' in stderr.lower():
        print("[FAIL] Verbose option not recognized")
        return False

    print("[PASS] Verbose option test passed")
    return True


def test_verbose_short_option():
    """Test -v short option works."""
    returncode, stdout, stderr = run_command(['-v'])

    if returncode == 2 and 'unrecognized' in stderr.lower():
        print("[FAIL] Short verbose option not recognized")
        return False

    print("[PASS] Short verbose option test passed")
    return True


def test_warn_only_option():
    """Test --warn-only option is accepted."""
    returncode, stdout, stderr = run_command(['--warn-only'])

    if returncode == 2 and 'unrecognized' in stderr.lower():
        print("[FAIL] Warn-only option not recognized")
        return False

    print("[PASS] Warn-only option test passed")
    return True


def test_warn_only_short_option():
    """Test -w short option works."""
    returncode, stdout, stderr = run_command(['-w'])

    if returncode == 2 and 'unrecognized' in stderr.lower():
        print("[FAIL] Short warn-only option not recognized")
        return False

    print("[PASS] Short warn-only option test passed")
    return True


def test_severity_option():
    """Test --severity option is accepted."""
    returncode, stdout, stderr = run_command(['--severity', 'critical'])

    if returncode == 2 and 'invalid choice' in stderr.lower():
        print("[FAIL] Severity option not recognized")
        return False

    print("[PASS] Severity option test passed")
    return True


def test_severity_option_warning():
    """Test --severity warning option."""
    returncode, stdout, stderr = run_command(['--severity', 'warning'])

    if returncode == 2 and 'invalid choice' in stderr.lower():
        print("[FAIL] Severity warning not accepted")
        return False

    print("[PASS] Severity warning option test passed")
    return True


def test_severity_option_all():
    """Test --severity all option."""
    returncode, stdout, stderr = run_command(['--severity', 'all'])

    if returncode == 2 and 'invalid choice' in stderr.lower():
        print("[FAIL] Severity all not accepted")
        return False

    print("[PASS] Severity all option test passed")
    return True


def test_invalid_severity_option():
    """Test that invalid severity is rejected."""
    returncode, stdout, stderr = run_command(['--severity', 'invalid'])

    if returncode != 2:
        print(f"[FAIL] Invalid severity should return exit code 2, got {returncode}")
        return False

    print("[PASS] Invalid severity option test passed")
    return True


def test_combined_options():
    """Test combining multiple options."""
    returncode, stdout, stderr = run_command([
        '-n', 'production',
        '--verbose',
        '--warn-only',
        '--format', 'json'
    ])

    # Should accept all options
    if returncode == 2 and 'unrecognized' in stderr.lower():
        print("[FAIL] Combined options not accepted")
        return False

    print("[PASS] Combined options test passed")
    return True


def test_script_has_shebang():
    """Test that script has proper shebang."""
    with open('k8s_init_container_analyzer.py', 'r') as f:
        first_line = f.readline()

    if not first_line.startswith('#!'):
        print("[FAIL] Script missing shebang")
        return False

    if 'python' not in first_line.lower():
        print("[FAIL] Shebang should reference python")
        return False

    print("[PASS] Shebang test passed")
    return True


def test_script_has_docstring():
    """Test that script has module-level docstring."""
    with open('k8s_init_container_analyzer.py', 'r') as f:
        content = f.read()

    if '"""' not in content[:500]:
        print("[FAIL] Script missing docstring")
        return False

    if 'init container' not in content[:1000].lower():
        print("[FAIL] Docstring should mention init container")
        return False

    print("[PASS] Docstring test passed")
    return True


def test_script_has_exit_codes_documented():
    """Test that exit codes are documented."""
    with open('k8s_init_container_analyzer.py', 'r') as f:
        content = f.read()

    if 'Exit codes:' not in content:
        print("[FAIL] Exit codes not documented")
        return False

    if '0 -' not in content or '1 -' not in content or '2 -' not in content:
        print("[FAIL] Exit codes 0, 1, 2 should be documented")
        return False

    print("[PASS] Exit codes documented test passed")
    return True


def test_script_imports():
    """Test that script imports necessary modules."""
    with open('k8s_init_container_analyzer.py', 'r') as f:
        content = f.read()

    required_imports = ['argparse', 'subprocess', 'json', 'sys']
    for module in required_imports:
        if f'import {module}' not in content:
            print(f"[FAIL] Missing import: {module}")
            return False

    print("[PASS] Script imports test passed")
    return True


def test_script_has_main_function():
    """Test that script has main function."""
    with open('k8s_init_container_analyzer.py', 'r') as f:
        content = f.read()

    if 'def main()' not in content:
        print("[FAIL] Missing main function")
        return False

    if "if __name__ == '__main__':" not in content:
        print("[FAIL] Missing __main__ check")
        return False

    print("[PASS] Main function test passed")
    return True


def test_script_handles_kubectl_not_found():
    """Test that script mentions kubectl requirement."""
    with open('k8s_init_container_analyzer.py', 'r') as f:
        content = f.read()

    if 'kubectl' not in content.lower():
        print("[FAIL] Script should reference kubectl")
        return False

    if 'FileNotFoundError' not in content:
        print("[FAIL] Script should handle kubectl not found")
        return False

    print("[PASS] Kubectl handling test passed")
    return True


def test_script_has_issue_types():
    """Test that script defines various issue types."""
    with open('k8s_init_container_analyzer.py', 'r') as f:
        content = f.read()

    issue_types = [
        'init_container_failed',
        'init_image_pull_error',
        'init_crashloop',
        'init_config_error'
    ]

    for issue_type in issue_types:
        if issue_type not in content:
            print(f"[FAIL] Missing issue type: {issue_type}")
            return False

    print("[PASS] Issue types test passed")
    return True


def test_script_has_remediation():
    """Test that script includes remediation suggestions."""
    with open('k8s_init_container_analyzer.py', 'r') as f:
        content = f.read()

    if 'remediation' not in content.lower():
        print("[FAIL] Script should include remediation suggestions")
        return False

    if 'get_remediation_suggestions' not in content:
        print("[FAIL] Missing get_remediation_suggestions function")
        return False

    print("[PASS] Remediation test passed")
    return True


def test_script_handles_common_errors():
    """Test that script handles common init container errors."""
    with open('k8s_init_container_analyzer.py', 'r') as f:
        content = f.read()

    common_errors = [
        'ImagePullBackOff',
        'CrashLoopBackOff',
        'OOMKilled',
        'CreateContainerConfigError'
    ]

    for error in common_errors:
        if error not in content:
            print(f"[FAIL] Missing handling for: {error}")
            return False

    print("[PASS] Common errors handling test passed")
    return True


def test_examples_in_help():
    """Test that help includes examples."""
    returncode, stdout, stderr = run_command(['--help'])

    if 'Examples:' not in stdout:
        print("[FAIL] Help missing Examples section")
        return False

    if 'k8s_init_container_analyzer.py' not in stdout:
        print("[FAIL] Examples should include script name")
        return False

    print("[PASS] Examples in help test passed")
    return True


def test_no_arguments_runs():
    """Test that script runs with no arguments."""
    returncode, stdout, stderr = run_command([])

    # Should either run successfully or fail gracefully
    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Unexpected exit code: {returncode}")
        return False

    print("[PASS] No arguments run test passed")
    return True


if __name__ == "__main__":
    print("Testing k8s_init_container_analyzer.py...")
    print()

    tests = [
        test_help_message,
        test_help_short_flag,
        test_namespace_option,
        test_namespace_short_option,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format_option,
        test_verbose_option,
        test_verbose_short_option,
        test_warn_only_option,
        test_warn_only_short_option,
        test_severity_option,
        test_severity_option_warning,
        test_severity_option_all,
        test_invalid_severity_option,
        test_combined_options,
        test_script_has_shebang,
        test_script_has_docstring,
        test_script_has_exit_codes_documented,
        test_script_imports,
        test_script_has_main_function,
        test_script_handles_kubectl_not_found,
        test_script_has_issue_types,
        test_script_has_remediation,
        test_script_handles_common_errors,
        test_examples_in_help,
        test_no_arguments_runs,
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
