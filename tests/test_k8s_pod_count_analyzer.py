#!/usr/bin/env python3
"""
Test script for k8s_pod_count_analyzer.py functionality.
Tests argument parsing and error handling without requiring actual kubectl access.
"""

import subprocess
import sys


def run_command(cmd_args):
    """Helper function to run a command and return result"""
    try:
        proc = subprocess.Popen(cmd_args,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_pod_count_analyzer.py', '--help'])

    if return_code == 0 and 'pod count' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_format_option_table():
    """Test that the table format option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_pod_count_analyzer.py', '--format', 'table'])

    # Will fail due to missing kubectl, but should parse args correctly
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Format table option test passed")
        return True
    else:
        print("[FAIL] Format table option test failed with return code: " + str(return_code))
        return False


def test_format_option_json():
    """Test that the json format option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_pod_count_analyzer.py', '--format', 'json'])

    # Will fail due to missing kubectl, but should parse args correctly
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Format json option test passed")
        return True
    else:
        print("[FAIL] Format json option test failed with return code: " + str(return_code))
        return False


def test_format_option_plain():
    """Test that the plain format option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_pod_count_analyzer.py', '--format', 'plain'])

    # Will fail due to missing kubectl, but should parse args correctly
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print("[FAIL] Format plain option test failed with return code: " + str(return_code))
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_pod_count_analyzer.py', '--format', 'invalid'])

    # Should fail with argument error
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_namespace_option():
    """Test that the namespace option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_pod_count_analyzer.py', '-n', 'default'])

    # Will fail due to missing kubectl, but should parse args correctly
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print("[FAIL] Namespace option test failed with return code: " + str(return_code))
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_pod_count_analyzer.py', '--warn-only'])

    # Will fail due to missing kubectl, but should parse args correctly
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: " + str(return_code))
        return False


def test_deployments_only_option():
    """Test that the deployments-only option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_pod_count_analyzer.py', '--deployments-only'])

    # Will fail due to missing kubectl, but should parse args correctly
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Deployments-only option test passed")
        return True
    else:
        print("[FAIL] Deployments-only option test failed with return code: " + str(return_code))
        return False


def test_statefulsets_only_option():
    """Test that the statefulsets-only option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_pod_count_analyzer.py', '--statefulsets-only'])

    # Will fail due to missing kubectl, but should parse args correctly
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] StatefulSets-only option test passed")
        return True
    else:
        print("[FAIL] StatefulSets-only option test failed with return code: " + str(return_code))
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_count_analyzer.py',
        '-n', 'production',
        '--format', 'json',
        '--warn-only'
    ])

    # Will fail due to missing kubectl, but should parse args correctly
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: " + str(return_code))
        return False


def test_long_namespace_option():
    """Test that the --namespace long option works"""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_pod_count_analyzer.py', '--namespace', 'kube-system'])

    # Will fail due to missing kubectl, but should parse args correctly
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Long namespace option test passed")
        return True
    else:
        print("[FAIL] Long namespace option test failed with return code: " + str(return_code))
        return False


if __name__ == "__main__":
    print("Testing k8s_pod_count_analyzer.py...")

    tests = [
        test_help_message,
        test_format_option_table,
        test_format_option_json,
        test_format_option_plain,
        test_invalid_format,
        test_namespace_option,
        test_warn_only_option,
        test_deployments_only_option,
        test_statefulsets_only_option,
        test_combined_options,
        test_long_namespace_option,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print("\nTest Results: " + str(passed) + "/" + str(total) + " tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
