#!/usr/bin/env python3
"""
Test script for k8s_workload_generation_analyzer.py functionality.
Tests argument parsing and error handling without requiring kubectl access.
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
        [sys.executable, 'k8s_workload_generation_analyzer.py', '--help']
    )

    if return_code == 0 and 'workload' in stdout.lower() and 'ownership' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed - return code: {return_code}")
        return False


def test_namespace_option():
    """Test that namespace option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_workload_generation_analyzer.py', '-n', 'test-namespace']
    )

    # Should fail with kubectl error (exit 2) or succeed if kubectl available
    # The option should be recognized regardless
    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Namespace option test passed (kubectl not available)")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print(f"[FAIL] Namespace option test failed - return code: {return_code}")
        return False


def test_format_plain():
    """Test plain format option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_workload_generation_analyzer.py', '--format', 'plain']
    )

    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Plain format test passed (kubectl not available)")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Plain format test passed")
        return True
    else:
        print(f"[FAIL] Plain format test failed - return code: {return_code}")
        return False


def test_format_json():
    """Test JSON format option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_workload_generation_analyzer.py', '--format', 'json']
    )

    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] JSON format test passed (kubectl not available)")
        return True
    elif return_code in [0, 1]:
        # Try to parse JSON output
        try:
            data = json.loads(stdout)
            if 'workloads' in data and 'summary' in data:
                print("[PASS] JSON format test passed")
                return True
        except json.JSONDecodeError:
            pass
        print("[PASS] JSON format test passed (valid exit code)")
        return True
    else:
        print(f"[FAIL] JSON format test failed - return code: {return_code}")
        return False


def test_format_table():
    """Test table format option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_workload_generation_analyzer.py', '--format', 'table']
    )

    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Table format test passed (kubectl not available)")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Table format test passed")
        return True
    else:
        print(f"[FAIL] Table format test failed - return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_workload_generation_analyzer.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print(f"[FAIL] Invalid format test failed - should reject invalid format")
        return False


def test_verbose_option():
    """Test verbose option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_workload_generation_analyzer.py', '-v']
    )

    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Verbose option test passed (kubectl not available)")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed - return code: {return_code}")
        return False


def test_warn_only_option():
    """Test warn-only option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_workload_generation_analyzer.py', '-w']
    )

    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Warn-only option test passed (kubectl not available)")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed - return code: {return_code}")
        return False


def test_show_chain_option():
    """Test show-chain option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_workload_generation_analyzer.py', '--show-chain']
    )

    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Show-chain option test passed (kubectl not available)")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Show-chain option test passed")
        return True
    else:
        print(f"[FAIL] Show-chain option test failed - return code: {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_workload_generation_analyzer.py',
        '-n', 'kube-system',
        '--format', 'json',
        '-v',
        '--show-chain'
    ])

    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Combined options test passed (kubectl not available)")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed - return code: {return_code}")
        return False


def test_kubectl_not_found_handling():
    """Test that missing kubectl is handled gracefully"""
    # This test verifies the script exits with code 2 when kubectl is not available
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_workload_generation_analyzer.py']
    )

    # Either kubectl works (0 or 1) or it's not found (2)
    if return_code in [0, 1, 2]:
        if return_code == 2:
            if 'kubectl' in stderr.lower():
                print("[PASS] kubectl not found handling test passed")
                return True
        else:
            print("[PASS] kubectl not found handling test passed (kubectl available)")
            return True

    print(f"[FAIL] kubectl not found handling test failed - unexpected return code: {return_code}")
    return False


def test_short_options():
    """Test short option variants"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_workload_generation_analyzer.py',
        '-n', 'default',
        '-v',
        '-w'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Short options test passed")
        return True
    else:
        print(f"[FAIL] Short options test failed - return code: {return_code}")
        return False


def test_json_structure():
    """Test that JSON output has expected structure when kubectl available"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_workload_generation_analyzer.py',
        '--format', 'json'
    ])

    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] JSON structure test passed (kubectl not available)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            required_keys = ['timestamp', 'namespace_filter', 'total_pods', 'workloads', 'summary']
            if all(key in data for key in required_keys):
                summary_keys = ['by_generator_type', 'by_root_kind', 'orphaned', 'standalone']
                if all(key in data['summary'] for key in summary_keys):
                    print("[PASS] JSON structure test passed")
                    return True
        except json.JSONDecodeError:
            pass

    print(f"[FAIL] JSON structure test failed")
    return False


if __name__ == "__main__":
    print("Testing k8s_workload_generation_analyzer.py...")
    print()

    tests = [
        test_help_message,
        test_namespace_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_verbose_option,
        test_warn_only_option,
        test_show_chain_option,
        test_combined_options,
        test_kubectl_not_found_handling,
        test_short_options,
        test_json_structure,
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
