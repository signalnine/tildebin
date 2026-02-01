#!/usr/bin/env python3
"""
Test script for k8s_namespace_resource_summary.py functionality.
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
        [sys.executable, 'k8s_namespace_resource_summary.py', '--help']
    )

    if return_code == 0 and 'namespace' in stdout.lower() and 'resource' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_plain():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--format', 'plain']
    )

    # Should not fail with "invalid choice" error
    if 'invalid choice' not in stderr:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print("[FAIL] Plain format option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_format_option_json():
    """Test that JSON format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--format', 'json']
    )

    # Should not fail with "invalid choice" error
    if 'invalid choice' not in stderr:
        print("[PASS] JSON format option test passed")
        return True
    else:
        print("[FAIL] JSON format option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_format_option_table():
    """Test that table format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--format', 'table']
    )

    # Should not fail with "invalid choice" error
    if 'invalid choice' not in stderr:
        print("[PASS] Table format option test passed")
        return True
    else:
        print("[FAIL] Table format option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_sort_option_cpu():
    """Test that sort by CPU option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--sort', 'cpu']
    )

    if 'invalid choice' not in stderr:
        print("[PASS] Sort by CPU option test passed")
        return True
    else:
        print("[FAIL] Sort by CPU option not recognized")
        return False


def test_sort_option_memory():
    """Test that sort by memory option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--sort', 'memory']
    )

    if 'invalid choice' not in stderr:
        print("[PASS] Sort by memory option test passed")
        return True
    else:
        print("[FAIL] Sort by memory option not recognized")
        return False


def test_sort_option_pods():
    """Test that sort by pods option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--sort', 'pods']
    )

    if 'invalid choice' not in stderr:
        print("[PASS] Sort by pods option test passed")
        return True
    else:
        print("[FAIL] Sort by pods option not recognized")
        return False


def test_sort_option_name():
    """Test that sort by name option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--sort', 'name']
    )

    if 'invalid choice' not in stderr:
        print("[PASS] Sort by name option test passed")
        return True
    else:
        print("[FAIL] Sort by name option not recognized")
        return False


def test_verbose_flag():
    """Test verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--verbose']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        return False


def test_all_flag():
    """Test --all flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--all']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] All flag test passed")
        return True
    else:
        print("[FAIL] All flag not recognized")
        return False


def test_warn_only_flag():
    """Test warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--warn-only']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        return False


def test_overprov_threshold_option():
    """Test --overprov-threshold option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--overprov-threshold', '50']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Overprov threshold option test passed")
        return True
    else:
        print("[FAIL] Overprov threshold option not recognized")
        return False


def test_invalid_overprov_threshold_zero():
    """Test that --overprov-threshold 0 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--overprov-threshold', '0']
    )

    if return_code == 2:
        print("[PASS] Zero overprov threshold test passed")
        return True
    else:
        print(f"[FAIL] Zero overprov threshold should return exit code 2, got {return_code}")
        return False


def test_invalid_overprov_threshold_negative():
    """Test that negative --overprov-threshold is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--overprov-threshold', '-10']
    )

    if return_code == 2:
        print("[PASS] Negative overprov threshold test passed")
        return True
    else:
        print(f"[FAIL] Negative overprov threshold should return exit code 2, got {return_code}")
        return False


def test_invalid_overprov_threshold_over_100():
    """Test that --overprov-threshold > 100 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--overprov-threshold', '150']
    )

    if return_code == 2:
        print("[PASS] Over 100 overprov threshold test passed")
        return True
    else:
        print(f"[FAIL] Overprov threshold > 100 should return exit code 2, got {return_code}")
        return False


def test_kubectl_missing_handling():
    """Test that missing kubectl is handled gracefully"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py']
    )

    # Should fail with exit code 2 if kubectl not available, or 0/1 if it works
    if return_code in [0, 1, 2]:
        if return_code == 2 and 'kubectl' in stderr.lower():
            print("[PASS] Kubectl missing handling test passed (kubectl not found)")
        else:
            print("[PASS] Kubectl missing handling test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_short_flags():
    """Test short flag aliases work"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '-f', 'json', '-s', 'memory', '-a', '-v']
    )

    # Should not fail due to unrecognized flags
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short flags test passed")
        return True
    else:
        print("[FAIL] Short flags not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py',
         '--format', 'table', '--sort', 'cpu', '--all', '--verbose',
         '--overprov-threshold', '30']
    )

    # Should not fail due to option conflicts
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options failed")
        print(f"  Return code: {return_code}")
        return False


def test_exit_code_validity():
    """Test that exit codes are valid (0, 1, or 2)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Exit code validity test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--help']
    )

    if return_code == 0 and 'Exit codes' in stdout:
        print("[PASS] Help documents exit codes")
        return True
    else:
        print("[FAIL] Help should document exit codes")
        return False


def test_help_contains_examples():
    """Test that help message includes examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--help']
    )

    if return_code == 0 and 'Example' in stdout:
        print("[PASS] Help contains examples")
        return True
    else:
        print("[FAIL] Help should contain examples")
        return False


def test_help_mentions_cost_attribution():
    """Test that help mentions cost attribution use case"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_namespace_resource_summary.py', '--help']
    )

    if return_code == 0 and 'cost' in stdout.lower():
        print("[PASS] Help mentions cost attribution")
        return True
    else:
        print("[FAIL] Help should mention cost attribution use case")
        return False


if __name__ == "__main__":
    print(f"Testing k8s_namespace_resource_summary.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_sort_option_cpu,
        test_sort_option_memory,
        test_sort_option_pods,
        test_sort_option_name,
        test_verbose_flag,
        test_all_flag,
        test_warn_only_flag,
        test_overprov_threshold_option,
        test_invalid_overprov_threshold_zero,
        test_invalid_overprov_threshold_negative,
        test_invalid_overprov_threshold_over_100,
        test_kubectl_missing_handling,
        test_short_flags,
        test_combined_options,
        test_exit_code_validity,
        test_help_contains_exit_codes,
        test_help_contains_examples,
        test_help_mentions_cost_attribution,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
