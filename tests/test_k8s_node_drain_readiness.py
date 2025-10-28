#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for k8s_node_drain_readiness.py functionality.
Tests argument parsing, pod analysis, and drain readiness checking.
"""

import subprocess
import sys
import os
import json
import tempfile


def run_command(cmd_args):
    """Helper function to run a command and return result"""
    try:
        proc = subprocess.Popen(cmd_args,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_drain_readiness.py', '--help']
    )

    if return_code == 0 and 'drain readiness' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed")
        return False


def test_missing_node_argument():
    """Test that action requiring node fails without node argument"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_drain_readiness.py', '--action', 'check']
    )

    if return_code != 0:
        print("[PASS] Missing node argument test passed")
        return True
    else:
        print("[FAIL] Missing node argument test failed - should require node")
        return False


def test_invalid_action():
    """Test that invalid action is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_drain_readiness.py', 'node-1',
         '--action', 'invalid_action']
    )

    if return_code != 0:
        print("[PASS] Invalid action test passed")
        return True
    else:
        print("[FAIL] Invalid action test failed - should reject invalid action")
        return False


def test_valid_actions():
    """Test that valid actions are recognized"""
    valid_actions = ['check', 'drain', 'uncordon', 'check-all']

    for action in valid_actions:
        if action == 'check-all':
            return_code, _, stderr = run_command(
                [sys.executable, 'k8s_node_drain_readiness.py',
                 '--action', action, '--dry-run']
            )
        else:
            return_code, _, stderr = run_command(
                [sys.executable, 'k8s_node_drain_readiness.py', 'test-node',
                 '--action', action, '--dry-run']
            )

        # If kubectl is not available, return code 2 is acceptable
        if return_code in [0, 1, 2]:
            print(f"[PASS] Valid action '{action}' test passed (exit code: {return_code})")
        else:
            print(f"[FAIL] Valid action '{action}' test failed (exit code: {return_code})")
            return False

    return True


def test_output_formats():
    """Test that output formats are accepted"""
    formats = ['plain', 'table', 'json']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_node_drain_readiness.py', 'test-node',
             '--format', fmt, '--action', 'check']
        )

        # Exit code 2 is acceptable if kubectl not available
        if return_code == 2 and 'kubectl' in stderr:
            print(f"[PASS] Format '{fmt}' test passed (kubectl not available)")
        elif return_code in [0, 1]:
            # Check output format is reasonable
            if fmt == 'json':
                try:
                    json.loads(stdout)
                    print(f"[PASS] Format '{fmt}' test passed - valid JSON output")
                except json.JSONDecodeError:
                    print(f"[FAIL] Format '{fmt}' test failed - invalid JSON output")
                    return False
            else:
                if stdout or return_code == 0:
                    print(f"[PASS] Format '{fmt}' test passed")
                else:
                    print(f"[FAIL] Format '{fmt}' test failed - no output")
                    return False
        else:
            print(f"[FAIL] Format '{fmt}' test failed (exit code: {return_code})")
            return False

    return True


def test_dry_run_flag():
    """Test that dry-run flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_drain_readiness.py', 'test-node',
         '--action', 'drain', '--dry-run']
    )

    # Should succeed or fail gracefully (not with usage error)
    if return_code != 2:
        print("[PASS] Dry-run flag test passed")
        return True
    else:
        if 'argument' in stderr.lower():
            print("[FAIL] Dry-run flag test failed - flag not recognized")
            return False
        else:
            print("[PASS] Dry-run flag test passed (kubectl not available)")
            return True


def test_force_flag():
    """Test that force flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_drain_readiness.py', 'test-node',
         '--action', 'drain', '--force', '--dry-run']
    )

    # Should succeed or fail gracefully (not with usage error)
    if return_code != 2 or 'argument' not in stderr.lower():
        print("[PASS] Force flag test passed")
        return True
    else:
        print("[FAIL] Force flag test failed - flag not recognized")
        return False


def test_grace_period_flag():
    """Test that grace-period flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_drain_readiness.py', 'test-node',
         '--action', 'drain', '--grace-period', '60', '--dry-run']
    )

    # Should succeed or fail gracefully (not with usage error)
    if return_code != 2 or 'argument' not in stderr.lower():
        print("[PASS] Grace-period flag test passed")
        return True
    else:
        print("[FAIL] Grace-period flag test failed - flag not recognized")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_drain_readiness.py', 'test-node',
         '--action', 'check', '--warn-only']
    )

    # Should succeed or fail gracefully
    if return_code != 2 or 'argument' not in stderr.lower():
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag test failed - flag not recognized")
        return False


def run_all_tests():
    """Run all tests and report results"""
    tests = [
        test_help_message,
        test_missing_node_argument,
        test_invalid_action,
        test_valid_actions,
        test_output_formats,
        test_dry_run_flag,
        test_force_flag,
        test_grace_period_flag,
        test_warn_only_flag,
    ]

    print("Running k8s_node_drain_readiness.py tests...\n")

    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"[ERROR] Test {test.__name__} raised exception: {e}")
            results.append(False)

    print(f"\n{'='*60}")
    passed = sum(results)
    total = len(results)
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        return 0
    else:
        print(f"{total - passed} tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(run_all_tests())
