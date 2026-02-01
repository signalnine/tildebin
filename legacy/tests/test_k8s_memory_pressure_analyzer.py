#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for k8s_memory_pressure_analyzer.py functionality.
Tests memory parsing, pod analysis, node pressure checking, and formatting.
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
        [sys.executable, 'k8s_memory_pressure_analyzer.py', '--help']
    )

    if return_code == 0 and 'memory pressure' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed")
        print(f"  Expected: return_code=0 and 'memory pressure' in output")
        print(f"  Got: return_code={return_code}")
        return False


def test_argument_parsing():
    """Test various argument combinations"""
    test_cases = [
        (['-n', 'default'], "namespace argument"),
        (['--namespace', 'kube-system'], "long namespace argument"),
        (['--nodes-only'], "nodes-only flag"),
        (['--pods-only'], "pods-only flag"),
    ]

    all_passed = True
    for args, description in test_cases:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_memory_pressure_analyzer.py'] + args
        )

        # We expect either success (0) or failure if kubectl not available (2)
        # or if the cluster doesn't exist (1)
        if return_code in [0, 1, 2]:
            print(f"[PASS] Argument parsing test ({description})")
        else:
            print(f"[FAIL] Argument parsing test ({description})")
            print(f"  Got unexpected return code: {return_code}")
            print(f"  stderr: {stderr}")
            all_passed = False

    return all_passed


def test_memory_value_parsing():
    """Test memory value parsing without importing the module"""
    # Create a test Python script that uses parse_memory_value
    test_script = '''
import sys
sys.path.insert(0, '.')
from k8s_memory_pressure_analyzer import parse_memory_value

test_cases = [
    ('512Mi', 512 * 1024 ** 2),
    ('1Gi', 1024 ** 3),
    ('2Gi', 2 * 1024 ** 3),
    ('256Ki', 256 * 1024),
    ('1024', 1024),
    ('0', 0),
    ('', 0),
    ('invalid', 0),
]

all_passed = True
for input_val, expected in test_cases:
    result = parse_memory_value(input_val)
    if result == expected:
        print(f"[PASS] Memory parsing: {input_val} -> {result}")
    else:
        print(f"[FAIL] Memory parsing: {input_val}")
        print(f"  Expected: {expected}")
        print(f"  Got: {result}")
        all_passed = False

sys.exit(0 if all_passed else 1)
'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_script)
        f.flush()
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            [sys.executable, temp_file]
        )

        print(stdout)
        if return_code == 0:
            print("[PASS] Memory value parsing tests passed")
            return True
        else:
            print("[FAIL] Memory value parsing tests failed")
            if stderr:
                print(f"  stderr: {stderr}")
            return False
    finally:
        os.unlink(temp_file)


def test_format_bytes():
    """Test byte formatting"""
    test_script = '''
import sys
sys.path.insert(0, '.')
from k8s_memory_pressure_analyzer import format_bytes

test_cases = [
    (0, 'B'),
    (512, 'B'),
    (1024, 'Ki'),
    (1024 * 512, 'Ki'),
    (1024 ** 2, 'Mi'),
    (512 * 1024 ** 2, 'Mi'),
    (1024 ** 3, 'Gi'),
    (2 * 1024 ** 3, 'Gi'),
]

all_passed = True
for input_val, expected_unit in test_cases:
    result = format_bytes(input_val)
    # Check if the result contains the expected unit
    if expected_unit in result:
        print(f"[PASS] Format bytes: {input_val} -> {result}")
    else:
        print(f"[FAIL] Format bytes: {input_val}")
        print(f"  Expected unit: {expected_unit}")
        print(f"  Got: {result}")
        all_passed = False

sys.exit(0 if all_passed else 1)
'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_script)
        f.flush()
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            [sys.executable, temp_file]
        )

        print(stdout)
        if return_code == 0:
            print("[PASS] Byte formatting tests passed")
            return True
        else:
            print("[FAIL] Byte formatting tests failed")
            if stderr:
                print(f"  stderr: {stderr}")
            return False
    finally:
        os.unlink(temp_file)


def test_invalid_arguments():
    """Test handling of invalid arguments"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_memory_pressure_analyzer.py', '--invalid-arg']
    )

    if return_code != 0:
        print("[PASS] Invalid argument handling test passed")
        return True
    else:
        print("[FAIL] Invalid argument handling test failed")
        return False


def test_namespace_option():
    """Test that namespace option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_memory_pressure_analyzer.py', '-n', 'kube-system']
    )

    # Should fail with kubectl error but accept the flag
    if return_code in [1, 2]:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print("[FAIL] Namespace option test failed")
        return False


def test_all_namespaces_flag():
    """Test that --all-namespaces flag works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_memory_pressure_analyzer.py', '--all-namespaces']
    )

    # Should fail with kubectl error but accept the flag
    if return_code in [1, 2]:
        print("[PASS] All namespaces flag test passed")
        return True
    else:
        print("[FAIL] All namespaces flag test failed")
        return False


def test_threshold_option():
    """Test that threshold option accepts values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_memory_pressure_analyzer.py', '--threshold', '90']
    )

    # Should fail with kubectl error but accept the flag
    if return_code in [1, 2]:
        print("[PASS] Threshold option test passed")
        return True
    else:
        print("[FAIL] Threshold option test failed")
        return False


def test_output_format_options():
    """Test that output format options work"""
    for fmt in ['plain', 'json']:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_memory_pressure_analyzer.py', '--format', fmt]
        )

        # Should fail with kubectl error but accept the flag
        if return_code not in [1, 2]:
            print(f"[FAIL] Format {fmt} test failed")
            return False

    print("[PASS] Output format options test passed")
    return True


def test_script_syntax():
    """Test that the script has valid Python syntax"""
    return_code, stdout, stderr = run_command(
        [sys.executable, '-m', 'py_compile', 'k8s_memory_pressure_analyzer.py']
    )

    if return_code == 0:
        print("[PASS] Python syntax validation test passed")
        return True
    else:
        print("[FAIL] Python syntax validation test failed")
        print(f"  stderr: {stderr}")
        return False


def run_all_tests():
    """Run all tests and return results"""
    print("=" * 60)
    print("Running k8s_memory_pressure_analyzer.py tests")
    print("=" * 60)

    tests = [
        ("Script syntax validation", test_script_syntax),
        ("Help message", test_help_message),
        ("Argument parsing", test_argument_parsing),
        ("Memory value parsing", test_memory_value_parsing),
        ("Byte formatting", test_format_bytes),
        ("Invalid argument handling", test_invalid_arguments),
        ("Namespace option", test_namespace_option),
        ("All namespaces flag", test_all_namespaces_flag),
        ("Threshold option", test_threshold_option),
        ("Output format options", test_output_format_options),
    ]

    results = []
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"[ERROR] Test raised exception: {e}")
            results.append((test_name, False))

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    passed = sum(1 for _, result in results if result)
    total = len(results)

    print(f"\nTest Results: {passed}/{total} tests passed")

    for test_name, result in results:
        status = "✓" if result else "✗"
        print(f"  {status} {test_name}")

    return 0 if passed == total else 1


if __name__ == '__main__':
    sys.exit(run_all_tests())
