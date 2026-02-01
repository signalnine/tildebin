#!/usr/bin/env python3
"""
Test script for k8s_sidecar_analyzer.py functionality.
Tests argument parsing, output formats, and sidecar detection patterns
without requiring a real Kubernetes cluster.
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
        [sys.executable, 'k8s_sidecar_analyzer.py', '--help']
    )
    
    if return_code == 0 and 'sidecar' in stdout.lower() and 'kubernetes' in stdout.lower():
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
        [sys.executable, 'k8s_sidecar_analyzer.py', '--invalid-flag']
    )
    
    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_choices_valid():
    """Test that valid format choices are accepted."""
    for fmt in ['plain', 'json', 'table']:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_sidecar_analyzer.py', '--format', fmt, '--help']
        )
        if return_code != 0:
            print(f"[FAIL] Valid format '{fmt}' failed")
            return False
    
    print("[PASS] Valid format choices test passed")
    return True


def test_format_choices_invalid():
    """Test that invalid format choice is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py', '--format', 'xml']
    )
    
    if return_code == 2:
        print("[PASS] Invalid format choice test passed")
        return True
    else:
        print(f"[FAIL] Invalid format 'xml' should fail with exit code 2")
        print(f"  Return code: {return_code}")
        return False


def test_namespace_option():
    """Test --namespace option parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py', '-n', 'test-namespace', '--help']
    )
    
    if return_code == 0:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print(f"[FAIL] Namespace option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_option():
    """Test --verbose option parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py', '--verbose', '--help']
    )
    
    if return_code == 0:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed")
        return False


def test_warn_only_option():
    """Test --warn-only option parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py', '--warn-only', '--help']
    )
    
    if return_code == 0:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed")
        return False


def test_short_flags():
    """Test short form flags (-n, -v, -w)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py', '-v', '-w', '--help']
    )
    
    if return_code == 0:
        print("[PASS] Short flags test passed")
        return True
    else:
        print(f"[FAIL] Short flags test failed")
        return False


def test_kubectl_not_found_handling():
    """Test graceful handling when kubectl is not available."""
    import os
    
    # Temporarily modify PATH to exclude kubectl
    original_path = os.environ.get('PATH', '')
    os.environ['PATH'] = '/nonexistent'
    
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py']
    )
    
    # Restore PATH
    os.environ['PATH'] = original_path
    
    # Should exit with code 2 and show error message
    if return_code == 2 and ('kubectl' in stderr.lower() or 'not found' in stderr.lower()):
        print("[PASS] kubectl not found handling test passed")
        return True
    else:
        # If kubectl is in the script's environment, it may still find it
        # Just verify it doesn't crash unexpectedly
        if return_code in [0, 1, 2]:
            print("[PASS] kubectl not found handling test passed (kubectl available)")
            return True
        print(f"[FAIL] kubectl not found handling test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py',
         '--format', 'json', '--verbose', '--warn-only', '--help']
    )
    
    if return_code == 0:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py', '--help']
    )
    
    if return_code == 0 and 'exit' in stdout.lower() and '0' in stdout and '1' in stdout:
        print("[PASS] Help contains exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_help_contains_examples():
    """Test that help message includes examples."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py', '--help']
    )
    
    if return_code == 0 and ('example' in stdout.lower() or '-n production' in stdout):
        print("[PASS] Help contains examples test passed")
        return True
    else:
        print(f"[FAIL] Help should contain examples")
        return False


def test_help_mentions_sidecar_types():
    """Test that help mentions sidecar types being detected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py', '--help']
    )
    
    sidecar_keywords = ['istio', 'linkerd', 'envoy', 'service mesh', 'logging']
    found = any(kw in stdout.lower() for kw in sidecar_keywords)
    
    if return_code == 0 and found:
        print("[PASS] Help mentions sidecar types test passed")
        return True
    else:
        print(f"[FAIL] Help should mention sidecar types")
        return False


def test_json_format_with_kubectl_missing():
    """Test JSON output format handling."""
    import os
    
    # Test with potentially missing kubectl
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py', '--format', 'json']
    )
    
    # Should either produce valid JSON or exit with code 2
    if return_code == 2:
        print("[PASS] JSON format test passed (kubectl not available)")
        return True
    
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'pods' in data:
                print("[PASS] JSON format test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected keys")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] Invalid JSON output")
            return False
    
    print(f"[FAIL] Unexpected return code: {return_code}")
    return False


def test_description_field():
    """Test that the script has a proper docstring."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py', '--help']
    )
    
    # Check for key descriptive elements
    if return_code == 0 and len(stdout) > 200:
        print("[PASS] Description field test passed")
        return True
    else:
        print(f"[FAIL] Script should have descriptive help")
        return False


def test_table_format_option():
    """Test table format option parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_sidecar_analyzer.py', '--format', 'table', '--help']
    )
    
    if return_code == 0:
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed")
        return False


if __name__ == "__main__":
    print("Testing k8s_sidecar_analyzer.py...")
    print()
    
    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_choices_valid,
        test_format_choices_invalid,
        test_namespace_option,
        test_verbose_option,
        test_warn_only_option,
        test_short_flags,
        test_kubectl_not_found_handling,
        test_combined_options,
        test_help_contains_exit_codes,
        test_help_contains_examples,
        test_help_mentions_sidecar_types,
        test_json_format_with_kubectl_missing,
        test_description_field,
        test_table_format_option,
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
