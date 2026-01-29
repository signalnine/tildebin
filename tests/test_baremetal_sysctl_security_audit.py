#!/usr/bin/env python3
"""
Test script for baremetal_sysctl_security_audit.py functionality.
Tests argument parsing, output formats, and error handling without requiring
root access or specific sysctl values.

When sysctl is not available, tests verify that the script properly exits
with code 2 (missing dependency).
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


def is_sysctl_available():
    """Check if sysctl command is available on the system"""
    returncode, _, _ = run_command(['which', 'sysctl'])
    return returncode == 0


# Check once at module load
SYSCTL_AVAILABLE = is_sysctl_available()


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py', '--help']
    )

    if return_code != 0:
        print("[FAIL] Help message test failed - non-zero exit code")
        print("  Return code:", return_code)
        print("  Stderr:", stderr[:200])
        return False

    expected_texts = [
        'security',
        '--format',
        '--category',
        '--severity',
        '--verbose',
        '--warn-only',
    ]

    for text in expected_texts:
        if text not in stdout.lower():
            print("[FAIL] Help message missing expected text: {}".format(text))
            return False

    print("[PASS] Help message test passed")
    return True


def test_list_checks():
    """Test that --list-checks shows all security checks"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py', '--list-checks']
    )

    if return_code != 0:
        print("[FAIL] List checks test failed - non-zero exit code")
        print("  Return code:", return_code)
        print("  Stderr:", stderr[:200])
        return False

    # Should show categories and parameters
    expected_texts = [
        'network_ipv4',
        'network_ipv6',
        'kernel_memory',
        'filesystem',
        'net.ipv4.ip_forward',
        'kernel.randomize_va_space',
        'fs.protected_symlinks',
        'Total:',
    ]

    for text in expected_texts:
        if text not in stdout:
            print("[FAIL] List checks missing expected text: {}".format(text))
            print("  First 500 chars of output:", stdout[:500])
            return False

    print("[PASS] List checks test passed")
    return True


def test_missing_sysctl_handling():
    """Test that missing sysctl is handled gracefully"""
    if SYSCTL_AVAILABLE:
        print("[SKIP] Missing sysctl test - sysctl is available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py', '--format', 'json']
    )

    if return_code == 2 and 'sysctl' in stderr.lower():
        print("[PASS] Missing sysctl handling test passed")
        return True
    else:
        print("[FAIL] Should exit with code 2 when sysctl missing")
        print("  Return code:", return_code)
        print("  Stderr:", stderr[:200])
        return False


def test_json_output_format():
    """Test JSON output format is valid JSON"""
    if not SYSCTL_AVAILABLE:
        print("[SKIP] JSON output test - sysctl not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py', '--format', 'json']
    )

    # Exit code could be 0 or 1 depending on system config
    if return_code == 2:
        print("[FAIL] JSON output test failed - exit code 2 (usage error)")
        print("  Stderr:", stderr[:200])
        return False

    try:
        data = json.loads(stdout)

        # Check expected structure
        if 'summary' not in data:
            print("[FAIL] JSON output missing 'summary' key")
            return False

        if 'results' not in data:
            print("[FAIL] JSON output missing 'results' key")
            return False

        # Check summary structure
        summary = data['summary']
        required_keys = ['total_checks', 'passed', 'failed', 'unavailable', 'by_severity']
        for key in required_keys:
            if key not in summary:
                print("[FAIL] JSON summary missing key: {}".format(key))
                return False

        print("[PASS] JSON output format test passed")
        return True

    except json.JSONDecodeError as e:
        print("[FAIL] JSON parsing failed: {}".format(str(e)))
        print("  First 200 chars of output:", stdout[:200])
        return False


def test_table_output_format():
    """Test table output format"""
    if not SYSCTL_AVAILABLE:
        print("[SKIP] Table output test - sysctl not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py', '--format', 'table']
    )

    if return_code == 2:
        print("[FAIL] Table output test failed - exit code 2 (usage error)")
        print("  Stderr:", stderr[:200])
        return False

    # Table should have headers or show "All checks passed"
    if 'Status' in stdout or 'Severity' in stdout or 'passed' in stdout.lower():
        print("[PASS] Table output format test passed")
        return True
    else:
        print("[FAIL] Table output missing expected header elements")
        print("  First 300 chars of output:", stdout[:300])
        return False


def test_plain_output_format():
    """Test plain output format"""
    if not SYSCTL_AVAILABLE:
        print("[SKIP] Plain output test - sysctl not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py', '--format', 'plain']
    )

    if return_code == 2:
        print("[FAIL] Plain output test failed - exit code 2 (usage error)")
        print("  Stderr:", stderr[:200])
        return False

    # Plain output should have readable text (either summary or "passed" message)
    if len(stdout) > 0:
        print("[PASS] Plain output format test passed")
        return True
    else:
        print("[FAIL] Plain output was empty")
        return False


def test_category_filter_network():
    """Test filtering by network category"""
    if not SYSCTL_AVAILABLE:
        print("[SKIP] Category filter (network) test - sysctl not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py',
         '--category', 'network', '--format', 'json']
    )

    if return_code == 2:
        print("[FAIL] Category filter test failed - exit code 2 (usage error)")
        return False

    try:
        data = json.loads(stdout)
        results = data.get('results', [])

        # All results should be from network categories
        for r in results:
            if not r['category'].startswith('network'):
                print("[FAIL] Non-network category found: {}".format(r['category']))
                return False

        print("[PASS] Category filter (network) test passed")
        return True

    except json.JSONDecodeError:
        print("[FAIL] JSON parsing failed in category filter test")
        return False


def test_category_filter_kernel():
    """Test filtering by kernel category"""
    if not SYSCTL_AVAILABLE:
        print("[SKIP] Category filter (kernel) test - sysctl not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py',
         '--category', 'kernel', '--format', 'json']
    )

    if return_code == 2:
        print("[FAIL] Category filter test failed - exit code 2 (usage error)")
        return False

    try:
        data = json.loads(stdout)
        results = data.get('results', [])

        # All results should be from kernel categories
        valid_categories = ['kernel_memory', 'kernel_modules', 'user_namespaces']
        for r in results:
            if r['category'] not in valid_categories:
                print("[FAIL] Invalid category found: {}".format(r['category']))
                return False

        print("[PASS] Category filter (kernel) test passed")
        return True

    except json.JSONDecodeError:
        print("[FAIL] JSON parsing failed in category filter test")
        return False


def test_severity_filter():
    """Test filtering by severity"""
    if not SYSCTL_AVAILABLE:
        print("[SKIP] Severity filter test - sysctl not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py',
         '--severity', 'high', '--format', 'json']
    )

    if return_code == 2:
        print("[FAIL] Severity filter test failed - exit code 2 (usage error)")
        return False

    try:
        data = json.loads(stdout)
        results = data.get('results', [])

        # All results should be high or critical severity
        for r in results:
            if r['severity'] not in ['high', 'critical']:
                print("[FAIL] Lower severity found: {}".format(r['severity']))
                return False

        print("[PASS] Severity filter test passed")
        return True

    except json.JSONDecodeError:
        print("[FAIL] JSON parsing failed in severity filter test")
        return False


def test_verbose_mode():
    """Test verbose mode shows passed checks"""
    if not SYSCTL_AVAILABLE:
        print("[SKIP] Verbose mode test - sysctl not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py',
         '--verbose', '--format', 'json']
    )

    if return_code == 2:
        print("[FAIL] Verbose mode test failed - exit code 2 (usage error)")
        return False

    try:
        data = json.loads(stdout)
        results = data.get('results', [])

        # Verbose mode should include results
        if len(results) >= 1:
            print("[PASS] Verbose mode test passed")
            return True
        else:
            print("[FAIL] Verbose mode returned no results")
            return False

    except json.JSONDecodeError:
        print("[FAIL] JSON parsing failed in verbose mode test")
        return False


def test_warn_only_mode():
    """Test warn-only mode only shows failures"""
    if not SYSCTL_AVAILABLE:
        print("[SKIP] Warn-only mode test - sysctl not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py',
         '--warn-only', '--format', 'json']
    )

    if return_code == 2:
        print("[FAIL] Warn-only mode test failed - exit code 2 (usage error)")
        return False

    try:
        data = json.loads(stdout)
        results = data.get('results', [])

        # Warn-only should only have fail/unavailable status
        for r in results:
            if r['status'] == 'pass':
                print("[FAIL] Passed check found in warn-only mode")
                return False

        print("[PASS] Warn-only mode test passed")
        return True

    except json.JSONDecodeError:
        print("[FAIL] JSON parsing failed in warn-only mode test")
        return False


def test_invalid_category():
    """Test that invalid category option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py',
         '--category', 'invalid_category']
    )

    if return_code == 2:
        print("[PASS] Invalid category test passed (rejected with exit code 2)")
        return True
    else:
        print("[FAIL] Invalid category should be rejected")
        return False


def test_invalid_severity():
    """Test that invalid severity option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py',
         '--severity', 'super_critical']
    )

    if return_code == 2:
        print("[PASS] Invalid severity test passed (rejected with exit code 2)")
        return True
    else:
        print("[FAIL] Invalid severity should be rejected")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py',
         '--format', 'yaml']
    )

    if return_code == 2:
        print("[PASS] Invalid format test passed (rejected with exit code 2)")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        return False


def test_result_structure():
    """Test that results have expected structure"""
    if not SYSCTL_AVAILABLE:
        print("[SKIP] Result structure test - sysctl not available")
        return True

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py',
         '--verbose', '--format', 'json']
    )

    if return_code == 2:
        print("[FAIL] Result structure test failed - exit code 2 (usage error)")
        return False

    try:
        data = json.loads(stdout)
        results = data.get('results', [])

        if not results:
            print("[FAIL] No results returned")
            return False

        # Check first result has expected fields
        r = results[0]
        required_fields = ['parameter', 'expected', 'actual', 'severity',
                          'description', 'status', 'passed', 'category']

        for field in required_fields:
            if field not in r:
                print("[FAIL] Result missing field: {}".format(field))
                return False

        print("[PASS] Result structure test passed")
        return True

    except json.JSONDecodeError:
        print("[FAIL] JSON parsing failed in result structure test")
        return False


def test_exit_code_semantics():
    """Test that exit codes follow convention"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_security_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code semantics test passed (exit code: {})".format(
            return_code))
        return True
    elif return_code == 2:
        # This is OK if sysctl isn't available (missing dependency)
        if 'sysctl' in stderr.lower() and 'not found' in stderr.lower():
            print("[PASS] Exit code semantics test passed "
                  "(exit code 2 for missing sysctl)")
            return True
        # Also OK for invalid arguments (but we used valid ones)
        print("[FAIL] Unexpected exit code 2: {}".format(stderr[:200]))
        return False
    else:
        print("[FAIL] Unexpected exit code: {}".format(return_code))
        return False


if __name__ == "__main__":
    print("Testing baremetal_sysctl_security_audit.py...")
    print("sysctl available: {}".format(SYSCTL_AVAILABLE))
    print()

    tests = [
        test_help_message,
        test_list_checks,
        test_missing_sysctl_handling,
        test_json_output_format,
        test_table_output_format,
        test_plain_output_format,
        test_category_filter_network,
        test_category_filter_kernel,
        test_severity_filter,
        test_verbose_mode,
        test_warn_only_mode,
        test_invalid_category,
        test_invalid_severity,
        test_invalid_format,
        test_result_structure,
        test_exit_code_semantics,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print("[FAIL] {} raised exception: {}".format(test.__name__, str(e)))
            failed += 1

    print()
    print("=" * 50)
    print("Test Results: {}/{} tests passed".format(passed, passed + failed))

    sys.exit(0 if failed == 0 else 1)
