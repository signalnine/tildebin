#!/usr/bin/env python3
"""
Test script for baremetal_kernel_security_audit.py functionality.
Tests argument parsing and error handling without requiring special permissions.
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
        [sys.executable, 'baremetal_kernel_security_audit.py', '--help']
    )

    if return_code == 0 and 'security' in stdout.lower() and 'kernel' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_format_option_plain():
    """Test plain format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--format', 'plain']
    )

    # Should succeed (exit 0 or 1 depending on system config)
    if return_code in [0, 1]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_format_option_json():
    """Test JSON format option is accepted and produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON format option test failed - unexpected return code")
        print(f"  Return code: {return_code}")
        return False

    try:
        data = json.loads(stdout)
        if 'results' in data and 'timestamp' in data and 'summary' in data:
            print("[PASS] JSON format option test passed")
            return True
        else:
            print(f"[FAIL] JSON missing expected keys")
            print(f"  Keys found: {list(data.keys())}")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_format_option_table():
    """Test table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '-v']
    )

    if return_code in [0, 1]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_flag():
    """Test warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--warn-only']
    )

    if return_code in [0, 1]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_category_option():
    """Test category filtering option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--category', 'network']
    )

    if return_code in [0, 1] and 'network' in stdout.lower():
        print("[PASS] Category option test passed")
        return True
    else:
        print(f"[FAIL] Category option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_multiple_categories():
    """Test multiple category filtering"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py',
         '--category', 'network', '--category', 'memory']
    )

    if return_code in [0, 1]:
        print("[PASS] Multiple categories test passed")
        return True
    else:
        print(f"[FAIL] Multiple categories test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_category():
    """Test that invalid category is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--category', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr.lower():
        print("[PASS] Invalid category test passed")
        return True
    else:
        print(f"[FAIL] Invalid category should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_strict_mode():
    """Test strict mode flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--strict']
    )

    if return_code in [0, 1]:
        print("[PASS] Strict mode test passed")
        return True
    else:
        print(f"[FAIL] Strict mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_list_parameters():
    """Test list-parameters option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--list-parameters']
    )

    if return_code == 0 and 'net.ipv4' in stdout and 'kernel.' in stdout:
        print("[PASS] List parameters test passed")
        return True
    else:
        print(f"[FAIL] List parameters test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_combined_flags():
    """Test combining multiple flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py',
         '--format', 'json', '-v', '--warn-only']
    )

    if return_code in [0, 1]:
        print("[PASS] Combined flags test passed")
        return True
    else:
        print(f"[FAIL] Combined flags test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_structure():
    """Test JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON structure test failed - bad return code")
        return False

    try:
        data = json.loads(stdout)

        # Check top-level keys
        required_keys = ['timestamp', 'hostname', 'results', 'summary']
        has_keys = all(key in data for key in required_keys)

        if not has_keys:
            print(f"[FAIL] JSON missing required keys")
            print(f"  Found: {list(data.keys())}")
            return False

        # Check summary structure
        summary_keys = ['total', 'pass', 'fail', 'score']
        has_summary = all(key in data['summary'] for key in summary_keys)

        if not has_summary:
            print(f"[FAIL] JSON summary missing keys")
            print(f"  Found: {list(data['summary'].keys())}")
            return False

        # Check result structure if any exist
        if data['results']:
            result = data['results'][0]
            result_keys = ['parameter', 'recommended', 'current', 'severity', 'category', 'status']
            has_result_keys = all(key in result for key in result_keys)
            if not has_result_keys:
                print(f"[FAIL] Result entry missing keys")
                print(f"  Found: {list(result.keys())}")
                return False

        print("[PASS] JSON structure test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_exit_codes_documented():
    """Test that exit codes are documented in help"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--help']
    )

    if 'exit code' in stdout.lower() or 'Exit codes' in stdout:
        print("[PASS] Exit codes documentation test passed")
        return True
    else:
        print(f"[FAIL] Exit codes should be documented in help")
        return False


def test_examples_in_help():
    """Test that examples are included in help"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--help']
    )

    if 'example' in stdout.lower() or 'Examples' in stdout:
        print("[PASS] Examples in help test passed")
        return True
    else:
        print(f"[FAIL] Examples should be in help")
        return False


def test_categories_documented():
    """Test that categories are documented in help"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--help']
    )

    categories = ['network', 'memory', 'kernel', 'filesystem', 'namespace']
    found_categories = sum(1 for cat in categories if cat in stdout.lower())

    if found_categories >= 3:  # At least 3 categories mentioned
        print("[PASS] Categories documented test passed")
        return True
    else:
        print(f"[FAIL] Categories should be documented in help")
        return False


def test_output_contains_security_info():
    """Test that output contains security parameter information"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py']
    )

    # Should have at least some parameter info
    if return_code in [0, 1] and ('net.ipv4' in stdout or 'kernel.' in stdout or 'SUMMARY' in stdout):
        print("[PASS] Output contains security info test passed")
        return True
    else:
        print(f"[FAIL] Output should contain security info")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_format_headers():
    """Test table format has proper headers"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        # Check for header elements
        if 'Parameter' in stdout or 'Recommended' in stdout or 'meet recommendations' in stdout:
            print("[PASS] Table format headers test passed")
            return True

    print(f"[FAIL] Table format should have headers")
    print(f"  Output: {stdout[:200]}")
    return False


def test_summary_includes_score():
    """Test that summary includes security score"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py']
    )

    if return_code in [0, 1] and 'score' in stdout.lower():
        print("[PASS] Summary includes score test passed")
        return True
    else:
        print(f"[FAIL] Summary should include security score")
        return False


def test_json_summary_has_score():
    """Test that JSON summary includes numerical score"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_security_audit.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON summary score test failed - bad return code")
        return False

    try:
        data = json.loads(stdout)
        score = data.get('summary', {}).get('score')

        if isinstance(score, (int, float)) and 0 <= score <= 100:
            print("[PASS] JSON summary has score test passed")
            return True
        else:
            print(f"[FAIL] Score should be a number between 0-100")
            print(f"  Score: {score}")
            return False

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_kernel_security_audit.py...")
    print()

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_category_option,
        test_multiple_categories,
        test_invalid_category,
        test_strict_mode,
        test_list_parameters,
        test_combined_flags,
        test_json_structure,
        test_exit_codes_documented,
        test_examples_in_help,
        test_categories_documented,
        test_output_contains_security_info,
        test_table_format_headers,
        test_summary_includes_score,
        test_json_summary_has_score,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
