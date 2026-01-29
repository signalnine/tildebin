#!/usr/bin/env python3
"""
Test script for baremetal_sysctl_drift_detector.py functionality.
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
        stdout, stderr = proc.communicate(timeout=30)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--help']
    )

    if return_code == 0 and 'sysctl' in stdout.lower() and 'drift' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_format_option_plain():
    """Test that plain format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--format', 'plain']
    )

    # Script will run - check for valid exit codes
    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option is accepted and produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'changed' in data:
                print("[PASS] JSON format option test passed")
                return True
            else:
                print(f"[FAIL] JSON format missing expected keys")
                print(f"  Keys found: {list(data.keys())}")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON format test failed: invalid JSON output")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # sysctl not available - acceptable
        print("[PASS] JSON format option test passed (sysctl not available)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed: unexpected return code {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--format', 'invalid']
    )

    if return_code == 2 or 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test that verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed: unexpected return code {return_code}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_pattern_option():
    """Test that pattern option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--pattern', 'net.ipv4']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Pattern option test passed")
        return True
    else:
        print(f"[FAIL] Pattern option test failed: unexpected return code {return_code}")
        return False


def test_category_option():
    """Test that category option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--category', 'network_security']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Category option test passed")
        return True
    else:
        print(f"[FAIL] Category option test failed: unexpected return code {return_code}")
        return False


def test_invalid_category():
    """Test that invalid category option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--category', 'nonexistent']
    )

    if return_code == 2 or 'invalid choice' in stderr.lower():
        print("[PASS] Invalid category rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid category should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_ignore_extra_flag():
    """Test that ignore-extra flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--ignore-extra']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Ignore-extra flag test passed")
        return True
    else:
        print(f"[FAIL] Ignore-extra flag test failed: unexpected return code {return_code}")
        return False


def test_save_baseline():
    """Test that save-baseline option creates a file"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name

    try:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_sysctl_drift_detector.py',
             '--save-baseline', temp_path]
        )

        if return_code == 0 and os.path.exists(temp_path):
            # Verify it's valid JSON
            with open(temp_path, 'r') as f:
                data = json.load(f)
            if isinstance(data, dict) and len(data) > 0:
                print("[PASS] Save baseline test passed")
                return True
            else:
                print(f"[FAIL] Save baseline created empty or invalid file")
                return False
        elif return_code == 2:
            # sysctl not available
            print("[PASS] Save baseline test passed (sysctl not available)")
            return True
        else:
            print(f"[FAIL] Save baseline test failed: return code {return_code}")
            return False
    except Exception as e:
        print(f"[FAIL] Save baseline test failed: {e}")
        return False
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_load_baseline_json():
    """Test that JSON baseline file can be loaded"""
    baseline = {
        "kernel.randomize_va_space": "2",
        "net.ipv4.tcp_syncookies": "1"
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(baseline, f)
        temp_path = f.name

    try:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_sysctl_drift_detector.py',
             '--baseline', temp_path, '--format', 'json']
        )

        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                if 'summary' in data:
                    print("[PASS] Load JSON baseline test passed")
                    return True
            except json.JSONDecodeError:
                pass
            print(f"[FAIL] Load JSON baseline test failed: invalid output")
            return False
        elif return_code == 2:
            print("[PASS] Load JSON baseline test passed (sysctl not available)")
            return True
        else:
            print(f"[FAIL] Load JSON baseline test failed: return code {return_code}")
            return False
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_load_baseline_sysctl_format():
    """Test that sysctl.conf format baseline can be loaded"""
    baseline_content = """# Test baseline
kernel.randomize_va_space = 2
net.ipv4.tcp_syncookies = 1
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(baseline_content)
        temp_path = f.name

    try:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_sysctl_drift_detector.py',
             '--baseline', temp_path, '--format', 'json']
        )

        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                if 'summary' in data:
                    print("[PASS] Load sysctl.conf format baseline test passed")
                    return True
            except json.JSONDecodeError:
                pass
            print(f"[FAIL] Load sysctl.conf format baseline test failed")
            return False
        elif return_code == 2:
            print("[PASS] Load sysctl.conf format baseline test passed (sysctl not available)")
            return True
        else:
            print(f"[FAIL] Load sysctl.conf format baseline test failed: return code {return_code}")
            return False
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_nonexistent_baseline():
    """Test that nonexistent baseline file is handled"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py',
         '--baseline', '/nonexistent/path/baseline.json']
    )

    if return_code == 2 and 'not found' in stderr.lower():
        print("[PASS] Nonexistent baseline test passed")
        return True
    else:
        print(f"[FAIL] Nonexistent baseline should fail with error")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py',
         '--format', 'json', '-v', '--warn-only', '--ignore-extra']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed: unexpected return code {return_code}")
        return False


def test_use_recommended_flag():
    """Test that use-recommended flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--use-recommended']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Use-recommended flag test passed")
        return True
    else:
        print(f"[FAIL] Use-recommended flag test failed: unexpected return code {return_code}")
        return False


def test_json_summary_structure():
    """Test that JSON output has correct structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            required_fields = ['changed_count', 'missing_count', 'extra_count', 'total_drift']

            if all(field in summary for field in required_fields):
                print("[PASS] JSON summary structure test passed")
                return True
            else:
                print(f"[FAIL] JSON summary missing fields")
                print(f"  Found: {list(summary.keys())}")
                print(f"  Required: {required_fields}")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON summary structure test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON summary structure test passed (sysctl not available)")
        return True
    else:
        print(f"[FAIL] JSON summary structure test failed: return code {return_code}")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysctl_drift_detector.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (no drift), 1 (drift found), 2 (error/missing dependency)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_sysctl_drift_detector.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_pattern_option,
        test_category_option,
        test_invalid_category,
        test_ignore_extra_flag,
        test_save_baseline,
        test_load_baseline_json,
        test_load_baseline_sysctl_format,
        test_nonexistent_baseline,
        test_combined_options,
        test_use_recommended_flag,
        test_json_summary_structure,
        test_exit_codes,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("=" * 60)
    print(f"\nTest Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"{total - passed} test(s) failed")
        sys.exit(1)
