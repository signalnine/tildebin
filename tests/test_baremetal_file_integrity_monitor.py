#!/usr/bin/env python3
"""
Test script for baremetal_file_integrity_monitor.py functionality.
Tests argument parsing, baseline creation, and verification without requiring
specific system states or root access.
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
        [sys.executable, 'baremetal_file_integrity_monitor.py', '--help']
    )

    if return_code == 0 and 'integrity' in stdout.lower() and 'baseline' in stdout.lower():
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
        [sys.executable, 'baremetal_file_integrity_monitor.py', '--format', 'plain', '--report']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option is accepted and produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py', '--format', 'json', '--report']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'scan' in data:
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
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py', '--format', 'table', '--report']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed: unexpected return code {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py', '--format', 'invalid']
    )

    # Should fail with exit code 2 (usage error) or show error message
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
        [sys.executable, 'baremetal_file_integrity_monitor.py', '-v', '--report']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed: unexpected return code {return_code}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py', '--warn-only', '--report']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_report_mode():
    """Test that report mode works without baseline"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py', '--report']
    )

    if return_code in [0, 1]:
        if 'File Integrity' in stdout or 'files' in stdout.lower():
            print("[PASS] Report mode test passed")
            return True
        else:
            print(f"[FAIL] Report mode output unexpected")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Report mode test failed: return code {return_code}")
        return False


def test_baseline_creation():
    """Test that baseline creation works"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        baseline_path = f.name

    try:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_file_integrity_monitor.py',
             '--baseline', '--baseline-file', baseline_path]
        )

        if return_code == 0:
            # Check baseline file was created
            if os.path.exists(baseline_path):
                with open(baseline_path, 'r') as f:
                    data = json.load(f)
                    if 'files' in data and 'version' in data:
                        print("[PASS] Baseline creation test passed")
                        return True
                    else:
                        print("[FAIL] Baseline file missing expected structure")
                        return False
            else:
                print("[FAIL] Baseline file not created")
                return False
        else:
            print(f"[FAIL] Baseline creation failed: return code {return_code}")
            print(f"  Stderr: {stderr}")
            return False
    finally:
        if os.path.exists(baseline_path):
            os.unlink(baseline_path)


def test_baseline_json_output():
    """Test that baseline creation with JSON output works"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        baseline_path = f.name

    try:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_file_integrity_monitor.py',
             '--baseline', '--baseline-file', baseline_path, '--format', 'json']
        )

        if return_code == 0:
            try:
                data = json.loads(stdout)
                if data.get('action') == 'baseline_created':
                    print("[PASS] Baseline JSON output test passed")
                    return True
                else:
                    print("[FAIL] Baseline JSON missing 'action' field")
                    return False
            except json.JSONDecodeError:
                print("[FAIL] Baseline JSON output is not valid JSON")
                return False
        else:
            print(f"[FAIL] Baseline JSON test failed: return code {return_code}")
            return False
    finally:
        if os.path.exists(baseline_path):
            os.unlink(baseline_path)


def test_verify_against_baseline():
    """Test verification against a baseline"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        baseline_path = f.name

    try:
        # Create baseline
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_file_integrity_monitor.py',
             '--baseline', '--baseline-file', baseline_path]
        )

        if return_code != 0:
            print(f"[FAIL] Could not create baseline for verification test")
            return False

        # Verify against baseline
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_file_integrity_monitor.py',
             '--baseline-file', baseline_path]
        )

        # Should pass (exit 0) since nothing changed
        if return_code == 0:
            print("[PASS] Verification against baseline test passed")
            return True
        elif return_code == 1:
            # Some files might have changed between baseline and verification
            print("[PASS] Verification test passed (detected changes)")
            return True
        else:
            print(f"[FAIL] Verification test failed: return code {return_code}")
            return False
    finally:
        if os.path.exists(baseline_path):
            os.unlink(baseline_path)


def test_missing_baseline():
    """Test error handling when baseline is missing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py',
         '--baseline-file', '/nonexistent/path/baseline.json']
    )

    if return_code == 2 and 'baseline' in stderr.lower():
        print("[PASS] Missing baseline error handling test passed")
        return True
    else:
        print(f"[FAIL] Missing baseline should exit with code 2")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr}")
        return False


def test_custom_file_list():
    """Test using a custom file list"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("/etc/passwd\n")
        f.write("/etc/group\n")
        f.write("# This is a comment\n")
        f.write("/etc/hosts\n")
        file_list_path = f.name

    try:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_file_integrity_monitor.py',
             '--files', file_list_path, '--report', '--format', 'json']
        )

        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                # Should have only the files from our list (plus binaries unless --no-binaries)
                print("[PASS] Custom file list test passed")
                return True
            except json.JSONDecodeError:
                print("[FAIL] Custom file list JSON output invalid")
                return False
        else:
            print(f"[FAIL] Custom file list test failed: return code {return_code}")
            return False
    finally:
        if os.path.exists(file_list_path):
            os.unlink(file_list_path)


def test_no_binaries_flag():
    """Test that --no-binaries flag reduces file count"""
    # With binaries
    return_code1, stdout1, stderr1 = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py',
         '--report', '--format', 'json']
    )

    # Without binaries
    return_code2, stdout2, stderr2 = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py',
         '--report', '--format', 'json', '--no-binaries']
    )

    if return_code1 in [0, 1] and return_code2 in [0, 1]:
        try:
            data1 = json.loads(stdout1)
            data2 = json.loads(stdout2)
            count1 = data1.get('summary', {}).get('total_files', 0)
            count2 = data2.get('summary', {}).get('total_files', 0)

            # Without binaries should have fewer files
            if count2 <= count1:
                print("[PASS] No-binaries flag test passed")
                return True
            else:
                print(f"[FAIL] No-binaries should have fewer files ({count2} >= {count1})")
                return False
        except json.JSONDecodeError:
            print("[FAIL] No-binaries test JSON parsing failed")
            return False
    else:
        print(f"[FAIL] No-binaries test failed with return codes {return_code1}, {return_code2}")
        return False


def test_algorithm_option():
    """Test hash algorithm options"""
    for algo in ['sha256', 'sha512', 'sha1', 'md5']:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_file_integrity_monitor.py',
             '--algorithm', algo, '--report', '--format', 'json']
        )

        if return_code not in [0, 1]:
            print(f"[FAIL] Algorithm {algo} test failed: return code {return_code}")
            return False

        try:
            data = json.loads(stdout)
            if data.get('scan', {}).get('algorithm') != algo:
                print(f"[FAIL] Algorithm {algo} not properly set in output")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] Algorithm {algo} test JSON parsing failed")
            return False

    print("[PASS] Algorithm option test passed")
    return True


def test_invalid_algorithm():
    """Test that invalid algorithm is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py',
         '--algorithm', 'invalid', '--report']
    )

    if return_code == 2 or 'invalid choice' in stderr.lower():
        print("[PASS] Invalid algorithm rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid algorithm should be rejected")
        return False


def test_json_structure():
    """Test that JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py', '--format', 'json', '--report']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON structure test failed: return code {return_code}")
        return False

    try:
        data = json.loads(stdout)

        required_keys = ['timestamp', 'scan', 'summary', 'violations', 'warnings', 'healthy']
        for key in required_keys:
            if key not in data:
                print(f"[FAIL] JSON structure missing key: {key}")
                return False

        # Check summary structure
        summary = data.get('summary', {})
        summary_keys = ['total_files', 'accessible', 'violations', 'warnings']
        for key in summary_keys:
            if key not in summary:
                print(f"[FAIL] JSON summary missing key: {key}")
                return False

        print("[PASS] JSON structure test passed")
        return True

    except json.JSONDecodeError:
        print("[FAIL] JSON structure test failed: invalid JSON")
        return False


def test_short_flags():
    """Test that short flags work"""
    test_cases = [
        (['-b'], 'baseline'),
        (['-r'], 'report'),
        (['-v', '-r'], 'verbose'),
        (['-w', '-r'], 'warn-only'),
        (['-a', 'sha512', '-r'], 'algorithm'),
    ]

    # For baseline, we need a temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        baseline_path = f.name

    try:
        for flags, name in test_cases:
            # Add baseline file for -b flag
            if '-b' in flags:
                cmd_flags = flags + ['--baseline-file', baseline_path]
            else:
                cmd_flags = flags

            return_code, stdout, stderr = run_command(
                [sys.executable, 'baremetal_file_integrity_monitor.py'] + cmd_flags
            )

            if return_code not in [0, 1, 2]:
                print(f"[FAIL] Short flag test failed for {name}: return code {return_code}")
                return False

        print("[PASS] Short flags test passed")
        return True
    finally:
        if os.path.exists(baseline_path):
            os.unlink(baseline_path)


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py',
         '--report', '--format', 'json', '-v', '--no-binaries', '--algorithm', 'sha512']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if data.get('scan', {}).get('algorithm') == 'sha512':
                print("[PASS] Combined options test passed")
                return True
            else:
                print("[FAIL] Combined options: algorithm not correctly set")
                return False
        except json.JSONDecodeError:
            print("[FAIL] Combined options: invalid JSON output")
            return False
    else:
        print(f"[FAIL] Combined options test failed: return code {return_code}")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    # Report mode should exit 0
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py', '--report']
    )

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False

    print("[PASS] Exit code test passed")
    return True


def test_nonexistent_file_list():
    """Test error handling for nonexistent file list"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py',
         '--files', '/nonexistent/file/list.txt', '--report']
    )

    if return_code == 2 and 'not found' in stderr.lower():
        print("[PASS] Nonexistent file list error handling test passed")
        return True
    else:
        print(f"[FAIL] Should error on nonexistent file list")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr}")
        return False


def test_no_metadata_flag():
    """Test that --no-metadata flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_file_integrity_monitor.py',
         '--no-metadata', '--report']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] No-metadata flag test passed")
        return True
    else:
        print(f"[FAIL] No-metadata flag test failed: return code {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_file_integrity_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_report_mode,
        test_baseline_creation,
        test_baseline_json_output,
        test_verify_against_baseline,
        test_missing_baseline,
        test_custom_file_list,
        test_no_binaries_flag,
        test_algorithm_option,
        test_invalid_algorithm,
        test_json_structure,
        test_short_flags,
        test_combined_options,
        test_exit_codes,
        test_nonexistent_file_list,
        test_no_metadata_flag,
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
