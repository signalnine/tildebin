#!/usr/bin/env python3
"""
Test script for baremetal_memory_fragmentation_analyzer.py functionality.
Tests argument parsing and error handling without requiring specific system state.
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
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--help']
    )

    if return_code == 0 and 'fragmentation' in stdout.lower() and 'buddy' in stdout.lower():
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
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_frag_warn_high():
    """Test that frag-warn threshold > 100 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--frag-warn', '150']
    )

    if return_code == 2:
        print("[PASS] Invalid frag-warn threshold (>100) test passed")
        return True
    else:
        print(f"[FAIL] Invalid frag-warn threshold should return exit code 2, got {return_code}")
        return False


def test_invalid_frag_warn_zero():
    """Test that frag-warn threshold of 0 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--frag-warn', '0']
    )

    if return_code == 2:
        print("[PASS] Invalid frag-warn threshold (0) test passed")
        return True
    else:
        print(f"[FAIL] frag-warn=0 should return exit code 2, got {return_code}")
        return False


def test_invalid_frag_crit_high():
    """Test that frag-crit threshold > 100 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--frag-crit', '150']
    )

    if return_code == 2:
        print("[PASS] Invalid frag-crit threshold (>100) test passed")
        return True
    else:
        print(f"[FAIL] Invalid frag-crit threshold should return exit code 2, got {return_code}")
        return False


def test_frag_warn_exceeds_crit():
    """Test that frag-warn >= frag-crit is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py',
         '--frag-warn', '80', '--frag-crit', '75']
    )

    if return_code == 2:
        print("[PASS] frag-warn >= frag-crit test passed")
        return True
    else:
        print(f"[FAIL] frag-warn >= frag-crit should return exit code 2, got {return_code}")
        return False


def test_negative_hugepage_warn():
    """Test that negative hugepage-warn is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--hugepage-warn', '-5']
    )

    if return_code == 2:
        print("[PASS] Negative hugepage-warn test passed")
        return True
    else:
        print(f"[FAIL] Negative hugepage-warn should return exit code 2, got {return_code}")
        return False


def test_format_option():
    """Test that format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--format', 'json']
    )

    # Should either succeed (0), find issues (1), or fail with missing data (2)
    # Should NOT fail with "invalid choice" error
    if 'invalid choice' not in stderr:
        print("[PASS] Format option test passed")
        return True
    else:
        print("[FAIL] Format option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--format', 'json']
    )

    # If missing buddyinfo, expected to fail with exit code 2
    if return_code == 2:
        if 'buddyinfo' in stderr.lower() or 'permission' in stderr.lower():
            print("[PASS] JSON output format test passed (buddyinfo not available)")
            return True
        else:
            print(f"[FAIL] Expected buddyinfo-related error, got: {stderr[:100]}")
            return False

    # If it succeeds, validate JSON
    if return_code in [0, 1]:  # 0 = healthy, 1 = issues
        try:
            data = json.loads(stdout)
            # Validate expected fields
            if 'summary' in data and 'zones' in data and 'issues' in data:
                print("[PASS] JSON output format test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected fields")
                print(f"  Data keys: {list(data.keys())}")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON parsing failed")
            print(f"  Output: {stdout[:100]}")
            return False

    print(f"[FAIL] Unexpected return code: {return_code}")
    print(f"  Stderr: {stderr[:100]}")
    return False


def test_table_format():
    """Test table format option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--format', 'table']
    )

    # Should either work or fail with missing data
    if return_code == 2:
        if 'buddyinfo' in stderr.lower() or 'permission' in stderr.lower():
            print("[PASS] Table format test passed (buddyinfo not available)")
            return True

    # If succeeds, check for table elements
    if return_code in [0, 1]:
        if 'Node' in stdout or 'Zone' in stdout or 'Free' in stdout:
            print("[PASS] Table format test passed")
            return True
        else:
            print("[FAIL] Table format missing expected headers")
            print(f"  Output: {stdout[:200]}")
            return False

    print(f"[FAIL] Table format test failed with code {return_code}")
    return False


def test_verbose_flag():
    """Test verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--verbose']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_warn_only_flag():
    """Test warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--warn-only']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py',
         '--format', 'json', '--verbose', '--warn-only',
         '--frag-warn', '40', '--frag-crit', '80', '--hugepage-warn', '5']
    )

    # Should not fail due to option conflicts
    if return_code in [0, 1, 2]:  # Any valid exit code
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:100]}")
        return False


def test_exit_code_validity():
    """Test that exit code is valid (0, 1, or 2)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py']
    )

    # Valid exit codes: 0 (healthy), 1 (issues), 2 (usage/data error)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code validity test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_frag_warn_threshold_option():
    """Test that --frag-warn option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--frag-warn', '40']
    )

    # Should not fail due to invalid value
    if 'invalid' not in stderr.lower() or 'threshold' not in stderr.lower():
        print("[PASS] frag-warn threshold option test passed")
        return True
    else:
        print("[FAIL] frag-warn threshold option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_frag_crit_threshold_option():
    """Test that --frag-crit option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--frag-crit', '90']
    )

    # Should not fail due to invalid value
    if 'invalid' not in stderr.lower() or 'threshold' not in stderr.lower():
        print("[PASS] frag-crit threshold option test passed")
        return True
    else:
        print("[FAIL] frag-crit threshold option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_hugepage_warn_option():
    """Test that --hugepage-warn option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--hugepage-warn', '20']
    )

    # Should not fail due to invalid value
    if 'invalid' not in stderr.lower() or 'hugepage' not in stderr.lower():
        print("[PASS] hugepage-warn option test passed")
        return True
    else:
        print("[FAIL] hugepage-warn option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_plain_output_content():
    """Test plain output contains expected content when data available"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_fragmentation_analyzer.py', '--format', 'plain']
    )

    if return_code == 2:
        # Data not available, that's okay
        print("[PASS] Plain output test passed (data not available)")
        return True

    if return_code in [0, 1]:
        # Check for expected content
        if 'fragmentation' in stdout.lower() or 'memory' in stdout.lower():
            print("[PASS] Plain output content test passed")
            return True
        else:
            print("[FAIL] Plain output missing expected content")
            print(f"  Output: {stdout[:200]}")
            return False

    print(f"[FAIL] Plain output test failed with code {return_code}")
    return False


if __name__ == "__main__":
    print(f"Testing baremetal_memory_fragmentation_analyzer.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_invalid_frag_warn_high,
        test_invalid_frag_warn_zero,
        test_invalid_frag_crit_high,
        test_frag_warn_exceeds_crit,
        test_negative_hugepage_warn,
        test_format_option,
        test_json_output_format,
        test_table_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_combined_options,
        test_exit_code_validity,
        test_frag_warn_threshold_option,
        test_frag_crit_threshold_option,
        test_hugepage_warn_option,
        test_plain_output_content,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
