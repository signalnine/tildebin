#!/usr/bin/env python3
"""
Test script for baremetal_page_cache_monitor.py functionality.
Tests argument parsing and output formats without requiring specific memory configurations.
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
        [sys.executable, 'baremetal_page_cache_monitor.py', '--help']
    )

    if return_code == 0 and 'page cache' in stdout.lower():
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
        [sys.executable, 'baremetal_page_cache_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py']
    )

    # Should succeed (exit 0 or 1 depending on memory status)
    if return_code in [0, 1] and ('Page Cache:' in stdout or 'cache' in stdout.lower()):
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'page_cache' not in data:
            print("[FAIL] JSON output missing 'page_cache' key")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify page_cache data structure
        pc = data['page_cache']
        required_keys = ['total_kb', 'cached_kb', 'buffers_kb', 'cache_ratio']
        if not all(key in pc for key in required_keys):
            print("[FAIL] JSON page_cache data missing required keys")
            print(f"  Page cache keys: {list(pc.keys())}")
            return False

        # Verify dirty_pages exists
        if 'dirty_pages' not in data:
            print("[FAIL] JSON output missing 'dirty_pages' key")
            return False

        # Verify memory exists
        if 'memory' not in data:
            print("[FAIL] JSON output missing 'memory' key")
            return False

        # Verify issues list exists
        if 'issues' not in data:
            print("[FAIL] JSON output missing 'issues' key")
            return False

        print("[PASS] JSON output format test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and ('PAGE CACHE' in stdout or 'Metric' in stdout):
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode includes additional information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py', '--verbose']
    )

    # Should succeed and include file cache or limits info
    if return_code in [0, 1] and ('Active(file)' in stdout or 'dirty_ratio' in stdout or 'File Cache' in stdout):
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on memory state)
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_dirty_thresholds():
    """Test custom dirty page threshold arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py',
         '--dirty-warn', '5', '--dirty-crit', '15']
    )

    # Should succeed with custom thresholds
    if return_code in [0, 1]:
        print("[PASS] Custom dirty thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom dirty thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_available_thresholds():
    """Test custom available memory threshold arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py',
         '--avail-warn', '15', '--avail-crit', '3']
    )

    # Should succeed with custom thresholds
    if return_code in [0, 1]:
        print("[PASS] Custom available thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom available thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_dirty_threshold_range():
    """Test that invalid dirty threshold values are rejected."""
    # Test dirty-warn > 100
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py', '--dirty-warn', '150']
    )

    if return_code == 2:
        print("[PASS] Invalid dirty threshold range test passed (warn > 100)")
        return True

    # Test dirty-warn >= dirty-crit
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py',
         '--dirty-warn', '25', '--dirty-crit', '20']
    )

    if return_code == 2:
        print("[PASS] Invalid dirty threshold range test passed (warn >= crit)")
        return True
    else:
        print(f"[FAIL] Invalid dirty threshold range test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_available_threshold_range():
    """Test that invalid available memory threshold values are rejected."""
    # Test avail-crit >= avail-warn (critical should be lower than warning)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py',
         '--avail-warn', '5', '--avail-crit', '10']
    )

    if return_code == 2:
        print("[PASS] Invalid available threshold range test passed (crit >= warn)")
        return True
    else:
        print(f"[FAIL] Invalid available threshold range test failed")
        print(f"  Return code: {return_code}")
        return False


def test_writeback_threshold():
    """Test writeback warning threshold argument."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py', '--writeback-warn', '50']
    )

    # Should succeed with custom writeback threshold
    if return_code in [0, 1]:
        print("[PASS] Writeback threshold test passed")
        return True
    else:
        print(f"[FAIL] Writeback threshold test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_verbose_includes_extra_data():
    """Test JSON verbose output includes additional data."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py', '--format', 'json', '--verbose']
    )

    try:
        data = json.loads(stdout)

        # Verbose mode should include file_cache
        if 'file_cache' not in data:
            print("[FAIL] JSON verbose missing file_cache data")
            return False

        # Should include limits
        if 'limits' not in data:
            print("[FAIL] JSON verbose missing limits data")
            return False

        print("[PASS] JSON verbose output test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON verbose parsing failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_data_types():
    """Test that JSON output has correct data types."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Check page_cache values are numeric
        pc = data['page_cache']
        if not isinstance(pc['total_kb'], (int, float)):
            print("[FAIL] page_cache.total_kb should be numeric")
            return False

        if not isinstance(pc['cache_ratio'], (int, float)):
            print("[FAIL] page_cache.cache_ratio should be numeric")
            return False

        # Check dirty_pages values are numeric
        dp = data['dirty_pages']
        if not isinstance(dp['dirty_kb'], (int, float)):
            print("[FAIL] dirty_pages.dirty_kb should be numeric")
            return False

        # Check memory values are numeric
        mem = data['memory']
        if not isinstance(mem['total_kb'], (int, float)):
            print("[FAIL] memory.total_kb should be numeric")
            return False

        # Check issues is a list
        if not isinstance(data['issues'], list):
            print("[FAIL] issues should be a list")
            return False

        print("[PASS] JSON data types test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False
    except KeyError as e:
        print(f"[FAIL] Missing key in JSON: {e}")
        return False


def test_memory_values_reasonable():
    """Test that reported memory values are reasonable."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_page_cache_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Total memory should be > 0
        total = data['memory']['total_kb']
        if total <= 0:
            print("[FAIL] Total memory should be > 0")
            return False

        # Cache ratio should be between 0 and 100
        cache_ratio = data['page_cache']['cache_ratio']
        if cache_ratio < 0 or cache_ratio > 100:
            print(f"[FAIL] Cache ratio {cache_ratio} should be between 0 and 100")
            return False

        # Available ratio should be between 0 and 100
        avail_ratio = data['memory']['available_ratio']
        if avail_ratio < 0 or avail_ratio > 100:
            print(f"[FAIL] Available ratio {avail_ratio} should be between 0 and 100")
            return False

        print("[PASS] Memory values reasonable test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False
    except KeyError as e:
        print(f"[FAIL] Missing key in JSON: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_page_cache_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_custom_dirty_thresholds,
        test_custom_available_thresholds,
        test_invalid_dirty_threshold_range,
        test_invalid_available_threshold_range,
        test_writeback_threshold,
        test_json_verbose_includes_extra_data,
        test_exit_codes,
        test_json_data_types,
        test_memory_values_reasonable,
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
