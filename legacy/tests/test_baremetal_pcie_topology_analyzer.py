#!/usr/bin/env python3
"""
Test script for baremetal_pcie_topology_analyzer.py functionality.
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
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--help']
    )

    if return_code == 0 and 'pcie' in stdout.lower() and 'iommu' in stdout.lower():
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
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option():
    """Test that format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--format', 'json']
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
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--format', 'json']
    )

    # If missing PCI sysfs, expected to fail with exit code 2
    if return_code == 2:
        if 'pci' in stderr.lower() or 'sysfs' in stderr.lower() or 'not' in stderr.lower():
            print("[PASS] JSON output format test passed (PCI sysfs not available)")
            return True
        else:
            print(f"[FAIL] Expected PCI-related error, got: {stderr[:100]}")
            return False

    # If it succeeds, validate JSON
    if return_code in [0, 1]:  # 0 = healthy, 1 = issues
        try:
            data = json.loads(stdout)
            # Validate expected fields
            if 'summary' in data and 'devices' in data and 'issues' in data:
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
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--format', 'table']
    )

    # Should either work or fail with missing data
    if return_code == 2:
        if 'pci' in stderr.lower() or 'sysfs' in stderr.lower() or 'not' in stderr.lower():
            print("[PASS] Table format test passed (PCI sysfs not available)")
            return True

    # If succeeds, check for table elements
    if return_code in [0, 1]:
        if 'Address' in stdout or 'NUMA' in stdout or 'IOMMU' in stdout:
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
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--verbose']
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
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--warn-only']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_no_numa_check_flag():
    """Test --no-numa-check flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--no-numa-check']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] No-numa-check flag test passed")
        return True
    else:
        print("[FAIL] No-numa-check flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_no_link_check_flag():
    """Test --no-link-check flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--no-link-check']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] No-link-check flag test passed")
        return True
    else:
        print("[FAIL] No-link-check flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pcie_topology_analyzer.py',
         '--format', 'json', '--verbose', '--warn-only',
         '--no-numa-check', '--no-link-check']
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
        [sys.executable, 'baremetal_pcie_topology_analyzer.py']
    )

    # Valid exit codes: 0 (healthy), 1 (issues), 2 (usage/data error)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code validity test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_plain_output_content():
    """Test plain output contains expected content when data available"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--format', 'plain']
    )

    if return_code == 2:
        # Data not available, that's okay
        print("[PASS] Plain output test passed (data not available)")
        return True

    if return_code in [0, 1]:
        # Check for expected content
        if 'pcie' in stdout.lower() or 'numa' in stdout.lower() or 'device' in stdout.lower():
            print("[PASS] Plain output content test passed")
            return True
        else:
            print("[FAIL] Plain output missing expected content")
            print(f"  Output: {stdout[:200]}")
            return False

    print(f"[FAIL] Plain output test failed with code {return_code}")
    return False


def test_json_structure():
    """Test JSON output structure when data available"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--format', 'json']
    )

    if return_code == 2:
        # Data not available
        print("[PASS] JSON structure test passed (data not available)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check summary structure
            if 'summary' in data:
                summary = data['summary']
                if 'total_devices' in summary and 'issue_count' in summary:
                    print("[PASS] JSON structure test passed")
                    return True
                else:
                    print("[FAIL] JSON summary missing expected fields")
                    print(f"  Summary keys: {list(summary.keys())}")
                    return False
            else:
                print("[FAIL] JSON missing summary field")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON parsing failed")
            return False

    print(f"[FAIL] JSON structure test failed with code {return_code}")
    return False


def test_all_format_options():
    """Test all format options are valid"""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--format', fmt]
        )

        if 'invalid choice' in stderr:
            print(f"[FAIL] Format '{fmt}' not recognized")
            return False

    print("[PASS] All format options test passed")
    return True


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '--format', 'xml']
    )

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should fail")
        return False


def test_short_verbose_flag():
    """Test -v short verbose flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '-v']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short verbose flag test passed")
        return True
    else:
        print("[FAIL] Short verbose flag not recognized")
        return False


def test_short_warn_only_flag():
    """Test -w short warn-only flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pcie_topology_analyzer.py', '-w']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short warn-only flag test passed")
        return True
    else:
        print("[FAIL] Short warn-only flag not recognized")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_pcie_topology_analyzer.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option,
        test_json_output_format,
        test_table_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_no_numa_check_flag,
        test_no_link_check_flag,
        test_combined_options,
        test_exit_code_validity,
        test_plain_output_content,
        test_json_structure,
        test_all_format_options,
        test_invalid_format,
        test_short_verbose_flag,
        test_short_warn_only_flag,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
