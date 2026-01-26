#!/usr/bin/env python3
"""
Test script for baremetal_smt_status_monitor.py functionality.
Tests argument parsing and output formats without requiring specific system conditions.
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
        [sys.executable, 'baremetal_smt_status_monitor.py', '--help']
    )

    if return_code == 0 and 'smt' in stdout.lower():
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
        [sys.executable, 'baremetal_smt_status_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_smt_status_monitor.py']
    )

    # Should succeed (exit 0 or 1 depending on findings)
    if return_code in [0, 1] and ('SMT' in stdout or 'Status' in stdout):
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_smt_status_monitor.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'smt' not in data or 'topology' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify SMT structure
        smt = data['smt']
        if 'control' not in smt or 'active' not in smt:
            print("[FAIL] JSON smt section missing required keys")
            print(f"  SMT keys: {list(smt.keys())}")
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
        [sys.executable, 'baremetal_smt_status_monitor.py', '--format', 'table']
    )

    # Should succeed and contain table elements
    if return_code in [0, 1] and ('SMT' in stdout or '===' in stdout):
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
        [sys.executable, 'baremetal_smt_status_monitor.py', '--verbose']
    )

    # Should succeed and contain detailed info (core mapping or vulnerabilities)
    if return_code in [0, 1] and ('Core Mapping' in stdout or 'Vulnerabilities' in stdout
                                   or 'Topology' in stdout):
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output when no warnings."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_smt_status_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on system state)
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_require_disabled_option():
    """Test --require-disabled option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_smt_status_monitor.py', '--require-disabled']
    )

    # Should succeed - exit code depends on whether SMT is actually enabled
    if return_code in [0, 1]:
        print("[PASS] Require-disabled option test passed")
        return True
    else:
        print(f"[FAIL] Require-disabled option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_smt_status_monitor.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_topology_structure():
    """Test that JSON topology has expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_smt_status_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        topology = data.get('topology', {})

        # Expected topology fields
        expected_keys = ['num_packages', 'num_physical_cores', 'num_logical_cpus', 'threads_per_core']
        missing_keys = [k for k in expected_keys if k not in topology]

        if missing_keys:
            print(f"[FAIL] JSON topology missing expected keys: {missing_keys}")
            print(f"  Found keys: {list(topology.keys())}")
            return False

        print("[PASS] JSON topology structure test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] JSON topology test failed: {e}")
        return False


def test_json_summary_structure():
    """Test that JSON summary has expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_smt_status_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        summary = data.get('summary', {})

        # Expected summary fields
        expected_keys = ['warning_count', 'info_count']
        missing_keys = [k for k in expected_keys if k not in summary]

        if missing_keys:
            print(f"[FAIL] JSON summary missing expected keys: {missing_keys}")
            print(f"  Found keys: {list(summary.keys())}")
            return False

        # Check values are numeric
        if not isinstance(summary['warning_count'], int):
            print("[FAIL] summary.warning_count is not an integer")
            return False
        if not isinstance(summary['info_count'], int):
            print("[FAIL] summary.info_count is not an integer")
            return False

        print("[PASS] JSON summary structure test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] JSON summary test failed: {e}")
        return False


def test_json_vulnerabilities_present():
    """Test that JSON includes vulnerabilities section."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_smt_status_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Vulnerabilities section should exist (may be empty dict)
        if 'vulnerabilities' not in data:
            print("[FAIL] JSON missing vulnerabilities section")
            return False

        # Should be a dict
        if not isinstance(data['vulnerabilities'], dict):
            print("[FAIL] vulnerabilities is not a dict")
            return False

        print("[PASS] JSON vulnerabilities present test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON vulnerabilities test failed: {e}")
        return False


def test_json_issues_structure():
    """Test that JSON issues is a list."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_smt_status_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Issues section should be a list
        if 'issues' not in data:
            print("[FAIL] JSON missing issues section")
            return False

        if not isinstance(data['issues'], list):
            print("[FAIL] issues is not a list")
            return False

        print("[PASS] JSON issues structure test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON issues test failed: {e}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_smt_status_monitor.py',
         '--format', 'json', '--verbose', '--require-disabled']
    )

    try:
        data = json.loads(stdout)

        # Should have all expected fields
        required_keys = ['smt', 'topology', 'vulnerabilities', 'issues', 'summary']
        missing_keys = [k for k in required_keys if k not in data]

        if missing_keys:
            print(f"[FAIL] Combined options missing expected fields: {missing_keys}")
            print(f"  Keys: {list(data.keys())}")
            return False

        print("[PASS] Combined options test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] Combined options test failed: {e}")
        return False


def test_topology_values_reasonable():
    """Test that topology values are reasonable."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_smt_status_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        topology = data['topology']

        # Basic sanity checks
        if topology['num_logical_cpus'] < 1:
            print("[FAIL] num_logical_cpus should be at least 1")
            return False

        if topology['num_physical_cores'] < 1:
            print("[FAIL] num_physical_cores should be at least 1")
            return False

        if topology['threads_per_core'] < 1:
            print("[FAIL] threads_per_core should be at least 1")
            return False

        # Logical CPUs should be >= physical cores
        if topology['num_logical_cpus'] < topology['num_physical_cores']:
            print("[FAIL] num_logical_cpus should be >= num_physical_cores")
            return False

        print("[PASS] Topology values reasonable test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] Topology values test failed: {e}")
        return False


def test_help_mentions_security():
    """Test that help mentions security implications."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_smt_status_monitor.py', '--help']
    )

    security_terms = ['security', 'vulnerabil', 'spectre', 'mds', 'l1tf']
    found_terms = [t for t in security_terms if t in stdout.lower()]

    if return_code == 0 and len(found_terms) >= 2:
        print("[PASS] Help mentions security test passed")
        return True
    else:
        print(f"[FAIL] Help should mention security implications")
        print(f"  Found terms: {found_terms}")
        return False


def test_plain_output_shows_topology():
    """Test that plain output shows topology information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_smt_status_monitor.py']
    )

    topology_terms = ['Cores', 'CPUs', 'Threads', 'Socket']
    found_terms = [t for t in topology_terms if t in stdout]

    if return_code in [0, 1] and len(found_terms) >= 2:
        print("[PASS] Plain output shows topology test passed")
        return True
    else:
        print(f"[FAIL] Plain output should show topology")
        print(f"  Found terms: {found_terms}")
        print(f"  Output: {stdout[:300]}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_smt_status_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_require_disabled_option,
        test_exit_codes,
        test_json_topology_structure,
        test_json_summary_structure,
        test_json_vulnerabilities_present,
        test_json_issues_structure,
        test_combined_options,
        test_topology_values_reasonable,
        test_help_mentions_security,
        test_plain_output_shows_topology,
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
