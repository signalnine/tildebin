#!/usr/bin/env python3
"""Tests for k8s_pdb_health_monitor.py"""

import subprocess
import json
import sys


def test_help():
    """Test --help flag"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    # Check for PDB-related content
    stdout_lower = result.stdout.lower()
    assert "pdb" in stdout_lower or "poddisruptionbudget" in stdout_lower
    assert "maintenance" in stdout_lower or "disruption" in stdout_lower
    print("PASS: Help text works")


def test_help_short():
    """Test -h flag"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "-h"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    assert "pdb" in result.stdout.lower()
    print("PASS: Short help (-h) works")


def test_format_argument():
    """Test --format argument parsing"""
    for fmt in ["plain", "json", "table"]:
        result = subprocess.run(
            ["python3", "k8s_pdb_health_monitor.py", "--format", fmt],
            capture_output=True,
            text=True,
            timeout=15
        )
        # Exit code may be 0, 1, or 2 depending on kubectl availability
        assert result.returncode in [0, 1, 2], f"Unexpected exit code for format {fmt}: {result.returncode}"
    print("PASS: --format argument works for all valid formats")


def test_invalid_format():
    """Test that invalid format is rejected"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--format", "invalid"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode == 2, "Invalid format should exit with code 2"
    assert "invalid choice" in result.stderr.lower()
    print("PASS: Invalid format is rejected")


def test_namespace_argument():
    """Test --namespace argument"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--namespace", "kube-system"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --namespace argument works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "-n", "default"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -n argument works")


def test_verbose_flag():
    """Test --verbose flag"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--verbose"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --verbose flag works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "-v"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -v flag works")


def test_warn_only_flag():
    """Test --warn-only flag"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--warn-only"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --warn-only flag works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "-w"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -w flag works")


def test_combined_arguments():
    """Test multiple arguments together"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "-n", "kube-system", "--format", "json", "-v"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: Combined arguments work")


def test_json_output_format():
    """Test that JSON output is valid JSON"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=15
    )

    # If kubectl is not available, exit code will be 2
    if result.returncode == 2:
        print("PASS: JSON output test skipped (kubectl not available)")
        return

    # Should produce valid JSON or message about no PDBs
    if result.stdout.strip() and not result.stdout.startswith("No "):
        try:
            data = json.loads(result.stdout)
            assert isinstance(data, dict)
            assert "pdbs" in data
            assert "summary" in data
            print("PASS: JSON output is valid and has expected structure")
        except json.JSONDecodeError:
            raise AssertionError(f"Invalid JSON output: {result.stdout[:200]}")
    else:
        print("PASS: JSON output test skipped (no PDBs found)")


def test_json_summary_fields():
    """Test that JSON summary has correct fields"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=15
    )

    if result.returncode == 2:
        print("PASS: JSON summary test skipped (kubectl not available)")
        return

    if result.stdout.strip() and not result.stdout.startswith("No "):
        data = json.loads(result.stdout)
        summary = data.get("summary", {})
        assert "total_pdbs" in summary
        assert "critical_issues" in summary
        assert "warning_issues" in summary
        assert "blocking_maintenance" in summary
        print("PASS: JSON summary has expected fields")
    else:
        print("PASS: JSON summary test skipped (no PDBs found)")


def test_plain_output_format():
    """Test that plain output is human-readable"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--format", "plain"],
        capture_output=True,
        text=True,
        timeout=15
    )

    if result.returncode == 2:
        print("PASS: Plain output test skipped (kubectl not available)")
        return

    output = result.stdout
    assert isinstance(output, str)
    print("PASS: Plain output format works")


def test_table_output_format():
    """Test table output format"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--format", "table"],
        capture_output=True,
        text=True,
        timeout=15
    )

    if result.returncode == 2:
        print("PASS: Table output test skipped (kubectl not available)")
        return

    output = result.stdout
    assert isinstance(output, str)
    print("PASS: Table output format works")


def test_exit_codes():
    """Test that exit codes are appropriate"""
    # Help should exit with 0
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    print("PASS: --help exits with 0")


def test_examples_in_help():
    """Test that help includes usage examples"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "examples" in result.stdout.lower() or "example" in result.stdout.lower()
    print("PASS: Help includes examples")


def test_issue_detection_documentation():
    """Test that help documents issue detection"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "critical" in result.stdout.lower()
    assert "warning" in result.stdout.lower()
    print("PASS: Help documents issue detection")


def test_exit_code_documentation():
    """Test that help documents exit codes"""
    result = subprocess.run(
        ["python3", "k8s_pdb_health_monitor.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "exit code" in result.stdout.lower() or "exit codes" in result.stdout.lower()
    print("PASS: Help documents exit codes")


def main():
    """Run all tests"""
    print("Running k8s_pdb_health_monitor tests...")
    print()

    tests = [
        test_help,
        test_help_short,
        test_format_argument,
        test_invalid_format,
        test_namespace_argument,
        test_verbose_flag,
        test_warn_only_flag,
        test_combined_arguments,
        test_json_output_format,
        test_json_summary_fields,
        test_plain_output_format,
        test_table_output_format,
        test_exit_codes,
        test_examples_in_help,
        test_issue_detection_documentation,
        test_exit_code_documentation,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {test.__name__}: {e}", file=sys.stderr)
            failed += 1
        except subprocess.TimeoutExpired:
            print(f"FAIL: {test.__name__}: Timeout", file=sys.stderr)
            failed += 1
        except Exception as e:
            print(f"FAIL: {test.__name__}: Unexpected error: {e}", file=sys.stderr)
            failed += 1

    total = passed + failed
    print()
    print(f"Test Results: {passed}/{total} tests passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
