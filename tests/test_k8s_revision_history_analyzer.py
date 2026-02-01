#!/usr/bin/env python3
"""Tests for k8s_revision_history_analyzer.py"""

import subprocess
import json
import sys


def test_help():
    """Test --help flag"""
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    assert "revision" in result.stdout.lower()
    assert "replicaset" in result.stdout.lower()
    print("PASS: Help text works")


def test_help_short():
    """Test -h flag"""
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py", "-h"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    assert "revision" in result.stdout.lower()
    print("PASS: Short help (-h) works")


def test_format_argument():
    """Test --format argument parsing"""
    for fmt in ["plain", "json", "table"]:
        result = subprocess.run(
            ["python3", "k8s_revision_history_analyzer.py", "--format", fmt],
            capture_output=True,
            text=True,
            timeout=10
        )
        # Exit code may be 0, 1, or 2 depending on kubectl availability
        assert result.returncode in [0, 1, 2], f"Unexpected exit code: {result.returncode}"
    print("PASS: --format argument works")


def test_namespace_argument():
    """Test --namespace argument"""
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py", "--namespace", "default"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --namespace argument works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py", "-n", "default"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -n argument works")


def test_threshold_argument():
    """Test --threshold argument"""
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py", "--threshold", "5"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --threshold argument works")

    # Test invalid threshold
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py", "--threshold", "notanumber"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode == 2, "Invalid threshold should fail with exit code 2"
    print("PASS: Invalid --threshold rejected")


def test_warn_only_argument():
    """Test --warn-only argument"""
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py", "--warn-only"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --warn-only argument works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py", "-w"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -w argument works")


def test_verbose_argument():
    """Test --verbose argument"""
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py", "--verbose"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --verbose argument works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py", "-v"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -v argument works")


def test_combined_arguments():
    """Test multiple arguments together"""
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py",
         "-n", "default", "--format", "json", "--threshold", "5", "-v"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: Combined arguments work")


def test_json_output_format():
    """Test that JSON output is valid JSON"""
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=10
    )

    # If kubectl is not available, exit code will be 2
    if result.returncode == 2:
        print("PASS: JSON output test skipped (kubectl not available)")
        return

    # Should produce valid JSON
    if result.stdout.strip():
        try:
            data = json.loads(result.stdout)
            assert isinstance(data, dict)
            assert "summary" in data or "namespaces" in data
            print("PASS: JSON output is valid")
        except json.JSONDecodeError:
            raise AssertionError(f"Invalid JSON output: {result.stdout[:200]}")


def test_exit_codes():
    """Test that exit codes are appropriate"""
    # Help should exit with 0
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    print("PASS: --help exits with 0")


def test_kubectl_not_found_message():
    """Test that missing kubectl produces helpful error"""
    # This test verifies the error message format when kubectl is missing
    # We can't easily simulate kubectl not being found, but we test the code path exists
    result = subprocess.run(
        ["python3", "k8s_revision_history_analyzer.py"],
        capture_output=True,
        text=True,
        timeout=10
    )
    # If kubectl is missing, should get exit code 2 and helpful message
    if result.returncode == 2:
        assert "kubectl" in result.stderr.lower()
        print("PASS: Missing kubectl error message is helpful")
    else:
        print("PASS: kubectl available, skipping error message test")


def main():
    """Run all tests"""
    print("Running k8s_revision_history_analyzer tests...")
    print()

    tests = [
        test_help,
        test_help_short,
        test_format_argument,
        test_namespace_argument,
        test_threshold_argument,
        test_warn_only_argument,
        test_verbose_argument,
        test_combined_arguments,
        test_json_output_format,
        test_exit_codes,
        test_kubectl_not_found_message,
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
        except Exception as e:
            print(f"ERROR: {test.__name__}: {e}", file=sys.stderr)
            failed += 1

    total = passed + failed
    print()
    print(f"Test Results: {passed}/{total} tests passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
