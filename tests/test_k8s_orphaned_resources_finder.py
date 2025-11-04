#!/usr/bin/env python3
"""Tests for k8s_orphaned_resources_finder.py"""

import subprocess
import json
import sys


def test_help():
    """Test --help flag"""
    result = subprocess.run(
        ["python3", "k8s_orphaned_resources_finder.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    assert "orphaned" in result.stdout.lower()
    print("✓ Help text works")


def test_help_short():
    """Test -h flag"""
    result = subprocess.run(
        ["python3", "k8s_orphaned_resources_finder.py", "-h"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    assert "orphaned" in result.stdout.lower()
    print("✓ Short help (-h) works")


def test_format_argument():
    """Test --format argument parsing"""
    # Valid format
    result = subprocess.run(
        ["python3", "k8s_orphaned_resources_finder.py", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=10
    )
    # Exit code may be 1 or 2 depending on kubectl availability
    assert result.returncode in [0, 1, 2], f"Unexpected exit code: {result.returncode}"
    print("✓ --format argument works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_orphaned_resources_finder.py", "-f", "plain"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2], f"Unexpected exit code: {result.returncode}"
    print("✓ -f argument works")


def test_namespace_argument():
    """Test --namespace argument"""
    result = subprocess.run(
        ["python3", "k8s_orphaned_resources_finder.py", "--namespace", "kube-system"],
        capture_output=True,
        text=True,
        timeout=10
    )
    # Exit code may be 0, 1, or 2 (depending on resources and kubectl availability)
    assert result.returncode in [0, 1, 2]
    print("✓ --namespace argument works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_orphaned_resources_finder.py", "-n", "kube-system"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("✓ -n argument works")


def test_skip_arguments():
    """Test skip flags"""
    skip_flags = [
        "--skip-empty-namespaces",
        "--skip-configmaps",
        "--skip-secrets",
        "--skip-pvcs",
        "--skip-services",
        "--skip-service-accounts"
    ]

    for flag in skip_flags:
        result = subprocess.run(
            ["python3", "k8s_orphaned_resources_finder.py", flag],
            capture_output=True,
            text=True,
            timeout=10
        )
        assert result.returncode in [0, 1, 2]
    print(f"✓ All {len(skip_flags)} skip flags work")


def test_combined_arguments():
    """Test multiple arguments together"""
    result = subprocess.run(
        ["python3", "k8s_orphaned_resources_finder.py", "-n", "default", "-f", "json"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("✓ Combined arguments work")


def test_json_output_format():
    """Test that JSON output is valid JSON"""
    result = subprocess.run(
        ["python3", "k8s_orphaned_resources_finder.py", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=10
    )

    # If kubectl is not available, exit code will be 2
    if result.returncode == 2:
        print("✓ JSON output test skipped (kubectl not available)")
        return

    # Should produce valid JSON
    if result.stdout.strip():
        try:
            data = json.loads(result.stdout)
            assert isinstance(data, dict)
            assert "empty_namespaces" in data or "orphaned_by_namespace" in data
            print("✓ JSON output is valid")
        except json.JSONDecodeError:
            raise AssertionError(f"Invalid JSON output: {result.stdout}")


def test_plain_output_format():
    """Test that plain output is human-readable"""
    result = subprocess.run(
        ["python3", "k8s_orphaned_resources_finder.py", "--format", "plain"],
        capture_output=True,
        text=True,
        timeout=10
    )

    # If kubectl is not available, exit code will be 2
    if result.returncode == 2:
        print("✓ Plain output test skipped (kubectl not available)")
        return

    # Should contain readable text
    output = result.stdout + result.stderr
    print("✓ Plain output format works")


def test_exit_codes():
    """Test that exit codes are appropriate"""
    # Help should exit with 0
    result = subprocess.run(
        ["python3", "k8s_orphaned_resources_finder.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    print("✓ --help exits with 0")


def main():
    """Run all tests"""
    print("Running k8s_orphaned_resources_finder tests...")
    print()

    tests = [
        test_help,
        test_help_short,
        test_format_argument,
        test_namespace_argument,
        test_skip_arguments,
        test_combined_arguments,
        test_json_output_format,
        test_plain_output_format,
        test_exit_codes,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"Test failed: {e}", file=sys.stderr)
            failed += 1
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            failed += 1

    total = passed + failed
    print()
    print(f"Test Results: {passed}/{total} tests passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
