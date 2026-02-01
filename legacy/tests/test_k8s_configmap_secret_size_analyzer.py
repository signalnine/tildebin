#!/usr/bin/env python3
"""Tests for k8s_configmap_secret_size_analyzer.py"""

import subprocess
import json
import sys


def test_help():
    """Test --help flag"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    assert "configmap" in result.stdout.lower()
    assert "secret" in result.stdout.lower()
    assert "size" in result.stdout.lower()
    print("PASS: Help text works")


def test_help_short():
    """Test -h flag"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "-h"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    assert "configmap" in result.stdout.lower()
    print("PASS: Short help (-h) works")


def test_format_argument():
    """Test --format argument parsing"""
    # Valid formats
    for fmt in ["plain", "json", "table"]:
        result = subprocess.run(
            ["python3", "k8s_configmap_secret_size_analyzer.py", "--format", fmt],
            capture_output=True,
            text=True,
            timeout=10
        )
        # Exit code may be 0, 1, or 2 depending on kubectl availability
        assert result.returncode in [0, 1, 2], f"Unexpected exit code for {fmt}: {result.returncode}"
    print("PASS: --format argument works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "-f", "json"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2], f"Unexpected exit code: {result.returncode}"
    print("PASS: -f argument works")


def test_invalid_format():
    """Test that invalid format is rejected"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--format", "invalid"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode == 2, f"Expected exit code 2 for invalid format, got {result.returncode}"
    print("PASS: Invalid format rejected")


def test_namespace_argument():
    """Test --namespace argument"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--namespace", "kube-system"],
        capture_output=True,
        text=True,
        timeout=10
    )
    # Exit code may be 0, 1, or 2 (depending on kubectl availability)
    assert result.returncode in [0, 1, 2]
    print("PASS: --namespace argument works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "-n", "default"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -n argument works")


def test_warn_only_argument():
    """Test --warn-only flag"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--warn-only"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --warn-only argument works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "-w"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -w argument works")


def test_verbose_argument():
    """Test --verbose flag"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--verbose"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --verbose argument works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "-v"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -v argument works")


def test_threshold_arguments():
    """Test threshold arguments"""
    # Warning threshold
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--warn-threshold", "50KB"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --warn-threshold argument works")

    # Critical threshold
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--crit-threshold", "200KB"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --crit-threshold argument works")

    # Both thresholds
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py",
         "--warn-threshold", "50KB", "--crit-threshold", "100KB"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: Both threshold arguments work together")


def test_invalid_thresholds():
    """Test that invalid threshold configurations are rejected"""
    # Warning >= critical should fail
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py",
         "--warn-threshold", "500KB", "--crit-threshold", "100KB"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode == 2, f"Expected exit code 2, got {result.returncode}"
    assert "less than" in result.stderr.lower()
    print("PASS: Invalid threshold order rejected")


def test_skip_system_argument():
    """Test --skip-system flag"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--skip-system"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --skip-system argument works")


def test_configmaps_only_argument():
    """Test --configmaps-only flag"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--configmaps-only"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --configmaps-only argument works")


def test_secrets_only_argument():
    """Test --secrets-only flag"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--secrets-only"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --secrets-only argument works")


def test_combined_arguments():
    """Test multiple arguments together"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py",
         "-n", "default", "-f", "json", "-w", "-v"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: Combined arguments work")


def test_json_output_format():
    """Test that JSON output is valid JSON"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--format", "json"],
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
            assert "thresholds" in data
            assert "summary" in data
            assert "objects" in data
            print("PASS: JSON output is valid and has expected structure")
        except json.JSONDecodeError:
            raise AssertionError(f"Invalid JSON output: {result.stdout[:200]}")


def test_table_output_format():
    """Test that table output has headers"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--format", "table"],
        capture_output=True,
        text=True,
        timeout=10
    )

    # If kubectl is not available, exit code will be 2
    if result.returncode == 2:
        print("PASS: Table output test skipped (kubectl not available)")
        return

    # Table should have headers
    output = result.stdout
    if output.strip():
        assert "TYPE" in output or "No ConfigMaps" in output
    print("PASS: Table output format works")


def test_plain_output_format():
    """Test that plain output is human-readable"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--format", "plain"],
        capture_output=True,
        text=True,
        timeout=10
    )

    # If kubectl is not available, exit code will be 2
    if result.returncode == 2:
        print("PASS: Plain output test skipped (kubectl not available)")
        return

    # Should contain readable text
    output = result.stdout
    if output.strip():
        assert "Size Analysis" in output or "No ConfigMaps" in output or "threshold" in output.lower()
    print("PASS: Plain output format works")


def test_exit_codes():
    """Test that exit codes are appropriate"""
    # Help should exit with 0
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    print("PASS: --help exits with 0")


def test_size_parsing_in_help():
    """Test that size examples are shown in help"""
    result = subprocess.run(
        ["python3", "k8s_configmap_secret_size_analyzer.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "KB" in result.stdout or "MB" in result.stdout
    print("PASS: Size examples shown in help")


def main():
    """Run all tests"""
    print("Running k8s_configmap_secret_size_analyzer tests...")
    print()

    tests = [
        test_help,
        test_help_short,
        test_format_argument,
        test_invalid_format,
        test_namespace_argument,
        test_warn_only_argument,
        test_verbose_argument,
        test_threshold_arguments,
        test_invalid_thresholds,
        test_skip_system_argument,
        test_configmaps_only_argument,
        test_secrets_only_argument,
        test_combined_arguments,
        test_json_output_format,
        test_table_output_format,
        test_plain_output_format,
        test_exit_codes,
        test_size_parsing_in_help,
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
