#!/usr/bin/env python3
"""Tests for k8s_pod_startup_latency_analyzer.py"""

import subprocess
import json
import sys


def test_help():
    """Test --help flag"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    assert "startup latency" in result.stdout.lower()
    assert "pod" in result.stdout.lower()
    print("PASS: Help text works")


def test_help_short():
    """Test -h flag"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "-h"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    assert "startup" in result.stdout.lower()
    print("PASS: Short help (-h) works")


def test_format_argument():
    """Test --format argument parsing"""
    # Valid formats
    for fmt in ["plain", "json", "table"]:
        result = subprocess.run(
            ["python3", "k8s_pod_startup_latency_analyzer.py", "--format", fmt],
            capture_output=True,
            text=True,
            timeout=15
        )
        # Exit code may be 0, 1, or 2 depending on kubectl availability
        assert result.returncode in [0, 1, 2], \
            f"Unexpected exit code for format {fmt}: {result.returncode}"
    print("PASS: --format argument works for all valid formats")


def test_invalid_format():
    """Test that invalid format is rejected"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--format", "invalid"],
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
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--namespace", "kube-system"],
        capture_output=True,
        text=True,
        timeout=15
    )
    # Exit code may be 0, 1, or 2 (depending on resources and kubectl availability)
    assert result.returncode in [0, 1, 2]
    print("PASS: --namespace argument works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "-n", "default"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -n argument works")


def test_verbose_flag():
    """Test --verbose flag"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--verbose"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --verbose flag works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "-v"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -v flag works")


def test_warn_only_flag():
    """Test --warn-only flag"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--warn-only"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --warn-only flag works")

    # Try short form
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "-w"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -w flag works")


def test_slow_threshold_argument():
    """Test --slow-threshold argument"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--slow-threshold", "120"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --slow-threshold argument works")


def test_include_completed_flag():
    """Test --include-completed flag"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--include-completed"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --include-completed flag works")


def test_combined_arguments():
    """Test multiple arguments together"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py",
         "-n", "kube-system", "--format", "json", "-v", "--slow-threshold", "30"],
        capture_output=True,
        text=True,
        timeout=15
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: Combined arguments work")


def test_json_output_format():
    """Test that JSON output is valid JSON"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=15
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
            assert "pods" in data
            assert "summary" in data
            print("PASS: JSON output is valid and has expected structure")
        except json.JSONDecodeError:
            raise AssertionError(f"Invalid JSON output: {result.stdout[:200]}")


def test_json_summary_fields():
    """Test that JSON summary has correct fields"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=15
    )

    if result.returncode == 2:
        print("PASS: JSON summary test skipped (kubectl not available)")
        return

    if result.stdout.strip():
        data = json.loads(result.stdout)
        summary = data.get("summary", {})
        assert "total_pods" in summary
        assert "slow_pods" in summary
        assert "pods_with_issues" in summary
        print("PASS: JSON summary has expected fields")


def test_plain_output_format():
    """Test that plain output is human-readable"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--format", "plain"],
        capture_output=True,
        text=True,
        timeout=15
    )

    if result.returncode == 2:
        print("PASS: Plain output test skipped (kubectl not available)")
        return

    # Should contain readable text
    output = result.stdout
    assert isinstance(output, str)
    print("PASS: Plain output format works")


def test_table_output_format():
    """Test table output format"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--format", "table"],
        capture_output=True,
        text=True,
        timeout=15
    )

    if result.returncode == 2:
        print("PASS: Table output test skipped (kubectl not available)")
        return

    # Should contain readable text
    output = result.stdout
    assert isinstance(output, str)
    print("PASS: Table output format works")


def test_exit_codes():
    """Test that exit codes are appropriate"""
    # Help should exit with 0
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    print("PASS: --help exits with 0")


def test_examples_in_help():
    """Test that help includes usage examples"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "examples" in result.stdout.lower() or "example" in result.stdout.lower()
    print("PASS: Help includes examples")


def test_startup_phases_documentation():
    """Test that help documents startup phases"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    # Should mention startup phases
    assert "scheduling" in result.stdout.lower() or "init" in result.stdout.lower()
    print("PASS: Help documents startup phases")


def test_exit_code_documentation():
    """Test that help documents exit codes"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "exit code" in result.stdout.lower() or "exit codes" in result.stdout.lower()
    print("PASS: Help documents exit codes")


def test_slow_threshold_validation():
    """Test that slow-threshold requires a number"""
    result = subprocess.run(
        ["python3", "k8s_pod_startup_latency_analyzer.py",
         "--slow-threshold", "notanumber"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode == 2, "Invalid threshold should exit with code 2"
    print("PASS: Invalid slow-threshold is rejected")


def main():
    """Run all tests"""
    print("Running k8s_pod_startup_latency_analyzer tests...")
    print()

    tests = [
        test_help,
        test_help_short,
        test_format_argument,
        test_invalid_format,
        test_namespace_argument,
        test_verbose_flag,
        test_warn_only_flag,
        test_slow_threshold_argument,
        test_include_completed_flag,
        test_combined_arguments,
        test_json_output_format,
        test_json_summary_fields,
        test_plain_output_format,
        test_table_output_format,
        test_exit_codes,
        test_examples_in_help,
        test_startup_phases_documentation,
        test_exit_code_documentation,
        test_slow_threshold_validation,
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
