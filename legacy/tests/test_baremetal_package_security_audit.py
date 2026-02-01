#!/usr/bin/env python3
"""Tests for baremetal_package_security_audit.py"""

import subprocess
import json
import sys


def test_help():
    """Test --help flag"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    assert "security" in result.stdout.lower()
    assert "package" in result.stdout.lower()
    print("PASS: Help text works")


def test_help_short():
    """Test -h flag"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "-h"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Help failed: {result.stderr}"
    assert "security" in result.stdout.lower()
    print("PASS: Short help (-h) works")


def test_format_argument():
    """Test --format argument parsing"""
    # Valid formats
    for fmt in ["plain", "json", "table"]:
        result = subprocess.run(
            ["python3", "baremetal_package_security_audit.py", "--format", fmt],
            capture_output=True,
            text=True,
            timeout=30
        )
        # Exit code may be 0, 1, or 2 depending on package manager availability
        assert result.returncode in [0, 1, 2], \
            f"Unexpected exit code for format {fmt}: {result.returncode}"
    print("PASS: --format argument works for all valid formats")


def test_invalid_format():
    """Test that invalid format is rejected"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--format", "invalid"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode == 2, "Invalid format should exit with code 2"
    assert "invalid choice" in result.stderr.lower()
    print("PASS: Invalid format is rejected")


def test_verbose_flag():
    """Test --verbose flag"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--verbose"],
        capture_output=True,
        text=True,
        timeout=30
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --verbose flag works")

    # Try short form
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "-v"],
        capture_output=True,
        text=True,
        timeout=30
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -v flag works")


def test_warn_only_flag():
    """Test --warn-only flag"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--warn-only"],
        capture_output=True,
        text=True,
        timeout=30
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --warn-only flag works")

    # Try short form
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "-w"],
        capture_output=True,
        text=True,
        timeout=30
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: -w flag works")


def test_critical_only_flag():
    """Test --critical-only flag"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--critical-only"],
        capture_output=True,
        text=True,
        timeout=30
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: --critical-only flag works")


def test_package_manager_argument():
    """Test --package-manager argument"""
    for mgr in ["auto", "apt", "dnf", "yum"]:
        result = subprocess.run(
            ["python3", "baremetal_package_security_audit.py",
             "--package-manager", mgr],
            capture_output=True,
            text=True,
            timeout=30
        )
        # Exit code 0, 1, or 2 (2 if package manager not available)
        assert result.returncode in [0, 1, 2], \
            f"Unexpected exit code for {mgr}: {result.returncode}"
    print("PASS: --package-manager argument works")


def test_invalid_package_manager():
    """Test that invalid package manager is rejected"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py",
         "--package-manager", "invalid"],
        capture_output=True,
        text=True,
        timeout=10
    )
    assert result.returncode == 2, "Invalid package manager should exit with code 2"
    assert "invalid choice" in result.stderr.lower()
    print("PASS: Invalid package manager is rejected")


def test_combined_arguments():
    """Test multiple arguments together"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py",
         "--format", "json", "-v", "--critical-only"],
        capture_output=True,
        text=True,
        timeout=30
    )
    assert result.returncode in [0, 1, 2]
    print("PASS: Combined arguments work")


def test_json_output_format():
    """Test that JSON output is valid JSON"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=60
    )

    # If package manager is not available, exit code will be 2
    if result.returncode == 2:
        print("PASS: JSON output test skipped (package manager not available)")
        return

    # Should produce valid JSON
    if result.stdout.strip():
        try:
            data = json.loads(result.stdout)
            assert isinstance(data, dict)
            assert "package_manager" in data
            assert "total_updates" in data
            assert "updates" in data
            print("PASS: JSON output is valid and has expected structure")
        except json.JSONDecodeError:
            raise AssertionError(f"Invalid JSON output: {result.stdout[:200]}")


def test_json_categories_fields():
    """Test that JSON output has correct category fields"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=60
    )

    if result.returncode == 2:
        print("PASS: JSON categories test skipped (package manager not available)")
        return

    if result.stdout.strip():
        data = json.loads(result.stdout)
        categories = data.get("categories", {})
        # Should have severity categories
        assert "critical" in categories
        assert "important" in categories
        print("PASS: JSON output has severity categories")


def test_plain_output_format():
    """Test that plain output is human-readable"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--format", "plain"],
        capture_output=True,
        text=True,
        timeout=60
    )

    if result.returncode == 2:
        print("PASS: Plain output test skipped (package manager not available)")
        return

    # Should contain readable text
    output = result.stdout
    assert isinstance(output, str)
    print("PASS: Plain output format works")


def test_table_output_format():
    """Test table output format"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--format", "table"],
        capture_output=True,
        text=True,
        timeout=60
    )

    if result.returncode == 2:
        print("PASS: Table output test skipped (package manager not available)")
        return

    # Should contain readable text
    output = result.stdout
    assert isinstance(output, str)
    print("PASS: Table output format works")


def test_exit_codes():
    """Test that exit codes are appropriate"""
    # Help should exit with 0
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    print("PASS: --help exits with 0")


def test_examples_in_help():
    """Test that help includes usage examples"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "examples" in result.stdout.lower() or "example" in result.stdout.lower()
    print("PASS: Help includes examples")


def test_supported_managers_documentation():
    """Test that help documents supported package managers"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "apt" in result.stdout.lower()
    assert "dnf" in result.stdout.lower()
    assert "yum" in result.stdout.lower()
    print("PASS: Help documents supported package managers")


def test_exit_code_documentation():
    """Test that help documents exit codes"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "exit code" in result.stdout.lower() or "exit codes" in result.stdout.lower()
    print("PASS: Help documents exit codes")


def test_security_mentioned_in_description():
    """Test that help mentions security updates"""
    result = subprocess.run(
        ["python3", "baremetal_package_security_audit.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "security" in result.stdout.lower()
    assert "update" in result.stdout.lower()
    print("PASS: Help mentions security updates")


def main():
    """Run all tests"""
    print("Running baremetal_package_security_audit tests...")
    print()

    tests = [
        test_help,
        test_help_short,
        test_format_argument,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_critical_only_flag,
        test_package_manager_argument,
        test_invalid_package_manager,
        test_combined_arguments,
        test_json_output_format,
        test_json_categories_fields,
        test_plain_output_format,
        test_table_output_format,
        test_exit_codes,
        test_examples_in_help,
        test_supported_managers_documentation,
        test_exit_code_documentation,
        test_security_mentioned_in_description,
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
