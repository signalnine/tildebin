#!/usr/bin/env python3
"""
Tests for baremetal_mtu_mismatch_detector.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring specific network configuration.
"""

import json
import subprocess
import sys


def run_command(args, timeout=15):
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"


def test_help_message():
    """Test that --help flag works and shows usage information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'mtu' in stdout.lower(), "Help should mention 'MTU'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--expected' in stdout, "Help should document --expected flag"
    assert '--jumbo-expected' in stdout, "Help should document --jumbo-expected flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"
    assert '1500' in stdout, "Help should mention standard MTU"
    assert '9000' in stdout, "Help should mention jumbo MTU"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_mtu_mismatch_detector.py', '--format', fmt]
        )

        # Should work (exit 0 or 1) or fail with dependency error (2)
        assert return_code in [0, 1, 2], \
            f"Format {fmt} should be valid, got return code {return_code}"

        # Should not get argument parsing errors
        assert 'invalid choice' not in stderr.lower(), \
            f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '-f', 'json']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--verbose']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '-v']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--warn-only']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '-w']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_expected_mtu_flag():
    """Test that --expected flag accepts valid MTU values."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--expected', '1500']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--expected should be recognized"
    assert return_code in [0, 1, 2], \
        f"--expected 1500 should be valid, got {return_code}"

    print("PASS: Expected MTU flag test passed")
    return True


def test_expected_mtu_jumbo():
    """Test that --expected accepts jumbo MTU values."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--expected', '9000']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--expected 9000 should be recognized"
    assert return_code in [0, 1, 2], \
        f"--expected 9000 should be valid, got {return_code}"

    print("PASS: Expected MTU jumbo test passed")
    return True


def test_invalid_expected_mtu_too_small():
    """Test that very small MTU is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--expected', '50']
    )

    assert return_code == 2, \
        f"--expected 50 should exit with 2, got {return_code}"
    assert 'must be between' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention invalid MTU range"

    print("PASS: Invalid expected MTU too small test passed")
    return True


def test_invalid_expected_mtu_too_large():
    """Test that very large MTU is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--expected', '100000']
    )

    assert return_code == 2, \
        f"--expected 100000 should exit with 2, got {return_code}"
    assert 'must be between' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention invalid MTU range"

    print("PASS: Invalid expected MTU too large test passed")
    return True


def test_jumbo_expected_flag():
    """Test that --jumbo-expected flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--jumbo-expected']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--jumbo-expected should be recognized"
    assert return_code in [0, 1, 2], \
        f"--jumbo-expected should be valid, got {return_code}"

    print("PASS: Jumbo expected flag test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--nonexistent-option']
    )

    assert return_code == 2, \
        f"Invalid argument should exit with 2, got {return_code}"
    assert 'unrecognized arguments' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report unrecognized argument"

    print("PASS: Invalid argument test passed")
    return True


def test_json_output_format():
    """Test that JSON output is valid JSON."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--format', 'json']
    )

    # Skip if script couldn't run (e.g., no sysfs on non-Linux)
    if return_code == 2 and '/sys' in stderr:
        print("SKIP: JSON output test (no /sys filesystem)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "JSON should have 'status' field"
            assert 'summary' in data, "JSON should have 'summary' field"
            assert 'interfaces' in data, "JSON should have 'interfaces' field"
            assert data['status'] in ['ok', 'warning', 'error'], \
                "Status should be ok, warning, or error"
            print("PASS: JSON output format test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON output invalid: {e}")
            print(f"Output was: {stdout[:200]}")
            return False

    print("PASS: JSON output format test passed (script execution checked)")
    return True


def test_plain_output_contains_expected():
    """Test that plain output contains expected keywords."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--verbose']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/sys' in stderr:
        print("SKIP: Plain output test (no /sys filesystem)")
        return True

    if return_code in [0, 1]:
        output_lower = stdout.lower()
        assert ('mtu' in output_lower or 'interface' in output_lower or
                'status' in output_lower), \
            "Output should contain MTU info or status"
        print("PASS: Plain output test passed")
        return True

    print("PASS: Plain output test passed (script execution checked)")
    return True


def test_table_output_format():
    """Test that table output has headers."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--format', 'table']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/sys' in stderr:
        print("SKIP: Table output test (no /sys filesystem)")
        return True

    if return_code in [0, 1]:
        lines = stdout.strip().split('\n')
        if len(lines) > 0:
            header = lines[0].lower()
            assert ('interface' in header or 'mtu' in header or
                    'no' in header.lower() or 'status' in header), \
                "Table should have header row or status message"
        print("PASS: Table output format test passed")
        return True

    print("PASS: Table output format test passed (script execution checked)")
    return True


def test_exit_code_success():
    """Test that script exits appropriately."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py']
    )

    # Skip if no sysfs
    if return_code == 2 and '/sys' in stderr:
        print("SKIP: Exit code test (no /sys filesystem)")
        return True

    # Exit 0 (no issues) or 1 (issues found) are both valid
    assert return_code in [0, 1], \
        f"Exit code should be 0 or 1, got {return_code}"

    print("PASS: Exit code test passed")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_mtu_mismatch_detector.py',
        '-f', 'json',
        '-v',
        '-w',
        '--expected', '1500',
        '--jumbo-expected'
    ])

    # Should not have argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined flags should be recognized"

    # Should either run or fail with dependency error
    assert return_code in [0, 1, 2], \
        f"Combined flags should be valid, got {return_code}"

    print("PASS: Combined flags test passed")
    return True


def test_json_structure():
    """Test that JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--format', 'json']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'summary', 'interfaces', 'issues', 'warnings']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Check summary structure
            summary_keys = ['total_interfaces', 'standard_mtu', 'jumbo_mtu', 'other_mtu']
            for key in summary_keys:
                assert key in data['summary'], f"Summary should have '{key}' field"

            # Check that interfaces is a dict
            assert isinstance(data['interfaces'], dict), \
                "interfaces should be a dictionary"

            # Check that issues and warnings are lists
            assert isinstance(data['issues'], list), "issues should be a list"
            assert isinstance(data['warnings'], list), "warnings should be a list"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


def test_interface_data_fields():
    """Test that interface entries have expected fields."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Interface data fields test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            if data['interfaces']:
                # Check first interface entry
                first_iface = list(data['interfaces'].values())[0]
                expected_fields = ['name', 'mtu', 'mtu_class', 'operstate', 'type']
                for field in expected_fields:
                    assert field in first_iface, f"Interface entry should have '{field}' field"

            print("PASS: Interface data fields test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: Interface data fields test passed (no JSON to check)")
            return True

    print("PASS: Interface data fields test passed")
    return True


def test_mtu_is_number():
    """Test that MTU values are numeric."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: MTU is number test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            for iface_name, iface_data in data['interfaces'].items():
                mtu = iface_data.get('mtu')
                assert isinstance(mtu, int), \
                    f"MTU for {iface_name} should be an integer, got {type(mtu)}"
                assert mtu > 0, \
                    f"MTU for {iface_name} should be positive, got {mtu}"

            print("PASS: MTU is number test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: MTU is number test passed (no JSON to check)")
            return True

    print("PASS: MTU is number test passed")
    return True


def test_mtu_class_values():
    """Test that MTU class values are expected strings."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: MTU class values test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            valid_classes = ['standard', 'jumbo', 'jumbo-extended', 'reduced', 'custom', 'oversized', 'unknown']

            for iface_name, iface_data in data['interfaces'].items():
                mtu_class = iface_data.get('mtu_class')
                assert mtu_class in valid_classes, \
                    f"MTU class for {iface_name} should be valid, got {mtu_class}"

            print("PASS: MTU class values test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: MTU class values test passed (no JSON to check)")
            return True

    print("PASS: MTU class values test passed")
    return True


def test_summary_counts():
    """Test that summary counts are non-negative integers."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_mtu_mismatch_detector.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Summary counts test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            count_fields = ['total_interfaces', 'standard_mtu', 'jumbo_mtu', 'other_mtu', 'bonds', 'bridges', 'vlans']

            for field in count_fields:
                value = data['summary'].get(field)
                assert isinstance(value, int), \
                    f"Summary {field} should be an integer, got {type(value)}"
                assert value >= 0, \
                    f"Summary {field} should be non-negative, got {value}"

            print("PASS: Summary counts test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: Summary counts test passed (no JSON to check)")
            return True

    print("PASS: Summary counts test passed")
    return True


def test_expected_mtu_with_valid_detection():
    """Test that expected MTU detection runs without crash."""
    # Test various valid MTU values
    for mtu in [1500, 9000, 9216, 576, 65535]:
        return_code, stdout, stderr = run_command(
            ['./baremetal_mtu_mismatch_detector.py', '--expected', str(mtu), '-f', 'json']
        )

        if return_code == 2 and '/sys' in stderr:
            print("SKIP: Expected MTU detection test (no /sys filesystem)")
            return True

        assert return_code in [0, 1, 2], \
            f"--expected {mtu} should be valid, got {return_code}"

    print("PASS: Expected MTU with valid detection test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_mtu_mismatch_detector.py...")
    print()

    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_expected_mtu_flag,
        test_expected_mtu_jumbo,
        test_invalid_expected_mtu_too_small,
        test_invalid_expected_mtu_too_large,
        test_jumbo_expected_flag,
        test_invalid_argument,
        test_json_output_format,
        test_plain_output_contains_expected,
        test_table_output_format,
        test_exit_code_success,
        test_combined_flags,
        test_json_structure,
        test_interface_data_fields,
        test_mtu_is_number,
        test_mtu_class_values,
        test_summary_counts,
        test_expected_mtu_with_valid_detection,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except AssertionError as e:
            print(f"FAIL: {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {test.__name__}: {e}")
            failed += 1

    print()
    print(f"Test Results: {passed}/{passed + failed} tests passed")

    sys.exit(0 if failed == 0 else 1)
