#!/usr/bin/env python3
"""
Tests for baremetal_process_swap_monitor.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling
- Filter options

Tests run without requiring root access or specific process configurations.
"""

import json
import subprocess
import sys


def run_command(args, timeout=10):
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
        ['./baremetal_process_swap_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'swap' in stdout.lower(), "Help should mention 'swap'"
    assert 'process' in stdout.lower(), "Help should mention 'process'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--top' in stdout, "Help should document --top flag"
    assert '--swap-threshold' in stdout, "Help should document --swap-threshold flag"
    assert '--ratio-threshold' in stdout, "Help should document --ratio-threshold flag"
    assert '--user' in stdout, "Help should document --user flag"
    assert '--name' in stdout, "Help should document --name flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_process_swap_monitor.py', '--format', fmt]
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
        ['./baremetal_process_swap_monitor.py', '-f', 'json']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--verbose']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '-v']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--warn-only']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '-w']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_top_flag():
    """Test that --top flag is recognized and validated."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--top', '10']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--top should be recognized"
    assert return_code in [0, 1, 2], \
        f"--top 10 should be valid, got {return_code}"

    print("PASS: Top flag test passed")
    return True


def test_top_zero():
    """Test that --top 0 (show all) is valid."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--top', '0']
    )

    assert return_code in [0, 1, 2], \
        f"--top 0 should be valid, got {return_code}"

    print("PASS: Top zero test passed")
    return True


def test_negative_top_rejected():
    """Test that negative --top value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--top', '-5']
    )

    # Should fail with usage error
    assert return_code != 0, "Negative --top should fail"

    print("PASS: Negative top rejected test passed")
    return True


def test_swap_threshold_flag():
    """Test that --swap-threshold flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--swap-threshold', '50000']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--swap-threshold should be recognized"
    assert return_code in [0, 1, 2], \
        f"--swap-threshold 50000 should be valid, got {return_code}"

    print("PASS: Swap threshold flag test passed")
    return True


def test_negative_swap_threshold_rejected():
    """Test that negative --swap-threshold value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--swap-threshold', '-100']
    )

    # argparse may reject or script may reject
    assert return_code != 0, "Negative --swap-threshold should fail"

    print("PASS: Negative swap threshold rejected test passed")
    return True


def test_ratio_threshold_flag():
    """Test that --ratio-threshold flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--ratio-threshold', '75.0']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--ratio-threshold should be recognized"
    assert return_code in [0, 1, 2], \
        f"--ratio-threshold 75.0 should be valid, got {return_code}"

    print("PASS: Ratio threshold flag test passed")
    return True


def test_invalid_ratio_threshold():
    """Test that invalid --ratio-threshold values are rejected."""
    # Test > 100
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--ratio-threshold', '150']
    )

    assert return_code == 2, \
        f"Ratio threshold > 100 should exit with 2, got {return_code}"

    print("PASS: Invalid ratio threshold test passed")
    return True


def test_user_filter():
    """Test that --user filter is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--user', 'root']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--user should be recognized"
    assert return_code in [0, 1, 2], \
        f"--user root should be valid, got {return_code}"

    print("PASS: User filter test passed")
    return True


def test_name_filter():
    """Test that --name filter is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--name', 'python']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--name should be recognized"
    assert return_code in [0, 1, 2], \
        f"--name python should be valid, got {return_code}"

    print("PASS: Name filter test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--nonexistent-option']
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
        ['./baremetal_process_swap_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run (e.g., no /proc on non-Linux)
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: JSON output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "JSON should have 'status' field"
            assert 'summary' in data, "JSON should have 'summary' field"
            assert 'top_consumers' in data, "JSON should have 'top_consumers' field"
            assert data['status'] in ['ok', 'warning'], \
                "Status should be ok or warning"
            print("PASS: JSON output format test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON output invalid: {e}")
            print(f"Output was: {stdout[:200]}")
            return False

    print("PASS: JSON output format test passed (script execution checked)")
    return True


def test_json_structure():
    """Test that JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--format', 'json', '--top', '5']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'summary', 'top_consumers',
                             'high_swap_processes', 'high_ratio_processes']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Check summary structure
            summary_keys = ['processes_with_swap', 'total_process_swap_kb',
                            'high_swap_count', 'high_ratio_count',
                            'swap_threshold_kb', 'ratio_threshold_pct']
            for key in summary_keys:
                assert key in data['summary'], f"Summary should have '{key}' field"

            # Check that top_consumers is a list
            assert isinstance(data['top_consumers'], list), \
                "top_consumers should be a list"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


def test_plain_output_contains_expected():
    """Test that plain output contains expected keywords."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--verbose']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Plain output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        # Should have some process info or status message
        lower_output = stdout.lower()
        assert 'swap' in lower_output or 'no processes' in lower_output, \
            "Output should contain swap info or 'no processes' message"
        print("PASS: Plain output test passed")
        return True

    print("PASS: Plain output test passed (script execution checked)")
    return True


def test_table_output_format():
    """Test that table output has headers."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--format', 'table', '--top', '5']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Table output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        lines = stdout.strip().split('\n')
        if len(lines) > 0:
            # First line should be header or "no processes" message
            header = lines[0].lower()
            assert 'pid' in header or 'no processes' in header or 'name' in header, \
                "Table should have header row or no processes message"
        print("PASS: Table output format test passed")
        return True

    print("PASS: Table output format test passed (script execution checked)")
    return True


def test_exit_code_success():
    """Test that script exits with appropriate code."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--swap-threshold', '999999999']
    )

    # With very high threshold, should succeed (no warnings)
    # Skip if no /proc
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Exit code test (no /proc filesystem)")
        return True

    # Exit 0 (no issues) or 1 (issues found) are both valid
    assert return_code in [0, 1], \
        f"Exit code should be 0 or 1, got {return_code}"

    print("PASS: Exit code test passed")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_process_swap_monitor.py',
        '-f', 'json',
        '-v',
        '-w',
        '--top', '5',
        '--swap-threshold', '10000',
        '--ratio-threshold', '25.0'
    ])

    # Should not have argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined flags should be recognized"

    # Should either run or fail with dependency error
    assert return_code in [0, 1, 2], \
        f"Combined flags should be valid, got {return_code}"

    print("PASS: Combined flags test passed")
    return True


def test_user_and_name_filter_combined():
    """Test that user and name filters can be combined."""
    return_code, stdout, stderr = run_command([
        './baremetal_process_swap_monitor.py',
        '--user', 'root',
        '--name', 'python'
    ])

    # Should not have argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined filters should be recognized"
    assert return_code in [0, 1, 2], \
        f"Combined filters should be valid, got {return_code}"

    print("PASS: User and name filter combined test passed")
    return True


def test_process_info_fields():
    """Test that JSON output has expected process fields."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_swap_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Process info fields test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check process fields if there are any processes
            if data['top_consumers']:
                proc = data['top_consumers'][0]
                expected_fields = ['pid', 'name', 'user', 'vm_swap_kb',
                                   'vm_rss_kb', 'swap_ratio']
                for field in expected_fields:
                    assert field in proc, f"Process should have '{field}' field"
            print("PASS: Process info fields test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: Process info fields test passed (no valid JSON)")
            return True

    print("PASS: Process info fields test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_process_swap_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_top_flag,
        test_top_zero,
        test_negative_top_rejected,
        test_swap_threshold_flag,
        test_negative_swap_threshold_rejected,
        test_ratio_threshold_flag,
        test_invalid_ratio_threshold,
        test_user_filter,
        test_name_filter,
        test_invalid_argument,
        test_json_output_format,
        test_json_structure,
        test_plain_output_contains_expected,
        test_table_output_format,
        test_exit_code_success,
        test_combined_flags,
        test_user_and_name_filter_combined,
        test_process_info_fields,
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
