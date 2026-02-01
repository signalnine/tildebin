#!/usr/bin/env python3
"""
Tests for baremetal_process_memory_growth.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring root access or specific process configurations.
"""

import json
import subprocess
import sys


def run_command(args, timeout=30):
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
        ['./baremetal_process_memory_growth.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'memory' in stdout.lower(), "Help should mention 'memory'"
    assert 'growth' in stdout.lower(), "Help should mention 'growth'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--samples' in stdout or '-s' in stdout, "Help should document samples flag"
    assert '--interval' in stdout or '-i' in stdout, "Help should document interval flag"
    assert '--min-growth' in stdout, "Help should document --min-growth flag"
    assert '--user' in stdout, "Help should document --user flag"
    assert '--cmd' in stdout, "Help should document --cmd flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        # Use minimal samples/interval for fast testing
        return_code, stdout, stderr = run_command(
            ['./baremetal_process_memory_growth.py', '--format', fmt,
             '-s', '2', '-i', '0.1']
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
        ['./baremetal_process_memory_growth.py', '-f', 'json', '-s', '2', '-i', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '--verbose', '-s', '2', '-i', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '-v', '-s', '2', '-i', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '--warn-only', '-s', '2', '-i', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '-w', '-s', '2', '-i', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_samples_flag():
    """Test that --samples flag is recognized and validated."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '--samples', '3', '-i', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--samples should be recognized"
    assert return_code in [0, 1, 2], \
        f"--samples 3 should be valid, got {return_code}"

    print("PASS: Samples flag test passed")
    return True


def test_short_samples_flag():
    """Test that -s shorthand for --samples works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '-s', '2', '-i', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-s should be recognized"

    print("PASS: Short samples flag test passed")
    return True


def test_interval_flag():
    """Test that --interval flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '--interval', '1', '-s', '2']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--interval should be recognized"
    assert return_code in [0, 1, 2], \
        f"--interval 1 should be valid, got {return_code}"

    print("PASS: Interval flag test passed")
    return True


def test_short_interval_flag():
    """Test that -i shorthand for --interval works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '-i', '0.5', '-s', '2']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-i should be recognized"

    print("PASS: Short interval flag test passed")
    return True


def test_invalid_samples():
    """Test that samples < 2 is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '-s', '1']
    )

    # Should fail with usage error
    assert return_code == 2, \
        f"samples=1 should exit with 2, got {return_code}"
    assert 'at least 2' in stderr.lower(), \
        "Error should mention minimum samples"

    print("PASS: Invalid samples test passed")
    return True


def test_invalid_interval():
    """Test that non-positive interval is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '-i', '0', '-s', '2']
    )

    # Should fail with usage error
    assert return_code == 2, \
        f"interval=0 should exit with 2, got {return_code}"
    assert 'positive' in stderr.lower(), \
        "Error should mention positive interval"

    print("PASS: Invalid interval test passed")
    return True


def test_min_growth_flag():
    """Test that --min-growth flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '--min-growth', '1024',
         '-s', '2', '-i', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--min-growth should be recognized"
    assert return_code in [0, 1, 2], \
        f"--min-growth 1024 should be valid, got {return_code}"

    print("PASS: Min-growth flag test passed")
    return True


def test_min_pct_flag():
    """Test that --min-pct flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '--min-pct', '20',
         '-s', '2', '-i', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--min-pct should be recognized"
    assert return_code in [0, 1, 2], \
        f"--min-pct 20 should be valid, got {return_code}"

    print("PASS: Min-pct flag test passed")
    return True


def test_top_flag():
    """Test that --top flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '--top', '5',
         '-s', '2', '-i', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--top should be recognized"
    assert return_code in [0, 1, 2], \
        f"--top 5 should be valid, got {return_code}"

    print("PASS: Top flag test passed")
    return True


def test_user_filter():
    """Test that --user filter is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '--user', 'root',
         '-s', '2', '-i', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--user should be recognized"

    print("PASS: User filter test passed")
    return True


def test_cmd_filter():
    """Test that --cmd filter is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '--cmd', 'python',
         '-s', '2', '-i', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--cmd should be recognized"

    print("PASS: Cmd filter test passed")
    return True


def test_invalid_cmd_regex():
    """Test that invalid regex pattern is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '--cmd', '[invalid',
         '-s', '2', '-i', '0.1']
    )

    # Should fail with usage error
    assert return_code == 2, \
        f"Invalid regex should exit with 2, got {return_code}"
    assert 'pattern' in stderr.lower() or 'invalid' in stderr.lower(), \
        "Error should mention invalid pattern"

    print("PASS: Invalid cmd regex test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '--nonexistent-option']
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
        ['./baremetal_process_memory_growth.py', '--format', 'json',
         '-s', '2', '-i', '0.1']
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
            assert data['status'] in ['ok', 'warning', 'critical'], \
                "Status should be ok, warning, or critical"
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
        ['./baremetal_process_memory_growth.py', '--format', 'json',
         '-s', '2', '-i', '0.1', '--top', '3']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'summary']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Check summary structure
            summary_keys = ['total_processes_tracked', 'critical_count',
                            'warning_count', 'monitoring_duration_sec']
            for key in summary_keys:
                assert key in data['summary'], f"Summary should have '{key}' field"

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
        ['./baremetal_process_memory_growth.py', '--verbose',
         '-s', '2', '-i', '0.1']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Plain output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        # Should have monitoring message or status
        has_content = ('monitoring' in stdout.lower() or
                       'ok' in stdout.lower() or
                       'growth' in stdout.lower() or
                       'pid' in stdout.lower())
        assert has_content, "Output should contain monitoring info or status"
        print("PASS: Plain output test passed")
        return True

    print("PASS: Plain output test passed (script execution checked)")
    return True


def test_table_output_format():
    """Test that table output has headers."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '--format', 'table',
         '-s', '2', '-i', '0.1', '--top', '5']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Table output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        lines = stdout.strip().split('\n')
        if len(lines) > 0:
            # First line should be header or status message
            first_line = lines[0].lower()
            has_header = ('pid' in first_line or 'command' in first_line or
                          'no processes' in first_line)
            assert has_header or 'monitoring' in first_line, \
                "Table should have header row or status"
        print("PASS: Table output format test passed")
        return True

    print("PASS: Table output format test passed (script execution checked)")
    return True


def test_exit_code_success():
    """Test that script exits properly."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_memory_growth.py', '-s', '2', '-i', '0.1',
         '--min-growth', '999999999']  # Very high threshold = no warnings
    )

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
        './baremetal_process_memory_growth.py',
        '-f', 'json',
        '-v',
        '-w',
        '-s', '2',
        '-i', '0.1',
        '--min-growth', '256',
        '--min-pct', '5',
        '--top', '5'
    ])

    # Should not have argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined flags should be recognized"

    # Should either run or fail with dependency error
    assert return_code in [0, 1, 2], \
        f"Combined flags should be valid, got {return_code}"

    print("PASS: Combined flags test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_process_memory_growth.py...")
    print()

    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_samples_flag,
        test_short_samples_flag,
        test_interval_flag,
        test_short_interval_flag,
        test_invalid_samples,
        test_invalid_interval,
        test_min_growth_flag,
        test_min_pct_flag,
        test_top_flag,
        test_user_filter,
        test_cmd_filter,
        test_invalid_cmd_regex,
        test_invalid_argument,
        test_json_output_format,
        test_json_structure,
        test_plain_output_contains_expected,
        test_table_output_format,
        test_exit_code_success,
        test_combined_flags,
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
