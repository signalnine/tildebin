#!/usr/bin/env python3
"""
Tests for baremetal_swap_pressure_analyzer.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring specific system states.
"""

import json
import subprocess
import sys


def run_command(args, timeout=60):
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
        ['./baremetal_swap_pressure_analyzer.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'swap' in stdout.lower(), "Help should mention 'swap'"
    assert 'memory' in stdout.lower(), "Help should mention 'memory'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--warn' in stdout, "Help should document --warn flag"
    assert '--crit' in stdout, "Help should document --crit flag"
    assert '--no-sample' in stdout, "Help should document --no-sample flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--format', 'invalid']
    )

    assert return_code == 2, \
        f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report invalid format choice"

    print("PASS: Invalid format test passed")
    return True


def test_negative_warn_threshold():
    """Test that negative --warn value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--warn', '-10', '--no-sample']
    )

    assert return_code == 2, \
        f"Negative warn threshold should exit with 2, got {return_code}"
    assert 'error' in stderr.lower(), "Error should be reported"

    print("PASS: Negative warn threshold test passed")
    return True


def test_warn_over_100():
    """Test that --warn over 100 is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--warn', '150', '--no-sample']
    )

    assert return_code == 2, \
        f"Warn > 100 should exit with 2, got {return_code}"
    assert 'error' in stderr.lower(), "Error should be reported"

    print("PASS: Warn over 100 test passed")
    return True


def test_negative_crit_threshold():
    """Test that negative --crit value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--crit', '-20', '--no-sample']
    )

    assert return_code == 2, \
        f"Negative crit threshold should exit with 2, got {return_code}"
    assert 'error' in stderr.lower(), "Error should be reported"

    print("PASS: Negative crit threshold test passed")
    return True


def test_crit_over_100():
    """Test that --crit over 100 is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--crit', '150', '--no-sample']
    )

    assert return_code == 2, \
        f"Crit > 100 should exit with 2, got {return_code}"
    assert 'error' in stderr.lower(), "Error should be reported"

    print("PASS: Crit over 100 test passed")
    return True


def test_crit_less_than_warn():
    """Test that --crit less than --warn is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--warn', '80', '--crit', '50', '--no-sample']
    )

    assert return_code == 2, \
        f"Crit < warn should exit with 2, got {return_code}"
    assert 'crit' in stderr.lower() or '>=' in stderr.lower(), \
        "Error should mention crit must be >= warn"

    print("PASS: Crit less than warn test passed")
    return True


def test_negative_swap_rate_warn():
    """Test that negative --swap-rate-warn is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--swap-rate-warn', '-50', '--no-sample']
    )

    assert return_code == 2, \
        f"Negative swap-rate-warn should exit with 2, got {return_code}"
    assert 'error' in stderr.lower(), "Error should be reported"

    print("PASS: Negative swap rate warn test passed")
    return True


def test_invalid_sample_interval():
    """Test that non-positive --sample-interval is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--sample-interval', '0']
    )

    assert return_code == 2, \
        f"Zero sample interval should exit with 2, got {return_code}"
    assert 'error' in stderr.lower(), "Error should be reported"

    print("PASS: Invalid sample interval test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--nonexistent-option']
    )

    assert return_code == 2, \
        f"Invalid argument should exit with 2, got {return_code}"
    assert 'unrecognized arguments' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report unrecognized argument"

    print("PASS: Invalid argument test passed")
    return True


def test_format_plain_accepted():
    """Test that --format plain is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--format', 'plain', '--no-sample']
    )

    assert 'invalid choice' not in stderr.lower(), "plain should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format plain should work"

    print("PASS: Format plain accepted test passed")
    return True


def test_format_json_accepted():
    """Test that --format json is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--format', 'json', '--no-sample']
    )

    assert 'invalid choice' not in stderr.lower(), "json should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format json should work"

    print("PASS: Format json accepted test passed")
    return True


def test_format_table_accepted():
    """Test that --format table is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--format', 'table', '--no-sample']
    )

    assert 'invalid choice' not in stderr.lower(), "table should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format table should work"

    print("PASS: Format table accepted test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '-f', 'json', '--no-sample']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--verbose', '--no-sample']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '-v', '--no-sample']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--warn-only', '--no-sample']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '-w', '--no-sample']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_no_sample_flag():
    """Test that --no-sample flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--no-sample']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--no-sample should be recognized"

    print("PASS: No sample flag test passed")
    return True


def test_sample_interval_flag():
    """Test that --sample-interval flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--sample-interval', '0.5', '--no-sample']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--sample-interval should be recognized"

    print("PASS: Sample interval flag test passed")
    return True


def test_warn_threshold_flag():
    """Test that --warn flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--warn', '60', '--no-sample']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn should be recognized"

    print("PASS: Warn threshold flag test passed")
    return True


def test_crit_threshold_flag():
    """Test that --crit flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--crit', '90', '--no-sample']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--crit should be recognized"

    print("PASS: Crit threshold flag test passed")
    return True


def test_swap_rate_warn_flag():
    """Test that --swap-rate-warn flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--swap-rate-warn', '200', '--no-sample']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--swap-rate-warn should be recognized"

    print("PASS: Swap rate warn flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_swap_pressure_analyzer.py',
        '-f', 'json',
        '-v',
        '--warn', '40',
        '--crit', '70',
        '--no-sample'
    ])

    # Should not have argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined flags should be recognized"

    # Should either run or fail with dependency error
    assert return_code in [0, 1, 2], \
        f"Combined flags should be valid, got {return_code}"

    print("PASS: Combined flags test passed")
    return True


def test_exit_code_valid():
    """Test that script exits with valid exit code."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--no-sample']
    )

    # Exit 0 (no issues), 1 (warnings), or 2 (error) are all valid
    assert return_code in [0, 1, 2], \
        f"Exit code should be 0, 1, or 2, got {return_code}"

    print("PASS: Exit code test passed")
    return True


def test_json_output_valid():
    """Test that JSON output is valid JSON."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--format', 'json', '--no-sample']
    )

    # Skip if script couldn't run
    if return_code == 2 and 'proc' in stderr.lower():
        print("SKIP: JSON output test (/proc not available)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "JSON should have 'status' field"
            assert 'swap' in data, "JSON should have 'swap' field"
            assert data['status'] in ['ok', 'warning', 'critical'], \
                "Status should be ok, warning, or critical"
            print("PASS: JSON output valid test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON output invalid: {e}")
            print(f"Output was: {stdout[:200]}")
            return False

    print("PASS: JSON output valid test passed (script execution checked)")
    return True


def test_json_structure():
    """Test that JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--format', 'json', '--no-sample']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'swap', 'memory', 'swap_state', 'pressure', 'issues']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Check swap structure
            swap_keys = ['total_bytes', 'used_bytes', 'free_bytes', 'percent_used']
            for key in swap_keys:
                assert key in data['swap'], f"Swap should have '{key}' field"

            # Check memory structure
            mem_keys = ['total_bytes', 'available_bytes', 'percent_used']
            for key in mem_keys:
                assert key in data['memory'], f"Memory should have '{key}' field"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


def test_plain_output_has_swap():
    """Test that plain output shows swap information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--format', 'plain', '--no-sample']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: Plain output test (script couldn't run)")
        return True

    # Should have swap output
    if return_code in [0, 1]:
        assert 'swap' in stdout.lower(), \
            "Plain output should show swap information"

    print("PASS: Plain output has swap test passed")
    return True


def test_table_output_format():
    """Test that table output has proper format."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--format', 'table', '--no-sample']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: Table output test (script couldn't run)")
        return True

    # Should have table-like output
    if return_code in [0, 1]:
        # Table should have metric names
        assert 'Swap' in stdout or 'Metric' in stdout or 'Memory' in stdout, \
            "Table output should have column headers or metric names"

    print("PASS: Table output format test passed")
    return True


def test_verbose_adds_interpretation():
    """Test that verbose mode adds interpretation."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--verbose', '--no-sample']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: Verbose interpretation test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        # Verbose should add interpretation
        assert 'Interpretation' in stdout or 'swap' in stdout.lower(), \
            "Verbose output should include interpretation"

    print("PASS: Verbose adds interpretation test passed")
    return True


def test_high_threshold_exits_zero():
    """Test that very high thresholds result in no warnings."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--warn', '99', '--crit', '100', '--no-sample']
    )

    # Skip if script couldn't run
    if return_code == 2 and 'proc' in stderr.lower():
        print("SKIP: High threshold test (/proc not available)")
        return True

    # With extremely high thresholds, should exit 0 unless swap is > 99%
    # Note: Could still be 1 if active swapping is detected
    assert return_code in [0, 1], \
        f"High thresholds should result in exit 0 or 1, got {return_code}"

    print("PASS: High threshold test passed")
    return True


def test_zero_warn_threshold():
    """Test that zero warn threshold is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--warn', '0', '--crit', '50', '--no-sample']
    )

    # Should not have argument parsing errors
    assert return_code in [0, 1, 2], \
        f"Zero warn threshold should be accepted, got {return_code}"
    assert 'error' not in stderr.lower() or 'proc' in stderr.lower(), \
        "Zero warn threshold should be accepted"

    print("PASS: Zero warn threshold test passed")
    return True


def test_no_sample_runs_faster():
    """Test that --no-sample makes the script run quickly."""
    import time

    start = time.time()
    return_code, stdout, stderr = run_command(
        ['./baremetal_swap_pressure_analyzer.py', '--no-sample']
    )
    elapsed = time.time() - start

    # Without sampling, should complete in under 1 second
    assert elapsed < 2.0, \
        f"--no-sample should run quickly, took {elapsed:.1f}s"

    print("PASS: No sample runs faster test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_swap_pressure_analyzer.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_format,
        test_negative_warn_threshold,
        test_warn_over_100,
        test_negative_crit_threshold,
        test_crit_over_100,
        test_crit_less_than_warn,
        test_negative_swap_rate_warn,
        test_invalid_sample_interval,
        test_invalid_argument,
        test_format_plain_accepted,
        test_format_json_accepted,
        test_format_table_accepted,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_no_sample_flag,
        test_sample_interval_flag,
        test_warn_threshold_flag,
        test_crit_threshold_flag,
        test_swap_rate_warn_flag,
        test_combined_flags,
        test_exit_code_valid,
        test_json_output_valid,
        test_json_structure,
        test_plain_output_has_swap,
        test_table_output_format,
        test_verbose_adds_interpretation,
        test_high_threshold_exits_zero,
        test_zero_warn_threshold,
        test_no_sample_runs_faster,
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
