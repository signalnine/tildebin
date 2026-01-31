#!/usr/bin/env python3
"""
Tests for baremetal_process_tree_depth_monitor.py

These tests validate:
- Argument parsing
- Help message
- Output format options
- Threshold validation
- Exit codes
- JSON output structure

Tests run without requiring specific process tree conditions.
"""

import subprocess
import sys
import json
import os
import stat


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
        ['./baremetal_process_tree_depth_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'process' in stdout.lower(), "Help should mention process"
    assert 'tree' in stdout.lower() or 'depth' in stdout.lower(), \
        "Help should mention tree or depth"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--depth-warning' in stdout, "Help should document --depth-warning flag"
    assert '--depth-critical' in stdout, "Help should document --depth-critical flag"
    assert '--child-warning' in stdout, "Help should document --child-warning flag"
    assert '--warn-only' in stdout, "Help should document --warn-only flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_short_help_flag():
    """Test that -h shorthand for --help works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '-h']
    )

    assert return_code == 0, f"Short help flag should exit with 0, got {return_code}"
    assert 'process' in stdout.lower(), "Help should mention process"

    print("PASS: Short help flag test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_process_tree_depth_monitor.py', '--format', fmt]
        )

        # Should succeed (0 or 1 depending on tree depth), not fail on arg parsing
        assert return_code in [0, 1], f"Format {fmt} should be valid, got {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '-f', 'json']
    )

    assert return_code in [0, 1], f"Short format flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"

    print("PASS: Short format flag test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--format', 'invalid']
    )

    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("PASS: Invalid format rejection test passed")
    return True


def test_depth_warning_flag():
    """Test that --depth-warning flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--depth-warning', '10']
    )

    assert return_code in [0, 1], f"Depth warning flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--depth-warning should be recognized"

    print("PASS: Depth warning flag test passed")
    return True


def test_depth_critical_flag():
    """Test that --depth-critical flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--depth-critical', '50']
    )

    assert return_code in [0, 1], f"Depth critical flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--depth-critical should be recognized"

    print("PASS: Depth critical flag test passed")
    return True


def test_child_warning_flag():
    """Test that --child-warning flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--child-warning', '100']
    )

    assert return_code in [0, 1], f"Child warning flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--child-warning should be recognized"

    print("PASS: Child warning flag test passed")
    return True


def test_child_critical_flag():
    """Test that --child-critical flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--child-critical', '500']
    )

    assert return_code in [0, 1], f"Child critical flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--child-critical should be recognized"

    print("PASS: Child critical flag test passed")
    return True


def test_invalid_depth_threshold_warning_gte_critical():
    """Test that depth-warning >= depth-critical is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py',
         '--depth-warning', '30', '--depth-critical', '30']
    )

    assert return_code == 2, f"Equal depth thresholds should exit with 2, got {return_code}"
    assert 'depth' in stderr.lower() or 'threshold' in stderr.lower(), \
        "Should mention depth or threshold in error"

    print("PASS: Invalid depth threshold (warning >= critical) test passed")
    return True


def test_invalid_child_threshold_warning_gte_critical():
    """Test that child-warning >= child-critical is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py',
         '--child-warning', '200', '--child-critical', '200']
    )

    assert return_code == 2, f"Equal child thresholds should exit with 2, got {return_code}"
    assert 'child' in stderr.lower() or 'threshold' in stderr.lower(), \
        "Should mention child or threshold in error"

    print("PASS: Invalid child threshold (warning >= critical) test passed")
    return True


def test_invalid_negative_threshold():
    """Test that zero or negative thresholds are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--depth-warning', '0']
    )

    assert return_code == 2, f"Zero threshold should exit with 2, got {return_code}"
    assert 'threshold' in stderr.lower() or 'positive' in stderr.lower(), \
        "Should mention threshold error"

    print("PASS: Invalid threshold (zero/negative) test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--warn-only']
    )

    assert return_code in [0, 1], f"Warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '-w']
    )

    assert return_code in [0, 1], f"Short warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--verbose']
    )

    assert return_code in [0, 1], f"Verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '-v']
    )

    assert return_code in [0, 1], f"Short verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './baremetal_process_tree_depth_monitor.py',
        '--format', 'table',
        '--depth-warning', '20',
        '--depth-critical', '50',
        '--verbose'
    ])

    assert return_code in [0, 1], f"Combined flags should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("PASS: Combined flags test passed")
    return True


def test_json_output_valid():
    """Test that JSON output is valid JSON with expected fields."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"JSON format should work, got {return_code}"

    try:
        data = json.loads(stdout)
        assert isinstance(data, dict), "JSON output should be a dictionary"

        # Verify required fields
        required_fields = ['timestamp', 'total_processes', 'max_depth',
                          'deepest_chains', 'status', 'issues', 'warnings', 'healthy']
        for field in required_fields:
            assert field in data, f"JSON should contain '{field}' field"

        # Verify types
        assert isinstance(data['total_processes'], int), "total_processes should be int"
        assert isinstance(data['max_depth'], int), "max_depth should be int"
        assert isinstance(data['deepest_chains'], list), "deepest_chains should be a list"
        assert isinstance(data['issues'], list), "issues should be a list"
        assert isinstance(data['warnings'], list), "warnings should be a list"
        assert isinstance(data['healthy'], bool), "healthy should be a boolean"

    except json.JSONDecodeError as e:
        raise AssertionError(f"JSON output is invalid: {e}\nOutput: {stdout[:200]}")

    print("PASS: JSON output structure test passed")
    return True


def test_plain_output_contains_expected_info():
    """Test that plain output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--format', 'plain']
    )

    assert return_code in [0, 1], f"Plain format should work, got {return_code}"
    assert 'process' in stdout.lower(), "Plain output should mention process"
    assert 'depth' in stdout.lower(), "Plain output should mention depth"

    print("PASS: Plain output content test passed")
    return True


def test_table_output_contains_expected_info():
    """Test that table output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--format', 'table']
    )

    assert return_code in [0, 1], f"Table format should work, got {return_code}"
    assert '+' in stdout or '|' in stdout, "Table output should have table formatting"

    print("PASS: Table output content test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    script_path = './baremetal_process_tree_depth_monitor.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("PASS: Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./baremetal_process_tree_depth_monitor.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("PASS: Shebang test passed")
    return True


def test_docstring_present():
    """Test that script has a module docstring."""
    with open('./baremetal_process_tree_depth_monitor.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert 'process' in content.lower(), "Docstring should mention process"

    print("PASS: Docstring test passed")
    return True


def test_exit_code_documentation():
    """Test that exit codes are properly documented."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--help']
    )

    assert '0' in stdout, "Help should document exit code 0"
    assert '1' in stdout, "Help should document exit code 1"
    assert '2' in stdout, "Help should document exit code 2"

    print("PASS: Exit code documentation test passed")
    return True


def test_process_count_positive():
    """Test that process count in JSON output is positive."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)
    assert data['total_processes'] > 0, "Should find at least one process"
    assert data['max_depth'] >= 0, "Max depth should be non-negative"

    print("PASS: Process count positive test passed")
    return True


def test_status_value_valid():
    """Test that status value in JSON output is valid."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)
    valid_statuses = ['healthy', 'warning', 'critical']

    assert data['status'] in valid_statuses, \
        f"Status should be one of {valid_statuses}, got {data['status']}"

    print("PASS: Status value validation test passed")
    return True


def test_high_threshold_no_warnings():
    """Test that very high thresholds produce no warnings on typical systems."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--format', 'json',
         '--depth-warning', '500', '--depth-critical', '1000',
         '--child-warning', '50000', '--child-critical', '100000']
    )

    assert return_code == 0, f"High thresholds should produce healthy status, got {return_code}"

    data = json.loads(stdout)
    assert data['healthy'] is True, "Should be healthy with very high thresholds"
    assert len(data['issues']) == 0, "Should have no issues with very high thresholds"

    print("PASS: High threshold no warnings test passed")
    return True


def test_deepest_chains_structure():
    """Test that deepest_chains in JSON has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_tree_depth_monitor.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)
    chains = data['deepest_chains']

    if chains:  # At least one chain should exist
        chain = chains[0]
        assert 'pid' in chain, "Chain should have pid"
        assert 'depth' in chain, "Chain should have depth"
        assert 'chain' in chain, "Chain should have chain list"
        assert isinstance(chain['chain'], list), "Chain list should be a list"

    print("PASS: Deepest chains structure test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_short_help_flag,
        test_format_flag_recognized,
        test_short_format_flag,
        test_invalid_format_rejected,
        test_depth_warning_flag,
        test_depth_critical_flag,
        test_child_warning_flag,
        test_child_critical_flag,
        test_invalid_depth_threshold_warning_gte_critical,
        test_invalid_child_threshold_warning_gte_critical,
        test_invalid_negative_threshold,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_combined_flags,
        test_json_output_valid,
        test_plain_output_contains_expected_info,
        test_table_output_contains_expected_info,
        test_script_is_executable,
        test_shebang_present,
        test_docstring_present,
        test_exit_code_documentation,
        test_process_count_positive,
        test_status_value_valid,
        test_high_threshold_no_warnings,
        test_deepest_chains_structure,
    ]

    print(f"Running {len(tests)} tests for baremetal_process_tree_depth_monitor.py...")
    print()

    failed = []
    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"FAIL: {test.__name__} failed: {e}")
            failed.append(test.__name__)
        except Exception as e:
            print(f"FAIL: {test.__name__} error: {e}")
            failed.append(test.__name__)

    print()
    if failed:
        print(f"Failed tests: {', '.join(failed)}")
        return 1
    else:
        print(f"All {len(tests)} tests passed!")
        return 0


if __name__ == '__main__':
    sys.exit(main())
