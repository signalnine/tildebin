#!/usr/bin/env python3
"""
Tests for baremetal_numa_topology_analyzer.py

These tests validate:
- Argument parsing and flag recognition
- Help message content
- Output format options (plain, json, table)
- Exit code behavior
- JSON output structure

Tests run without requiring specific NUMA hardware configuration.
"""

import subprocess
import sys
import json
import os
import stat


def run_command(args, timeout=5):
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
        ['./baremetal_numa_topology_analyzer.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'numa' in stdout.lower(), "Help should mention NUMA"
    assert 'memory' in stdout.lower(), "Help should mention memory"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_numa_topology_analyzer.py', '--format', fmt]
        )

        # Should succeed (0 or 1 depending on configuration), or 2 if NUMA unavailable
        assert return_code in [0, 1, 2], f"Format {fmt} should be valid, got {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '-f', 'json']
    )

    assert return_code in [0, 1, 2], f"Short format flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"

    print("PASS: Short format flag test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'invalid']
    )

    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("PASS: Invalid format rejection test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--verbose']
    )

    assert return_code in [0, 1, 2], f"Verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '-v']
    )

    assert return_code in [0, 1, 2], f"Short verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--warn-only']
    )

    assert return_code in [0, 1, 2], f"Warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '-w']
    )

    assert return_code in [0, 1, 2], f"Short warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './baremetal_numa_topology_analyzer.py',
        '--format', 'table',
        '--verbose'
    ])

    assert return_code in [0, 1, 2], f"Combined flags should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("PASS: Combined flags test passed")
    return True


def test_json_output_valid():
    """Test that JSON output is valid JSON with expected fields."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'json']
    )

    # Exit code 2 means NUMA not available (e.g., in container or non-NUMA system)
    if return_code == 2:
        print("SKIP: JSON output test skipped (NUMA info unavailable)")
        return True

    assert return_code in [0, 1], f"JSON format should work, got {return_code}"

    try:
        data = json.loads(stdout)
        assert isinstance(data, dict), "JSON output should be a dictionary"

        # Verify required fields
        required_fields = ['timestamp', 'numa_nodes', 'nodes', 'status',
                          'issues', 'warnings', 'healthy']
        for field in required_fields:
            assert field in data, f"JSON should contain '{field}' field"

        # Verify types
        assert isinstance(data['numa_nodes'], int), "numa_nodes should be an integer"
        assert isinstance(data['nodes'], dict), "nodes should be a dictionary"
        assert isinstance(data['issues'], list), "issues should be a list"
        assert isinstance(data['warnings'], list), "warnings should be a list"
        assert isinstance(data['healthy'], bool), "healthy should be a boolean"
        assert data['status'] in ['healthy', 'warning', 'critical'], \
            f"status should be valid, got {data['status']}"

    except json.JSONDecodeError as e:
        raise AssertionError(f"JSON output is invalid: {e}\nOutput: {stdout[:200]}")

    print("PASS: JSON output structure test passed")
    return True


def test_json_node_structure():
    """Test that JSON output has proper per-node structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: JSON node structure test skipped (NUMA info unavailable)")
        return True

    data = json.loads(stdout)

    # Check that we have at least one node
    assert len(data['nodes']) > 0, "Should have at least one NUMA node"

    # Check node structure
    for node_id, node_data in data['nodes'].items():
        assert 'cpus' in node_data, f"Node {node_id} should have 'cpus' field"
        assert 'cpu_count' in node_data, f"Node {node_id} should have 'cpu_count' field"
        assert 'memory' in node_data, f"Node {node_id} should have 'memory' field"
        assert 'stats' in node_data, f"Node {node_id} should have 'stats' field"

        assert isinstance(node_data['cpus'], list), f"Node {node_id} cpus should be a list"
        assert isinstance(node_data['cpu_count'], int), f"Node {node_id} cpu_count should be int"
        assert isinstance(node_data['memory'], dict), f"Node {node_id} memory should be dict"
        assert isinstance(node_data['stats'], dict), f"Node {node_id} stats should be dict"

    print("PASS: JSON node structure test passed")
    return True


def test_plain_output_contains_expected_info():
    """Test that plain output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'plain']
    )

    if return_code == 2:
        print("SKIP: Plain output test skipped (NUMA info unavailable)")
        return True

    assert return_code in [0, 1], f"Plain format should work, got {return_code}"
    assert 'numa' in stdout.lower(), "Plain output should mention NUMA"
    assert 'node' in stdout.lower(), "Plain output should mention node"

    print("PASS: Plain output content test passed")
    return True


def test_table_output_contains_expected_info():
    """Test that table output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'table']
    )

    if return_code == 2:
        print("SKIP: Table output test skipped (NUMA info unavailable)")
        return True

    assert return_code in [0, 1], f"Table format should work, got {return_code}"
    assert '+' in stdout or '|' in stdout, "Table output should have table formatting"

    print("PASS: Table output content test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    script_path = './baremetal_numa_topology_analyzer.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("PASS: Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./baremetal_numa_topology_analyzer.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("PASS: Shebang test passed")
    return True


def test_docstring_present():
    """Test that script has a module docstring."""
    with open('./baremetal_numa_topology_analyzer.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert 'numa' in content.lower(), "Docstring should mention NUMA"
    assert 'memory' in content.lower(), "Docstring should mention memory"

    print("PASS: Docstring test passed")
    return True


def test_exit_code_documentation():
    """Test that exit codes are properly documented."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--help']
    )

    assert '0' in stdout, "Help should document exit code 0"
    assert '1' in stdout, "Help should document exit code 1"
    assert '2' in stdout, "Help should document exit code 2"

    print("PASS: Exit code documentation test passed")
    return True


def test_status_value_valid():
    """Test that status value in JSON output is valid."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Status value test skipped (NUMA info unavailable)")
        return True

    data = json.loads(stdout)
    valid_statuses = ['healthy', 'warning', 'critical']

    assert data['status'] in valid_statuses, \
        f"Status should be one of {valid_statuses}, got {data['status']}"

    print("PASS: Status value validation test passed")
    return True


def test_healthy_matches_status():
    """Test that healthy boolean matches status field."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Healthy/status match test skipped (NUMA info unavailable)")
        return True

    data = json.loads(stdout)

    if data['status'] == 'healthy':
        assert data['healthy'] is True, "healthy should be True when status is healthy"
    else:
        assert data['healthy'] is False, "healthy should be False when status is not healthy"

    print("PASS: Healthy matches status test passed")
    return True


def test_exit_code_matches_status():
    """Test that exit code matches the status."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Exit code/status match test skipped (NUMA info unavailable)")
        return True

    data = json.loads(stdout)

    if data['status'] == 'healthy':
        assert return_code == 0, f"Exit code should be 0 for healthy status, got {return_code}"
    else:
        assert return_code == 1, f"Exit code should be 1 for non-healthy status, got {return_code}"

    print("PASS: Exit code matches status test passed")
    return True


def test_numa_nodes_count_matches():
    """Test that numa_nodes count matches nodes dictionary."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: NUMA nodes count test skipped (NUMA info unavailable)")
        return True

    data = json.loads(stdout)

    assert data['numa_nodes'] == len(data['nodes']), \
        f"numa_nodes ({data['numa_nodes']}) should match nodes count ({len(data['nodes'])})"

    print("PASS: NUMA nodes count matches test passed")
    return True


def test_verbose_output_more_detailed():
    """Test that verbose output includes additional details."""
    return_code_normal, stdout_normal, _ = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'plain']
    )

    return_code_verbose, stdout_verbose, _ = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'plain', '--verbose']
    )

    if return_code_normal == 2 or return_code_verbose == 2:
        print("SKIP: Verbose comparison test skipped (NUMA info unavailable)")
        return True

    # Verbose should have same or more content
    assert len(stdout_verbose) >= len(stdout_normal), \
        "Verbose output should have at least as much content as normal"

    print("PASS: Verbose output more detailed test passed")
    return True


def test_balancing_field_present():
    """Test that NUMA balancing info is included in JSON output."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Balancing field test skipped (NUMA info unavailable)")
        return True

    data = json.loads(stdout)

    assert 'balancing' in data, "JSON should contain 'balancing' field"
    assert isinstance(data['balancing'], dict), "balancing should be a dictionary"

    print("PASS: Balancing field present test passed")
    return True


def test_distances_field_present():
    """Test that NUMA distances info is included in JSON output."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Distances field test skipped (NUMA info unavailable)")
        return True

    data = json.loads(stdout)

    assert 'distances' in data, "JSON should contain 'distances' field"
    assert isinstance(data['distances'], dict), "distances should be a dictionary"

    print("PASS: Distances field present test passed")
    return True


def test_info_field_present():
    """Test that info messages field is included in JSON output."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_numa_topology_analyzer.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Info field test skipped (NUMA info unavailable)")
        return True

    data = json.loads(stdout)

    assert 'info' in data, "JSON should contain 'info' field"
    assert isinstance(data['info'], list), "info should be a list"

    print("PASS: Info field present test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_invalid_format_rejected,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_combined_flags,
        test_json_output_valid,
        test_json_node_structure,
        test_plain_output_contains_expected_info,
        test_table_output_contains_expected_info,
        test_script_is_executable,
        test_shebang_present,
        test_docstring_present,
        test_exit_code_documentation,
        test_status_value_valid,
        test_healthy_matches_status,
        test_exit_code_matches_status,
        test_numa_nodes_count_matches,
        test_verbose_output_more_detailed,
        test_balancing_field_present,
        test_distances_field_present,
        test_info_field_present,
    ]

    print(f"Running {len(tests)} tests for baremetal_numa_topology_analyzer.py...")
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
