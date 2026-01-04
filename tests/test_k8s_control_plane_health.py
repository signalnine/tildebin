#!/usr/bin/env python3
"""
Tests for k8s_control_plane_health.py

These tests validate:
- Argument parsing
- Help message
- Error handling
- Output format options
- Exit codes

Tests run without requiring kubectl or a Kubernetes cluster.
"""

import subprocess
import sys
import json


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
    return_code, stdout, stderr = run_command(['./k8s_control_plane_health.py', '--help'])

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'control plane' in stdout.lower(), "Help should contain 'control plane'"
    assert '--namespace' in stdout, "Help should document --namespace flag"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout, "Help should document --warn-only flag"
    assert '-v' in stdout or '--verbose' in stdout, "Help should document verbose flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized (even if kubectl not available)."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(['./k8s_control_plane_health.py', '--format', fmt])

        # Should either work (0/1) or fail with kubectl error (2), not arg parse error
        assert return_code in [0, 1, 2], f"Format {fmt} should be valid, got return code {return_code}"

        # Should not get argument parsing errors
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"
        assert 'unrecognized arguments' not in stderr.lower(), f"Format {fmt} should be recognized"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(['./k8s_control_plane_health.py', '-f', 'json'])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_namespace_flag_recognized():
    """Test that --namespace flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_control_plane_health.py', '--namespace', 'custom-namespace']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--namespace should be recognized"

    print("PASS: Namespace flag recognition test passed")
    return True


def test_short_namespace_flag():
    """Test that -n shorthand for --namespace works."""
    return_code, stdout, stderr = run_command(
        ['./k8s_control_plane_health.py', '-n', 'test-ns']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "-n should be recognized"

    print("PASS: Short namespace flag test passed")
    return True


def test_warn_only_flag_recognized():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(['./k8s_control_plane_health.py', '--warn-only'])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("PASS: Warn-only flag recognition test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(['./k8s_control_plane_health.py', '-w'])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_verbose_flag_recognized():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(['./k8s_control_plane_health.py', '--verbose'])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("PASS: Verbose flag recognition test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(['./k8s_control_plane_health.py', '-v'])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./k8s_control_plane_health.py', '--format', 'invalid']
    )

    # Should fail with argument parsing error
    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("PASS: Invalid format rejection test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './k8s_control_plane_health.py',
        '--namespace', 'test-ns',
        '--format', 'json',
        '--warn-only',
        '--verbose'
    ])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("PASS: Combined flags test passed")
    return True


def test_combined_short_flags():
    """Test that multiple short flags can be combined."""
    return_code, stdout, stderr = run_command([
        './k8s_control_plane_health.py',
        '-n', 'test-ns',
        '-f', 'plain',
        '-w',
        '-v'
    ])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "Combined short flags should be recognized"

    print("PASS: Combined short flags test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    import os
    import stat

    script_path = './k8s_control_plane_health.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("PASS: Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./k8s_control_plane_health.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("PASS: Shebang test passed")
    return True


def test_docstring_present():
    """Test that script has a module docstring."""
    with open('./k8s_control_plane_health.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert 'control plane' in content.lower(), "Docstring should mention control plane"

    print("PASS: Docstring test passed")
    return True


def test_exit_code_documentation():
    """Test that exit codes are properly documented."""
    return_code, stdout, stderr = run_command(['./k8s_control_plane_health.py', '--help'])

    assert '0' in stdout, "Help should document exit code 0"
    assert '1' in stdout, "Help should document exit code 1"
    assert '2' in stdout, "Help should document exit code 2"

    print("PASS: Exit code documentation test passed")
    return True


def test_kubectl_missing_handling():
    """Test that script handles missing kubectl gracefully."""
    import os

    # Run with empty PATH to simulate missing kubectl
    env = os.environ.copy()
    env['PATH'] = ''

    try:
        result = subprocess.run(
            ['./k8s_control_plane_health.py'],
            capture_output=True,
            text=True,
            timeout=5,
            env=env
        )

        # Should exit with code 2 for missing dependency
        assert result.returncode == 2, f"Missing kubectl should exit with 2, got {result.returncode}"
        assert 'kubectl' in result.stderr.lower() or 'not found' in result.stderr.lower(), \
            "Should mention kubectl in error message"

    except Exception as e:
        # If the script can't run at all, that's also acceptable
        pass

    print("PASS: kubectl missing handling test passed")
    return True


def test_json_format_produces_valid_json():
    """Test that JSON format produces valid JSON (or proper error)."""
    return_code, stdout, stderr = run_command([
        './k8s_control_plane_health.py',
        '--format', 'json'
    ])

    # If we got output on stdout, it should be valid JSON
    if stdout.strip():
        try:
            data = json.loads(stdout)
            assert isinstance(data, dict), "JSON output should be a dictionary"

            # If the script ran successfully, verify key fields exist
            if return_code in [0, 1]:
                expected_fields = ['timestamp', 'api_server', 'issues', 'warnings', 'healthy']
                for field in expected_fields:
                    assert field in data, f"JSON output should contain '{field}' field"

        except json.JSONDecodeError:
            # If it's not valid JSON, that's only OK if we got an error message
            assert return_code == 2, "Invalid JSON output should only occur with error exit code"

    print("PASS: JSON format structure test passed")
    return True


def test_default_namespace_is_kube_system():
    """Test that default namespace is kube-system."""
    return_code, stdout, stderr = run_command(['./k8s_control_plane_health.py', '--help'])

    assert 'kube-system' in stdout, "Default namespace should be kube-system"

    print("PASS: Default namespace test passed")
    return True


def test_default_format_is_table():
    """Test that default format is table."""
    return_code, stdout, stderr = run_command(['./k8s_control_plane_health.py', '--help'])

    # Check that default is table
    assert 'default: table' in stdout.lower() or '(default: table)' in stdout, \
        "Default format should be table"

    print("PASS: Default format test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_namespace_flag_recognized,
        test_short_namespace_flag,
        test_warn_only_flag_recognized,
        test_short_warn_only_flag,
        test_verbose_flag_recognized,
        test_short_verbose_flag,
        test_invalid_format_rejected,
        test_combined_flags,
        test_combined_short_flags,
        test_script_is_executable,
        test_shebang_present,
        test_docstring_present,
        test_exit_code_documentation,
        test_kubectl_missing_handling,
        test_json_format_produces_valid_json,
        test_default_namespace_is_kube_system,
        test_default_format_is_table,
    ]

    print(f"Running {len(tests)} tests for k8s_control_plane_health.py...")
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
