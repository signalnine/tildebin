#!/usr/bin/env python3
"""
Tests for k8s_metrics_server_health_monitor.py

These tests validate:
- Argument parsing
- Help message
- Error handling
- Output format options
- Exit codes
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
    return_code, stdout, stderr = run_command(
        ['./k8s_metrics_server_health_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'Monitor Kubernetes Metrics Server health' in stdout, \
        "Help should contain description"
    assert '--namespace' in stdout, "Help should document --namespace flag"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout, "Help should document --warn-only flag"
    assert '--verbose' in stdout, "Help should document --verbose flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"
    assert 'HPA' in stdout or 'Horizontal Pod Autoscaler' in stdout or \
           'autoscal' in stdout.lower(), \
        "Help should mention HPA/autoscaling context"

    print("OK Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized (even if kubectl not available)."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./k8s_metrics_server_health_monitor.py', '--format', fmt]
        )

        # Should either work (0/1) or fail with kubectl error (2), but not arg parse error
        assert return_code in [0, 1, 2], \
            f"Format {fmt} should be valid, got return code {return_code}"

        # Should not get argument parsing errors
        assert 'invalid choice' not in stderr.lower(), \
            f"Format {fmt} should be a valid choice"
        assert 'unrecognized arguments' not in stderr.lower(), \
            f"Format {fmt} should be recognized"

    print("OK Format flag recognition test passed")
    return True


def test_namespace_flag_recognized():
    """Test that --namespace flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_metrics_server_health_monitor.py', '--namespace', 'monitoring']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "--namespace should be recognized"

    print("OK Namespace flag recognition test passed")
    return True


def test_namespace_short_flag_recognized():
    """Test that -n short flag for namespace is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_metrics_server_health_monitor.py', '-n', 'monitoring']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "-n should be recognized as namespace flag"

    print("OK Namespace short flag recognition test passed")
    return True


def test_warn_only_flag_recognized():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_metrics_server_health_monitor.py', '--warn-only']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("OK Warn-only flag recognition test passed")
    return True


def test_verbose_flag_recognized():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_metrics_server_health_monitor.py', '--verbose']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("OK Verbose flag recognition test passed")
    return True


def test_verbose_short_flag_recognized():
    """Test that -v short flag for verbose is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_metrics_server_health_monitor.py', '-v']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "-v should be recognized as verbose flag"

    print("OK Verbose short flag recognition test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./k8s_metrics_server_health_monitor.py', '--format', 'invalid']
    )

    # Should fail with argument parsing error
    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("OK Invalid format rejection test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './k8s_metrics_server_health_monitor.py',
        '--namespace', 'monitoring',
        '--format', 'json',
        '--warn-only',
        '--verbose'
    ])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined flags should be recognized"

    print("OK Combined flags test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    import os
    import stat

    script_path = './k8s_metrics_server_health_monitor.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("OK Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./k8s_metrics_server_health_monitor.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("OK Shebang test passed")
    return True


def test_docstring_has_exit_codes():
    """Test that script docstring documents exit codes."""
    with open('./k8s_metrics_server_health_monitor.py', 'r') as f:
        content = f.read()

    assert 'Exit codes:' in content, "Script should document exit codes in docstring"
    assert '0 -' in content, "Should document exit code 0"
    assert '1 -' in content, "Should document exit code 1"
    assert '2 -' in content, "Should document exit code 2"

    print("OK Docstring exit codes test passed")
    return True


def test_json_format_structure():
    """Test that JSON output (if produced) is valid JSON with expected structure."""
    return_code, stdout, stderr = run_command([
        './k8s_metrics_server_health_monitor.py',
        '--format', 'json'
    ])

    # If we got output on stdout, it should be valid JSON
    if stdout.strip():
        try:
            data = json.loads(stdout)
            # Verify it's a dictionary
            assert isinstance(data, dict), "JSON output should be a dictionary"

            # If the script ran successfully, verify key fields exist
            if return_code in [0, 1]:
                expected_fields = [
                    'timestamp', 'deployment', 'pods', 'api_service',
                    'metrics', 'issues', 'warnings', 'healthy'
                ]
                for field in expected_fields:
                    assert field in data, f"JSON output should contain '{field}' field"

                # Verify nested structure
                assert 'exists' in data['api_service'], \
                    "api_service should have 'exists' field"
                assert 'nodes_reporting' in data['metrics'], \
                    "metrics should have 'nodes_reporting' field"
                assert isinstance(data['issues'], list), \
                    "issues should be a list"
                assert isinstance(data['warnings'], list), \
                    "warnings should be a list"
                assert isinstance(data['healthy'], bool), \
                    "healthy should be a boolean"

        except json.JSONDecodeError:
            # If it's not valid JSON, that's only OK if we got an error message
            assert return_code == 2, \
                "Invalid JSON output should only occur with error exit code"

    print("OK JSON format structure test passed")
    return True


def test_kubectl_missing_message():
    """Test that missing kubectl produces helpful error message."""
    # This test is tricky because kubectl might actually be installed
    # Just verify the script handles it gracefully if it's not available

    return_code, stdout, stderr = run_command(
        ['./k8s_metrics_server_health_monitor.py']
    )

    # If kubectl is not available, should exit with 2 and show error
    if return_code == 2:
        assert 'kubectl' in stderr.lower() or 'kubectl' in stdout.lower(), \
            "Missing kubectl error should mention kubectl"

    print("OK kubectl missing message test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_namespace_flag_recognized,
        test_namespace_short_flag_recognized,
        test_warn_only_flag_recognized,
        test_verbose_flag_recognized,
        test_verbose_short_flag_recognized,
        test_invalid_format_rejected,
        test_combined_flags,
        test_script_is_executable,
        test_shebang_present,
        test_docstring_has_exit_codes,
        test_json_format_structure,
        test_kubectl_missing_message,
    ]

    print(f"Running {len(tests)} tests for k8s_metrics_server_health_monitor.py...")
    print()

    failed = []
    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"FAIL {test.__name__}: {e}")
            failed.append(test.__name__)
        except Exception as e:
            print(f"ERROR {test.__name__}: {e}")
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
