#!/usr/bin/env python3
"""
Tests for k8s_cni_health_monitor.py

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
    return_code, stdout, stderr = run_command(['./k8s_cni_health_monitor.py', '--help'])

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'Monitor Kubernetes CNI' in stdout, "Help should contain description"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout, "Help should document --warn-only flag"
    assert '--verbose' in stdout, "Help should document --verbose flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"
    assert 'Calico' in stdout, "Help should mention supported CNI plugins"
    assert 'Cilium' in stdout, "Help should mention supported CNI plugins"

    print("PASS Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized (even if kubectl not available)."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(['./k8s_cni_health_monitor.py', '--format', fmt])

        # Should either work (0/1) or fail with kubectl error (2), but not arg parse error
        assert return_code in [0, 1, 2], f"Format {fmt} should be valid, got return code {return_code}"

        # Should not get argument parsing errors
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"
        assert 'unrecognized arguments' not in stderr.lower(), f"Format {fmt} should be recognized"

    print("PASS Format flag recognition test passed")
    return True


def test_warn_only_flag_recognized():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(['./k8s_cni_health_monitor.py', '--warn-only'])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("PASS Warn-only flag recognition test passed")
    return True


def test_verbose_flag_recognized():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(['./k8s_cni_health_monitor.py', '--verbose'])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("PASS Verbose flag recognition test passed")
    return True


def test_short_flags_recognized():
    """Test that short flags -w and -v are recognized."""
    # Test -w
    return_code, stdout, stderr = run_command(['./k8s_cni_health_monitor.py', '-w'])
    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    # Test -v
    return_code, stdout, stderr = run_command(['./k8s_cni_health_monitor.py', '-v'])
    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS Short flags recognition test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./k8s_cni_health_monitor.py', '--format', 'invalid']
    )

    # Should fail with argument parsing error
    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("PASS Invalid format rejection test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './k8s_cni_health_monitor.py',
        '--format', 'json',
        '--warn-only',
        '--verbose'
    ])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("PASS Combined flags test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    import os
    import stat

    script_path = './k8s_cni_health_monitor.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("PASS Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./k8s_cni_health_monitor.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("PASS Shebang test passed")
    return True


def test_json_format_structure():
    """Test that JSON output (if produced) is valid JSON."""
    return_code, stdout, stderr = run_command([
        './k8s_cni_health_monitor.py',
        '--format', 'json'
    ])

    # If we got output on stdout, it should be valid JSON
    if stdout.strip():
        try:
            data = json.loads(stdout)
            # Verify expected structure
            assert isinstance(data, dict), "JSON output should be a dictionary"

            # If the script ran successfully, verify key fields exist
            if return_code in [0, 1]:
                expected_fields = [
                    'timestamp', 'detected_plugins', 'daemonset_status',
                    'pods', 'nodes', 'issues', 'warnings', 'healthy'
                ]
                for field in expected_fields:
                    assert field in data, f"JSON output should contain '{field}' field"

        except json.JSONDecodeError:
            # If it's not valid JSON, that's only OK if we got an error message
            assert return_code == 2, "Invalid JSON output should only occur with error exit code"

    print("PASS JSON format structure test passed")
    return True


def test_kubectl_error_handling():
    """Test that script handles missing kubectl gracefully."""
    # This test verifies the error message when kubectl is not available
    # In environments with kubectl, this test still passes (checks argument parsing)

    return_code, stdout, stderr = run_command(['./k8s_cni_health_monitor.py'])

    # If kubectl is not available, should exit with code 2 and show helpful message
    if return_code == 2:
        assert 'kubectl' in stderr.lower(), "Error should mention kubectl"
        # Should provide helpful guidance
        assert 'install' in stderr.lower() or 'configure' in stderr.lower() or 'available' in stderr.lower(), \
            "Error should provide guidance"

    print("PASS kubectl error handling test passed")
    return True


def test_docstring_present():
    """Test that script has comprehensive docstring."""
    with open('./k8s_cni_health_monitor.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert 'CNI' in content, "Docstring should describe CNI monitoring"

    print("PASS Docstring test passed")
    return True


def test_exit_code_documentation():
    """Test that exit codes are properly documented."""
    return_code, stdout, stderr = run_command(['./k8s_cni_health_monitor.py', '--help'])

    assert '0' in stdout, "Help should document exit code 0"
    assert '1' in stdout, "Help should document exit code 1"
    assert '2' in stdout, "Help should document exit code 2"

    print("PASS Exit code documentation test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_warn_only_flag_recognized,
        test_verbose_flag_recognized,
        test_short_flags_recognized,
        test_invalid_format_rejected,
        test_combined_flags,
        test_script_is_executable,
        test_shebang_present,
        test_json_format_structure,
        test_kubectl_error_handling,
        test_docstring_present,
        test_exit_code_documentation,
    ]

    print(f"Running {len(tests)} tests for k8s_cni_health_monitor.py...")
    print()

    failed = []
    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"FAIL {test.__name__} failed: {e}")
            failed.append(test.__name__)
        except Exception as e:
            print(f"FAIL {test.__name__} error: {e}")
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
