#!/usr/bin/env python3
"""
Tests for k8s_dns_health_monitor.py

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
    return_code, stdout, stderr = run_command(['./k8s_dns_health_monitor.py', '--help'])

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'Monitor Kubernetes DNS health' in stdout, "Help should contain description"
    assert '--namespace' in stdout, "Help should document --namespace flag"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout, "Help should document --warn-only flag"
    assert '--no-dns-test' in stdout, "Help should document --no-dns-test flag"
    assert '--test-domain' in stdout, "Help should document --test-domain flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("✓ Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized (even if kubectl not available)."""
    # Test each format option - they should be recognized as valid args
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(['./k8s_dns_health_monitor.py', '--format', fmt])

        # Should either work (0) or fail with kubectl error (2), but not arg parse error
        assert return_code in [0, 1, 2], f"Format {fmt} should be valid, got return code {return_code}"

        # Should not get argument parsing errors
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"
        assert 'unrecognized arguments' not in stderr.lower(), f"Format {fmt} should be recognized"

    print("✓ Format flag recognition test passed")
    return True


def test_namespace_flag_recognized():
    """Test that --namespace flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_dns_health_monitor.py', '--namespace', 'custom-namespace']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--namespace should be recognized"

    print("✓ Namespace flag recognition test passed")
    return True


def test_warn_only_flag_recognized():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(['./k8s_dns_health_monitor.py', '--warn-only'])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("✓ Warn-only flag recognition test passed")
    return True


def test_no_dns_test_flag_recognized():
    """Test that --no-dns-test flag is recognized."""
    return_code, stdout, stderr = run_command(['./k8s_dns_health_monitor.py', '--no-dns-test'])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--no-dns-test should be recognized"

    print("✓ No-DNS-test flag recognition test passed")
    return True


def test_test_domain_flag_recognized():
    """Test that --test-domain flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_dns_health_monitor.py', '--test-domain', 'example.com']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--test-domain should be recognized"

    print("✓ Test-domain flag recognition test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./k8s_dns_health_monitor.py', '--format', 'invalid']
    )

    # Should fail with argument parsing error
    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("✓ Invalid format rejection test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './k8s_dns_health_monitor.py',
        '--namespace', 'test-ns',
        '--format', 'json',
        '--warn-only',
        '--no-dns-test'
    ])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("✓ Combined flags test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    import os
    import stat

    script_path = './k8s_dns_health_monitor.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("✓ Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./k8s_dns_health_monitor.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("✓ Shebang test passed")
    return True


def test_json_format_structure():
    """Test that JSON output (if produced) is valid JSON."""
    # This test will pass even if kubectl is not available
    # We just verify that when --format json is used, any output is valid JSON or there's a clear error

    return_code, stdout, stderr = run_command([
        './k8s_dns_health_monitor.py',
        '--format', 'json',
        '--no-dns-test'
    ])

    # If we got output on stdout, it should be valid JSON
    if stdout.strip():
        try:
            data = json.loads(stdout)
            # Verify expected structure
            assert isinstance(data, dict), "JSON output should be a dictionary"

            # If the script ran successfully, verify key fields exist
            if return_code == 0 or return_code == 1:
                # These fields should exist in the JSON output
                expected_fields = ['timestamp', 'pods', 'service', 'endpoints', 'issues', 'warnings', 'healthy']
                for field in expected_fields:
                    assert field in data, f"JSON output should contain '{field}' field"

        except json.JSONDecodeError:
            # If it's not valid JSON, that's only OK if we got an error message
            assert return_code == 2, "Invalid JSON output should only occur with error exit code"

    print("✓ JSON format structure test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_namespace_flag_recognized,
        test_warn_only_flag_recognized,
        test_no_dns_test_flag_recognized,
        test_test_domain_flag_recognized,
        test_invalid_format_rejected,
        test_combined_flags,
        test_script_is_executable,
        test_shebang_present,
        test_json_format_structure,
    ]

    print(f"Running {len(tests)} tests for k8s_dns_health_monitor.py...")
    print()

    failed = []
    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"✗ {test.__name__} failed: {e}")
            failed.append(test.__name__)
        except Exception as e:
            print(f"✗ {test.__name__} error: {e}")
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
