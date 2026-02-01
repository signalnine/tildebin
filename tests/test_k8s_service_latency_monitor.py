#!/usr/bin/env python3
"""
Tests for k8s_service_latency_monitor.py

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
    return_code, stdout, stderr = run_command(['./k8s_service_latency_monitor.py', '--help'])

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'Monitor Kubernetes service endpoint latency' in stdout, "Help should contain description"
    assert '--namespace' in stdout, "Help should document --namespace flag"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout, "Help should document --warn-only flag"
    assert '--warn-threshold' in stdout, "Help should document --warn-threshold flag"
    assert '--critical-threshold' in stdout, "Help should document --critical-threshold flag"
    assert '--include-system' in stdout, "Help should document --include-system flag"
    assert '--selector' in stdout, "Help should document --selector flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("✓ Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized (even if kubectl not available)."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(['./k8s_service_latency_monitor.py', '--format', fmt])

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
        ['./k8s_service_latency_monitor.py', '--namespace', 'custom-namespace']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--namespace should be recognized"

    print("✓ Namespace flag recognition test passed")
    return True


def test_short_namespace_flag():
    """Test that -n short flag works for namespace."""
    return_code, stdout, stderr = run_command(
        ['./k8s_service_latency_monitor.py', '-n', 'test-ns']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "-n should be recognized"

    print("✓ Short namespace flag test passed")
    return True


def test_warn_only_flag_recognized():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(['./k8s_service_latency_monitor.py', '--warn-only'])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("✓ Warn-only flag recognition test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w short flag works for warn-only."""
    return_code, stdout, stderr = run_command(['./k8s_service_latency_monitor.py', '-w'])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("✓ Short warn-only flag test passed")
    return True


def test_selector_flag_recognized():
    """Test that --selector flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_service_latency_monitor.py', '--selector', 'app=nginx']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--selector should be recognized"

    print("✓ Selector flag recognition test passed")
    return True


def test_short_selector_flag():
    """Test that -l short flag works for selector."""
    return_code, stdout, stderr = run_command(
        ['./k8s_service_latency_monitor.py', '-l', 'app=web']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "-l should be recognized"

    print("✓ Short selector flag test passed")
    return True


def test_warn_threshold_flag():
    """Test that --warn-threshold flag is recognized and accepts integer."""
    return_code, stdout, stderr = run_command(
        ['./k8s_service_latency_monitor.py', '--warn-threshold', '100']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-threshold should be recognized"

    print("✓ Warn threshold flag test passed")
    return True


def test_critical_threshold_flag():
    """Test that --critical-threshold flag is recognized and accepts integer."""
    return_code, stdout, stderr = run_command(
        ['./k8s_service_latency_monitor.py', '--critical-threshold', '500']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--critical-threshold should be recognized"

    print("✓ Critical threshold flag test passed")
    return True


def test_include_system_flag():
    """Test that --include-system flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_service_latency_monitor.py', '--include-system']
    )

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--include-system should be recognized"

    print("✓ Include system flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(['./k8s_service_latency_monitor.py', '--verbose'])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("✓ Verbose flag test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./k8s_service_latency_monitor.py', '--format', 'invalid']
    )

    # Should fail with argument parsing error
    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("✓ Invalid format rejection test passed")
    return True


def test_invalid_threshold_rejected():
    """Test that non-integer threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./k8s_service_latency_monitor.py', '--warn-threshold', 'abc']
    )

    # Should fail with argument parsing error
    assert return_code == 2, f"Invalid threshold should exit with 2, got {return_code}"

    print("✓ Invalid threshold rejection test passed")
    return True


def test_threshold_validation():
    """Test that warn-threshold < critical-threshold is enforced."""
    # This test only works if kubectl is available
    # If not, the threshold validation won't be reached
    return_code, stdout, stderr = run_command([
        './k8s_service_latency_monitor.py',
        '--warn-threshold', '500',
        '--critical-threshold', '100'
    ])

    # Should fail either with kubectl error (2) or threshold validation error (2)
    # Either way, it should not succeed
    assert return_code != 0, "Invalid thresholds (warn >= critical) should not succeed"

    print("✓ Threshold validation test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './k8s_service_latency_monitor.py',
        '--namespace', 'test-ns',
        '--format', 'json',
        '--warn-only',
        '--warn-threshold', '100',
        '--critical-threshold', '500',
        '--include-system'
    ])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("✓ Combined flags test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    script_path = './k8s_service_latency_monitor.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("✓ Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./k8s_service_latency_monitor.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("✓ Shebang test passed")
    return True


def test_json_format_structure():
    """Test that JSON output (if produced) is valid JSON."""
    return_code, stdout, stderr = run_command([
        './k8s_service_latency_monitor.py',
        '--format', 'json'
    ])

    # If we got output on stdout, it should be valid JSON
    if stdout.strip():
        try:
            data = json.loads(stdout)
            # Verify expected structure
            assert isinstance(data, dict), "JSON output should be a dictionary"

            # If the script ran successfully, verify key fields exist
            if return_code == 0 or return_code == 1:
                expected_fields = ['timestamp', 'services', 'has_issues']
                for field in expected_fields:
                    assert field in data, f"JSON output should contain '{field}' field"

                # Verify summary structure if present
                if 'summary' in data:
                    for field in ['total_checked', 'healthy', 'warning', 'critical']:
                        assert field in data['summary'], f"Summary should contain '{field}' field"

        except json.JSONDecodeError:
            # If it's not valid JSON, that's only OK if we got an error message
            assert return_code == 2, "Invalid JSON output should only occur with error exit code"

    print("✓ JSON format structure test passed")
    return True


def test_docstring_present():
    """Test that script has proper docstring with exit codes."""
    with open('./k8s_service_latency_monitor.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert '0 -' in content, "Should document exit code 0"
    assert '1 -' in content, "Should document exit code 1"
    assert '2 -' in content, "Should document exit code 2"

    print("✓ Docstring test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_namespace_flag_recognized,
        test_short_namespace_flag,
        test_warn_only_flag_recognized,
        test_short_warn_only_flag,
        test_selector_flag_recognized,
        test_short_selector_flag,
        test_warn_threshold_flag,
        test_critical_threshold_flag,
        test_include_system_flag,
        test_verbose_flag,
        test_invalid_format_rejected,
        test_invalid_threshold_rejected,
        test_threshold_validation,
        test_combined_flags,
        test_script_is_executable,
        test_shebang_present,
        test_json_format_structure,
        test_docstring_present,
    ]

    print(f"Running {len(tests)} tests for k8s_service_latency_monitor.py...")
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
