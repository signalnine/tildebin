#!/usr/bin/env python3
"""
Tests for k8s_kubeconfig_health_check.py

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
import tempfile


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
    return_code, stdout, stderr = run_command(['./k8s_kubeconfig_health_check.py', '--help'])

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'kubeconfig' in stdout.lower(), "Help should mention kubeconfig"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--no-connectivity' in stdout, "Help should document --no-connectivity flag"
    assert '--timeout' in stdout, "Help should document --timeout flag"
    assert '--warn-only' in stdout, "Help should document --warn-only flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("  Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized (even if kubectl not available)."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./k8s_kubeconfig_health_check.py', '--format', fmt, '--no-connectivity']
        )

        # Should either work (0, 1) or fail with dependency error (2)
        assert return_code in [0, 1, 2], f"Format {fmt} should be valid, got return code {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"
        assert 'unrecognized arguments' not in stderr.lower(), f"Format {fmt} should be recognized"

    print("  Format flag recognition test passed")
    return True


def test_kubeconfig_flag_recognized():
    """Test that --kubeconfig flag is recognized."""
    return_code, stdout, stderr = run_command([
        './k8s_kubeconfig_health_check.py',
        '--kubeconfig', '/nonexistent/kubeconfig',
        '--no-connectivity'
    ])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--kubeconfig should be recognized"

    print("  Kubeconfig flag recognition test passed")
    return True


def test_multiple_kubeconfig_flags():
    """Test that multiple --kubeconfig flags can be specified."""
    return_code, stdout, stderr = run_command([
        './k8s_kubeconfig_health_check.py',
        '--kubeconfig', '/path/one',
        '--kubeconfig', '/path/two',
        '--no-connectivity'
    ])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "Multiple --kubeconfig should be recognized"

    print("  Multiple kubeconfig flags test passed")
    return True


def test_no_connectivity_flag_recognized():
    """Test that --no-connectivity flag is recognized."""
    return_code, stdout, stderr = run_command([
        './k8s_kubeconfig_health_check.py', '--no-connectivity'
    ])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--no-connectivity should be recognized"

    print("  No-connectivity flag recognition test passed")
    return True


def test_timeout_flag_recognized():
    """Test that --timeout flag is recognized."""
    return_code, stdout, stderr = run_command([
        './k8s_kubeconfig_health_check.py', '--timeout', '10', '--no-connectivity'
    ])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--timeout should be recognized"

    print("  Timeout flag recognition test passed")
    return True


def test_warn_only_flag_recognized():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command([
        './k8s_kubeconfig_health_check.py', '--warn-only', '--no-connectivity'
    ])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("  Warn-only flag recognition test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command([
        './k8s_kubeconfig_health_check.py', '--format', 'invalid'
    ])

    # Should fail with argument parsing error
    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("  Invalid format rejection test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './k8s_kubeconfig_health_check.py',
        '--kubeconfig', '/nonexistent',
        '--format', 'json',
        '--no-connectivity',
        '--timeout', '10',
        '--warn-only'
    ])

    # Should not get argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("  Combined flags test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    import stat

    script_path = './k8s_kubeconfig_health_check.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("  Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./k8s_kubeconfig_health_check.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("  Shebang test passed")
    return True


def test_nonexistent_kubeconfig_handling():
    """Test that nonexistent kubeconfig files are handled gracefully."""
    return_code, stdout, stderr = run_command([
        './k8s_kubeconfig_health_check.py',
        '--kubeconfig', '/nonexistent/path/kubeconfig',
        '--no-connectivity'
    ])

    # Should report the issue (exit code 1) or handle gracefully
    # Should not crash with unhandled exception
    assert return_code in [0, 1, 2], f"Should handle nonexistent file, got {return_code}"

    # Output should mention the file not being found
    combined = stdout + stderr
    assert 'not found' in combined.lower() or 'nonexistent' in combined.lower() or \
           'does not exist' in combined.lower() or 'no such file' in combined.lower() or \
           return_code == 2, \
        "Should indicate file not found or report error"

    print("  Nonexistent kubeconfig handling test passed")
    return True


def test_json_format_structure():
    """Test that JSON output (if produced) is valid JSON with expected structure."""
    return_code, stdout, stderr = run_command([
        './k8s_kubeconfig_health_check.py',
        '--format', 'json',
        '--no-connectivity'
    ])

    # If we got JSON output, validate it
    if stdout.strip() and return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert isinstance(data, dict), "JSON output should be a dictionary"

            # Verify expected top-level fields
            expected_fields = ['timestamp', 'kubeconfigs', 'issues', 'warnings', 'healthy']
            for field in expected_fields:
                assert field in data, f"JSON output should contain '{field}' field"

            # Verify kubeconfigs is a list
            assert isinstance(data['kubeconfigs'], list), "kubeconfigs should be a list"

        except json.JSONDecodeError as e:
            assert False, f"JSON output should be valid: {e}"

    print("  JSON format structure test passed")
    return True


def test_exit_code_for_missing_kubectl():
    """Test that missing kubectl returns exit code 2."""
    # Run with PATH that doesn't include kubectl
    env = os.environ.copy()
    env['PATH'] = '/nonexistent'

    try:
        result = subprocess.run(
            [sys.executable, './k8s_kubeconfig_health_check.py', '--no-connectivity'],
            capture_output=True,
            text=True,
            timeout=5,
            env=env
        )

        # Should return 2 for missing dependency
        assert result.returncode == 2, f"Missing kubectl should exit with 2, got {result.returncode}"
        assert 'kubectl' in result.stderr.lower(), "Should mention kubectl in error message"

    except subprocess.TimeoutExpired:
        assert False, "Command should not timeout"

    print("  Exit code for missing kubectl test passed")
    return True


def test_table_format_output():
    """Test that table format produces reasonable output."""
    return_code, stdout, stderr = run_command([
        './k8s_kubeconfig_health_check.py',
        '--format', 'table',
        '--no-connectivity'
    ])

    # If we got output, it should look like a table
    if stdout.strip() and return_code in [0, 1]:
        # Tables typically have separators
        assert '+' in stdout or '-' in stdout or '|' in stdout, \
            "Table format should contain table-like characters"
        assert 'Context' in stdout or 'Health' in stdout or 'Kubeconfig' in stdout, \
            "Table should have headers"

    print("  Table format output test passed")
    return True


def test_with_temp_kubeconfig():
    """Test with a minimal valid kubeconfig file."""
    # Create a minimal kubeconfig
    kubeconfig_content = """
apiVersion: v1
kind: Config
clusters:
- name: test-cluster
  cluster:
    server: https://127.0.0.1:6443
contexts:
- name: test-context
  context:
    cluster: test-cluster
    user: test-user
users:
- name: test-user
  user:
    token: fake-token
current-context: test-context
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(kubeconfig_content)
        temp_path = f.name

    try:
        return_code, stdout, stderr = run_command([
            './k8s_kubeconfig_health_check.py',
            '--kubeconfig', temp_path,
            '--no-connectivity',
            '--format', 'json'
        ])

        # Should parse the config (may fail connectivity but should parse)
        if stdout.strip():
            try:
                data = json.loads(stdout)
                # Should have found our context
                assert len(data['kubeconfigs']) > 0, "Should have parsed kubeconfig"
                contexts = data['kubeconfigs'][0].get('contexts', [])
                context_names = [c['name'] for c in contexts]
                assert 'test-context' in context_names, "Should have found test-context"
            except json.JSONDecodeError:
                pass  # OK if kubectl wasn't available

    finally:
        os.unlink(temp_path)

    print("  Temp kubeconfig test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_kubeconfig_flag_recognized,
        test_multiple_kubeconfig_flags,
        test_no_connectivity_flag_recognized,
        test_timeout_flag_recognized,
        test_warn_only_flag_recognized,
        test_invalid_format_rejected,
        test_combined_flags,
        test_script_is_executable,
        test_shebang_present,
        test_nonexistent_kubeconfig_handling,
        test_json_format_structure,
        test_exit_code_for_missing_kubectl,
        test_table_format_output,
        test_with_temp_kubeconfig,
    ]

    print(f"Running {len(tests)} tests for k8s_kubeconfig_health_check.py...")
    print()

    failed = []
    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"  {test.__name__} failed: {e}")
            failed.append(test.__name__)
        except Exception as e:
            print(f"  {test.__name__} error: {e}")
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
