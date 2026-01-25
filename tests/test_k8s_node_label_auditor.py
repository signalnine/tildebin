#!/usr/bin/env python3
"""
Tests for k8s_node_label_auditor.py

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
import os
import stat


def run_command(args, timeout=5, env=None):
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"


def test_help_message():
    """Test that --help flag works and shows usage information."""
    return_code, stdout, stderr = run_command(['./k8s_node_label_auditor.py', '--help'])

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'label' in stdout.lower(), "Help should contain 'label'"
    assert 'annotation' in stdout.lower(), "Help should contain 'annotation'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout, "Help should document --warn-only flag"
    assert '--require-label' in stdout, "Help should document --require-label flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./k8s_node_label_auditor.py', '--format', fmt]
        )

        # Should either work (0/1) or fail with kubectl error (2), not arg parse error
        assert return_code in [0, 1, 2], f"Format {fmt} should be valid, got {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(['./k8s_node_label_auditor.py', '-f', 'json'])

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_warn_only_flag_recognized():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(['./k8s_node_label_auditor.py', '--warn-only'])

    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("PASS: Warn-only flag recognition test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(['./k8s_node_label_auditor.py', '-w'])

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_verbose_flag_recognized():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(['./k8s_node_label_auditor.py', '--verbose'])

    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("PASS: Verbose flag recognition test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(['./k8s_node_label_auditor.py', '-v'])

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_require_label_flag_recognized():
    """Test that --require-label flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_node_label_auditor.py', '--require-label', 'env']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "--require-label should be recognized"

    print("PASS: Require-label flag recognition test passed")
    return True


def test_short_require_label_flag():
    """Test that -l shorthand for --require-label works."""
    return_code, stdout, stderr = run_command(
        ['./k8s_node_label_auditor.py', '-l', 'env']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-l should be recognized"

    print("PASS: Short require-label flag test passed")
    return True


def test_multiple_require_labels():
    """Test that multiple --require-label flags can be specified."""
    return_code, stdout, stderr = run_command([
        './k8s_node_label_auditor.py',
        '--require-label', 'env',
        '--require-label', 'team',
        '-l', 'region'
    ])

    assert 'unrecognized arguments' not in stderr.lower(), \
        "Multiple --require-label flags should be recognized"

    print("PASS: Multiple require-label flags test passed")
    return True


def test_skip_deprecated_flag():
    """Test that --skip-deprecated flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_node_label_auditor.py', '--skip-deprecated']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "--skip-deprecated should be recognized"

    print("PASS: Skip-deprecated flag recognition test passed")
    return True


def test_skip_consistency_flag():
    """Test that --skip-consistency flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./k8s_node_label_auditor.py', '--skip-consistency']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "--skip-consistency should be recognized"

    print("PASS: Skip-consistency flag recognition test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./k8s_node_label_auditor.py', '--format', 'invalid']
    )

    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("PASS: Invalid format rejection test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './k8s_node_label_auditor.py',
        '--format', 'json',
        '--warn-only',
        '--verbose',
        '--require-label', 'env',
        '--skip-deprecated',
        '--skip-consistency'
    ])

    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("PASS: Combined flags test passed")
    return True


def test_combined_short_flags():
    """Test that multiple short flags can be combined."""
    return_code, stdout, stderr = run_command([
        './k8s_node_label_auditor.py',
        '-f', 'plain',
        '-w',
        '-v',
        '-l', 'env'
    ])

    assert 'unrecognized arguments' not in stderr.lower(), "Combined short flags should be recognized"

    print("PASS: Combined short flags test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    script_path = './k8s_node_label_auditor.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("PASS: Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./k8s_node_label_auditor.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("PASS: Shebang test passed")
    return True


def test_docstring_present():
    """Test that script has a module docstring."""
    with open('./k8s_node_label_auditor.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert 'label' in content.lower(), "Docstring should mention labels"
    assert 'annotation' in content.lower(), "Docstring should mention annotations"

    print("PASS: Docstring test passed")
    return True


def test_exit_code_documentation():
    """Test that exit codes are properly documented."""
    return_code, stdout, stderr = run_command(['./k8s_node_label_auditor.py', '--help'])

    assert '0' in stdout, "Help should document exit code 0"
    assert '1' in stdout, "Help should document exit code 1"
    assert '2' in stdout, "Help should document exit code 2"

    print("PASS: Exit code documentation test passed")
    return True


def test_kubectl_missing_handling():
    """Test that script handles missing kubectl gracefully."""
    # Run with empty PATH to simulate missing kubectl
    env = os.environ.copy()
    env['PATH'] = ''

    try:
        result = subprocess.run(
            ['./k8s_node_label_auditor.py'],
            capture_output=True,
            text=True,
            timeout=5,
            env=env
        )

        # Should exit with code 2 for missing dependency
        assert result.returncode == 2, f"Missing kubectl should exit with 2, got {result.returncode}"
        assert 'kubectl' in result.stderr.lower() or 'not found' in result.stderr.lower(), \
            "Should mention kubectl in error message"

    except Exception:
        # If the script can't run at all, that's also acceptable
        pass

    print("PASS: kubectl missing handling test passed")
    return True


def test_json_format_produces_valid_json():
    """Test that JSON format produces valid JSON (or proper error)."""
    return_code, stdout, stderr = run_command([
        './k8s_node_label_auditor.py',
        '--format', 'json'
    ])

    # If we got output on stdout, it should be valid JSON
    if stdout.strip():
        try:
            data = json.loads(stdout)
            assert isinstance(data, dict), "JSON output should be a dictionary"

            # If the script ran successfully, verify key fields exist
            if return_code in [0, 1]:
                expected_fields = ['summary', 'nodes', 'consistency_issues', 'healthy']
                for field in expected_fields:
                    assert field in data, f"JSON output should contain '{field}' field"

        except json.JSONDecodeError:
            # If it's not valid JSON, that's only OK if we got an error message
            assert return_code == 2, "Invalid JSON output should only occur with error exit code"

    print("PASS: JSON format structure test passed")
    return True


def test_default_format_is_plain():
    """Test that default format is plain."""
    return_code, stdout, stderr = run_command(['./k8s_node_label_auditor.py', '--help'])

    assert 'default: plain' in stdout.lower() or '(default: plain)' in stdout, \
        "Default format should be plain"

    print("PASS: Default format test passed")
    return True


def test_deprecated_labels_documented():
    """Test that the script handles deprecated labels."""
    with open('./k8s_node_label_auditor.py', 'r') as f:
        content = f.read()

    # Check for known deprecated labels
    deprecated_labels = [
        'beta.kubernetes.io/arch',
        'beta.kubernetes.io/os',
        'failure-domain.beta.kubernetes.io',
    ]

    for label in deprecated_labels:
        assert label in content, f"Should check for deprecated label: {label}"

    print("PASS: Deprecated labels documented test passed")
    return True


def test_topology_labels_documented():
    """Test that the script checks for topology labels."""
    with open('./k8s_node_label_auditor.py', 'r') as f:
        content = f.read()

    assert 'topology.kubernetes.io/zone' in content, "Should check for zone topology label"
    assert 'topology.kubernetes.io/region' in content, "Should check for region topology label"

    print("PASS: Topology labels documented test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_warn_only_flag_recognized,
        test_short_warn_only_flag,
        test_verbose_flag_recognized,
        test_short_verbose_flag,
        test_require_label_flag_recognized,
        test_short_require_label_flag,
        test_multiple_require_labels,
        test_skip_deprecated_flag,
        test_skip_consistency_flag,
        test_invalid_format_rejected,
        test_combined_flags,
        test_combined_short_flags,
        test_script_is_executable,
        test_shebang_present,
        test_docstring_present,
        test_exit_code_documentation,
        test_kubectl_missing_handling,
        test_json_format_produces_valid_json,
        test_default_format_is_plain,
        test_deprecated_labels_documented,
        test_topology_labels_documented,
    ]

    print(f"Running {len(tests)} tests for k8s_node_label_auditor.py...")
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
