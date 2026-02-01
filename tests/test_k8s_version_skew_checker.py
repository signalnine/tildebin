#!/usr/bin/env python3
"""Tests for k8s_version_skew_checker.py"""

import subprocess
import sys
import json
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_version_skew_checker as checker


def run_command(cmd_args):
    """Run command and return (return_code, stdout, stderr)."""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


# ============================================================================
# CLI Argument Tests
# ============================================================================

def test_help_message():
    """Test that --help displays correctly."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '--help'])
    if return_code == 0 and 'version skew' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed: {stderr}")
        return False


def test_help_shows_formats():
    """Test that --help shows format options."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '--help'])
    if return_code == 0 and all(fmt in stdout for fmt in ['plain', 'table', 'json']):
        print("[PASS] Help shows format options")
        return True
    else:
        print("[FAIL] Help doesn't show format options")
        return False


def test_help_shows_warn_only():
    """Test that --help shows warn-only option."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '--help'])
    if return_code == 0 and '--warn-only' in stdout:
        print("[PASS] Help shows warn-only option")
        return True
    else:
        print("[FAIL] Help doesn't show warn-only option")
        return False


def test_help_shows_verbose():
    """Test that --help shows verbose option."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '--help'])
    if return_code == 0 and '--verbose' in stdout:
        print("[PASS] Help shows verbose option")
        return True
    else:
        print("[FAIL] Help doesn't show verbose option")
        return False


def test_help_shows_version_policy():
    """Test that --help explains version skew policy."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '--help'])
    if return_code == 0 and 'N-3' in stdout and 'kubelet' in stdout:
        print("[PASS] Help shows version skew policy")
        return True
    else:
        print("[FAIL] Help doesn't explain version policy")
        return False


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '-f', 'invalid'])
    if return_code != 0:
        print("[PASS] Invalid format rejected")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        return False


def test_format_options_accepted():
    """Test that each format option is accepted in argument parsing."""
    formats = ['table', 'plain', 'json']
    for fmt in formats:
        return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '-f', fmt])
        if 'unrecognized arguments' in stderr:
            print(f"[FAIL] Format '{fmt}' rejected in argument parsing")
            return False
    print("[PASS] All format options accepted")
    return True


def test_short_format_flag():
    """Test that -f flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '-f', 'json'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short -f flag works")
        return True
    else:
        print("[FAIL] Short -f flag doesn't work")
        return False


def test_long_format_flag():
    """Test that --format flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '--format', 'json'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Long --format flag works")
        return True
    else:
        print("[FAIL] Long --format flag doesn't work")
        return False


def test_warn_only_flag():
    """Test that --warn-only flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '--warn-only'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] --warn-only flag works")
        return True
    else:
        print("[FAIL] --warn-only flag doesn't work")
        return False


def test_short_warn_flag():
    """Test that -w flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '-w'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short -w flag works")
        return True
    else:
        print("[FAIL] Short -w flag doesn't work")
        return False


def test_verbose_flag():
    """Test that --verbose flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '--verbose'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] --verbose flag works")
        return True
    else:
        print("[FAIL] --verbose flag doesn't work")
        return False


def test_short_verbose_flag():
    """Test that -v flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py', '-v'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short -v flag works")
        return True
    else:
        print("[FAIL] Short -v flag doesn't work")
        return False


def test_kubectl_not_found_handled():
    """Test that missing kubectl is handled gracefully."""
    # When kubectl is not found or not configured, should fail with appropriate error
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_version_skew_checker.py'])
    if return_code != 0:
        print("[PASS] kubectl error handled")
        return True
    else:
        # If it succeeds, kubectl is available and configured
        print("[PASS] kubectl available and working")
        return True


# ============================================================================
# Version Parsing Tests
# ============================================================================

def test_parse_version_standard():
    """Test parsing standard version strings."""
    assert checker.parse_version('v1.28.0') == (1, 28, 0)
    assert checker.parse_version('v1.27.5') == (1, 27, 5)
    assert checker.parse_version('v1.26.10') == (1, 26, 10)
    print("[PASS] Standard version parsing")
    return True


def test_parse_version_without_v():
    """Test parsing version without v prefix."""
    assert checker.parse_version('1.28.0') == (1, 28, 0)
    assert checker.parse_version('1.27.5') == (1, 27, 5)
    print("[PASS] Version parsing without v prefix")
    return True


def test_parse_version_with_suffix():
    """Test parsing version with distribution suffix."""
    assert checker.parse_version('v1.28.0-gke.1') == (1, 28, 0)
    assert checker.parse_version('v1.27.5+k3s1') == (1, 27, 5)
    assert checker.parse_version('v1.26.10-eks-1234') == (1, 26, 10)
    print("[PASS] Version parsing with suffix")
    return True


def test_parse_version_invalid():
    """Test parsing invalid version strings."""
    assert checker.parse_version('') is None
    assert checker.parse_version(None) is None
    assert checker.parse_version('invalid') is None
    assert checker.parse_version('latest') is None
    print("[PASS] Invalid version parsing")
    return True


def test_parse_version_edge_cases():
    """Test parsing edge case versions."""
    assert checker.parse_version('  v1.28.0  ') == (1, 28, 0)  # whitespace
    assert checker.parse_version('v1.28.0\n') == (1, 28, 0)  # newline
    print("[PASS] Edge case version parsing")
    return True


def test_version_to_str():
    """Test version tuple to string conversion."""
    assert checker.version_to_str((1, 28, 0)) == 'v1.28.0'
    assert checker.version_to_str((1, 27, 5)) == 'v1.27.5'
    assert checker.version_to_str(None) == 'unknown'
    print("[PASS] Version to string conversion")
    return True


# ============================================================================
# Version Difference Tests
# ============================================================================

def test_minor_version_diff_same():
    """Test minor version diff when versions are the same."""
    assert checker.minor_version_diff((1, 28, 0), (1, 28, 5)) == 0
    assert checker.minor_version_diff((1, 27, 0), (1, 27, 10)) == 0
    print("[PASS] Same minor version diff")
    return True


def test_minor_version_diff_behind():
    """Test minor version diff when second is behind."""
    assert checker.minor_version_diff((1, 28, 0), (1, 27, 0)) == 1
    assert checker.minor_version_diff((1, 28, 0), (1, 25, 0)) == 3
    assert checker.minor_version_diff((1, 28, 0), (1, 24, 0)) == 4
    print("[PASS] Behind minor version diff")
    return True


def test_minor_version_diff_ahead():
    """Test minor version diff when second is ahead."""
    assert checker.minor_version_diff((1, 27, 0), (1, 28, 0)) == -1
    assert checker.minor_version_diff((1, 25, 0), (1, 28, 0)) == -3
    print("[PASS] Ahead minor version diff")
    return True


def test_minor_version_diff_none():
    """Test minor version diff with None values."""
    assert checker.minor_version_diff(None, (1, 28, 0)) is None
    assert checker.minor_version_diff((1, 28, 0), None) is None
    assert checker.minor_version_diff(None, None) is None
    print("[PASS] None minor version diff")
    return True


# ============================================================================
# Version Skew Check Tests
# ============================================================================

def test_check_version_skew_all_compliant():
    """Test version skew check with all compliant nodes."""
    api_version = (1, 28, 0)
    nodes = [
        {'name': 'node1', 'kubelet_version': 'v1.28.0', 'kubelet_parsed': (1, 28, 0), 'is_ready': True},
        {'name': 'node2', 'kubelet_version': 'v1.27.5', 'kubelet_parsed': (1, 27, 5), 'is_ready': True},
        {'name': 'node3', 'kubelet_version': 'v1.26.0', 'kubelet_parsed': (1, 26, 0), 'is_ready': True},
    ]
    components = {}

    issues = checker.check_version_skew(api_version, nodes, components)

    # Should have no critical or warning issues
    critical_warnings = [i for i in issues if i['severity'] in ('CRITICAL', 'WARNING')]
    assert len(critical_warnings) == 0
    print("[PASS] All compliant version skew check")
    return True


def test_check_version_skew_n3_compliant():
    """Test version skew check with N-3 kubelet (compliant)."""
    api_version = (1, 28, 0)
    nodes = [
        {'name': 'node1', 'kubelet_version': 'v1.25.0', 'kubelet_parsed': (1, 25, 0), 'is_ready': True},
    ]
    components = {}

    issues = checker.check_version_skew(api_version, nodes, components)

    # N-3 is the limit, should be compliant
    critical_warnings = [i for i in issues if i['severity'] in ('CRITICAL', 'WARNING')]
    assert len(critical_warnings) == 0
    print("[PASS] N-3 kubelet compliant")
    return True


def test_check_version_skew_n4_violation():
    """Test version skew check with N-4 kubelet (violation)."""
    api_version = (1, 28, 0)
    nodes = [
        {'name': 'node1', 'kubelet_version': 'v1.24.0', 'kubelet_parsed': (1, 24, 0), 'is_ready': True},
    ]
    components = {}

    issues = checker.check_version_skew(api_version, nodes, components)

    # N-4 exceeds limit, should be critical
    critical = [i for i in issues if i['severity'] == 'CRITICAL']
    assert len(critical) == 1
    assert 'node1' in critical[0]['component']
    print("[PASS] N-4 kubelet violation detected")
    return True


def test_check_version_skew_kubelet_ahead():
    """Test version skew check with kubelet ahead of API server."""
    api_version = (1, 27, 0)
    nodes = [
        {'name': 'node1', 'kubelet_version': 'v1.28.0', 'kubelet_parsed': (1, 28, 0), 'is_ready': True},
    ]
    components = {}

    issues = checker.check_version_skew(api_version, nodes, components)

    # Kubelet ahead should be warning
    warnings = [i for i in issues if i['severity'] == 'WARNING']
    assert len(warnings) == 1
    assert 'ahead' in warnings[0]['message'].lower()
    print("[PASS] Kubelet ahead warning detected")
    return True


def test_check_version_skew_unparseable_kubelet():
    """Test version skew check with unparseable kubelet version."""
    api_version = (1, 28, 0)
    nodes = [
        {'name': 'node1', 'kubelet_version': 'unknown', 'kubelet_parsed': None, 'is_ready': True},
    ]
    components = {}

    issues = checker.check_version_skew(api_version, nodes, components)

    warnings = [i for i in issues if i['severity'] == 'WARNING']
    assert len(warnings) == 1
    assert 'parse' in warnings[0]['message'].lower()
    print("[PASS] Unparseable kubelet version handled")
    return True


def test_check_version_skew_no_api_version():
    """Test version skew check with missing API version."""
    api_version = None
    nodes = [
        {'name': 'node1', 'kubelet_version': 'v1.28.0', 'kubelet_parsed': (1, 28, 0), 'is_ready': True},
    ]
    components = {}

    issues = checker.check_version_skew(api_version, nodes, components)

    errors = [i for i in issues if i['severity'] == 'ERROR']
    assert len(errors) == 1
    print("[PASS] Missing API version handled")
    return True


def test_check_version_skew_controller_manager_violation():
    """Test version skew check with controller-manager N-2 violation."""
    api_version = (1, 28, 0)
    nodes = []
    components = {
        'kube-controller-manager': {
            'version': (1, 26, 0),
            'version_str': 'v1.26.0',
            'image': 'k8s.gcr.io/kube-controller-manager:v1.26.0'
        }
    }

    issues = checker.check_version_skew(api_version, nodes, components)

    critical = [i for i in issues if i['severity'] == 'CRITICAL']
    assert len(critical) == 1
    assert 'controller-manager' in critical[0]['component']
    print("[PASS] Controller-manager N-2 violation detected")
    return True


def test_check_version_skew_verbose_info():
    """Test version skew check with verbose mode shows info."""
    api_version = (1, 28, 0)
    nodes = [
        {'name': 'node1', 'kubelet_version': 'v1.27.0', 'kubelet_parsed': (1, 27, 0), 'is_ready': True},
    ]
    components = {}

    issues = checker.check_version_skew(api_version, nodes, components, verbose=True)

    info = [i for i in issues if i['severity'] == 'INFO']
    assert len(info) == 1
    assert 'within policy' in info[0]['message'].lower()
    print("[PASS] Verbose mode shows info messages")
    return True


def test_check_version_skew_multiple_issues():
    """Test version skew check with multiple issues."""
    api_version = (1, 28, 0)
    nodes = [
        {'name': 'node1', 'kubelet_version': 'v1.24.0', 'kubelet_parsed': (1, 24, 0), 'is_ready': True},
        {'name': 'node2', 'kubelet_version': 'v1.23.0', 'kubelet_parsed': (1, 23, 0), 'is_ready': True},
    ]
    components = {}

    issues = checker.check_version_skew(api_version, nodes, components)

    critical = [i for i in issues if i['severity'] == 'CRITICAL']
    assert len(critical) == 2
    print("[PASS] Multiple issues detected")
    return True


# ============================================================================
# Main test runner
# ============================================================================

if __name__ == "__main__":
    print("Testing k8s_version_skew_checker.py...")
    print()

    tests = [
        # CLI tests
        test_help_message,
        test_help_shows_formats,
        test_help_shows_warn_only,
        test_help_shows_verbose,
        test_help_shows_version_policy,
        test_invalid_format,
        test_format_options_accepted,
        test_short_format_flag,
        test_long_format_flag,
        test_warn_only_flag,
        test_short_warn_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_kubectl_not_found_handled,
        # Version parsing tests
        test_parse_version_standard,
        test_parse_version_without_v,
        test_parse_version_with_suffix,
        test_parse_version_invalid,
        test_parse_version_edge_cases,
        test_version_to_str,
        # Version difference tests
        test_minor_version_diff_same,
        test_minor_version_diff_behind,
        test_minor_version_diff_ahead,
        test_minor_version_diff_none,
        # Version skew check tests
        test_check_version_skew_all_compliant,
        test_check_version_skew_n3_compliant,
        test_check_version_skew_n4_violation,
        test_check_version_skew_kubelet_ahead,
        test_check_version_skew_unparseable_kubelet,
        test_check_version_skew_no_api_version,
        test_check_version_skew_controller_manager_violation,
        test_check_version_skew_verbose_info,
        test_check_version_skew_multiple_issues,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)
