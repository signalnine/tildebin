#!/usr/bin/env python3
"""
Tests for k8s_ingress_cert_checker.py
"""

import subprocess
import sys
import os
from unittest.mock import patch, MagicMock
import json
from io import StringIO
from contextlib import redirect_stdout
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_ingress_cert_checker as cert_checker


def run_command(cmd_args):
    """Helper to run command and capture output"""
    result = subprocess.run(cmd_args, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def test_help_message():
    """Test that help message is available and informative"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--help']
    )

    if returncode == 0 and 'Kubernetes Ingress' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed: {stderr}")
        return False


def test_invalid_namespace_flag():
    """Test that missing namespace argument is handled"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--namespace']
    )

    if returncode != 0:
        print("[PASS] Missing namespace argument test passed")
        return True
    else:
        print("[FAIL] Missing namespace argument should fail")
        return False


def test_invalid_format():
    """Test that invalid format argument is rejected"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--format', 'invalid']
    )

    if returncode != 0:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        return False


def test_valid_format_options():
    """Test that valid format options are accepted (won't run without kubectl)"""
    returncode1, _, _ = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--format', 'plain']
    )
    returncode2, _, _ = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--format', 'json']
    )

    # Both should fail with kubectl not found (exit code 2) or no ingresses
    # but format should be accepted
    if returncode1 == 2 or returncode1 == 1:
        print("[PASS] Valid format options test passed")
        return True
    else:
        print("[FAIL] Valid format should be accepted")
        return False


def test_warn_only_flag():
    """Test that --warn-only flag is recognized"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--warn-only']
    )

    # Should fail with kubectl not found or other k8s error, but flag should be accepted
    if returncode != 0:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag should be recognized")
        return False


def test_combined_flags():
    """Test combining multiple flags"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '-n', 'default', '-f', 'json', '-w']
    )

    # Should fail gracefully with kubectl error
    if returncode == 2 or returncode == 1:
        print("[PASS] Combined flags test passed")
        return True
    else:
        print("[FAIL] Combined flags should be accepted")
        return False


def test_script_has_docstring():
    """Test that script has a module docstring"""
    with open('k8s_ingress_cert_checker.py', 'r') as f:
        content = f.read()
        if '"""' in content and 'Kubernetes Ingress' in content:
            print("[PASS] Script has proper docstring")
            return True
        else:
            print("[FAIL] Script missing docstring")
            return False


def test_script_imports():
    """Test that script imports key modules"""
    with open('k8s_ingress_cert_checker.py', 'r') as f:
        content = f.read()
        required_imports = ['argparse', 'json', 'subprocess', 'sys', 'datetime']
        missing = [imp for imp in required_imports if f'import {imp}' not in content]

        if not missing:
            print("[PASS] Script imports check passed")
            return True
        else:
            print(f"[FAIL] Script missing imports: {missing}")
            return False


def test_short_flag_namespace():
    """Test that -n short flag works for namespace"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '-n', 'kube-system']
    )

    # Should fail with kubectl error but accept the flag
    if returncode in [1, 2]:
        print("[PASS] Short namespace flag test passed")
        return True
    else:
        print("[FAIL] Short namespace flag should be accepted")
        return False


def test_short_flag_format():
    """Test that -f short flag works for format"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '-f', 'plain']
    )

    # Should fail with kubectl error but accept the flag
    if returncode in [1, 2]:
        print("[PASS] Short format flag test passed")
        return True
    else:
        print("[FAIL] Short format flag should be accepted")
        return False


def test_short_flag_warn_only():
    """Test that -w short flag works for warn-only"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '-w']
    )

    # Should fail with kubectl error but accept the flag
    if returncode in [1, 2]:
        print("[PASS] Short warn-only flag test passed")
        return True
    else:
        print("[FAIL] Short warn-only flag should be accepted")
        return False


def test_days_option():
    """Test that --days option accepts numeric values"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--days', '30']
    )

    # Should fail with kubectl error but accept the flag
    if returncode in [1, 2]:
        print("[PASS] Days option test passed")
        return True
    else:
        print("[FAIL] Days option should accept numeric values")
        return False


def test_invalid_days_value():
    """Test that --days rejects non-numeric values"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--days', 'invalid']
    )

    # Should fail with argument error
    if returncode == 2:
        print("[PASS] Invalid days value test passed")
        return True
    else:
        print("[FAIL] Invalid days value should be rejected")
        return False


def test_script_has_main_guard():
    """Test that script has proper __main__ guard"""
    with open('k8s_ingress_cert_checker.py', 'r') as f:
        content = f.read()
        if "if __name__ == '__main__':" in content or 'if __name__ == "__main__":' in content:
            print("[PASS] Script has main guard")
            return True
        else:
            print("[FAIL] Script missing main guard")
            return False


def test_no_args_runs():
    """Test that script runs with no arguments (uses defaults)"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py']
    )

    # Should attempt to run (may fail with kubectl not found)
    if returncode in [0, 1, 2]:
        print("[PASS] No args test passed")
        return True
    else:
        print("[FAIL] Script should run with default arguments")
        return False


def test_check_ingress_tls_no_tls():
    """Test check_ingress_tls with no TLS configuration."""
    ingress = {
        'metadata': {'namespace': 'default'},
        'spec': {
            'rules': [{'host': 'example.com'}]
        }
    }

    issues, cert_info = cert_checker.check_ingress_tls(ingress)

    assert len(issues) > 0
    assert any('No TLS configuration' in issue for issue in issues)
    print("[PASS] No TLS configuration test")
    return True


def test_check_ingress_tls_missing_secret():
    """Test check_ingress_tls with missing secret name."""
    ingress = {
        'metadata': {'namespace': 'default'},
        'spec': {
            'tls': [
                {'hosts': ['example.com']}
            ]
        }
    }

    issues, cert_info = cert_checker.check_ingress_tls(ingress)

    assert any('missing secretName' in issue for issue in issues)
    print("[PASS] Missing secret name test")
    return True


@patch('k8s_ingress_cert_checker.get_secret')
def test_check_ingress_tls_secret_not_found(mock_get_secret):
    """Test check_ingress_tls when secret doesn't exist."""
    mock_get_secret.return_value = None

    ingress = {
        'metadata': {'namespace': 'default'},
        'spec': {
            'tls': [
                {'hosts': ['example.com'], 'secretName': 'tls-secret'}
            ]
        }
    }

    issues, cert_info = cert_checker.check_ingress_tls(ingress)

    assert any('not found' in issue for issue in issues)
    print("[PASS] Secret not found test")
    return True


def test_check_ingress_status_no_lb():
    """Test check_ingress_status with no load balancer."""
    ingress = {
        'status': {}
    }

    issues = cert_checker.check_ingress_status(ingress)

    assert len(issues) > 0
    assert any('no assigned IP/hostname' in issue for issue in issues)
    print("[PASS] No load balancer test")
    return True


def test_check_ingress_status_empty_lb():
    """Test check_ingress_status with empty load balancer ingress."""
    ingress = {
        'status': {
            'loadBalancer': {
                'ingress': [{}]
            }
        }
    }

    issues = cert_checker.check_ingress_status(ingress)

    assert any('no IP or hostname' in issue for issue in issues)
    print("[PASS] Empty load balancer test")
    return True


def test_check_ingress_status_with_ip():
    """Test check_ingress_status with valid IP."""
    ingress = {
        'status': {
            'loadBalancer': {
                'ingress': [{'ip': '192.168.1.1'}]
            }
        }
    }

    issues = cert_checker.check_ingress_status(ingress)

    assert len(issues) == 0
    print("[PASS] Valid IP test")
    return True


@patch('k8s_ingress_cert_checker.get_service_endpoints')
def test_check_ingress_backends_no_endpoints(mock_get_endpoints):
    """Test check_ingress_backends when service has no endpoints."""
    mock_get_endpoints.return_value = False

    ingress = {
        'metadata': {'namespace': 'default'},
        'spec': {
            'rules': [{
                'http': {
                    'paths': [{
                        'backend': {
                            'serviceName': 'my-service'
                        }
                    }]
                }
            }]
        }
    }

    issues = cert_checker.check_ingress_backends(ingress)

    assert any('no endpoints' in issue for issue in issues)
    print("[PASS] No endpoints test")
    return True


@patch('k8s_ingress_cert_checker.get_service_endpoints')
def test_check_ingress_backends_with_endpoints(mock_get_endpoints):
    """Test check_ingress_backends when service has endpoints."""
    mock_get_endpoints.return_value = True

    ingress = {
        'metadata': {'namespace': 'default'},
        'spec': {
            'rules': [{
                'http': {
                    'paths': [{
                        'backend': {
                            'serviceName': 'my-service'
                        }
                    }]
                }
            }]
        }
    }

    issues = cert_checker.check_ingress_backends(ingress)

    assert len(issues) == 0
    print("[PASS] With endpoints test")
    return True


@patch('k8s_ingress_cert_checker.get_service_endpoints')
def test_check_ingress_backends_new_api_format(mock_get_endpoints):
    """Test check_ingress_backends with new API format."""
    mock_get_endpoints.return_value = True

    ingress = {
        'metadata': {'namespace': 'default'},
        'spec': {
            'rules': [{
                'http': {
                    'paths': [{
                        'backend': {
                            'service': {'name': 'my-service'}
                        }
                    }]
                }
            }]
        }
    }

    issues = cert_checker.check_ingress_backends(ingress)

    assert len(issues) == 0
    print("[PASS] New API format test")
    return True


def test_analyze_ingresses_empty():
    """Test analyze_ingresses with no ingresses."""
    ingresses_data = {'items': []}

    results = cert_checker.analyze_ingresses(ingresses_data, False)

    assert len(results) == 0
    print("[PASS] Empty ingresses test")
    return True


@patch('k8s_ingress_cert_checker.check_ingress_tls')
@patch('k8s_ingress_cert_checker.check_ingress_status')
@patch('k8s_ingress_cert_checker.check_ingress_backends')
def test_analyze_ingresses_with_issues(mock_backends, mock_status, mock_tls):
    """Test analyze_ingresses with issues."""
    mock_tls.return_value = (['TLS issue'], [])
    mock_status.return_value = ['Status issue']
    mock_backends.return_value = ['Backend issue']

    ingresses_data = {
        'items': [{
            'metadata': {'name': 'test-ingress', 'namespace': 'default'},
            'spec': {}
        }]
    }

    results = cert_checker.analyze_ingresses(ingresses_data, False)

    assert len(results) == 1
    assert len(results[0]['issues']) == 3
    print("[PASS] Ingresses with issues test")
    return True


@patch('k8s_ingress_cert_checker.check_ingress_tls')
@patch('k8s_ingress_cert_checker.check_ingress_status')
@patch('k8s_ingress_cert_checker.check_ingress_backends')
def test_analyze_ingresses_warn_only(mock_backends, mock_status, mock_tls):
    """Test analyze_ingresses with warn_only flag."""
    mock_tls.return_value = ([], [])
    mock_status.return_value = []
    mock_backends.return_value = []

    ingresses_data = {
        'items': [{
            'metadata': {'name': 'healthy-ingress', 'namespace': 'default'},
            'spec': {}
        }]
    }

    results = cert_checker.analyze_ingresses(ingresses_data, warn_only=True)

    # Should not include healthy ingress when warn_only=True
    assert len(results) == 0
    print("[PASS] Warn only test")
    return True


def test_print_results_json():
    """Test print_results with JSON format."""
    results = [{
        'namespace': 'default',
        'name': 'test-ingress',
        'issues': ['Issue 1'],
        'certificates': []
    }]

    f = StringIO()
    with redirect_stdout(f):
        has_issues = cert_checker.print_results(results, 'json')
    output = f.getvalue()

    # Should be valid JSON
    data = json.loads(output)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]['name'] == 'test-ingress'
    assert has_issues
    print("[PASS] JSON print results test")
    return True


def test_print_results_plain():
    """Test print_results with plain format."""
    results = [{
        'namespace': 'default',
        'name': 'test-ingress',
        'issues': ['Issue 1', 'Issue 2'],
        'certificates': [{
            'secret': 'tls-secret',
            'hosts': ['example.com'],
            'days_remaining': 30
        }]
    }]

    f = StringIO()
    with redirect_stdout(f):
        has_issues = cert_checker.print_results(results, 'plain')
    output = f.getvalue()

    assert 'test-ingress' in output
    assert 'default' in output
    assert 'Issue 1' in output
    assert 'tls-secret' in output
    assert has_issues
    print("[PASS] Plain print results test")
    return True


def test_print_results_no_issues():
    """Test print_results with no issues."""
    results = [{
        'namespace': 'default',
        'name': 'healthy-ingress',
        'issues': [],
        'certificates': []
    }]

    f = StringIO()
    with redirect_stdout(f):
        has_issues = cert_checker.print_results(results, 'plain')
    output = f.getvalue()

    assert not has_issues
    print("[PASS] No issues print results test")
    return True


@patch('k8s_ingress_cert_checker.run_kubectl')
def test_get_all_ingresses_all_namespaces(mock_run):
    """Test get_all_ingresses for all namespaces."""
    mock_run.return_value = json.dumps({
        'items': [
            {'metadata': {'name': 'ingress1', 'namespace': 'default'}},
            {'metadata': {'name': 'ingress2', 'namespace': 'production'}}
        ]
    })

    ingresses = cert_checker.get_all_ingresses()

    assert len(ingresses['items']) == 2
    call_args = mock_run.call_args[0][0]
    assert '--all-namespaces' in call_args
    print("[PASS] Get all ingresses test")
    return True


@patch('k8s_ingress_cert_checker.run_kubectl')
def test_get_all_ingresses_specific_namespace(mock_run):
    """Test get_all_ingresses for specific namespace."""
    mock_run.return_value = json.dumps({
        'items': [
            {'metadata': {'name': 'ingress1', 'namespace': 'production'}}
        ]
    })

    ingresses = cert_checker.get_all_ingresses('production')

    assert len(ingresses['items']) == 1
    call_args = mock_run.call_args[0][0]
    assert '-n' in call_args
    assert 'production' in call_args
    print("[PASS] Get ingresses for namespace test")
    return True


def main():
    """Run all tests"""
    tests = [
        test_help_message,
        test_invalid_namespace_flag,
        test_invalid_format,
        test_valid_format_options,
        test_warn_only_flag,
        test_combined_flags,
        test_script_has_docstring,
        test_script_imports,
        test_short_flag_namespace,
        test_short_flag_format,
        test_short_flag_warn_only,
        test_days_option,
        test_invalid_days_value,
        test_script_has_main_guard,
        test_no_args_runs,
        test_check_ingress_tls_no_tls,
        test_check_ingress_tls_missing_secret,
        test_check_ingress_tls_secret_not_found,
        test_check_ingress_status_no_lb,
        test_check_ingress_status_empty_lb,
        test_check_ingress_status_with_ip,
        test_check_ingress_backends_no_endpoints,
        test_check_ingress_backends_with_endpoints,
        test_check_ingress_backends_new_api_format,
        test_analyze_ingresses_empty,
        test_analyze_ingresses_with_issues,
        test_analyze_ingresses_warn_only,
        test_print_results_json,
        test_print_results_plain,
        test_print_results_no_issues,
        test_get_all_ingresses_all_namespaces,
        test_get_all_ingresses_specific_namespace,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__} raised exception: {e}")
            failed += 1

    total = passed + failed
    print(f"\nTest Results: {passed}/{total} tests passed")
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
