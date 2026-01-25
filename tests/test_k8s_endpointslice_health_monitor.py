#!/usr/bin/env python3
"""
Tests for k8s_endpointslice_health_monitor.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and core functions.
"""

import subprocess
import sys
import unittest
from unittest.mock import patch
import json
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_endpointslice_health_monitor as eps_monitor


def run_command(cmd_args, input_data=None):
    """Run the k8s_endpointslice_health_monitor.py script with given arguments."""
    cmd = [sys.executable, 'k8s_endpointslice_health_monitor.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sEndpointSliceHealthMonitor(unittest.TestCase):
    """Test cases for k8s_endpointslice_health_monitor.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('EndpointSlice', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('EndpointSlice', stdout)

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Either exits 2 (no kubectl) or 1 (kubectl error)
        self.assertIn(returncode, [1, 2])

    def test_format_option_json(self):
        """Test --format json option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [1, 2])

    def test_format_option_short(self):
        """Test -f short option works."""
        returncode, stdout, stderr = run_command(['-f', 'json'])
        self.assertIn(returncode, [1, 2])

    def test_invalid_format(self):
        """Test that invalid format values are rejected."""
        returncode, stdout, stderr = run_command(['--format', 'invalid'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid choice', stderr)

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'default'])
        self.assertIn(returncode, [1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'kube-system'])
        self.assertIn(returncode, [1, 2])

    def test_warn_only_option(self):
        """Test --warn-only option is accepted."""
        returncode, stdout, stderr = run_command(['--warn-only'])
        self.assertIn(returncode, [1, 2])

    def test_warn_only_short(self):
        """Test -w short option works."""
        returncode, stdout, stderr = run_command(['-w'])
        self.assertIn(returncode, [1, 2])

    def test_include_headless_option(self):
        """Test --include-headless option is accepted."""
        returncode, stdout, stderr = run_command(['--include-headless'])
        self.assertIn(returncode, [1, 2])

    def test_frag_threshold_option(self):
        """Test --frag-threshold option is accepted."""
        returncode, stdout, stderr = run_command(['--frag-threshold', '5'])
        self.assertIn(returncode, [1, 2])

    def test_skip_coverage_check_option(self):
        """Test --skip-coverage-check option is accepted."""
        returncode, stdout, stderr = run_command(['--skip-coverage-check'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-n', 'default'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command([
            '--format', 'plain',
            '--warn-only',
            '--namespace', 'kube-system',
            '--frag-threshold', '15',
            '--include-headless'
        ])
        self.assertIn(returncode, [1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        returncode, stdout, stderr = run_command([])
        # Should exit with error code 1 or 2
        self.assertNotEqual(returncode, 0)
        if returncode == 2:
            self.assertIn('kubectl', stderr.lower())

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (will fail without kubectl, but args are valid)
        self.assertIn(returncode, [1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_endpointslice_health_monitor.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_endpointslice_health_monitor.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('EndpointSlice', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_endpointslice_health_monitor.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)


class TestAnalyzeEndpointSlice(unittest.TestCase):
    """Test analyze_endpointslice function."""

    def test_healthy_endpointslice(self):
        """Test analysis of healthy EndpointSlice with all ready endpoints."""
        eps = {
            'metadata': {
                'name': 'my-service-abc123',
                'namespace': 'default',
                'labels': {'kubernetes.io/service-name': 'my-service'}
            },
            'endpoints': [
                {
                    'addresses': ['10.0.0.1'],
                    'conditions': {'ready': True, 'serving': True, 'terminating': False}
                },
                {
                    'addresses': ['10.0.0.2'],
                    'conditions': {'ready': True, 'serving': True, 'terminating': False}
                }
            ],
            'ports': [{'name': 'http', 'port': 80, 'protocol': 'TCP'}]
        }

        result = eps_monitor.analyze_endpointslice(eps)

        self.assertTrue(result['healthy'])
        self.assertEqual(result['ready'], 2)
        self.assertEqual(result['not_ready'], 0)
        self.assertEqual(result['total'], 2)
        self.assertEqual(result['service'], 'my-service')
        self.assertEqual(len(result['issues']), 0)

    def test_no_endpoints(self):
        """Test EndpointSlice with no endpoints."""
        eps = {
            'metadata': {
                'name': 'my-service-abc123',
                'namespace': 'default',
                'labels': {'kubernetes.io/service-name': 'my-service'}
            },
            'endpoints': [],
            'ports': [{'name': 'http', 'port': 80}]
        }

        result = eps_monitor.analyze_endpointslice(eps)

        self.assertFalse(result['healthy'])
        self.assertEqual(result['total'], 0)
        self.assertTrue(any('No endpoints' in issue for issue in result['issues']))

    def test_no_ready_endpoints(self):
        """Test EndpointSlice with all not-ready endpoints."""
        eps = {
            'metadata': {
                'name': 'my-service-abc123',
                'namespace': 'default',
                'labels': {'kubernetes.io/service-name': 'my-service'}
            },
            'endpoints': [
                {
                    'addresses': ['10.0.0.1'],
                    'conditions': {'ready': False, 'serving': False, 'terminating': False}
                },
                {
                    'addresses': ['10.0.0.2'],
                    'conditions': {'ready': False, 'serving': False, 'terminating': False}
                }
            ],
            'ports': [{'name': 'http', 'port': 80}]
        }

        result = eps_monitor.analyze_endpointslice(eps)

        self.assertFalse(result['healthy'])
        self.assertEqual(result['ready'], 0)
        self.assertEqual(result['not_ready'], 2)
        self.assertTrue(any('No ready endpoints' in issue for issue in result['issues']))

    def test_all_terminating_endpoints(self):
        """Test EndpointSlice with all terminating endpoints."""
        eps = {
            'metadata': {
                'name': 'my-service-abc123',
                'namespace': 'default',
                'labels': {'kubernetes.io/service-name': 'my-service'}
            },
            'endpoints': [
                {
                    'addresses': ['10.0.0.1'],
                    'conditions': {'ready': False, 'serving': False, 'terminating': True}
                },
                {
                    'addresses': ['10.0.0.2'],
                    'conditions': {'ready': False, 'serving': False, 'terminating': True}
                }
            ],
            'ports': [{'name': 'http', 'port': 80}]
        }

        result = eps_monitor.analyze_endpointslice(eps)

        self.assertFalse(result['healthy'])
        self.assertEqual(result['terminating'], 2)
        self.assertTrue(any('terminating' in issue for issue in result['issues']))

    def test_high_not_ready_ratio(self):
        """Test EndpointSlice with high not-ready ratio (>50%)."""
        eps = {
            'metadata': {
                'name': 'my-service-abc123',
                'namespace': 'default',
                'labels': {'kubernetes.io/service-name': 'my-service'}
            },
            'endpoints': [
                {'addresses': ['10.0.0.1'], 'conditions': {'ready': True}},
                {'addresses': ['10.0.0.2'], 'conditions': {'ready': False}},
                {'addresses': ['10.0.0.3'], 'conditions': {'ready': False}},
                {'addresses': ['10.0.0.4'], 'conditions': {'ready': False}}
            ],
            'ports': [{'name': 'http', 'port': 80}]
        }

        result = eps_monitor.analyze_endpointslice(eps)

        self.assertFalse(result['healthy'])
        self.assertEqual(result['ready'], 1)
        self.assertEqual(result['not_ready'], 3)
        self.assertTrue(any('not-ready ratio' in issue.lower() for issue in result['issues']))

    def test_some_not_ready_low_ratio(self):
        """Test EndpointSlice with some not-ready but low ratio."""
        eps = {
            'metadata': {
                'name': 'my-service-abc123',
                'namespace': 'default',
                'labels': {'kubernetes.io/service-name': 'my-service'}
            },
            'endpoints': [
                {'addresses': ['10.0.0.1'], 'conditions': {'ready': True}},
                {'addresses': ['10.0.0.2'], 'conditions': {'ready': True}},
                {'addresses': ['10.0.0.3'], 'conditions': {'ready': True}},
                {'addresses': ['10.0.0.4'], 'conditions': {'ready': True}},
                {'addresses': ['10.0.0.5'], 'conditions': {'ready': False}}
            ],
            'ports': [{'name': 'http', 'port': 80}]
        }

        result = eps_monitor.analyze_endpointslice(eps)

        # Should be healthy but with informational issue
        self.assertTrue(result['healthy'])
        self.assertEqual(result['ready'], 4)
        self.assertEqual(result['not_ready'], 1)

    def test_missing_ports(self):
        """Test EndpointSlice with no ports defined."""
        eps = {
            'metadata': {
                'name': 'my-service-abc123',
                'namespace': 'default',
                'labels': {'kubernetes.io/service-name': 'my-service'}
            },
            'endpoints': [
                {'addresses': ['10.0.0.1'], 'conditions': {'ready': True}}
            ],
            'ports': []
        }

        result = eps_monitor.analyze_endpointslice(eps)

        self.assertTrue(any('No ports' in issue for issue in result['issues']))

    def test_some_terminating_endpoints(self):
        """Test EndpointSlice with some (not all) terminating endpoints."""
        eps = {
            'metadata': {
                'name': 'my-service-abc123',
                'namespace': 'default',
                'labels': {'kubernetes.io/service-name': 'my-service'}
            },
            'endpoints': [
                {'addresses': ['10.0.0.1'], 'conditions': {'ready': True, 'terminating': False}},
                {'addresses': ['10.0.0.2'], 'conditions': {'ready': False, 'terminating': True}}
            ],
            'ports': [{'name': 'http', 'port': 80}]
        }

        result = eps_monitor.analyze_endpointslice(eps)

        self.assertEqual(result['ready'], 1)
        self.assertEqual(result['terminating'], 1)
        self.assertTrue(any('terminating' in issue for issue in result['issues']))


class TestCheckServiceCoverage(unittest.TestCase):
    """Test check_service_coverage function."""

    def test_service_with_endpointslice(self):
        """Test that service with EndpointSlice is not flagged."""
        services = {
            'items': [{
                'metadata': {'name': 'my-service', 'namespace': 'default'},
                'spec': {
                    'type': 'ClusterIP',
                    'clusterIP': '10.96.0.1',
                    'selector': {'app': 'myapp'}
                }
            }]
        }
        endpointslices_by_service = {
            'default/my-service': [{'name': 'my-service-abc', 'total': 2}]
        }

        missing = eps_monitor.check_service_coverage(
            services, endpointslices_by_service, exclude_headless=True
        )

        self.assertEqual(len(missing), 0)

    def test_service_without_endpointslice(self):
        """Test that service without EndpointSlice is flagged."""
        services = {
            'items': [{
                'metadata': {'name': 'my-service', 'namespace': 'default'},
                'spec': {
                    'type': 'ClusterIP',
                    'clusterIP': '10.96.0.1',
                    'selector': {'app': 'myapp'}
                }
            }]
        }
        endpointslices_by_service = {}

        missing = eps_monitor.check_service_coverage(
            services, endpointslices_by_service, exclude_headless=True
        )

        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]['name'], 'my-service')

    def test_externalname_service_excluded(self):
        """Test that ExternalName services are excluded."""
        services = {
            'items': [{
                'metadata': {'name': 'external-service', 'namespace': 'default'},
                'spec': {
                    'type': 'ExternalName',
                    'externalName': 'example.com'
                }
            }]
        }
        endpointslices_by_service = {}

        missing = eps_monitor.check_service_coverage(
            services, endpointslices_by_service, exclude_headless=True
        )

        self.assertEqual(len(missing), 0)

    def test_headless_service_excluded(self):
        """Test that headless services are excluded by default."""
        services = {
            'items': [{
                'metadata': {'name': 'headless-service', 'namespace': 'default'},
                'spec': {
                    'type': 'ClusterIP',
                    'clusterIP': 'None',
                    'selector': {'app': 'myapp'}
                }
            }]
        }
        endpointslices_by_service = {}

        missing = eps_monitor.check_service_coverage(
            services, endpointslices_by_service, exclude_headless=True
        )

        self.assertEqual(len(missing), 0)

    def test_headless_service_included(self):
        """Test that headless services are included when flag is set."""
        services = {
            'items': [{
                'metadata': {'name': 'headless-service', 'namespace': 'default'},
                'spec': {
                    'type': 'ClusterIP',
                    'clusterIP': 'None',
                    'selector': {'app': 'myapp'}
                }
            }]
        }
        endpointslices_by_service = {}

        missing = eps_monitor.check_service_coverage(
            services, endpointslices_by_service, exclude_headless=False
        )

        self.assertEqual(len(missing), 1)

    def test_service_without_selector_excluded(self):
        """Test that services without selector are excluded."""
        services = {
            'items': [{
                'metadata': {'name': 'manual-service', 'namespace': 'default'},
                'spec': {
                    'type': 'ClusterIP',
                    'clusterIP': '10.96.0.1'
                    # No selector - manually managed endpoints
                }
            }]
        }
        endpointslices_by_service = {}

        missing = eps_monitor.check_service_coverage(
            services, endpointslices_by_service, exclude_headless=True
        )

        self.assertEqual(len(missing), 0)


class TestCheckEndpointSliceFragmentation(unittest.TestCase):
    """Test check_endpointslice_fragmentation function."""

    def test_no_fragmentation(self):
        """Test service with low EndpointSlice count."""
        endpointslices_by_service = {
            'default/my-service': [
                {'name': 'slice-1', 'total': 50},
                {'name': 'slice-2', 'total': 50}
            ]
        }

        fragmented = eps_monitor.check_endpointslice_fragmentation(
            endpointslices_by_service, threshold=10
        )

        self.assertEqual(len(fragmented), 0)

    def test_high_fragmentation(self):
        """Test service with high EndpointSlice count."""
        slices = [{'name': f'slice-{i}', 'total': 10} for i in range(15)]
        endpointslices_by_service = {
            'default/my-service': slices
        }

        fragmented = eps_monitor.check_endpointslice_fragmentation(
            endpointslices_by_service, threshold=10
        )

        self.assertEqual(len(fragmented), 1)
        self.assertEqual(fragmented[0]['name'], 'my-service')
        self.assertEqual(fragmented[0]['slice_count'], 15)
        self.assertEqual(fragmented[0]['total_endpoints'], 150)

    def test_custom_threshold(self):
        """Test fragmentation with custom threshold."""
        slices = [{'name': f'slice-{i}', 'total': 10} for i in range(6)]
        endpointslices_by_service = {
            'default/my-service': slices
        }

        # Should not be flagged with threshold 10
        fragmented = eps_monitor.check_endpointslice_fragmentation(
            endpointslices_by_service, threshold=10
        )
        self.assertEqual(len(fragmented), 0)

        # Should be flagged with threshold 5
        fragmented = eps_monitor.check_endpointslice_fragmentation(
            endpointslices_by_service, threshold=5
        )
        self.assertEqual(len(fragmented), 1)


class TestPrintResults(unittest.TestCase):
    """Test print_results function."""

    def test_print_results_json_format(self):
        """Test print_results with JSON format."""
        results = [{
            'name': 'my-service-abc',
            'namespace': 'default',
            'service': 'my-service',
            'ready': 2,
            'not_ready': 0,
            'terminating': 0,
            'unknown': 0,
            'total': 2,
            'ports': 1,
            'healthy': True,
            'issues': []
        }]
        missing_services = []
        fragmented = []

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = eps_monitor.print_results(
                results, missing_services, fragmented, 'json', False
            )

        output = f.getvalue()
        self.assertFalse(has_issues)

        # Verify JSON is valid
        data = json.loads(output)
        self.assertIn('endpointslices', data)
        self.assertIn('missing_services', data)
        self.assertIn('fragmented_services', data)
        self.assertIn('summary', data)

    def test_print_results_plain_format(self):
        """Test print_results with plain format."""
        results = [{
            'name': 'my-service-abc',
            'namespace': 'default',
            'service': 'my-service',
            'ready': 2,
            'not_ready': 0,
            'terminating': 0,
            'unknown': 0,
            'total': 2,
            'ports': 1,
            'healthy': True,
            'issues': []
        }]
        missing_services = []
        fragmented = []

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = eps_monitor.print_results(
                results, missing_services, fragmented, 'plain', False
            )

        output = f.getvalue()
        self.assertIn('my-service-abc', output)
        self.assertIn('EndpointSlice', output)

    def test_print_results_with_issues(self):
        """Test print_results with unhealthy EndpointSlice."""
        results = [{
            'name': 'my-service-abc',
            'namespace': 'default',
            'service': 'my-service',
            'ready': 0,
            'not_ready': 2,
            'terminating': 0,
            'unknown': 0,
            'total': 2,
            'ports': 1,
            'healthy': False,
            'issues': ['No ready endpoints (2 not ready)']
        }]
        missing_services = []
        fragmented = []

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = eps_monitor.print_results(
                results, missing_services, fragmented, 'json', False
            )

        self.assertTrue(has_issues)
        data = json.loads(f.getvalue())
        self.assertEqual(data['summary']['unhealthy_slices'], 1)

    def test_print_results_warn_only(self):
        """Test print_results with warn_only flag."""
        results = [
            {
                'name': 'healthy-slice',
                'namespace': 'default',
                'service': 'healthy-svc',
                'ready': 2,
                'not_ready': 0,
                'terminating': 0,
                'unknown': 0,
                'total': 2,
                'ports': 1,
                'healthy': True,
                'issues': []
            },
            {
                'name': 'unhealthy-slice',
                'namespace': 'default',
                'service': 'unhealthy-svc',
                'ready': 0,
                'not_ready': 2,
                'terminating': 0,
                'unknown': 0,
                'total': 2,
                'ports': 1,
                'healthy': False,
                'issues': ['No ready endpoints']
            }
        ]
        missing_services = []
        fragmented = []

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = eps_monitor.print_results(
                results, missing_services, fragmented, 'json', True
            )

        data = json.loads(f.getvalue())
        # Only unhealthy slice should be in output
        self.assertEqual(len(data['endpointslices']), 1)
        self.assertEqual(data['endpointslices'][0]['name'], 'unhealthy-slice')

    def test_print_results_with_missing_services(self):
        """Test print_results with missing services."""
        results = []
        missing_services = [
            {'name': 'orphan-svc', 'namespace': 'default', 'type': 'ClusterIP', 'selector': {'app': 'test'}}
        ]
        fragmented = []

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = eps_monitor.print_results(
                results, missing_services, fragmented, 'json', False
            )

        self.assertTrue(has_issues)
        data = json.loads(f.getvalue())
        self.assertEqual(len(data['missing_services']), 1)


class TestGetEndpointSlices(unittest.TestCase):
    """Test get_endpointslices function with mocking."""

    @patch('k8s_endpointslice_health_monitor.run_kubectl')
    def test_get_endpointslices_all_namespaces(self, mock_run):
        """Test getting EndpointSlices from all namespaces."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'eps1', 'namespace': 'default'}},
                {'metadata': {'name': 'eps2', 'namespace': 'kube-system'}}
            ]
        })

        eps = eps_monitor.get_endpointslices()

        self.assertEqual(len(eps['items']), 2)
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        self.assertIn('--all-namespaces', call_args)

    @patch('k8s_endpointslice_health_monitor.run_kubectl')
    def test_get_endpointslices_specific_namespace(self, mock_run):
        """Test getting EndpointSlices from specific namespace."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'eps1', 'namespace': 'production'}}
            ]
        })

        eps = eps_monitor.get_endpointslices('production')

        self.assertEqual(len(eps['items']), 1)
        call_args = mock_run.call_args[0][0]
        self.assertIn('-n', call_args)
        self.assertIn('production', call_args)


class TestGetServices(unittest.TestCase):
    """Test get_services function with mocking."""

    @patch('k8s_endpointslice_health_monitor.run_kubectl')
    def test_get_services_all_namespaces(self, mock_run):
        """Test getting services from all namespaces."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'svc1', 'namespace': 'default'}}
            ]
        })

        services = eps_monitor.get_services()

        self.assertEqual(len(services['items']), 1)
        call_args = mock_run.call_args[0][0]
        self.assertIn('--all-namespaces', call_args)


if __name__ == '__main__':
    # Run tests with custom runner to report results in expected format
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)

    # Print results in expected format
    passed = result.testsRun - len(result.failures) - len(result.errors)
    print(f"\nTest Results: {passed}/{result.testsRun} tests passed")

    sys.exit(0 if result.wasSuccessful() else 1)
