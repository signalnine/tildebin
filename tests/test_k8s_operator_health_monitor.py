#!/usr/bin/env python3
"""
Tests for k8s_operator_health_monitor.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and core functions.
"""

import subprocess
import sys
import unittest
from unittest.mock import patch, MagicMock
import json
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_operator_health_monitor as op_health


def run_command(cmd_args, input_data=None):
    """Run the k8s_operator_health_monitor.py script with given arguments."""
    cmd = [sys.executable, 'k8s_operator_health_monitor.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sOperatorHealthMonitor(unittest.TestCase):
    """Test cases for k8s_operator_health_monitor.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Operator', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('--list-known', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('Operator', stdout)

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Either exits 2 (no kubectl) or 1 (kubectl error) or 0 (success)
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_json(self):
        """Test --format json option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_short(self):
        """Test -f short option works."""
        returncode, stdout, stderr = run_command(['-f', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_invalid_format(self):
        """Test that invalid format values are rejected."""
        returncode, stdout, stderr = run_command(['--format', 'invalid'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid choice', stderr)

    def test_warn_only_option(self):
        """Test --warn-only option is accepted."""
        returncode, stdout, stderr = run_command(['--warn-only'])
        self.assertIn(returncode, [0, 1, 2])

    def test_warn_only_short(self):
        """Test -w short option works."""
        returncode, stdout, stderr = run_command(['-w'])
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_option(self):
        """Test --verbose option is accepted."""
        returncode, stdout, stderr = run_command(['--verbose'])
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [0, 1, 2])

    def test_list_known_option(self):
        """Test --list-known option works and lists operators."""
        returncode, stdout, stderr = run_command(['--list-known'])
        self.assertEqual(returncode, 0)
        self.assertIn('Known Operators:', stdout)
        self.assertIn('prometheus-operator', stdout)
        self.assertIn('cert-manager', stdout)
        self.assertIn('argocd', stdout)
        self.assertIn('flux', stdout)

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-v'])
        self.assertIn(returncode, [0, 1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command(['--format', 'plain', '--warn-only', '--verbose'])
        self.assertIn(returncode, [0, 1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        returncode, stdout, stderr = run_command([])
        # Should exit with error code 1 or 2 (or 0 if kubectl works)
        self.assertIn(returncode, [0, 1, 2])
        # Error message should be helpful if kubectl missing
        if returncode == 2:
            self.assertIn('kubectl', stderr.lower())

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (will fail without kubectl, but args are valid)
        self.assertIn(returncode, [0, 1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_operator_health_monitor.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_operator_health_monitor.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('Operator', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_operator_health_monitor.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)


class TestKnownOperators(unittest.TestCase):
    """Test the KNOWN_OPERATORS constant."""

    def test_known_operators_structure(self):
        """Test that KNOWN_OPERATORS has correct structure."""
        self.assertIsInstance(op_health.KNOWN_OPERATORS, dict)
        self.assertGreater(len(op_health.KNOWN_OPERATORS), 0)

        for name, info in op_health.KNOWN_OPERATORS.items():
            self.assertIn('namespaces', info)
            self.assertIn('deployments', info)
            self.assertIn('crds', info)
            self.assertIn('description', info)
            self.assertIsInstance(info['namespaces'], list)
            self.assertIsInstance(info['deployments'], list)
            self.assertIsInstance(info['crds'], list)
            self.assertIsInstance(info['description'], str)

    def test_known_operators_have_namespaces(self):
        """Test that each operator has at least one namespace defined."""
        for name, info in op_health.KNOWN_OPERATORS.items():
            self.assertGreater(len(info['namespaces']), 0,
                             f"Operator {name} has no namespaces defined")

    def test_known_operators_have_descriptions(self):
        """Test that each operator has a non-empty description."""
        for name, info in op_health.KNOWN_OPERATORS.items():
            self.assertGreater(len(info['description']), 0,
                             f"Operator {name} has empty description")

    def test_expected_operators_present(self):
        """Test that expected common operators are defined."""
        expected = ['prometheus-operator', 'cert-manager', 'argocd', 'flux',
                   'istio', 'nginx-ingress', 'external-dns']
        for op in expected:
            self.assertIn(op, op_health.KNOWN_OPERATORS,
                         f"Expected operator {op} not found")


class TestDetectOperators(unittest.TestCase):
    """Test detect_operators function."""

    def test_detect_prometheus_by_namespace(self):
        """Test detecting Prometheus operator by namespace."""
        namespaces = ['default', 'kube-system', 'monitoring']
        crds = []

        detected = op_health.detect_operators(namespaces, crds)

        self.assertIn('prometheus-operator', detected)
        self.assertIn('monitoring', detected['prometheus-operator']['namespaces'])

    def test_detect_cert_manager_by_crd(self):
        """Test detecting cert-manager by CRD."""
        namespaces = ['default', 'kube-system']
        crds = ['certificates.cert-manager.io', 'issuers.cert-manager.io']

        detected = op_health.detect_operators(namespaces, crds)

        self.assertIn('cert-manager', detected)
        self.assertIn('certificates.cert-manager.io', detected['cert-manager']['crds'])

    def test_detect_multiple_operators(self):
        """Test detecting multiple operators."""
        namespaces = ['default', 'kube-system', 'monitoring', 'argocd', 'flux-system']
        crds = ['certificates.cert-manager.io']

        detected = op_health.detect_operators(namespaces, crds)

        self.assertIn('prometheus-operator', detected)
        self.assertIn('argocd', detected)
        self.assertIn('flux', detected)
        self.assertIn('cert-manager', detected)

    def test_detect_no_operators(self):
        """Test when no operators are detected."""
        # Use namespaces that don't match any known operator patterns
        namespaces = ['default', 'my-app', 'production', 'staging']
        crds = ['myapp.example.com']

        detected = op_health.detect_operators(namespaces, crds)

        self.assertEqual(len(detected), 0)

    def test_detect_by_both_namespace_and_crd(self):
        """Test operator detected by both namespace and CRD."""
        namespaces = ['cert-manager']
        crds = ['certificates.cert-manager.io', 'issuers.cert-manager.io']

        detected = op_health.detect_operators(namespaces, crds)

        self.assertIn('cert-manager', detected)
        self.assertIn('cert-manager', detected['cert-manager']['namespaces'])
        self.assertEqual(len(detected['cert-manager']['crds']), 2)


class TestCheckDeploymentHealth(unittest.TestCase):
    """Test check_deployment_health function."""

    def test_healthy_deployment(self):
        """Test status checking for healthy deployment."""
        deployment = {
            'metadata': {'name': 'cert-manager'},
            'spec': {'replicas': 3},
            'status': {
                'replicas': 3,
                'readyReplicas': 3,
                'availableReplicas': 3,
                'updatedReplicas': 3,
                'conditions': [
                    {'type': 'Available', 'status': 'True'},
                    {'type': 'Progressing', 'status': 'True'}
                ]
            }
        }

        issues, warnings = op_health.check_deployment_health(deployment)

        self.assertEqual(len(issues), 0)
        self.assertEqual(len(warnings), 0)

    def test_deployment_not_ready(self):
        """Test deployment with pods not ready."""
        deployment = {
            'metadata': {'name': 'cert-manager'},
            'spec': {'replicas': 3},
            'status': {
                'replicas': 3,
                'readyReplicas': 1,
                'availableReplicas': 1,
                'updatedReplicas': 3,
                'conditions': []
            }
        }

        issues, warnings = op_health.check_deployment_health(deployment)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('ready' in issue.lower() for issue in issues))

    def test_deployment_rollout_in_progress(self):
        """Test deployment with rollout in progress."""
        deployment = {
            'metadata': {'name': 'argocd-server'},
            'spec': {'replicas': 3},
            'status': {
                'replicas': 3,
                'readyReplicas': 3,
                'availableReplicas': 3,
                'updatedReplicas': 1,
                'conditions': []
            }
        }

        issues, warnings = op_health.check_deployment_health(deployment)

        self.assertGreater(len(warnings), 0)
        self.assertTrue(any('rollout' in w.lower() or 'updated' in w.lower()
                           for w in warnings))

    def test_deployment_unavailable(self):
        """Test deployment with unavailable condition."""
        deployment = {
            'metadata': {'name': 'prometheus-operator'},
            'spec': {'replicas': 1},
            'status': {
                'replicas': 1,
                'readyReplicas': 0,
                'availableReplicas': 0,
                'updatedReplicas': 1,
                'conditions': [
                    {'type': 'Available', 'status': 'False',
                     'message': 'Deployment does not have minimum availability'}
                ]
            }
        }

        issues, warnings = op_health.check_deployment_health(deployment)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('available' in issue.lower() for issue in issues))


class TestCheckPodHealth(unittest.TestCase):
    """Test check_pod_health function."""

    def test_healthy_pod(self):
        """Test status checking for healthy pod."""
        pod = {
            'metadata': {'name': 'cert-manager-abc123'},
            'status': {
                'phase': 'Running',
                'containerStatuses': [
                    {
                        'name': 'cert-manager',
                        'ready': True,
                        'restartCount': 0,
                        'state': {'running': {}}
                    }
                ]
            }
        }

        issues = op_health.check_pod_health(pod)

        self.assertEqual(len(issues), 0)

    def test_pod_not_running(self):
        """Test pod in non-running phase."""
        pod = {
            'metadata': {'name': 'cert-manager-abc123'},
            'status': {
                'phase': 'Pending',
                'containerStatuses': []
            }
        }

        issues = op_health.check_pod_health(pod)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('Pending' in issue for issue in issues))

    def test_container_not_ready(self):
        """Test container not ready."""
        pod = {
            'metadata': {'name': 'argocd-server-abc123'},
            'status': {
                'phase': 'Running',
                'containerStatuses': [
                    {
                        'name': 'argocd-server',
                        'ready': False,
                        'restartCount': 0,
                        'state': {
                            'waiting': {
                                'reason': 'CrashLoopBackOff',
                                'message': 'Back-off restarting failed container'
                            }
                        }
                    }
                ]
            }
        }

        issues = op_health.check_pod_health(pod)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('not ready' in issue.lower() or 'crashloopbackoff' in issue.lower()
                           for issue in issues))

    def test_container_high_restarts(self):
        """Test container with high restart count."""
        pod = {
            'metadata': {'name': 'prometheus-operator-abc123'},
            'status': {
                'phase': 'Running',
                'containerStatuses': [
                    {
                        'name': 'prometheus-operator',
                        'ready': True,
                        'restartCount': 10,
                        'state': {'running': {}}
                    }
                ]
            }
        }

        issues = op_health.check_pod_health(pod)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('restart' in issue.lower() for issue in issues))


class TestCheckOperatorHealth(unittest.TestCase):
    """Test check_operator_health function with mocking."""

    @patch('k8s_operator_health_monitor.get_deployments')
    @patch('k8s_operator_health_monitor.get_pods_for_deployment')
    @patch('k8s_operator_health_monitor.get_events')
    def test_healthy_operator(self, mock_events, mock_pods, mock_deps):
        """Test health check for healthy operator."""
        mock_deps.return_value = [{
            'metadata': {'name': 'cert-manager', 'namespace': 'cert-manager'},
            'spec': {'replicas': 1},
            'status': {
                'replicas': 1,
                'readyReplicas': 1,
                'availableReplicas': 1,
                'updatedReplicas': 1,
                'conditions': [
                    {'type': 'Available', 'status': 'True'}
                ]
            }
        }]
        mock_pods.return_value = [{
            'metadata': {'name': 'cert-manager-abc123'},
            'status': {
                'phase': 'Running',
                'containerStatuses': [
                    {'name': 'cert-manager', 'ready': True, 'restartCount': 0,
                     'state': {'running': {}}}
                ]
            }
        }]
        mock_events.return_value = []

        operator_info = {
            'namespaces': ['cert-manager'],
            'crds': ['certificates.cert-manager.io'],
            'expected_crds': ['certificates.cert-manager.io'],
            'expected_deployments': ['cert-manager'],
            'description': 'Certificate management'
        }

        is_healthy, issues, warnings, details = op_health.check_operator_health(
            'cert-manager', operator_info
        )

        self.assertTrue(is_healthy)
        self.assertEqual(len(issues), 0)

    @patch('k8s_operator_health_monitor.get_deployments')
    @patch('k8s_operator_health_monitor.get_pods_for_deployment')
    @patch('k8s_operator_health_monitor.get_events')
    def test_unhealthy_operator(self, mock_events, mock_pods, mock_deps):
        """Test health check for unhealthy operator."""
        mock_deps.return_value = [{
            'metadata': {'name': 'cert-manager', 'namespace': 'cert-manager'},
            'spec': {'replicas': 1},
            'status': {
                'replicas': 1,
                'readyReplicas': 0,
                'availableReplicas': 0,
                'updatedReplicas': 1,
                'conditions': [
                    {'type': 'Available', 'status': 'False',
                     'message': 'Deployment has minimum availability.'}
                ]
            }
        }]
        mock_pods.return_value = []
        mock_events.return_value = []

        operator_info = {
            'namespaces': ['cert-manager'],
            'crds': ['certificates.cert-manager.io'],
            'expected_crds': ['certificates.cert-manager.io'],
            'expected_deployments': ['cert-manager'],
            'description': 'Certificate management'
        }

        is_healthy, issues, warnings, details = op_health.check_operator_health(
            'cert-manager', operator_info
        )

        self.assertFalse(is_healthy)
        self.assertGreater(len(issues), 0)


class TestOutputFormats(unittest.TestCase):
    """Test output formatting functions."""

    def test_print_json_empty(self):
        """Test JSON output with no operators."""
        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = op_health.print_json({})

        output = f.getvalue()
        data = json.loads(output)

        self.assertFalse(has_issues)
        self.assertEqual(data['summary']['total_operators'], 0)
        self.assertIn('timestamp', data)

    def test_print_json_with_operators(self):
        """Test JSON output with operators."""
        from io import StringIO
        from contextlib import redirect_stdout

        operators_status = {
            'cert-manager': {
                'healthy': True,
                'description': 'Certificate management',
                'namespaces': ['cert-manager'],
                'issues': [],
                'warnings': [],
                'details': {
                    'deployments': [],
                    'pods': [],
                    'crds': {'found': [], 'missing': []}
                }
            }
        }

        f = StringIO()
        with redirect_stdout(f):
            has_issues = op_health.print_json(operators_status)

        output = f.getvalue()
        data = json.loads(output)

        self.assertFalse(has_issues)
        self.assertEqual(data['summary']['total_operators'], 1)
        self.assertEqual(data['summary']['healthy'], 1)
        self.assertIn('cert-manager', data['operators'])

    def test_print_plain_empty(self):
        """Test plain output with no operators."""
        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = op_health.print_plain({})

        output = f.getvalue()

        self.assertFalse(has_issues)
        self.assertIn('No operators detected', output)

    def test_print_plain_with_operators(self):
        """Test plain output with operators."""
        from io import StringIO
        from contextlib import redirect_stdout

        operators_status = {
            'cert-manager': {
                'healthy': True,
                'description': 'Certificate management',
                'namespaces': ['cert-manager'],
                'issues': [],
                'warnings': [],
                'details': {
                    'deployments': [
                        {'name': 'cert-manager', 'namespace': 'cert-manager',
                         'replicas': 1, 'ready': 1, 'issues': [], 'warnings': []}
                    ],
                    'pods': [],
                    'crds': {'found': ['certificates.cert-manager.io'], 'missing': []}
                }
            }
        }

        f = StringIO()
        with redirect_stdout(f):
            has_issues = op_health.print_plain(operators_status)

        output = f.getvalue()

        self.assertFalse(has_issues)
        self.assertIn('cert-manager', output)
        self.assertIn('Certificate management', output)
        self.assertIn('✓', output)

    def test_print_plain_warn_only(self):
        """Test plain output with warn_only flag."""
        from io import StringIO
        from contextlib import redirect_stdout

        operators_status = {
            'cert-manager': {
                'healthy': True,
                'description': 'Certificate management',
                'namespaces': ['cert-manager'],
                'issues': [],
                'warnings': [],
                'details': {
                    'deployments': [],
                    'pods': [],
                    'crds': {'found': [], 'missing': []}
                }
            },
            'argocd': {
                'healthy': False,
                'description': 'GitOps CD',
                'namespaces': ['argocd'],
                'issues': ['Deployment not ready'],
                'warnings': [],
                'details': {
                    'deployments': [],
                    'pods': [],
                    'crds': {'found': [], 'missing': []}
                }
            }
        }

        f = StringIO()
        with redirect_stdout(f):
            has_issues = op_health.print_plain(operators_status, warn_only=True)

        output = f.getvalue()

        self.assertTrue(has_issues)
        # Healthy cert-manager should be hidden
        self.assertNotIn('Certificate management', output)
        # Unhealthy argocd should be shown
        self.assertIn('argocd', output)


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
