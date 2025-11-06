#!/usr/bin/env python3
"""
Tests for k8s_deployment_status.py

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

import k8s_deployment_status as deployment_status


def run_command(cmd_args, input_data=None):
    """Run the k8s_deployment_status.py script with given arguments."""
    cmd = [sys.executable, 'k8s_deployment_status.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sDeploymentStatus(unittest.TestCase):
    """Test cases for k8s_deployment_status.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Deployment', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('Deployment', stdout)

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        # Will fail without kubectl, but should parse args correctly
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

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-n', 'default'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command(['--format', 'plain', '--warn-only', '--namespace', 'kube-system'])
        self.assertIn(returncode, [1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        # This test assumes kubectl might not be in PATH
        # If it fails because kubectl IS found, that's also fine
        returncode, stdout, stderr = run_command([])
        # Should exit with error code 1 or 2
        self.assertNotEqual(returncode, 0)
        # Error message should be helpful
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
        with open('k8s_deployment_status.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_deployment_status.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('Deployment', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_deployment_status.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)


class TestCheckDeploymentStatus(unittest.TestCase):
    """Test check_deployment_status function."""

    def test_healthy_deployment(self):
        """Test status checking for healthy deployment."""
        deployment = {
            'metadata': {'name': 'test-deploy', 'generation': 5},
            'spec': {'replicas': 3},
            'status': {
                'readyReplicas': 3,
                'updatedReplicas': 3,
                'availableReplicas': 3,
                'observedGeneration': 5,
                'conditions': [
                    {'type': 'Progressing', 'status': 'True'},
                    {'type': 'Available', 'status': 'True'}
                ]
            }
        }

        is_healthy, issues, replicas = deployment_status.check_deployment_status(deployment)

        self.assertTrue(is_healthy)
        self.assertEqual(len(issues), 0)
        self.assertEqual(replicas['desired'], 3)
        self.assertEqual(replicas['ready'], 3)

    def test_unhealthy_deployment_not_ready(self):
        """Test status checking for deployment with pods not ready."""
        deployment = {
            'metadata': {'name': 'test-deploy', 'generation': 5},
            'spec': {'replicas': 3},
            'status': {
                'readyReplicas': 1,
                'updatedReplicas': 3,
                'availableReplicas': 1,
                'observedGeneration': 5,
                'conditions': []
            }
        }

        is_healthy, issues, replicas = deployment_status.check_deployment_status(deployment)

        self.assertFalse(is_healthy)
        self.assertGreater(len(issues), 0)
        self.assertTrue(any('Not fully rolled out' in issue for issue in issues))

    def test_deployment_generation_not_observed(self):
        """Test deployment with generation not yet observed."""
        deployment = {
            'metadata': {'name': 'test-deploy', 'generation': 5},
            'spec': {'replicas': 3},
            'status': {
                'readyReplicas': 3,
                'updatedReplicas': 3,
                'availableReplicas': 3,
                'observedGeneration': 4,
                'conditions': []
            }
        }

        is_healthy, issues, replicas = deployment_status.check_deployment_status(deployment)

        self.assertFalse(is_healthy)
        self.assertTrue(any('generation not yet observed' in issue for issue in issues))

    def test_deployment_progressing_false(self):
        """Test deployment with Progressing condition false."""
        deployment = {
            'metadata': {'name': 'test-deploy', 'generation': 5},
            'spec': {'replicas': 3},
            'status': {
                'readyReplicas': 3,
                'updatedReplicas': 3,
                'availableReplicas': 3,
                'observedGeneration': 5,
                'conditions': [
                    {'type': 'Progressing', 'status': 'False', 'reason': 'ProgressDeadlineExceeded', 'message': 'Timeout'}
                ]
            }
        }

        is_healthy, issues, replicas = deployment_status.check_deployment_status(deployment)

        self.assertFalse(is_healthy)
        self.assertTrue(any('Progressing' in issue for issue in issues))

    def test_deployment_not_available(self):
        """Test deployment with Available condition false."""
        deployment = {
            'metadata': {'name': 'test-deploy', 'generation': 5},
            'spec': {'replicas': 3},
            'status': {
                'readyReplicas': 0,
                'updatedReplicas': 0,
                'availableReplicas': 0,
                'observedGeneration': 5,
                'conditions': [
                    {'type': 'Available', 'status': 'False', 'reason': 'MinimumReplicasUnavailable'}
                ]
            }
        }

        is_healthy, issues, replicas = deployment_status.check_deployment_status(deployment)

        self.assertFalse(is_healthy)
        self.assertTrue(any('Available' in issue for issue in issues))


class TestCheckStatefulSetStatus(unittest.TestCase):
    """Test check_statefulset_status function."""

    def test_healthy_statefulset(self):
        """Test status checking for healthy statefulset."""
        statefulset = {
            'metadata': {'name': 'test-sts', 'generation': 3},
            'spec': {'replicas': 3},
            'status': {
                'readyReplicas': 3,
                'updatedReplicas': 3,
                'currentReplicas': 3,
                'observedGeneration': 3,
                'conditions': []
            }
        }

        is_healthy, issues, replicas = deployment_status.check_statefulset_status(statefulset)

        self.assertTrue(is_healthy)
        self.assertEqual(len(issues), 0)
        self.assertEqual(replicas['desired'], 3)
        self.assertEqual(replicas['ready'], 3)

    def test_unhealthy_statefulset(self):
        """Test status checking for unhealthy statefulset."""
        statefulset = {
            'metadata': {'name': 'test-sts', 'generation': 3},
            'spec': {'replicas': 3},
            'status': {
                'readyReplicas': 1,
                'updatedReplicas': 2,
                'currentReplicas': 3,
                'observedGeneration': 3,
                'conditions': []
            }
        }

        is_healthy, issues, replicas = deployment_status.check_statefulset_status(statefulset)

        self.assertFalse(is_healthy)
        self.assertGreater(len(issues), 0)


class TestGetImages(unittest.TestCase):
    """Test get_images function."""

    def test_get_single_image(self):
        """Test extracting single image."""
        resource = {
            'spec': {
                'template': {
                    'spec': {
                        'containers': [
                            {'image': 'nginx:latest'}
                        ]
                    }
                }
            }
        }

        images = deployment_status.get_images(resource)

        self.assertEqual(len(images), 1)
        self.assertEqual(images[0], 'nginx:latest')

    def test_get_multiple_images(self):
        """Test extracting multiple images."""
        resource = {
            'spec': {
                'template': {
                    'spec': {
                        'containers': [
                            {'image': 'nginx:latest'},
                            {'image': 'redis:6'},
                            {'image': 'postgres:13'}
                        ]
                    }
                }
            }
        }

        images = deployment_status.get_images(resource)

        self.assertEqual(len(images), 3)
        self.assertIn('nginx:latest', images)
        self.assertIn('redis:6', images)

    def test_get_images_empty(self):
        """Test extracting images from empty containers."""
        resource = {
            'spec': {
                'template': {
                    'spec': {
                        'containers': []
                    }
                }
            }
        }

        images = deployment_status.get_images(resource)

        self.assertEqual(len(images), 0)


class TestGetDeployments(unittest.TestCase):
    """Test get_deployments function with mocking."""

    @patch('k8s_deployment_status.run_kubectl')
    def test_get_deployments_all_namespaces(self, mock_run):
        """Test getting deployments from all namespaces."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'deploy1', 'namespace': 'default'}},
                {'metadata': {'name': 'deploy2', 'namespace': 'kube-system'}}
            ]
        })

        deployments = deployment_status.get_deployments()

        self.assertEqual(len(deployments['items']), 2)
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        self.assertIn('--all-namespaces', call_args)

    @patch('k8s_deployment_status.run_kubectl')
    def test_get_deployments_specific_namespace(self, mock_run):
        """Test getting deployments from specific namespace."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'deploy1', 'namespace': 'production'}}
            ]
        })

        deployments = deployment_status.get_deployments('production')

        self.assertEqual(len(deployments['items']), 1)
        call_args = mock_run.call_args[0][0]
        self.assertIn('-n', call_args)
        self.assertIn('production', call_args)


class TestGetStatefulSets(unittest.TestCase):
    """Test get_statefulsets function with mocking."""

    @patch('k8s_deployment_status.run_kubectl')
    def test_get_statefulsets_all_namespaces(self, mock_run):
        """Test getting statefulsets from all namespaces."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'sts1', 'namespace': 'default'}}
            ]
        })

        statefulsets = deployment_status.get_statefulsets()

        self.assertEqual(len(statefulsets['items']), 1)
        call_args = mock_run.call_args[0][0]
        self.assertIn('--all-namespaces', call_args)


class TestPrintStatus(unittest.TestCase):
    """Test print_status function."""

    def test_print_status_json_format(self):
        """Test print_status with JSON format."""
        deployments = {
            'items': [{
                'metadata': {'name': 'test-deploy', 'namespace': 'default', 'generation': 1},
                'spec': {'replicas': 3, 'template': {'spec': {'containers': [{'image': 'nginx:latest'}]}}},
                'status': {
                    'readyReplicas': 3,
                    'updatedReplicas': 3,
                    'availableReplicas': 3,
                    'observedGeneration': 1,
                    'conditions': [
                        {'type': 'Progressing', 'status': 'True'},
                        {'type': 'Available', 'status': 'True'}
                    ]
                }
            }]
        }
        statefulsets = {'items': []}

        # Capture stdout
        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = deployment_status.print_status(deployments, statefulsets, 'json', False)

        output = f.getvalue()
        self.assertFalse(has_issues)

        # Verify JSON is valid
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)

    def test_print_status_plain_format(self):
        """Test print_status with plain format."""
        deployments = {
            'items': [{
                'metadata': {'name': 'test-deploy', 'namespace': 'default', 'generation': 1},
                'spec': {'replicas': 3, 'template': {'spec': {'containers': [{'image': 'nginx:latest'}]}}},
                'status': {
                    'readyReplicas': 3,
                    'updatedReplicas': 3,
                    'availableReplicas': 3,
                    'observedGeneration': 1,
                    'conditions': []
                }
            }]
        }
        statefulsets = {'items': []}

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = deployment_status.print_status(deployments, statefulsets, 'plain', False)

        output = f.getvalue()
        self.assertIn('test-deploy', output)
        self.assertIn('default', output)

    def test_print_status_warn_only(self):
        """Test print_status with warn_only flag."""
        deployments = {
            'items': [
                {
                    'metadata': {'name': 'healthy-deploy', 'namespace': 'default', 'generation': 1},
                    'spec': {'replicas': 3, 'template': {'spec': {'containers': [{'image': 'nginx:latest'}]}}},
                    'status': {
                        'readyReplicas': 3,
                        'updatedReplicas': 3,
                        'availableReplicas': 3,
                        'observedGeneration': 1,
                        'conditions': []
                    }
                },
                {
                    'metadata': {'name': 'unhealthy-deploy', 'namespace': 'default', 'generation': 1},
                    'spec': {'replicas': 3, 'template': {'spec': {'containers': [{'image': 'nginx:latest'}]}}},
                    'status': {
                        'readyReplicas': 1,
                        'updatedReplicas': 1,
                        'availableReplicas': 1,
                        'observedGeneration': 1,
                        'conditions': []
                    }
                }
            ]
        }
        statefulsets = {'items': []}

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = deployment_status.print_status(deployments, statefulsets, 'json', True)

        output = f.getvalue()
        data = json.loads(output)

        # Only unhealthy deployment should be in output
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'unhealthy-deploy')
        self.assertTrue(has_issues)


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
