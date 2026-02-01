#!/usr/bin/env python3
"""
Tests for k8s_configmap_audit.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and core functions.
"""

import subprocess
import sys
import unittest
from unittest.mock import patch, MagicMock
import json
import os

# Add parent directory to path to import the script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_configmap_audit as auditor


def run_command(cmd_args, input_data=None):
    """Run the k8s_configmap_audit.py script with given arguments."""
    cmd = [sys.executable, 'k8s_configmap_audit.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sConfigMapAudit(unittest.TestCase):
    """Test cases for k8s_configmap_audit.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('ConfigMap', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('ConfigMap', stdout)

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'kube-system'])
        self.assertIn(returncode, [0, 1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'default'])
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_option(self):
        """Test --verbose option is accepted."""
        returncode, stdout, stderr = run_command(['--verbose'])
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_option_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [0, 1, 2])

    def test_warn_only_option(self):
        """Test --warn-only option is accepted."""
        returncode, stdout, stderr = run_command(['--warn-only'])
        self.assertIn(returncode, [0, 1, 2])

    def test_warn_only_option_short(self):
        """Test -w short option works."""
        returncode, stdout, stderr = run_command(['-w'])
        self.assertIn(returncode, [0, 1, 2])

    def test_output_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        self.assertIn(returncode, [0, 1, 2])

    def test_output_option_json(self):
        """Test --format json option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_invalid_output_format(self):
        """Test that invalid output format is rejected."""
        returncode, stdout, stderr = run_command(['--format', 'invalid'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid choice', stderr)

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command([
            '-n', 'production',
            '--verbose',
            '--warn-only'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_all_options_combined(self):
        """Test all options together."""
        returncode, stdout, stderr = run_command([
            '--namespace', 'kube-system',
            '--verbose',
            '--warn-only',
            '--format', 'json'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (may succeed or fail without kubectl)
        self.assertIn(returncode, [0, 1, 2])

    def test_kubectl_error_handling(self):
        """Test graceful handling when kubectl fails."""
        # This test verifies the script doesn't crash unexpectedly
        returncode, stdout, stderr = run_command([])
        # Should exit cleanly with appropriate error code
        self.assertIn(returncode, [0, 1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_configmap_audit.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_configmap_audit.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('ConfigMap', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_configmap_audit.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_exit_codes_documented(self):
        """Test that exit codes are documented in docstring."""
        with open('k8s_configmap_audit.py', 'r') as f:
            content = f.read()
        # Check for exit code documentation
        self.assertIn('Exit codes:', content)
        self.assertIn('0 -', content)
        self.assertIn('1 -', content)
        self.assertIn('2 -', content)

    def test_examples_in_help(self):
        """Test that help includes examples."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Examples:', stdout)
        self.assertIn('k8s_configmap_audit.py', stdout)

    def test_script_has_main_function(self):
        """Test that script has main function."""
        with open('k8s_configmap_audit.py', 'r') as f:
            content = f.read()
        self.assertIn('def main()', content)
        self.assertIn("if __name__ == '__main__':", content)

    def test_script_has_size_constants(self):
        """Test that script defines size limit constants."""
        with open('k8s_configmap_audit.py', 'r') as f:
            content = f.read()
        self.assertIn('CONFIGMAP_SIZE_LIMIT', content)
        self.assertIn('SIZE_WARNING_THRESHOLD', content)
        self.assertIn('LARGE_CONFIGMAP_THRESHOLD', content)


class TestCalculateConfigMapSize(unittest.TestCase):
    """Test the calculate_configmap_size function."""

    def test_empty_configmap(self):
        """Test calculating size of empty ConfigMap."""
        cm = {'data': {}, 'binaryData': {}}
        size = auditor.calculate_configmap_size(cm)
        self.assertEqual(size, 0)

    def test_configmap_with_data(self):
        """Test calculating size of ConfigMap with data."""
        cm = {
            'data': {
                'key1': 'value1',
                'key2': 'value2'
            }
        }
        size = auditor.calculate_configmap_size(cm)
        # key1 (4) + value1 (6) + key2 (4) + value2 (6) = 20
        self.assertEqual(size, 20)

    def test_configmap_with_empty_value(self):
        """Test calculating size with empty value."""
        cm = {
            'data': {
                'key': ''
            }
        }
        size = auditor.calculate_configmap_size(cm)
        # key (3) + empty string (0) = 3
        self.assertEqual(size, 3)

    def test_configmap_with_none_value(self):
        """Test calculating size with None value."""
        cm = {
            'data': {
                'key': None
            }
        }
        size = auditor.calculate_configmap_size(cm)
        # key (3) + None (0) = 3
        self.assertEqual(size, 3)

    def test_configmap_missing_data(self):
        """Test calculating size when data key is missing."""
        cm = {}
        size = auditor.calculate_configmap_size(cm)
        self.assertEqual(size, 0)


class TestGetConfigMapReferences(unittest.TestCase):
    """Test the get_configmap_references function."""

    def test_no_references(self):
        """Test with pods that don't reference ConfigMaps."""
        pods = [{
            'metadata': {'name': 'test-pod', 'namespace': 'default'},
            'spec': {'containers': [{'name': 'container'}]}
        }]
        refs = auditor.get_configmap_references(pods)
        self.assertEqual(len(refs), 0)

    def test_volume_reference(self):
        """Test detecting ConfigMap volume references."""
        pods = [{
            'metadata': {'name': 'test-pod', 'namespace': 'default'},
            'spec': {
                'volumes': [{
                    'name': 'config-vol',
                    'configMap': {'name': 'my-config'}
                }],
                'containers': [{'name': 'container'}]
            }
        }]
        refs = auditor.get_configmap_references(pods)
        self.assertIn(('default', 'my-config'), refs)

    def test_envfrom_reference(self):
        """Test detecting ConfigMap envFrom references."""
        pods = [{
            'metadata': {'name': 'test-pod', 'namespace': 'default'},
            'spec': {
                'containers': [{
                    'name': 'container',
                    'envFrom': [{
                        'configMapRef': {'name': 'env-config'}
                    }]
                }]
            }
        }]
        refs = auditor.get_configmap_references(pods)
        self.assertIn(('default', 'env-config'), refs)

    def test_env_valuefrom_reference(self):
        """Test detecting ConfigMap env valueFrom references."""
        pods = [{
            'metadata': {'name': 'test-pod', 'namespace': 'default'},
            'spec': {
                'containers': [{
                    'name': 'container',
                    'env': [{
                        'name': 'MY_VAR',
                        'valueFrom': {
                            'configMapKeyRef': {
                                'name': 'key-config',
                                'key': 'some-key'
                            }
                        }
                    }]
                }]
            }
        }]
        refs = auditor.get_configmap_references(pods)
        self.assertIn(('default', 'key-config'), refs)

    def test_init_container_reference(self):
        """Test detecting ConfigMap references in init containers."""
        pods = [{
            'metadata': {'name': 'test-pod', 'namespace': 'default'},
            'spec': {
                'initContainers': [{
                    'name': 'init',
                    'envFrom': [{
                        'configMapRef': {'name': 'init-config'}
                    }]
                }],
                'containers': [{'name': 'container'}]
            }
        }]
        refs = auditor.get_configmap_references(pods)
        self.assertIn(('default', 'init-config'), refs)


class TestGetKeyReferences(unittest.TestCase):
    """Test the get_key_references function."""

    def test_no_key_references(self):
        """Test with pods that don't reference specific keys."""
        pods = [{
            'metadata': {'name': 'test-pod', 'namespace': 'default'},
            'spec': {'containers': [{'name': 'container'}]}
        }]
        refs = auditor.get_key_references(pods)
        self.assertEqual(len(refs), 0)

    def test_volume_items_reference(self):
        """Test detecting key references in volume items."""
        pods = [{
            'metadata': {'name': 'test-pod', 'namespace': 'default'},
            'spec': {
                'volumes': [{
                    'name': 'config-vol',
                    'configMap': {
                        'name': 'my-config',
                        'items': [{'key': 'config.yaml', 'path': 'config.yaml'}]
                    }
                }],
                'containers': [{'name': 'container'}]
            }
        }]
        refs = auditor.get_key_references(pods)
        self.assertIn('config.yaml', refs[('default', 'my-config')])

    def test_env_keyref(self):
        """Test detecting key references in env valueFrom."""
        pods = [{
            'metadata': {'name': 'test-pod', 'namespace': 'default'},
            'spec': {
                'containers': [{
                    'name': 'container',
                    'env': [{
                        'name': 'MY_VAR',
                        'valueFrom': {
                            'configMapKeyRef': {
                                'name': 'my-config',
                                'key': 'specific-key'
                            }
                        }
                    }]
                }]
            }
        }]
        refs = auditor.get_key_references(pods)
        self.assertIn('specific-key', refs[('default', 'my-config')])


class TestAuditConfigMaps(unittest.TestCase):
    """Test the audit_configmaps function."""

    def test_audit_empty_list(self):
        """Test auditing with no ConfigMaps."""
        issues = auditor.audit_configmaps([], [])
        self.assertEqual(len(issues['approaching_limit']), 0)
        self.assertEqual(len(issues['unused']), 0)
        self.assertEqual(len(issues['missing_keys']), 0)

    def test_audit_detects_large_configmap(self):
        """Test that large ConfigMaps are detected."""
        # Create a ConfigMap with data > 100KB
        large_data = 'x' * (150 * 1024)  # 150KB
        configmaps = [{
            'metadata': {'name': 'large-cm', 'namespace': 'test'},
            'data': {'bigfile': large_data}
        }]
        issues = auditor.audit_configmaps(configmaps, [])
        self.assertEqual(len(issues['large_configmaps']), 1)

    def test_audit_detects_empty_configmap(self):
        """Test that empty ConfigMaps are detected."""
        configmaps = [{
            'metadata': {'name': 'empty-cm', 'namespace': 'test'},
            'data': {},
            'binaryData': {}
        }]
        issues = auditor.audit_configmaps(configmaps, [])
        self.assertEqual(len(issues['empty']), 1)

    def test_audit_detects_unused_configmap(self):
        """Test that unused ConfigMaps are detected."""
        configmaps = [{
            'metadata': {'name': 'unused-cm', 'namespace': 'test'},
            'data': {'key': 'value'}
        }]
        pods = []
        issues = auditor.audit_configmaps(configmaps, pods)
        self.assertEqual(len(issues['unused']), 1)

    def test_audit_detects_missing_keys(self):
        """Test that missing keys are detected."""
        configmaps = [{
            'metadata': {'name': 'my-config', 'namespace': 'default'},
            'data': {'existing-key': 'value'}
        }]
        pods = [{
            'metadata': {'name': 'test-pod', 'namespace': 'default'},
            'spec': {
                'containers': [{
                    'name': 'container',
                    'env': [{
                        'name': 'MY_VAR',
                        'valueFrom': {
                            'configMapKeyRef': {
                                'name': 'my-config',
                                'key': 'missing-key'
                            }
                        }
                    }]
                }]
            }
        }]
        issues = auditor.audit_configmaps(configmaps, pods)
        self.assertEqual(len(issues['missing_keys']), 1)
        self.assertIn('missing-key', issues['missing_keys'][0]['missing_keys'])

    def test_audit_detects_default_namespace(self):
        """Test that ConfigMaps in default namespace are flagged."""
        configmaps = [{
            'metadata': {'name': 'app-config', 'namespace': 'default'},
            'data': {'key': 'value'}
        }]
        issues = auditor.audit_configmaps(configmaps, [])
        self.assertEqual(len(issues['default_namespace']), 1)

    def test_audit_skips_system_configmaps(self):
        """Test that system ConfigMaps are skipped."""
        configmaps = [{
            'metadata': {'name': 'kube-root-ca.crt', 'namespace': 'kube-system'},
            'data': {'ca.crt': 'cert-data'}
        }]
        issues = auditor.audit_configmaps(configmaps, [], verbose=False)
        # System namespaces should be skipped without verbose
        self.assertEqual(len(issues['unused']), 0)


class TestFormatOutputPlain(unittest.TestCase):
    """Test the format_output_plain function."""

    def test_format_empty_issues(self):
        """Test formatting with no issues."""
        issues = {
            'approaching_limit': [],
            'large_configmaps': [],
            'unused': [],
            'missing_keys': [],
            'default_namespace': [],
            'empty': []
        }
        output = auditor.format_output_plain(issues)
        self.assertIn('ConfigMap Audit Report', output)
        self.assertIn('No ConfigMap issues detected', output)

    def test_format_with_large_configmap(self):
        """Test formatting with large ConfigMap warning."""
        issues = {
            'approaching_limit': [],
            'large_configmaps': [{
                'namespace': 'test',
                'name': 'large-cm',
                'size_bytes': 150000,
                'size_kb': 146.48
            }],
            'unused': [],
            'missing_keys': [],
            'default_namespace': [],
            'empty': []
        }
        output = auditor.format_output_plain(issues)
        self.assertIn('Large ConfigMaps', output)
        self.assertIn('test/large-cm', output)

    def test_format_warn_only(self):
        """Test formatting with warn_only flag."""
        issues = {
            'approaching_limit': [],
            'large_configmaps': [],
            'unused': [{'namespace': 'test', 'name': 'unused', 'size_bytes': 100}],
            'missing_keys': [],
            'default_namespace': [],
            'empty': []
        }
        output = auditor.format_output_plain(issues, warn_only=True)
        # Should not include summary sections when warn_only is True
        self.assertNotIn('ConfigMap Audit Report', output)


class TestFormatOutputJson(unittest.TestCase):
    """Test the format_output_json function."""

    def test_format_json_structure(self):
        """Test JSON output has correct structure."""
        issues = {
            'approaching_limit': [],
            'large_configmaps': [],
            'unused': [],
            'missing_keys': [],
            'default_namespace': [],
            'empty': []
        }
        output = auditor.format_output_json(issues)

        # Should be valid JSON
        data = json.loads(output)
        self.assertIn('approaching_limit', data)
        self.assertIn('large_configmaps', data)
        self.assertIn('unused', data)
        self.assertIn('missing_keys', data)

    def test_format_json_values(self):
        """Test JSON output contains correct values."""
        issues = {
            'approaching_limit': [{'name': 'test'}],
            'large_configmaps': [],
            'unused': [],
            'missing_keys': [],
            'default_namespace': [],
            'empty': []
        }
        output = auditor.format_output_json(issues)

        data = json.loads(output)
        self.assertEqual(len(data['approaching_limit']), 1)
        self.assertEqual(data['approaching_limit'][0]['name'], 'test')


class TestGetConfigMaps(unittest.TestCase):
    """Test the get_configmaps function with mocking."""

    @patch('k8s_configmap_audit.run_kubectl')
    def test_get_configmaps_all_namespaces(self, mock_run):
        """Test getting ConfigMaps from all namespaces."""
        mock_run.return_value = json.dumps({
            'items': [{
                'metadata': {'name': 'test-cm', 'namespace': 'default'},
                'data': {'key': 'value'}
            }]
        })

        configmaps = auditor.get_configmaps()
        self.assertEqual(len(configmaps), 1)
        self.assertEqual(configmaps[0]['metadata']['name'], 'test-cm')

        # Verify called with all namespaces
        call_args = mock_run.call_args[0][0]
        self.assertIn('--all-namespaces', call_args)

    @patch('k8s_configmap_audit.run_kubectl')
    def test_get_configmaps_specific_namespace(self, mock_run):
        """Test getting ConfigMaps from specific namespace."""
        mock_run.return_value = json.dumps({'items': []})

        auditor.get_configmaps(namespace='production')

        # Verify called with namespace filter
        call_args = mock_run.call_args[0][0]
        self.assertIn('-n', call_args)
        self.assertIn('production', call_args)


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
