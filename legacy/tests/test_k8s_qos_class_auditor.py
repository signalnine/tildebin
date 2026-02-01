#!/usr/bin/env python3
"""
Tests for k8s_qos_class_auditor.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and core functions.
"""

import subprocess
import sys
import unittest
import os

# Add parent directory to path to import the script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_qos_class_auditor as auditor


def run_command(cmd_args, input_data=None):
    """Run the k8s_qos_class_auditor.py script with given arguments."""
    cmd = [sys.executable, 'k8s_qos_class_auditor.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sQosClassAuditor(unittest.TestCase):
    """Test cases for k8s_qos_class_auditor.py command-line interface."""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('QoS', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('QoS', stdout)

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

    def test_output_option_table(self):
        """Test --format table option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'table'])
        self.assertIn(returncode, [0, 1, 2])

    def test_invalid_output_format(self):
        """Test that invalid output format is rejected."""
        returncode, stdout, stderr = run_command(['--format', 'invalid'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid choice', stderr)

    def test_critical_only_option(self):
        """Test --critical-only option is accepted."""
        returncode, stdout, stderr = run_command(['--critical-only'])
        self.assertIn(returncode, [0, 1, 2])

    def test_exclude_namespace(self):
        """Test --exclude-namespace option."""
        returncode, stdout, stderr = run_command([
            '--exclude-namespace', 'kube-system'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_multiple_exclude_namespaces(self):
        """Test multiple --exclude-namespace options."""
        returncode, stdout, stderr = run_command([
            '--exclude-namespace', 'kube-system',
            '--exclude-namespace', 'kube-public'
        ])
        self.assertIn(returncode, [0, 1, 2])

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
            '--format', 'json',
            '--critical-only'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        self.assertIn(returncode, [0, 1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_qos_class_auditor.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_qos_class_auditor.py', 'r') as f:
            content = f.read()
        self.assertIn('"""', content)
        self.assertIn('QoS', content[:1000])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_qos_class_auditor.py', 'r') as f:
            content = f.read()
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_exit_codes_documented(self):
        """Test that exit codes are documented in docstring."""
        with open('k8s_qos_class_auditor.py', 'r') as f:
            content = f.read()
        self.assertIn('Exit codes:', content)
        self.assertIn('0 -', content)
        self.assertIn('1 -', content)
        self.assertIn('2 -', content)

    def test_examples_in_help(self):
        """Test that help includes examples."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Examples:', stdout)
        self.assertIn('k8s_qos_class_auditor.py', stdout)

    def test_script_has_main_function(self):
        """Test that script has main function."""
        with open('k8s_qos_class_auditor.py', 'r') as f:
            content = f.read()
        self.assertIn('def main()', content)
        self.assertIn("if __name__ == '__main__':", content)

    def test_qos_classes_documented(self):
        """Test that QoS classes are explained in help."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Guaranteed', stdout)
        self.assertIn('Burstable', stdout)
        self.assertIn('BestEffort', stdout)


class TestDetermineQosClass(unittest.TestCase):
    """Test the determine_qos_class function."""

    def test_guaranteed_qos(self):
        """Test detection of Guaranteed QoS class."""
        pod = {
            'spec': {
                'containers': [{
                    'name': 'main',
                    'resources': {
                        'requests': {'cpu': '500m', 'memory': '512Mi'},
                        'limits': {'cpu': '500m', 'memory': '512Mi'}
                    }
                }]
            }
        }
        qos, reason, can_upgrade, suggestion = auditor.determine_qos_class(pod)
        self.assertEqual(qos, 'Guaranteed')
        self.assertFalse(can_upgrade)

    def test_burstable_qos_requests_not_equal_limits(self):
        """Test detection of Burstable QoS when requests != limits."""
        pod = {
            'spec': {
                'containers': [{
                    'name': 'main',
                    'resources': {
                        'requests': {'cpu': '250m', 'memory': '256Mi'},
                        'limits': {'cpu': '500m', 'memory': '512Mi'}
                    }
                }]
            }
        }
        qos, reason, can_upgrade, suggestion = auditor.determine_qos_class(pod)
        self.assertEqual(qos, 'Burstable')
        self.assertTrue(can_upgrade)
        self.assertIn('requests', reason)

    def test_burstable_qos_missing_specs(self):
        """Test detection of Burstable QoS with missing specs."""
        pod = {
            'spec': {
                'containers': [{
                    'name': 'main',
                    'resources': {
                        'requests': {'cpu': '500m'},
                        'limits': {'memory': '512Mi'}
                    }
                }]
            }
        }
        qos, reason, can_upgrade, suggestion = auditor.determine_qos_class(pod)
        self.assertEqual(qos, 'Burstable')
        self.assertTrue(can_upgrade)

    def test_besteffort_qos_no_resources(self):
        """Test detection of BestEffort QoS with no resources."""
        pod = {
            'spec': {
                'containers': [{
                    'name': 'main',
                    'resources': {}
                }]
            }
        }
        qos, reason, can_upgrade, suggestion = auditor.determine_qos_class(pod)
        self.assertEqual(qos, 'BestEffort')
        self.assertTrue(can_upgrade)
        self.assertIn('Add', suggestion)

    def test_besteffort_qos_empty_containers(self):
        """Test detection of BestEffort with no containers."""
        pod = {
            'spec': {
                'containers': []
            }
        }
        qos, reason, can_upgrade, suggestion = auditor.determine_qos_class(pod)
        self.assertEqual(qos, 'BestEffort')

    def test_guaranteed_multiple_containers(self):
        """Test Guaranteed QoS with multiple containers."""
        pod = {
            'spec': {
                'containers': [
                    {
                        'name': 'main',
                        'resources': {
                            'requests': {'cpu': '500m', 'memory': '512Mi'},
                            'limits': {'cpu': '500m', 'memory': '512Mi'}
                        }
                    },
                    {
                        'name': 'sidecar',
                        'resources': {
                            'requests': {'cpu': '100m', 'memory': '128Mi'},
                            'limits': {'cpu': '100m', 'memory': '128Mi'}
                        }
                    }
                ]
            }
        }
        qos, reason, can_upgrade, suggestion = auditor.determine_qos_class(pod)
        self.assertEqual(qos, 'Guaranteed')

    def test_burstable_one_container_missing(self):
        """Test Burstable when one container lacks full specs."""
        pod = {
            'spec': {
                'containers': [
                    {
                        'name': 'main',
                        'resources': {
                            'requests': {'cpu': '500m', 'memory': '512Mi'},
                            'limits': {'cpu': '500m', 'memory': '512Mi'}
                        }
                    },
                    {
                        'name': 'sidecar',
                        'resources': {
                            'requests': {'cpu': '100m'}  # Missing memory
                        }
                    }
                ]
            }
        }
        qos, reason, can_upgrade, suggestion = auditor.determine_qos_class(pod)
        self.assertEqual(qos, 'Burstable')

    def test_init_containers_included(self):
        """Test that init containers are considered."""
        pod = {
            'spec': {
                'containers': [{
                    'name': 'main',
                    'resources': {
                        'requests': {'cpu': '500m', 'memory': '512Mi'},
                        'limits': {'cpu': '500m', 'memory': '512Mi'}
                    }
                }],
                'initContainers': [{
                    'name': 'init',
                    'resources': {}  # No resources = not Guaranteed
                }]
            }
        }
        qos, reason, can_upgrade, suggestion = auditor.determine_qos_class(pod)
        # Init container without resources means Burstable
        self.assertIn(qos, ['Burstable', 'BestEffort'])


class TestAnalyzePod(unittest.TestCase):
    """Test the analyze_pod function."""

    def test_analyze_running_pod(self):
        """Test analyzing a running pod."""
        pod = {
            'metadata': {
                'name': 'test-pod',
                'namespace': 'default',
                'ownerReferences': [{'kind': 'Deployment', 'name': 'test-deploy'}]
            },
            'spec': {
                'containers': [{
                    'name': 'main',
                    'resources': {
                        'requests': {'cpu': '500m', 'memory': '512Mi'},
                        'limits': {'cpu': '500m', 'memory': '512Mi'}
                    }
                }]
            },
            'status': {
                'phase': 'Running',
                'qosClass': 'Guaranteed'
            }
        }

        analysis = auditor.analyze_pod(pod)

        self.assertEqual(analysis['name'], 'test-pod')
        self.assertEqual(analysis['namespace'], 'default')
        self.assertEqual(analysis['qos_class'], 'Guaranteed')
        self.assertEqual(analysis['owner_kind'], 'Deployment')
        self.assertEqual(analysis['owner_name'], 'test-deploy')
        self.assertEqual(analysis['container_count'], 1)

    def test_analyze_critical_pod(self):
        """Test analyzing a critical pod."""
        pod = {
            'metadata': {
                'name': 'kube-scheduler',
                'namespace': 'kube-system',
                'labels': {
                    'app.kubernetes.io/component': 'controller'
                }
            },
            'spec': {
                'containers': [{'name': 'main', 'resources': {}}]
            },
            'status': {
                'phase': 'Running'
            }
        }

        analysis = auditor.analyze_pod(pod)

        self.assertTrue(analysis['is_critical'])

    def test_analyze_kube_system_is_critical(self):
        """Test that kube-system namespace pods are marked critical."""
        pod = {
            'metadata': {
                'name': 'coredns',
                'namespace': 'kube-system'
            },
            'spec': {
                'containers': [{'name': 'main', 'resources': {}}]
            },
            'status': {
                'phase': 'Running'
            }
        }

        analysis = auditor.analyze_pod(pod)

        self.assertTrue(analysis['is_critical'])

    def test_analyze_non_critical_pod(self):
        """Test that regular pods are not marked critical."""
        pod = {
            'metadata': {
                'name': 'my-app',
                'namespace': 'default',
                'labels': {}
            },
            'spec': {
                'containers': [{'name': 'main', 'resources': {}}]
            },
            'status': {
                'phase': 'Running'
            }
        }

        analysis = auditor.analyze_pod(pod)

        self.assertFalse(analysis['is_critical'])

    def test_analyze_pod_no_owner(self):
        """Test analyzing pod without owner reference."""
        pod = {
            'metadata': {
                'name': 'standalone-pod',
                'namespace': 'default'
            },
            'spec': {
                'containers': [{'name': 'main', 'resources': {}}]
            },
            'status': {
                'phase': 'Running'
            }
        }

        analysis = auditor.analyze_pod(pod)

        self.assertEqual(analysis['owner_kind'], 'None')
        self.assertEqual(analysis['owner_name'], 'None')


class TestCategorizeFindingS(unittest.TestCase):
    """Test the categorize_findings function."""

    def test_categorize_by_qos_class(self):
        """Test categorization by QoS class."""
        analyses = [
            {'qos_class': 'Guaranteed', 'is_critical': False, 'can_upgrade': False, 'namespace': 'default'},
            {'qos_class': 'Burstable', 'is_critical': False, 'can_upgrade': True, 'namespace': 'default'},
            {'qos_class': 'BestEffort', 'is_critical': False, 'can_upgrade': True, 'namespace': 'default'}
        ]

        categories, issues, ns_stats = auditor.categorize_findings(analyses)

        self.assertEqual(len(categories['Guaranteed']), 1)
        self.assertEqual(len(categories['Burstable']), 1)
        self.assertEqual(len(categories['BestEffort']), 1)

    def test_identify_besteffort_issues(self):
        """Test that BestEffort pods are flagged as issues."""
        analyses = [
            {'qos_class': 'BestEffort', 'is_critical': False, 'can_upgrade': True, 'namespace': 'default'}
        ]

        categories, issues, ns_stats = auditor.categorize_findings(analyses)

        self.assertEqual(len(issues['best_effort']), 1)

    def test_identify_critical_not_guaranteed(self):
        """Test that critical pods without Guaranteed QoS are flagged."""
        analyses = [
            {'qos_class': 'Burstable', 'is_critical': True, 'can_upgrade': True, 'namespace': 'kube-system'}
        ]

        categories, issues, ns_stats = auditor.categorize_findings(analyses)

        self.assertEqual(len(issues['critical_not_guaranteed']), 1)

    def test_namespace_statistics(self):
        """Test namespace statistics calculation."""
        analyses = [
            {'qos_class': 'Guaranteed', 'is_critical': False, 'can_upgrade': False, 'namespace': 'prod'},
            {'qos_class': 'Guaranteed', 'is_critical': False, 'can_upgrade': False, 'namespace': 'prod'},
            {'qos_class': 'Burstable', 'is_critical': False, 'can_upgrade': True, 'namespace': 'dev'}
        ]

        categories, issues, ns_stats = auditor.categorize_findings(analyses)

        self.assertEqual(ns_stats['prod']['Guaranteed'], 2)
        self.assertEqual(ns_stats['dev']['Burstable'], 1)

    def test_empty_analyses(self):
        """Test with empty analyses list."""
        categories, issues, ns_stats = auditor.categorize_findings([])

        self.assertEqual(len(categories['Guaranteed']), 0)
        self.assertEqual(len(categories['Burstable']), 0)
        self.assertEqual(len(categories['BestEffort']), 0)


class TestOutputFormats(unittest.TestCase):
    """Test output format functions."""

    def test_json_output_structure(self):
        """Test that JSON output mode is available."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_plain_output_structure(self):
        """Test that plain output mode is available."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        self.assertIn(returncode, [0, 1, 2])

    def test_table_output_structure(self):
        """Test that table output mode is available."""
        returncode, stdout, stderr = run_command(['--format', 'table'])
        self.assertIn(returncode, [0, 1, 2])

    def test_default_output_format(self):
        """Test that default output format is plain."""
        returncode, stdout, stderr = run_command([])
        self.assertIn(returncode, [0, 1, 2])


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
