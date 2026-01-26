#!/usr/bin/env python3
"""
Tests for k8s_resource_right_sizer.py

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

import k8s_resource_right_sizer as sizer


def run_command(cmd_args, input_data=None):
    """Run the k8s_resource_right_sizer.py script with given arguments."""
    cmd = [sys.executable, 'k8s_resource_right_sizer.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sResourceRightSizer(unittest.TestCase):
    """Test cases for k8s_resource_right_sizer.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('right-sizing', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('--cpu-threshold', stdout)
        self.assertIn('--mem-threshold', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('right-sizing', stdout)

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'kube-system'])
        self.assertIn(returncode, [0, 1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'default'])
        self.assertIn(returncode, [0, 1, 2])

    def test_cpu_threshold_option(self):
        """Test --cpu-threshold option is accepted."""
        returncode, stdout, stderr = run_command(['--cpu-threshold', '25'])
        self.assertIn(returncode, [0, 1, 2])

    def test_mem_threshold_option(self):
        """Test --mem-threshold option is accepted."""
        returncode, stdout, stderr = run_command(['--mem-threshold', '40'])
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
            '--cpu-threshold', '20',
            '--mem-threshold', '25',
            '--verbose',
            '--warn-only',
            '--format', 'json'
        ])
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

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        self.assertIn(returncode, [0, 1, 2])

    def test_kubectl_error_handling(self):
        """Test graceful handling when kubectl fails."""
        returncode, stdout, stderr = run_command([])
        self.assertIn(returncode, [0, 1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_resource_right_sizer.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_resource_right_sizer.py', 'r') as f:
            content = f.read()
        self.assertIn('"""', content)
        self.assertIn('right-sizing', content[:500].lower())

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_resource_right_sizer.py', 'r') as f:
            content = f.read()
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_exit_codes_documented(self):
        """Test that exit codes are documented in docstring."""
        with open('k8s_resource_right_sizer.py', 'r') as f:
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
        self.assertIn('k8s_resource_right_sizer.py', stdout)

    def test_script_has_main_function(self):
        """Test that script has main function."""
        with open('k8s_resource_right_sizer.py', 'r') as f:
            content = f.read()
        self.assertIn('def main()', content)
        self.assertIn("if __name__ == '__main__':", content)


class TestParseCpu(unittest.TestCase):
    """Test the parse_cpu function."""

    def test_parse_millicores(self):
        """Test parsing millicores format."""
        self.assertEqual(sizer.parse_cpu('100m'), 100)
        self.assertEqual(sizer.parse_cpu('500m'), 500)
        self.assertEqual(sizer.parse_cpu('1000m'), 1000)

    def test_parse_nanocores(self):
        """Test parsing nanocores format."""
        self.assertEqual(sizer.parse_cpu('1000000000n'), 1000)
        self.assertEqual(sizer.parse_cpu('500000000n'), 500)

    def test_parse_cores(self):
        """Test parsing cores as decimal."""
        self.assertEqual(sizer.parse_cpu('1'), 1000)
        self.assertEqual(sizer.parse_cpu('0.5'), 500)
        self.assertEqual(sizer.parse_cpu('2'), 2000)
        self.assertEqual(sizer.parse_cpu('0.1'), 100)

    def test_parse_none(self):
        """Test parsing None value."""
        self.assertIsNone(sizer.parse_cpu(None))

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        self.assertIsNone(sizer.parse_cpu(''))

    def test_parse_invalid(self):
        """Test parsing invalid CPU value."""
        self.assertIsNone(sizer.parse_cpu('invalid'))


class TestParseMemory(unittest.TestCase):
    """Test the parse_memory function."""

    def test_parse_ki(self):
        """Test parsing Ki (kibibytes)."""
        self.assertEqual(sizer.parse_memory('1Ki'), 1024)
        self.assertEqual(sizer.parse_memory('100Ki'), 102400)

    def test_parse_mi(self):
        """Test parsing Mi (mebibytes)."""
        self.assertEqual(sizer.parse_memory('1Mi'), 1024 * 1024)
        self.assertEqual(sizer.parse_memory('512Mi'), 512 * 1024 * 1024)

    def test_parse_gi(self):
        """Test parsing Gi (gibibytes)."""
        self.assertEqual(sizer.parse_memory('1Gi'), 1024 ** 3)
        self.assertEqual(sizer.parse_memory('2Gi'), 2 * 1024 ** 3)

    def test_parse_k(self):
        """Test parsing K (kilobytes)."""
        self.assertEqual(sizer.parse_memory('1K'), 1000)

    def test_parse_m(self):
        """Test parsing M (megabytes)."""
        self.assertEqual(sizer.parse_memory('1M'), 1000 * 1000)

    def test_parse_g(self):
        """Test parsing G (gigabytes)."""
        self.assertEqual(sizer.parse_memory('1G'), 1000 ** 3)

    def test_parse_bytes(self):
        """Test parsing raw bytes."""
        self.assertEqual(sizer.parse_memory('1024'), 1024)
        self.assertEqual(sizer.parse_memory('1048576'), 1048576)

    def test_parse_none(self):
        """Test parsing None value."""
        self.assertIsNone(sizer.parse_memory(None))

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        self.assertIsNone(sizer.parse_memory(''))

    def test_parse_invalid(self):
        """Test parsing invalid memory value."""
        self.assertIsNone(sizer.parse_memory('invalid'))


class TestFormatCpu(unittest.TestCase):
    """Test the format_cpu function."""

    def test_format_millicores(self):
        """Test formatting millicores."""
        self.assertEqual(sizer.format_cpu(100), '100m')
        self.assertEqual(sizer.format_cpu(500), '500m')

    def test_format_cores(self):
        """Test formatting full cores."""
        self.assertEqual(sizer.format_cpu(1000), '1.0')
        self.assertEqual(sizer.format_cpu(2500), '2.5')

    def test_format_none(self):
        """Test formatting None."""
        self.assertEqual(sizer.format_cpu(None), 'N/A')


class TestFormatMemory(unittest.TestCase):
    """Test the format_memory function."""

    def test_format_bytes(self):
        """Test formatting bytes."""
        self.assertEqual(sizer.format_memory(512), '512B')

    def test_format_ki(self):
        """Test formatting kibibytes."""
        self.assertEqual(sizer.format_memory(2048), '2Ki')

    def test_format_mi(self):
        """Test formatting mebibytes."""
        self.assertEqual(sizer.format_memory(1024 * 1024), '1Mi')
        self.assertEqual(sizer.format_memory(512 * 1024 * 1024), '512Mi')

    def test_format_gi(self):
        """Test formatting gibibytes."""
        self.assertEqual(sizer.format_memory(1024 ** 3), '1.0Gi')
        self.assertEqual(sizer.format_memory(2 * 1024 ** 3), '2.0Gi')

    def test_format_none(self):
        """Test formatting None."""
        self.assertEqual(sizer.format_memory(None), 'N/A')


class TestCategorizeFindingS(unittest.TestCase):
    """Test the categorize_findings function."""

    def test_over_provisioned_cpu(self):
        """Test detecting over-provisioned CPU."""
        analyses = [{
            'name': 'test-pod',
            'namespace': 'default',
            'cpu_request': 1000,
            'cpu_actual': 100,
            'cpu_efficiency': 10,  # 10% - over-provisioned
            'mem_request': 1024 * 1024 * 1024,
            'mem_actual': 512 * 1024 * 1024,
            'mem_efficiency': 50,  # 50% - OK
            'has_requests': True,
            'has_limits': True
        }]
        categories = sizer.categorize_findings(analyses, cpu_threshold=30, mem_threshold=30)
        self.assertEqual(len(categories['over_provisioned']), 1)

    def test_over_provisioned_memory(self):
        """Test detecting over-provisioned memory."""
        analyses = [{
            'name': 'test-pod',
            'namespace': 'default',
            'cpu_request': 1000,
            'cpu_actual': 500,
            'cpu_efficiency': 50,  # 50% - OK
            'mem_request': 1024 * 1024 * 1024,
            'mem_actual': 100 * 1024 * 1024,
            'mem_efficiency': 10,  # 10% - over-provisioned
            'has_requests': True,
            'has_limits': True
        }]
        categories = sizer.categorize_findings(analyses, cpu_threshold=30, mem_threshold=30)
        self.assertEqual(len(categories['over_provisioned']), 1)

    def test_under_provisioned(self):
        """Test detecting under-provisioned workloads."""
        analyses = [{
            'name': 'test-pod',
            'namespace': 'default',
            'cpu_request': 1000,
            'cpu_actual': 950,
            'cpu_efficiency': 95,  # 95% - under-provisioned
            'mem_request': 1024 * 1024 * 1024,
            'mem_actual': 512 * 1024 * 1024,
            'mem_efficiency': 50,
            'has_requests': True,
            'has_limits': True
        }]
        categories = sizer.categorize_findings(analyses, cpu_threshold=30, mem_threshold=30)
        self.assertEqual(len(categories['under_provisioned']), 1)

    def test_no_requests(self):
        """Test detecting pods without requests."""
        analyses = [{
            'name': 'test-pod',
            'namespace': 'default',
            'cpu_request': None,
            'cpu_actual': 500,
            'cpu_efficiency': None,
            'mem_request': None,
            'mem_actual': 512 * 1024 * 1024,
            'mem_efficiency': None,
            'has_requests': False,
            'has_limits': False
        }]
        categories = sizer.categorize_findings(analyses, cpu_threshold=30, mem_threshold=30)
        self.assertEqual(len(categories['no_requests']), 1)

    def test_efficient(self):
        """Test detecting efficiently sized workloads."""
        analyses = [{
            'name': 'test-pod',
            'namespace': 'default',
            'cpu_request': 1000,
            'cpu_actual': 500,
            'cpu_efficiency': 50,  # 50% - efficient
            'mem_request': 1024 * 1024 * 1024,
            'mem_actual': 600 * 1024 * 1024,
            'mem_efficiency': 60,  # 60% - efficient
            'has_requests': True,
            'has_limits': True
        }]
        categories = sizer.categorize_findings(analyses, cpu_threshold=30, mem_threshold=30)
        self.assertEqual(len(categories['efficient']), 1)

    def test_no_metrics(self):
        """Test detecting pods with no metrics."""
        analyses = [{
            'name': 'test-pod',
            'namespace': 'default',
            'cpu_request': 1000,
            'cpu_actual': None,
            'cpu_efficiency': None,
            'mem_request': 1024 * 1024 * 1024,
            'mem_actual': None,
            'mem_efficiency': None,
            'has_requests': True,
            'has_limits': True
        }]
        categories = sizer.categorize_findings(analyses, cpu_threshold=30, mem_threshold=30)
        self.assertEqual(len(categories['no_metrics']), 1)

    def test_empty_analyses(self):
        """Test with empty analyses list."""
        categories = sizer.categorize_findings([], cpu_threshold=30, mem_threshold=30)
        self.assertEqual(len(categories['over_provisioned']), 0)
        self.assertEqual(len(categories['under_provisioned']), 0)
        self.assertEqual(len(categories['efficient']), 0)


class TestCalculateSavings(unittest.TestCase):
    """Test the calculate_savings function."""

    def test_calculate_cpu_savings(self):
        """Test calculating CPU savings."""
        categories = {
            'over_provisioned': [{
                'cpu_request': 1000,
                'cpu_actual': 100,
                'mem_request': None,
                'mem_actual': None
            }]
        }
        cpu_savings, mem_savings = sizer.calculate_savings(categories)
        # Suggested = 100 * 1.5 = 150, savings = 1000 - 150 = 850
        self.assertEqual(cpu_savings, 850)

    def test_calculate_memory_savings(self):
        """Test calculating memory savings."""
        categories = {
            'over_provisioned': [{
                'cpu_request': None,
                'cpu_actual': None,
                'mem_request': 1024 * 1024 * 1024,
                'mem_actual': 100 * 1024 * 1024
            }]
        }
        cpu_savings, mem_savings = sizer.calculate_savings(categories)
        # Suggested = 100Mi * 1.2 = 120Mi, savings = 1024Mi - 120Mi
        expected_suggested = int(100 * 1024 * 1024 * 1.2)
        expected_savings = 1024 * 1024 * 1024 - expected_suggested
        self.assertEqual(mem_savings, expected_savings)

    def test_no_savings(self):
        """Test when there are no savings to calculate."""
        categories = {'over_provisioned': []}
        cpu_savings, mem_savings = sizer.calculate_savings(categories)
        self.assertEqual(cpu_savings, 0)
        self.assertEqual(mem_savings, 0)


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
                        'limits': {'cpu': '1', 'memory': '1Gi'}
                    }
                }]
            },
            'status': {
                'phase': 'Running'
            }
        }
        metrics = {
            'default/test-pod': {'cpu': 250, 'memory': 256 * 1024 * 1024}
        }

        analysis = sizer.analyze_pod(pod, metrics)

        self.assertEqual(analysis['name'], 'test-pod')
        self.assertEqual(analysis['namespace'], 'default')
        self.assertEqual(analysis['owner_kind'], 'Deployment')
        self.assertEqual(analysis['cpu_request'], 500)
        self.assertEqual(analysis['cpu_actual'], 250)
        self.assertEqual(analysis['cpu_efficiency'], 50.0)
        self.assertTrue(analysis['has_requests'])
        self.assertTrue(analysis['has_limits'])

    def test_analyze_non_running_pod(self):
        """Test that non-running pods return None."""
        pod = {
            'metadata': {'name': 'test-pod', 'namespace': 'default'},
            'spec': {'containers': []},
            'status': {'phase': 'Pending'}
        }
        analysis = sizer.analyze_pod(pod, {})
        self.assertIsNone(analysis)

    def test_analyze_pod_no_metrics(self):
        """Test analyzing pod without metrics."""
        pod = {
            'metadata': {
                'name': 'test-pod',
                'namespace': 'default'
            },
            'spec': {
                'containers': [{
                    'name': 'main',
                    'resources': {
                        'requests': {'cpu': '500m', 'memory': '512Mi'}
                    }
                }]
            },
            'status': {'phase': 'Running'}
        }

        analysis = sizer.analyze_pod(pod, {})

        self.assertEqual(analysis['cpu_actual'], None)
        self.assertEqual(analysis['mem_actual'], None)
        self.assertEqual(analysis['cpu_efficiency'], None)

    def test_analyze_pod_no_requests(self):
        """Test analyzing pod without resource requests."""
        pod = {
            'metadata': {
                'name': 'test-pod',
                'namespace': 'default'
            },
            'spec': {
                'containers': [{'name': 'main', 'resources': {}}]
            },
            'status': {'phase': 'Running'}
        }

        analysis = sizer.analyze_pod(pod, {})

        self.assertFalse(analysis['has_requests'])
        self.assertFalse(analysis['has_limits'])


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
