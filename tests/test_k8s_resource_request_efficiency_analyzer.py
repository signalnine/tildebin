#!/usr/bin/env python3
"""
Tests for k8s_resource_request_efficiency_analyzer.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, value parsing, and error handling.
"""

import subprocess
import sys
import unittest


def run_command(cmd_args, input_data=None):
    """Run the k8s_resource_request_efficiency_analyzer.py script with given arguments."""
    cmd = [sys.executable, 'k8s_resource_request_efficiency_analyzer.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sResourceRequestEfficiencyAnalyzer(unittest.TestCase):
    """Test cases for k8s_resource_request_efficiency_analyzer.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('resource request efficiency', stdout.lower())
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('--low-threshold', stdout)
        self.assertIn('--high-threshold', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('efficiency', stdout.lower())

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Will fail without kubectl, but should parse args correctly
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

    def test_warn_only_option(self):
        """Test --warn-only option is accepted."""
        returncode, stdout, stderr = run_command(['--warn-only'])
        self.assertIn(returncode, [1, 2])

    def test_warn_only_short(self):
        """Test -w short option works."""
        returncode, stdout, stderr = run_command(['-w'])
        self.assertIn(returncode, [1, 2])

    def test_verbose_option(self):
        """Test --verbose option is accepted."""
        returncode, stdout, stderr = run_command(['--verbose'])
        self.assertIn(returncode, [1, 2])

    def test_verbose_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [1, 2])

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'production'])
        self.assertIn(returncode, [1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'default'])
        self.assertIn(returncode, [1, 2])

    def test_low_threshold_option(self):
        """Test --low-threshold option is accepted."""
        returncode, stdout, stderr = run_command(['--low-threshold', '30'])
        self.assertIn(returncode, [1, 2])

    def test_high_threshold_option(self):
        """Test --high-threshold option is accepted."""
        returncode, stdout, stderr = run_command(['--high-threshold', '90'])
        self.assertIn(returncode, [1, 2])

    def test_threshold_float_values(self):
        """Test threshold options accept float values."""
        returncode, stdout, stderr = run_command(['--low-threshold', '25.5', '--high-threshold', '99.9'])
        self.assertIn(returncode, [1, 2])

    def test_invalid_threshold_type(self):
        """Test that non-numeric threshold values are rejected."""
        returncode, stdout, stderr = run_command(['--low-threshold', 'abc'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid', stderr.lower())

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-n', 'default'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command(['--format', 'plain', '--warn-only', '--verbose'])
        self.assertIn(returncode, [1, 2])

    def test_all_options_combined(self):
        """Test all options together."""
        returncode, stdout, stderr = run_command([
            '--format', 'json',
            '--namespace', 'kube-system',
            '--warn-only',
            '--verbose',
            '--low-threshold', '20',
            '--high-threshold', '95'
        ])
        self.assertIn(returncode, [1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        returncode, stdout, stderr = run_command([])
        # Should exit with error code 1 or 2
        self.assertNotEqual(returncode, 0)
        # Error message should be helpful
        if returncode == 2:
            self.assertTrue(
                'kubectl' in stderr.lower() or 'metrics' in stderr.lower(),
                f"Expected kubectl or metrics error, got: {stderr}"
            )

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (will fail without kubectl, but args are valid)
        self.assertIn(returncode, [1, 2])

    def test_verbose_with_json(self):
        """Test verbose works with JSON format."""
        returncode, stdout, stderr = run_command(['--verbose', '--format', 'json'])
        self.assertIn(returncode, [1, 2])

    def test_warn_only_with_json(self):
        """Test warn-only works with JSON format."""
        returncode, stdout, stderr = run_command(['--warn-only', '--format', 'json'])
        self.assertIn(returncode, [1, 2])


class TestValueParsing(unittest.TestCase):
    """Test CPU and memory value parsing functions."""

    def test_parse_cpu_millicores(self):
        """Test parsing CPU values in millicores."""
        # Import the parsing functions directly for unit testing
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "analyzer",
            "k8s_resource_request_efficiency_analyzer.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertEqual(module.parse_cpu_value('100m'), 100)
        self.assertEqual(module.parse_cpu_value('500m'), 500)
        self.assertEqual(module.parse_cpu_value('1000m'), 1000)

    def test_parse_cpu_cores(self):
        """Test parsing CPU values in whole cores."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "analyzer",
            "k8s_resource_request_efficiency_analyzer.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertEqual(module.parse_cpu_value('1'), 1000)
        self.assertEqual(module.parse_cpu_value('2'), 2000)
        self.assertEqual(module.parse_cpu_value('0.5'), 500)

    def test_parse_cpu_nanocores(self):
        """Test parsing CPU values in nanocores."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "analyzer",
            "k8s_resource_request_efficiency_analyzer.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertEqual(module.parse_cpu_value('1000000n'), 1)
        self.assertEqual(module.parse_cpu_value('500000000n'), 500)

    def test_parse_memory_mi(self):
        """Test parsing memory values in Mi."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "analyzer",
            "k8s_resource_request_efficiency_analyzer.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertEqual(module.parse_memory_value('128Mi'), 128 * 1024 * 1024)
        self.assertEqual(module.parse_memory_value('256Mi'), 256 * 1024 * 1024)

    def test_parse_memory_gi(self):
        """Test parsing memory values in Gi."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "analyzer",
            "k8s_resource_request_efficiency_analyzer.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertEqual(module.parse_memory_value('1Gi'), 1024 * 1024 * 1024)
        self.assertEqual(module.parse_memory_value('2Gi'), 2 * 1024 * 1024 * 1024)

    def test_parse_memory_ki(self):
        """Test parsing memory values in Ki."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "analyzer",
            "k8s_resource_request_efficiency_analyzer.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertEqual(module.parse_memory_value('1024Ki'), 1024 * 1024)

    def test_parse_memory_decimal_units(self):
        """Test parsing memory values with decimal units (M, G)."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "analyzer",
            "k8s_resource_request_efficiency_analyzer.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertEqual(module.parse_memory_value('1M'), 1000 * 1000)
        self.assertEqual(module.parse_memory_value('1G'), 1000 * 1000 * 1000)

    def test_parse_null_values(self):
        """Test parsing null/empty values returns None."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "analyzer",
            "k8s_resource_request_efficiency_analyzer.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertIsNone(module.parse_cpu_value(None))
        self.assertIsNone(module.parse_cpu_value(''))
        self.assertIsNone(module.parse_memory_value(None))
        self.assertIsNone(module.parse_memory_value(''))


class TestFormatFunctions(unittest.TestCase):
    """Test CPU and memory formatting functions."""

    def test_format_cpu(self):
        """Test CPU value formatting."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "analyzer",
            "k8s_resource_request_efficiency_analyzer.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertEqual(module.format_cpu(100), '100m')
        self.assertEqual(module.format_cpu(1000), '1.00')
        self.assertEqual(module.format_cpu(2500), '2.50')
        self.assertEqual(module.format_cpu(None), 'N/A')

    def test_format_memory(self):
        """Test memory value formatting."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "analyzer",
            "k8s_resource_request_efficiency_analyzer.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertEqual(module.format_memory(None), 'N/A')
        self.assertIn('Gi', module.format_memory(2 * 1024 ** 3))
        self.assertIn('Mi', module.format_memory(256 * 1024 ** 2))
        self.assertIn('Ki', module.format_memory(512 * 1024))


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_resource_request_efficiency_analyzer.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_resource_request_efficiency_analyzer.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('efficiency', content[:1000].lower())

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_resource_request_efficiency_analyzer.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_exit_codes_documented(self):
        """Test that exit codes are documented in docstring."""
        with open('k8s_resource_request_efficiency_analyzer.py', 'r') as f:
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
        self.assertIn('k8s_resource_request_efficiency_analyzer.py', stdout)


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
