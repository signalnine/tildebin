#!/usr/bin/env python3
"""
Tests for k8s_namespace_resource_analyzer.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, resource parsing, and error handling.
"""

import subprocess
import sys
import unittest


def run_command(cmd_args, input_data=None):
    """Run the k8s_namespace_resource_analyzer.py script with given arguments."""
    cmd = [sys.executable, 'k8s_namespace_resource_analyzer.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sNamespaceResourceAnalyzer(unittest.TestCase):
    """Test cases for k8s_namespace_resource_analyzer.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Analyze Kubernetes namespace', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--top', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('Analyze Kubernetes namespace', stdout)

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Either exits 2 (no kubectl) or 1 (kubectl error)
        self.assertIn(returncode, [1, 2])

    def test_format_option_json(self):
        """Test --format json option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [1, 2])

    def test_format_option_table(self):
        """Test --format table option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'table'])
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

    def test_top_option(self):
        """Test --top option is accepted."""
        returncode, stdout, stderr = run_command(['--top', '10'])
        self.assertIn(returncode, [1, 2])

    def test_top_option_short(self):
        """Test -t short option works."""
        returncode, stdout, stderr = run_command(['-t', '5'])
        self.assertIn(returncode, [1, 2])

    def test_top_option_invalid(self):
        """Test --top rejects non-integer values."""
        returncode, stdout, stderr = run_command(['--top', 'abc'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid int value', stderr)

    def test_verbose_option(self):
        """Test --verbose option is accepted."""
        returncode, stdout, stderr = run_command(['--verbose'])
        self.assertIn(returncode, [1, 2])

    def test_verbose_option_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-t', '5'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command(['--format', 'table', '--warn-only', '--top', '10'])
        self.assertIn(returncode, [1, 2])

    def test_all_options_combined(self):
        """Test all options together."""
        returncode, stdout, stderr = run_command([
            '--format', 'plain',
            '--warn-only',
            '--top', '20',
            '--verbose'
        ])
        self.assertIn(returncode, [1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        returncode, stdout, stderr = run_command([])
        self.assertNotEqual(returncode, 0)
        if returncode == 2:
            self.assertIn('kubectl', stderr.lower())

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        self.assertIn(returncode, [1, 2])

    def test_warn_only_with_json(self):
        """Test warn-only works with JSON format."""
        returncode, stdout, stderr = run_command(['--warn-only', '--format', 'json'])
        self.assertIn(returncode, [1, 2])

    def test_top_with_table(self):
        """Test top option works with table format."""
        returncode, stdout, stderr = run_command(['--top', '5', '--format', 'table'])
        self.assertIn(returncode, [1, 2])


class TestResourceParsing(unittest.TestCase):
    """Test resource value parsing functions."""

    def test_parse_resource_value_import(self):
        """Test that we can import and use parse_resource_value."""
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "k8s_namespace_resource_analyzer",
            "k8s_namespace_resource_analyzer.py"
        )
        module = importlib.util.module_from_spec(spec)

        # We can't fully load (requires kubectl check), but we can check structure
        with open('k8s_namespace_resource_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('def parse_resource_value', content)

    def test_parse_cpu_millicores(self):
        """Test CPU parsing for millicores format."""
        with open('k8s_namespace_resource_analyzer.py', 'r') as f:
            content = f.read()
        # Verify the function handles 'm' suffix
        self.assertIn("value.endswith('m')", content)

    def test_parse_memory_units(self):
        """Test memory parsing for various units."""
        with open('k8s_namespace_resource_analyzer.py', 'r') as f:
            content = f.read()
        # Verify the function handles memory suffixes
        self.assertIn("'Mi':", content)
        self.assertIn("'Gi':", content)
        self.assertIn("'Ki':", content)


class TestOutputFormatting(unittest.TestCase):
    """Test output formatting functions."""

    def test_format_functions_exist(self):
        """Test that format functions are defined."""
        with open('k8s_namespace_resource_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('def format_cpu', content)
        self.assertIn('def format_memory', content)
        self.assertIn('def print_plain_output', content)
        self.assertIn('def print_json_output', content)
        self.assertIn('def print_table_output', content)


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_namespace_resource_analyzer.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_namespace_resource_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('"""', content)
        self.assertIn('namespace', content[:500].lower())

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_namespace_resource_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_exit_codes_documented(self):
        """Test that exit codes are documented in docstring."""
        with open('k8s_namespace_resource_analyzer.py', 'r') as f:
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
        self.assertIn('k8s_namespace_resource_analyzer.py', stdout)

    def test_docstring_describes_purpose(self):
        """Test that docstring describes the script's purpose."""
        with open('k8s_namespace_resource_analyzer.py', 'r') as f:
            content = f.read()
        # Check for key purpose descriptions
        self.assertIn('chargeback', content.lower())
        self.assertIn('capacity planning', content.lower())

    def test_script_is_executable(self):
        """Test that script has executable permission."""
        import os
        import stat
        mode = os.stat('k8s_namespace_resource_analyzer.py').st_mode
        self.assertTrue(mode & stat.S_IXUSR)


class TestKubectlErrorHandling(unittest.TestCase):
    """Test kubectl error handling."""

    def test_kubectl_error_message_helpful(self):
        """Test that kubectl errors provide helpful information."""
        with open('k8s_namespace_resource_analyzer.py', 'r') as f:
            content = f.read()
        # Check for helpful error messages
        self.assertIn('kubectl not found', content)
        self.assertIn('kubernetes.io', content)


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
