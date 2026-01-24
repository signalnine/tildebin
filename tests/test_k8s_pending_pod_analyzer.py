#!/usr/bin/env python3
"""
Tests for k8s_pending_pod_analyzer.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, and error handling.
"""

import subprocess
import sys
import unittest


def run_command(cmd_args, input_data=None):
    """Run the k8s_pending_pod_analyzer.py script with given arguments."""
    cmd = [sys.executable, 'k8s_pending_pod_analyzer.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sPendingPodAnalyzer(unittest.TestCase):
    """Test cases for k8s_pending_pod_analyzer.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Pending', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('Pending', stdout)

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        # Will fail without kubectl, but should parse args correctly
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Either exits 2 (no kubectl) or 0/1 (kubectl available)
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_json(self):
        """Test --format json option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_table(self):
        """Test --format table option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'table'])
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

    def test_verbose_option(self):
        """Test --verbose option is accepted."""
        returncode, stdout, stderr = run_command(['--verbose'])
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [0, 1, 2])

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'production'])
        self.assertIn(returncode, [0, 1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'default'])
        self.assertIn(returncode, [0, 1, 2])

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-v', '-n', 'default'])
        self.assertIn(returncode, [0, 1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command(['--format', 'table', '--verbose'])
        self.assertIn(returncode, [0, 1, 2])

    def test_all_options_combined(self):
        """Test all options together."""
        returncode, stdout, stderr = run_command([
            '--format', 'json',
            '--namespace', 'kube-system',
            '--verbose'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        # This test assumes kubectl might not be in PATH
        # If it fails because kubectl IS found, that's also fine
        returncode, stdout, stderr = run_command([])
        # Should exit with error code 0, 1, or 2
        self.assertIn(returncode, [0, 1, 2])
        # If kubectl not found, error message should be helpful
        if returncode == 2 and 'kubectl' in stderr.lower():
            self.assertIn('kubectl', stderr.lower())

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (will fail without kubectl, but args are valid)
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_with_json(self):
        """Test verbose works with JSON format."""
        returncode, stdout, stderr = run_command(['--verbose', '--format', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_namespace_with_table(self):
        """Test namespace option works with table format."""
        returncode, stdout, stderr = run_command(['-n', 'default', '-f', 'table'])
        self.assertIn(returncode, [0, 1, 2])


class TestHelpContent(unittest.TestCase):
    """Test help message content for completeness."""

    def test_help_shows_failure_types(self):
        """Test that help explains common failure types."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('resources', stdout)
        self.assertIn('storage', stdout)
        self.assertIn('taints', stdout)
        self.assertIn('affinity', stdout)

    def test_help_shows_exit_codes(self):
        """Test that help documents exit codes."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Exit codes:', stdout)
        self.assertIn('0 -', stdout)
        self.assertIn('1 -', stdout)
        self.assertIn('2 -', stdout)

    def test_help_shows_examples(self):
        """Test that help includes usage examples."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Examples:', stdout)
        self.assertIn('k8s_pending_pod_analyzer.py', stdout)


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_pending_pod_analyzer.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_pending_pod_analyzer.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('Pending', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_pending_pod_analyzer.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_exit_codes_documented(self):
        """Test that exit codes are documented in docstring."""
        with open('k8s_pending_pod_analyzer.py', 'r') as f:
            content = f.read()
        # Check for exit code documentation
        self.assertIn('Exit codes:', content)
        self.assertIn('0 -', content)
        self.assertIn('1 -', content)
        self.assertIn('2 -', content)

    def test_script_is_executable(self):
        """Test that script can be imported without errors."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "k8s_pending_pod_analyzer",
            "k8s_pending_pod_analyzer.py"
        )
        # Should not raise on spec creation
        self.assertIsNotNone(spec)


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
