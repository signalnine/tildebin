#!/usr/bin/env python3
"""
Tests for k8s_kubelet_health_monitor.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, and error handling.
"""

import subprocess
import sys
import unittest


def run_command(cmd_args, input_data=None):
    """Run the k8s_kubelet_health_monitor.py script with given arguments."""
    cmd = [sys.executable, 'k8s_kubelet_health_monitor.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestKubeletHealthMonitor(unittest.TestCase):
    """Test cases for k8s_kubelet_health_monitor.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('kubelet', stdout.lower())
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--node', stdout)
        self.assertIn('--label', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('kubelet', stdout.lower())

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

    def test_node_option(self):
        """Test --node option is accepted."""
        returncode, stdout, stderr = run_command(['--node', 'test-node'])
        self.assertIn(returncode, [1, 2])

    def test_node_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'test-node'])
        self.assertIn(returncode, [1, 2])

    def test_label_option(self):
        """Test --label option is accepted."""
        returncode, stdout, stderr = run_command(['--label', 'node-role.kubernetes.io/worker='])
        self.assertIn(returncode, [1, 2])

    def test_label_option_short(self):
        """Test -l short option works."""
        returncode, stdout, stderr = run_command(['-l', 'env=prod'])
        self.assertIn(returncode, [1, 2])

    def test_skip_events_option(self):
        """Test --skip-events option is accepted."""
        returncode, stdout, stderr = run_command(['--skip-events'])
        self.assertIn(returncode, [1, 2])

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
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '--skip-events'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command(
            ['--format', 'plain', '--warn-only', '--skip-events', '--verbose']
        )
        self.assertIn(returncode, [1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
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
        with open('k8s_kubelet_health_monitor.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_kubelet_health_monitor.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('kubelet', content[:500].lower())

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_kubelet_health_monitor.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_script_has_main_function(self):
        """Test that script has main function and proper entry point."""
        with open('k8s_kubelet_health_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('def main():', content)
        self.assertIn("if __name__ == '__main__':", content)

    def test_script_documents_exit_codes(self):
        """Test that script documents exit codes in docstring."""
        with open('k8s_kubelet_health_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('Exit codes:', content)
        self.assertIn('0 -', content)
        self.assertIn('1 -', content)
        self.assertIn('2 -', content)


class TestOutputFormats(unittest.TestCase):
    """Test output format handling."""

    def test_all_format_options_are_documented(self):
        """Test that all format options appear in help."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertIn('plain', stdout)
        self.assertIn('table', stdout)
        self.assertIn('json', stdout)

    def test_default_format_is_table(self):
        """Test that default format is table."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertIn('default: table', stdout)


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
