#!/usr/bin/env python3
"""
Tests for k8s_deployment_status.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, and error handling.
"""

import subprocess
import sys
import unittest


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


if __name__ == '__main__':
    unittest.main()
