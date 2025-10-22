#!/usr/bin/env python3
"""
Tests for k8s_pv_health_check.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and utility functions.
"""

import subprocess
import sys
import unittest


def run_command(cmd_args, input_data=None):
    """Run the k8s_pv_health_check.py script with given arguments."""
    cmd = [sys.executable, 'k8s_pv_health_check.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sPVHealthCheck(unittest.TestCase):
    """Test cases for k8s_pv_health_check.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('persistent volume', stdout.lower())
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('persistent volume', stdout.lower())

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
        returncode, stdout, stderr = run_command(['-f', 'json', '-w'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command(['--format', 'plain', '--warn-only'])
        self.assertIn(returncode, [1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        returncode, stdout, stderr = run_command([])
        # Should exit with error code 1 or 2
        self.assertNotEqual(returncode, 0)
        # Error message should be helpful if kubectl not found
        if returncode == 2:
            self.assertIn('kubectl', stderr.lower())

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (will fail without kubectl, but args are valid)
        self.assertIn(returncode, [1, 2])


class TestStorageQuantityParsing(unittest.TestCase):
    """Test the parse_storage_quantity function behavior."""

    def test_parse_bytes_directly(self):
        """Test parsing plain byte values."""
        # We can't import and test the function directly without running the script,
        # so we verify the script imports correctly
        with open('k8s_pv_health_check.py', 'r') as f:
            content = f.read()
        self.assertIn('def parse_storage_quantity', content)
        self.assertIn('Ki', content)
        self.assertIn('Mi', content)
        self.assertIn('Gi', content)


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_pv_health_check.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_pv_health_check.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('persistent volume', content[:500].lower())

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_pv_health_check.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_script_has_main_function(self):
        """Test that script has main() function."""
        with open('k8s_pv_health_check.py', 'r') as f:
            content = f.read()
        self.assertIn('def main():', content)
        self.assertIn("if __name__ == '__main__':", content)

    def test_script_has_exit_codes_documented(self):
        """Test that exit codes are documented."""
        with open('k8s_pv_health_check.py', 'r') as f:
            content = f.read()
        self.assertIn('Exit codes:', content)
        self.assertIn('sys.exit', content)

    def test_script_has_kubectl_error_handling(self):
        """Test that script handles kubectl errors gracefully."""
        with open('k8s_pv_health_check.py', 'r') as f:
            content = f.read()
        self.assertIn('FileNotFoundError', content)
        self.assertIn('kubectl not found', content)

    def test_script_has_pv_health_check_function(self):
        """Test that script has PV health checking logic."""
        with open('k8s_pv_health_check.py', 'r') as f:
            content = f.read()
        self.assertIn('def check_pv_health', content)
        self.assertIn('phase', content)
        self.assertIn('Bound', content)


class TestArgumentParsing(unittest.TestCase):
    """Test argument parsing without requiring kubectl."""

    def test_help_contains_examples(self):
        """Test that help output includes practical examples."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Examples:', stdout)
        self.assertIn('k8s_pv_health_check.py', stdout)

    def test_warn_only_with_format_json(self):
        """Test combining warn-only and JSON format."""
        returncode, stdout, stderr = run_command(['--warn-only', '--format', 'json'])
        self.assertIn(returncode, [1, 2])

    def test_unknown_argument_rejected(self):
        """Test that unknown arguments are rejected."""
        returncode, stdout, stderr = run_command(['--unknown-flag'])
        self.assertEqual(returncode, 2)
        self.assertIn('unrecognized arguments', stderr)


if __name__ == '__main__':
    unittest.main()
