#!/usr/bin/env python3
"""
Tests for baremetal_process_tree_analyzer.py

These tests validate the script's behavior without requiring specific
process states. Tests cover argument parsing, help messages, and error handling.
"""

import subprocess
import sys
import unittest


def run_command(cmd_args, input_data=None):
    """Run the baremetal_process_tree_analyzer.py script with given arguments."""
    cmd = [sys.executable, 'baremetal_process_tree_analyzer.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestBaremetalProcessTreeAnalyzer(unittest.TestCase):
    """Test cases for baremetal_process_tree_analyzer.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('process tree', stdout.lower())
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('--max-depth', stdout)
        self.assertIn('--max-children', stdout)
        self.assertIn('--orphan-age', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('process tree', stdout.lower())

    def test_default_execution(self):
        """Test that script runs with default arguments."""
        returncode, stdout, stderr = run_command([])
        # Should succeed and produce output
        self.assertIn(returncode, [0, 1])
        self.assertIn('Process Tree Analysis', stdout)
        self.assertIn('Total processes:', stdout)

    def test_format_option_plain(self):
        """Test --format plain option."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        self.assertIn(returncode, [0, 1])
        self.assertIn('Process Tree Analysis', stdout)

    def test_format_option_json(self):
        """Test --format json option produces valid JSON."""
        import json
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [0, 1])
        # Should be valid JSON
        data = json.loads(stdout)
        self.assertIn('issues', data)
        self.assertIn('warnings', data)
        self.assertIn('stats', data)
        self.assertIn('summary', data)
        self.assertIn('total_processes', data['stats'])

    def test_format_option_short(self):
        """Test -f short option works."""
        returncode, stdout, stderr = run_command(['-f', 'json'])
        self.assertIn(returncode, [0, 1])

    def test_invalid_format(self):
        """Test that invalid format values are rejected."""
        returncode, stdout, stderr = run_command(['--format', 'invalid'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid choice', stderr)

    def test_verbose_option(self):
        """Test --verbose option shows depth distribution."""
        returncode, stdout, stderr = run_command(['--verbose'])
        self.assertIn(returncode, [0, 1])
        self.assertIn('Depth Distribution:', stdout)

    def test_verbose_option_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [0, 1])
        self.assertIn('Depth Distribution:', stdout)

    def test_warn_only_option(self):
        """Test --warn-only option is accepted."""
        returncode, stdout, stderr = run_command(['--warn-only'])
        self.assertIn(returncode, [0, 1])

    def test_warn_only_short(self):
        """Test -w short option works."""
        returncode, stdout, stderr = run_command(['-w'])
        self.assertIn(returncode, [0, 1])

    def test_max_depth_option(self):
        """Test --max-depth option accepts integer values."""
        returncode, stdout, stderr = run_command(['--max-depth', '15'])
        self.assertIn(returncode, [0, 1])

    def test_max_depth_invalid_zero(self):
        """Test that --max-depth rejects zero."""
        returncode, stdout, stderr = run_command(['--max-depth', '0'])
        self.assertEqual(returncode, 2)
        self.assertIn('must be >= 1', stderr)

    def test_max_depth_invalid_negative(self):
        """Test that --max-depth rejects negative values."""
        returncode, stdout, stderr = run_command(['--max-depth', '-5'])
        self.assertEqual(returncode, 2)

    def test_max_depth_invalid_string(self):
        """Test that --max-depth rejects non-integer values."""
        returncode, stdout, stderr = run_command(['--max-depth', 'invalid'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid', stderr.lower())

    def test_max_children_option(self):
        """Test --max-children option accepts integer values."""
        returncode, stdout, stderr = run_command(['--max-children', '50'])
        self.assertIn(returncode, [0, 1])

    def test_max_children_invalid_zero(self):
        """Test that --max-children rejects zero."""
        returncode, stdout, stderr = run_command(['--max-children', '0'])
        self.assertEqual(returncode, 2)
        self.assertIn('must be >= 1', stderr)

    def test_orphan_age_option(self):
        """Test --orphan-age option accepts float values."""
        returncode, stdout, stderr = run_command(['--orphan-age', '12.5'])
        self.assertIn(returncode, [0, 1])

    def test_orphan_age_invalid_negative(self):
        """Test that --orphan-age rejects negative values."""
        returncode, stdout, stderr = run_command(['--orphan-age', '-1'])
        self.assertEqual(returncode, 2)
        self.assertIn('must be >= 0', stderr)

    def test_orphan_warn_option(self):
        """Test --orphan-warn option is accepted."""
        returncode, stdout, stderr = run_command(['--orphan-warn', '2.0'])
        self.assertIn(returncode, [0, 1])

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command([
            '-f', 'json', '-v', '--max-depth', '10', '--max-children', '50'
        ])
        self.assertIn(returncode, [0, 1])

    def test_json_stats_structure(self):
        """Test that JSON output has proper stats structure."""
        import json
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [0, 1])
        data = json.loads(stdout)

        # Check stats fields
        stats = data['stats']
        self.assertIn('total_processes', stats)
        self.assertIn('orphan_count', stats)
        self.assertIn('deep_trees', stats)
        self.assertIn('max_depth', stats)
        self.assertIn('max_children', stats)
        self.assertIn('depth_distribution', stats)

        # Check summary fields
        summary = data['summary']
        self.assertIn('issue_count', summary)
        self.assertIn('warning_count', summary)
        self.assertIn('healthy', summary)

    def test_process_count_positive(self):
        """Test that script finds a positive number of processes."""
        import json
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [0, 1])
        data = json.loads(stdout)
        self.assertGreater(data['stats']['total_processes'], 0)

    def test_depth_distribution_not_empty(self):
        """Test that depth distribution is populated."""
        import json
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [0, 1])
        data = json.loads(stdout)
        self.assertGreater(len(data['stats']['depth_distribution']), 0)


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('baremetal_process_tree_analyzer.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('baremetal_process_tree_analyzer.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('process tree', content[:500].lower())

    def test_script_has_exit_codes_documented(self):
        """Test that exit codes are documented in docstring."""
        with open('baremetal_process_tree_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('Exit codes:', content)
        self.assertIn('0 -', content)
        self.assertIn('1 -', content)
        self.assertIn('2 -', content)

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('baremetal_process_tree_analyzer.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)
        self.assertIn('import os', content)

    def test_script_has_main_function(self):
        """Test that script has main function."""
        with open('baremetal_process_tree_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('def main():', content)
        self.assertIn("if __name__ == '__main__':", content)

    def test_script_is_executable(self):
        """Test that script is executable."""
        import os
        import stat
        mode = os.stat('baremetal_process_tree_analyzer.py').st_mode
        self.assertTrue(mode & stat.S_IXUSR)


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
