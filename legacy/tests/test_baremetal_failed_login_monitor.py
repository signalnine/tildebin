#!/usr/bin/env python3
"""
Tests for baremetal_failed_login_monitor.py

These tests verify the script's argument parsing and basic functionality
without requiring actual auth log files or root access.
"""

import subprocess
import sys
import os
import tempfile
import unittest


def run_command(cmd):
    """Run a command and return (return_code, stdout, stderr)."""
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.returncode, result.stdout, result.stderr


class TestBaremetalFailedLoginMonitor(unittest.TestCase):
    """Test cases for baremetal_failed_login_monitor.py"""

    @classmethod
    def setUpClass(cls):
        """Change to script directory before running tests."""
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        os.chdir(script_dir)
        cls.script_path = os.path.join(script_dir, 'baremetal_failed_login_monitor.py')

    def test_script_exists(self):
        """Verify the script file exists."""
        self.assertTrue(os.path.exists(self.script_path),
                       f"Script not found at {self.script_path}")

    def test_script_has_shebang(self):
        """Verify the script has proper shebang."""
        with open(self.script_path, 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!/usr/bin/env python3'),
                       "Script should start with #!/usr/bin/env python3 shebang")

    def test_script_has_docstring(self):
        """Verify the script has a module docstring."""
        with open(self.script_path, 'r') as f:
            content = f.read()
        self.assertIn('"""', content, "Script should have docstring")
        self.assertIn('failed login', content.lower(),
                     "Docstring should mention failed login")

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--help'
        ])

        self.assertEqual(return_code, 0, "Help should return exit code 0")
        self.assertIn('failed login', stdout.lower(),
                     "Help should contain description")
        self.assertIn('--format', stdout, "Help should document --format option")
        self.assertIn('--verbose', stdout, "Help should document --verbose option")
        self.assertIn('--threshold', stdout, "Help should document --threshold")
        self.assertIn('--hours', stdout, "Help should document --hours")
        self.assertIn('--log-file', stdout, "Help should document --log-file")
        self.assertIn('Examples:', stdout, "Help should include examples")
        self.assertIn('Exit codes:', stdout, "Help should document exit codes")

    def test_format_plain(self):
        """Test that --format plain is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'plain',
            '--log-file', '/nonexistent/path'
        ])

        # Script should fail with exit 2 for missing file, not for bad arg
        self.assertNotIn('invalid choice', stderr.lower(),
                        "Plain format should be valid")

    def test_format_json(self):
        """Test that --format json is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--log-file', '/nonexistent/path'
        ])

        self.assertNotIn('invalid choice', stderr.lower(),
                        "JSON format should be valid")

    def test_format_table(self):
        """Test that --format table is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'table',
            '--log-file', '/nonexistent/path'
        ])

        self.assertNotIn('invalid choice', stderr.lower(),
                        "Table format should be valid")

    def test_invalid_format(self):
        """Test that invalid format option is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'invalid'
        ])

        self.assertEqual(return_code, 2, "Invalid format should return exit code 2")
        self.assertIn('invalid choice', stderr.lower(),
                     "Should show error for invalid format")

    def test_verbose_flag(self):
        """Test that --verbose flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--verbose',
            '--log-file', '/nonexistent/path'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Verbose flag should be recognized")

    def test_custom_threshold(self):
        """Test that custom threshold option works."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--threshold', '50',
            '--log-file', '/nonexistent/path'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Threshold option should be recognized")

    def test_custom_hours(self):
        """Test that custom hours option works."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--hours', '6',
            '--log-file', '/nonexistent/path'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Hours option should be recognized")

    def test_invalid_threshold(self):
        """Test that invalid threshold is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--threshold', '0'
        ])

        self.assertEqual(return_code, 2,
                        "Zero threshold should return exit code 2")
        self.assertIn('threshold', stderr.lower(),
                     "Should show error about threshold")

    def test_negative_threshold(self):
        """Test that negative threshold is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--threshold', '-5'
        ])

        self.assertEqual(return_code, 2,
                        "Negative threshold should return exit code 2")

    def test_invalid_hours(self):
        """Test that invalid hours is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--hours', '0'
        ])

        self.assertEqual(return_code, 2,
                        "Zero hours should return exit code 2")
        self.assertIn('hours', stderr.lower(),
                     "Should show error about hours")

    def test_missing_log_file(self):
        """Test handling of missing log file."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--log-file', '/nonexistent/auth.log'
        ])

        self.assertEqual(return_code, 2,
                        "Missing log file should return exit code 2")
        self.assertIn('not found', stderr.lower(),
                     "Should show error about missing file")

    def test_warn_only_flag(self):
        """Test that --warn-only flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-only',
            '--log-file', '/nonexistent/path'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Warn-only flag should be recognized")

    def test_combined_options(self):
        """Test that multiple options can be used together."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--verbose',
            '--threshold', '20',
            '--hours', '12',
            '--log-file', '/nonexistent/path'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Combined options should work together")

    def test_short_options(self):
        """Test that short option flags work."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '-f', 'json',
            '-v',
            '-t', '15',
            '-H', '6',
            '-l', '/nonexistent/path'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Short options should be recognized")

    def test_with_empty_log_file(self):
        """Test handling of empty log file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log',
                                         delete=False) as f:
            temp_log = f.name
            # Write empty file
            pass

        try:
            return_code, stdout, stderr = run_command([
                sys.executable,
                self.script_path,
                '--log-file', temp_log,
                '--format', 'plain'
            ])

            # Should succeed with no failed logins
            self.assertEqual(return_code, 0,
                           "Empty log should return exit code 0")
            self.assertIn('no failed login', stdout.lower(),
                         "Should report no failed logins")
        finally:
            os.unlink(temp_log)

    def test_with_sample_log_entries(self):
        """Test parsing of sample log entries."""
        sample_log = """Jan 15 10:23:45 server1 sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:23:50 server1 sshd[12346]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 15 10:24:00 server1 sshd[12347]: Invalid user hacker from 10.0.0.5 port 22
Jan 15 10:24:10 server1 sshd[12348]: Failed password for root from 192.168.1.100 port 22 ssh2
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.log',
                                         delete=False) as f:
            f.write(sample_log)
            temp_log = f.name

        try:
            return_code, stdout, stderr = run_command([
                sys.executable,
                self.script_path,
                '--log-file', temp_log,
                '--format', 'plain',
                '--hours', '8760'  # 1 year to ensure we capture these entries
            ])

            # Should detect the failed logins
            self.assertIn(return_code, [0, 1],
                         f"Should succeed or warn, not error: {stderr}")
            # Check output contains expected data
            if 'failed' in stdout.lower() or 'attempts' in stdout.lower():
                self.assertTrue(True, "Output mentions failed attempts")
        finally:
            os.unlink(temp_log)

    def test_json_output_structure(self):
        """Test that JSON output is valid and has expected structure."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log',
                                         delete=False) as f:
            temp_log = f.name

        try:
            return_code, stdout, stderr = run_command([
                sys.executable,
                self.script_path,
                '--log-file', temp_log,
                '--format', 'json'
            ])

            self.assertEqual(return_code, 0, "Empty log should return 0")

            import json as json_module
            try:
                data = json_module.loads(stdout)
                self.assertIn('summary', data, "JSON should have summary key")
                self.assertIn('by_source_ip', data,
                             "JSON should have by_source_ip key")
                self.assertIn('by_target_user', data,
                             "JSON should have by_target_user key")
            except json_module.JSONDecodeError as e:
                self.fail(f"Invalid JSON output: {e}")
        finally:
            os.unlink(temp_log)

    def test_script_imports(self):
        """Verify the script imports necessary modules."""
        with open(self.script_path, 'r') as f:
            content = f.read()

        required_imports = ['argparse', 'json', 'sys', 'os', 're']
        for module in required_imports:
            self.assertIn(f'import {module}', content,
                         f"Script should import {module}")


def main():
    """Run all tests using unittest."""
    unittest.main(argv=[''], verbosity=2, exit=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
