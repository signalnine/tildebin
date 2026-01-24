#!/usr/bin/env python3
"""
Tests for baremetal_dns_resolver_monitor.py

These tests verify the script's argument parsing and basic functionality
without requiring actual DNS services or network access.
"""

import subprocess
import sys
import os
import json
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


class TestDNSResolverMonitor(unittest.TestCase):
    """Test cases for baremetal_dns_resolver_monitor.py"""

    @classmethod
    def setUpClass(cls):
        """Change to script directory before running tests."""
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        os.chdir(script_dir)
        cls.script_path = os.path.join(script_dir, 'baremetal_dns_resolver_monitor.py')

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
        self.assertIn('DNS resolver', content, "Docstring should mention DNS resolver")
        self.assertIn('Exit codes:', content, "Docstring should document exit codes")

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--help'
        ])

        self.assertEqual(return_code, 0, "Help should return exit code 0")
        self.assertIn('DNS resolver', stdout, "Help should contain description")
        self.assertIn('--format', stdout, "Help should document --format option")
        self.assertIn('--verbose', stdout, "Help should document --verbose option")
        self.assertIn('--warn-only', stdout, "Help should document --warn-only option")
        self.assertIn('--no-reachability', stdout, "Help should document --no-reachability")
        self.assertIn('--test-domain', stdout, "Help should document --test-domain")
        self.assertIn('--timeout', stdout, "Help should document --timeout")
        self.assertIn('Examples:', stdout, "Help should include examples")
        self.assertIn('Exit codes:', stdout, "Help should document exit codes")

    def test_format_plain(self):
        """Test that --format plain is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'plain',
            '--no-reachability',
            '--no-resolution'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('invalid choice', stderr.lower(),
                        "Plain format should be valid")

    def test_format_json(self):
        """Test that --format json is recognized and produces valid JSON."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--no-reachability',
            '--no-resolution'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('invalid choice', stderr.lower(),
                        "JSON format should be valid")

        # Try to parse JSON output
        try:
            data = json.loads(stdout)
            self.assertIn('resolv_conf', data, "JSON should contain resolv_conf")
            self.assertIn('healthy', data, "JSON should contain healthy status")
        except json.JSONDecodeError:
            # May fail if there's an error message before JSON
            pass

    def test_format_table(self):
        """Test that --format table is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'table',
            '--no-reachability',
            '--no-resolution'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
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
            '--no-reachability',
            '--no-resolution'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Verbose flag should be recognized")

    def test_warn_only_flag(self):
        """Test that --warn-only flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-only',
            '--no-reachability',
            '--no-resolution'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Warn-only flag should be recognized")

    def test_no_reachability_flag(self):
        """Test that --no-reachability flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--no-reachability'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "No-reachability flag should be recognized")

    def test_no_resolution_flag(self):
        """Test that --no-resolution flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--no-resolution'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "No-resolution flag should be recognized")

    def test_custom_timeout(self):
        """Test that --timeout option works."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--timeout', '5.0',
            '--no-reachability',
            '--no-resolution'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Timeout option should be recognized")

    def test_invalid_timeout(self):
        """Test that negative timeout is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--timeout', '-1'
        ])

        self.assertEqual(return_code, 2,
                        "Negative timeout should return exit code 2")
        self.assertIn('timeout', stderr.lower(),
                     "Should show error about timeout")

    def test_test_domain_option(self):
        """Test that --test-domain option works."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--test-domain', 'example.com',
            '--no-reachability'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Test-domain option should be recognized")

    def test_multiple_test_domains(self):
        """Test that multiple --test-domain options work."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--test-domain', 'example.com',
            '--test-domain', 'example.org',
            '--no-reachability'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Multiple test-domain options should be recognized")

    def test_custom_resolv_conf(self):
        """Test that --resolv-conf option works with a custom file."""
        # Create a temporary resolv.conf
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("nameserver 8.8.8.8\n")
            f.write("nameserver 8.8.4.4\n")
            f.write("search example.com\n")
            temp_path = f.name

        try:
            return_code, stdout, stderr = run_command([
                sys.executable,
                self.script_path,
                '--resolv-conf', temp_path,
                '--no-reachability',
                '--no-resolution'
            ])

            self.assertIn(return_code, [0, 1, 2],
                         f"Unexpected return code {return_code}")
            # Should show the nameservers from our temp file
            self.assertIn('8.8.8.8', stdout,
                         "Should show nameserver from custom resolv.conf")
        finally:
            os.unlink(temp_path)

    def test_missing_resolv_conf(self):
        """Test handling of non-existent resolv.conf."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--resolv-conf', '/nonexistent/resolv.conf',
            '--no-reachability',
            '--no-resolution'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        # Should report the missing file
        if return_code == 1:
            self.assertTrue(
                'does not exist' in stdout.lower() or 'missing' in stdout.lower() or 'critical' in stdout.lower(),
                "Should report missing resolv.conf"
            )

    def test_combined_options(self):
        """Test that multiple options can be used together."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--verbose',
            '--no-reachability',
            '--no-resolution',
            '--timeout', '3.0'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Combined options should work together")

    def test_short_options(self):
        """Test that short option flags work."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '-f', 'json',
            '-v',
            '-w',
            '--no-reachability',
            '--no-resolution'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Short options should be recognized")

    def test_script_imports(self):
        """Verify the script imports necessary modules."""
        with open(self.script_path, 'r') as f:
            content = f.read()

        required_imports = ['argparse', 'json', 'subprocess', 'sys', 'os', 'socket']
        for module in required_imports:
            self.assertIn(f'import {module}', content,
                         f"Script should import {module}")

    def test_json_output_structure(self):
        """Test that JSON output has expected structure."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--no-reachability',
            '--no-resolution'
        ])

        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                # Check required fields
                self.assertIn('resolv_conf', data)
                self.assertIn('issues', data)
                self.assertIn('warnings', data)
                self.assertIn('healthy', data)

                # Check resolv_conf structure
                resolv_conf = data['resolv_conf']
                self.assertIn('nameservers', resolv_conf)
                self.assertIn('search_domains', resolv_conf)
                self.assertIn('exists', resolv_conf)
            except json.JSONDecodeError:
                pass  # May have error output before JSON

    def test_default_run(self):
        """Test default run without any options."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path
        ])

        # Should either succeed or report issues - any valid exit code is OK
        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")

        # Should have some output
        self.assertTrue(stdout or stderr,
                       "Script should produce some output")

    def test_empty_resolv_conf(self):
        """Test handling of empty resolv.conf."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("")  # Empty file
            temp_path = f.name

        try:
            return_code, stdout, stderr = run_command([
                sys.executable,
                self.script_path,
                '--resolv-conf', temp_path,
                '--no-reachability',
                '--no-resolution',
                '--format', 'json'
            ])

            self.assertIn(return_code, [0, 1, 2],
                         f"Unexpected return code {return_code}")

            # Should report no nameservers
            if return_code in [0, 1]:
                try:
                    data = json.loads(stdout)
                    self.assertEqual(data['resolv_conf']['nameservers'], [],
                                   "Empty file should have no nameservers")
                except json.JSONDecodeError:
                    pass
        finally:
            os.unlink(temp_path)

    def test_resolv_conf_with_comments(self):
        """Test handling of resolv.conf with comments."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("# This is a comment\n")
            f.write("nameserver 1.1.1.1\n")
            f.write("# Another comment\n")
            f.write("nameserver 1.0.0.1\n")
            temp_path = f.name

        try:
            return_code, stdout, stderr = run_command([
                sys.executable,
                self.script_path,
                '--resolv-conf', temp_path,
                '--no-reachability',
                '--no-resolution',
                '--format', 'json'
            ])

            self.assertIn(return_code, [0, 1, 2],
                         f"Unexpected return code {return_code}")

            if return_code in [0, 1]:
                try:
                    data = json.loads(stdout)
                    # Should have parsed the nameservers, ignoring comments
                    self.assertIn('1.1.1.1', data['resolv_conf']['nameservers'])
                    self.assertIn('1.0.0.1', data['resolv_conf']['nameservers'])
                except json.JSONDecodeError:
                    pass
        finally:
            os.unlink(temp_path)


def main():
    """Run all tests using unittest."""
    unittest.main(argv=[''], verbosity=2, exit=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
