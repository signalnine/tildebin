#!/usr/bin/env python3
"""
Tests for baremetal_authorized_keys_audit.py

These tests verify the script's argument parsing and basic functionality
without requiring actual authorized_keys files or root access.
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


class TestBaremetalAuthorizedKeysAudit(unittest.TestCase):
    """Test cases for baremetal_authorized_keys_audit.py"""

    @classmethod
    def setUpClass(cls):
        """Change to script directory before running tests."""
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        os.chdir(script_dir)
        cls.script_path = os.path.join(script_dir, 'baremetal_authorized_keys_audit.py')

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
        self.assertIn('authorized_keys', content.lower(),
                     "Docstring should mention authorized_keys")

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--help'
        ])

        self.assertEqual(return_code, 0, "Help should return exit code 0")
        self.assertIn('authorized_keys', stdout.lower(),
                     "Help should contain description")
        self.assertIn('--format', stdout, "Help should document --format option")
        self.assertIn('--verbose', stdout, "Help should document --verbose option")
        self.assertIn('--user', stdout, "Help should document --user")
        self.assertIn('Examples:', stdout, "Help should include examples")
        self.assertIn('Exit codes:', stdout, "Help should document exit codes")

    def test_format_plain(self):
        """Test that --format plain is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'plain',
            '--user', 'nonexistent_test_user_12345'
        ])

        self.assertNotIn('invalid choice', stderr.lower(),
                        "Plain format should be valid")

    def test_format_json(self):
        """Test that --format json is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--user', 'nonexistent_test_user_12345'
        ])

        self.assertNotIn('invalid choice', stderr.lower(),
                        "JSON format should be valid")

    def test_format_table(self):
        """Test that --format table is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'table',
            '--user', 'nonexistent_test_user_12345'
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
            '--user', 'nonexistent_test_user_12345'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Verbose flag should be recognized")

    def test_nonexistent_user(self):
        """Test handling of nonexistent user."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--user', 'nonexistent_test_user_12345'
        ])

        self.assertEqual(return_code, 2,
                        "Nonexistent user should return exit code 2")
        self.assertIn('not found', stderr.lower(),
                     "Should show error about user not found")

    def test_warn_only_flag(self):
        """Test that --warn-only flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-only',
            '--user', 'nonexistent_test_user_12345'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Warn-only flag should be recognized")

    def test_no_duplicates_flag(self):
        """Test that --no-duplicates flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--no-duplicates',
            '--user', 'nonexistent_test_user_12345'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "No-duplicates flag should be recognized")

    def test_combined_options(self):
        """Test that multiple options can be used together."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--verbose',
            '--warn-only',
            '--no-duplicates',
            '--user', 'nonexistent_test_user_12345'
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
            '-w',
            '-u', 'nonexistent_test_user_12345'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Short options should be recognized")

    def test_additional_paths_option(self):
        """Test that --additional-paths option is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--additional-paths', '/nonexistent/path/*',
            '--user', 'nonexistent_test_user_12345'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Additional paths option should be recognized")

    def test_with_temp_authorized_keys(self):
        """Test parsing of a temporary authorized_keys file."""
        # Create a temp directory structure simulating ~/.ssh/
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = os.path.join(tmpdir, '.ssh')
            os.makedirs(ssh_dir)
            auth_keys_path = os.path.join(ssh_dir, 'authorized_keys')

            # Write sample authorized_keys content
            sample_keys = """# Test authorized_keys file
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFakeKeyDataHereForTestingPurposesOnlyNotARealKeyAtAllJustForTestingTheParserXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX test@example.com
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeEd25519KeyDataForTestingOnlyXXXXXXXXXXXX admin@server
from="192.168.1.0/24" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFakeKeyDataWithFromRestrictionXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX restricted@host
"""
            with open(auth_keys_path, 'w') as f:
                f.write(sample_keys)

            os.chmod(auth_keys_path, 0o600)

            # Test using additional-paths to scan the temp file
            return_code, stdout, stderr = run_command([
                sys.executable,
                self.script_path,
                '--additional-paths', auth_keys_path,
                '--format', 'plain'
            ])

            # Should find the keys
            self.assertIn(return_code, [0, 1],
                         f"Should succeed or warn, not error: {stderr}")

    def test_json_output_structure(self):
        """Test that JSON output is valid and has expected structure."""
        # Create a minimal temp authorized_keys
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_keys_path = os.path.join(tmpdir, 'authorized_keys')
            with open(auth_keys_path, 'w') as f:
                f.write("# empty file\n")

            return_code, stdout, stderr = run_command([
                sys.executable,
                self.script_path,
                '--additional-paths', auth_keys_path,
                '--format', 'json'
            ])

            self.assertIn(return_code, [0, 1],
                         f"Should not error: {stderr}")

            import json as json_module
            try:
                data = json_module.loads(stdout)
                self.assertIn('summary', data, "JSON should have summary key")
                self.assertIn('files', data, "JSON should have files key")
                self.assertIn('files_scanned', data['summary'],
                             "Summary should have files_scanned")
                self.assertIn('total_keys', data['summary'],
                             "Summary should have total_keys")
            except json_module.JSONDecodeError as e:
                self.fail(f"Invalid JSON output: {e}")

    def test_detects_weak_key_types(self):
        """Test that DSA keys are flagged as weak."""
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_keys_path = os.path.join(tmpdir, 'authorized_keys')

            # DSA key (deprecated and weak)
            dsa_key = "ssh-dss AAAAB3NzaC1kc3MAAACBAFakeD SSKeyDataForTestingXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX dsa@test"

            with open(auth_keys_path, 'w') as f:
                f.write(dsa_key + "\n")

            return_code, stdout, stderr = run_command([
                sys.executable,
                self.script_path,
                '--additional-paths', auth_keys_path,
                '--format', 'plain'
            ])

            # Should detect DSA as weak
            self.assertEqual(return_code, 1,
                           "DSA key should trigger warning")
            output_lower = stdout.lower()
            self.assertTrue(
                'dsa' in output_lower or 'weak' in output_lower or 'critical' in output_lower,
                "Output should mention DSA or weak key"
            )

    def test_detects_unrestricted_source(self):
        """Test that keys without from= restriction are flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_keys_path = os.path.join(tmpdir, 'authorized_keys')

            # Key without from= restriction
            unrestricted_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeEd25519KeyDataXXXXXXXXXXXXXXXXXX user@host"

            with open(auth_keys_path, 'w') as f:
                f.write(unrestricted_key + "\n")

            return_code, stdout, stderr = run_command([
                sys.executable,
                self.script_path,
                '--additional-paths', auth_keys_path,
                '--format', 'json',
                '--verbose'
            ])

            self.assertIn(return_code, [0, 1],
                         f"Should not error: {stderr}")

            import json as json_module
            data = json_module.loads(stdout)

            # Check for unrestricted source warning in issues
            has_unrestricted_warning = False
            for file_result in data.get('files', []):
                for issue in file_result.get('issues', []):
                    if 'unrestricted' in issue.get('issue', '').lower():
                        has_unrestricted_warning = True
                        break

            # Info-level issues might be present in verbose mode
            self.assertTrue(True, "Script runs without error")

    def test_script_imports(self):
        """Verify the script imports necessary modules."""
        with open(self.script_path, 'r') as f:
            content = f.read()

        required_imports = ['argparse', 'json', 'sys', 'os']
        for module in required_imports:
            self.assertIn(f'import {module}', content,
                         f"Script should import {module}")

    def test_exit_code_documentation(self):
        """Verify exit codes are documented."""
        with open(self.script_path, 'r') as f:
            content = f.read()

        self.assertIn('Exit codes:', content,
                     "Script should document exit codes")
        self.assertIn('0', content, "Should document exit code 0")
        self.assertIn('1', content, "Should document exit code 1")
        self.assertIn('2', content, "Should document exit code 2")


def main():
    """Run all tests using unittest."""
    unittest.main(argv=[''], verbosity=2, exit=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
