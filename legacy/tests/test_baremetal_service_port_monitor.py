#!/usr/bin/env python3
"""
Tests for baremetal_service_port_monitor.py

These tests verify the script's argument parsing and basic functionality
without requiring actual network services to be running.
"""

import subprocess
import sys
import os
import json
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


class TestServicePortMonitor(unittest.TestCase):
    """Test cases for baremetal_service_port_monitor.py"""

    @classmethod
    def setUpClass(cls):
        """Change to script directory before running tests."""
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        os.chdir(script_dir)
        cls.script_path = os.path.join(script_dir, 'baremetal_service_port_monitor.py')

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
        self.assertIn('service port', content.lower(), "Docstring should mention service port")
        self.assertIn('Exit codes:', content, "Docstring should document exit codes")

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--help'
        ])

        self.assertEqual(return_code, 0, "Help should return exit code 0")
        self.assertIn('service', stdout.lower(), "Help should mention services")
        self.assertIn('--format', stdout, "Help should document --format option")
        self.assertIn('--verbose', stdout, "Help should document --verbose option")
        self.assertIn('--warn-only', stdout, "Help should document --warn-only option")
        self.assertIn('--timeout', stdout, "Help should document --timeout option")
        self.assertIn('--list-presets', stdout, "Help should document --list-presets")
        self.assertIn('Examples:', stdout, "Help should include examples")
        self.assertIn('Exit codes:', stdout, "Help should document exit codes")
        self.assertIn('redis', stdout.lower(), "Help should mention redis preset")
        self.assertIn('mysql', stdout.lower(), "Help should mention mysql preset")

    def test_list_presets(self):
        """Test that --list-presets shows available service presets."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--list-presets'
        ])

        self.assertEqual(return_code, 0, "List presets should return exit code 0")
        self.assertIn('ssh', stdout.lower(), "Should list ssh preset")
        self.assertIn('redis', stdout.lower(), "Should list redis preset")
        self.assertIn('mysql', stdout.lower(), "Should list mysql preset")
        self.assertIn('http', stdout.lower(), "Should list http preset")
        self.assertIn('port', stdout.lower(), "Should show port information")

    def test_no_services_error(self):
        """Test that running without services shows error."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path
        ])

        self.assertEqual(return_code, 2, "No services should return exit code 2")
        self.assertIn('error', stderr.lower(), "Should show error message")
        self.assertIn('service', stderr.lower(), "Should mention service requirement")

    def test_invalid_service_spec(self):
        """Test that invalid service specification is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'not_a_valid_service_name'
        ])

        self.assertEqual(return_code, 2, "Invalid service should return exit code 2")
        self.assertIn('error', stderr.lower(), "Should show error message")

    def test_invalid_port_number(self):
        """Test that invalid port number is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'localhost:invalid'
        ])

        self.assertEqual(return_code, 2, "Invalid port should return exit code 2")
        self.assertIn('error', stderr.lower(), "Should show error message")

    def test_port_out_of_range(self):
        """Test that out-of-range port is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'localhost:99999'
        ])

        self.assertEqual(return_code, 2, "Out-of-range port should return exit code 2")
        self.assertIn('error', stderr.lower(), "Should show error message")

    def test_format_plain(self):
        """Test that --format plain is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'plain',
            'localhost:65534',  # Unlikely to be listening
            '--timeout', '0.1'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('invalid choice', stderr.lower(),
                        "Plain format should be valid")

    def test_format_json(self):
        """Test that --format json produces valid JSON."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            'localhost:65534',
            '--timeout', '0.1'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")

        # Try to parse JSON output
        try:
            data = json.loads(stdout)
            self.assertIn('services', data, "JSON should contain services")
            self.assertIn('summary', data, "JSON should contain summary")
            self.assertIn('healthy', data, "JSON should contain healthy status")
        except json.JSONDecodeError:
            self.fail("Output should be valid JSON")

    def test_format_table(self):
        """Test that --format table is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'table',
            'localhost:65534',
            '--timeout', '0.1'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('invalid choice', stderr.lower(),
                        "Table format should be valid")
        # Table should have header columns
        self.assertIn('SERVICE', stdout, "Table should have SERVICE column")
        self.assertIn('PORT', stdout, "Table should have PORT column")
        self.assertIn('STATUS', stdout, "Table should have STATUS column")

    def test_invalid_format(self):
        """Test that invalid format option is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'invalid',
            'redis'
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
            'localhost:65534',
            '--timeout', '0.1'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Verbose flag should be recognized")

    def test_warn_only_flag(self):
        """Test that --warn-only flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-only',
            'localhost:65534',
            '--timeout', '0.1'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Warn-only flag should be recognized")

    def test_custom_timeout(self):
        """Test that --timeout option works."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--timeout', '1.0',
            'localhost:65534'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Timeout option should be recognized")

    def test_invalid_timeout(self):
        """Test that negative timeout is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--timeout', '-1',
            'redis'
        ])

        self.assertEqual(return_code, 2,
                        "Negative timeout should return exit code 2")
        self.assertIn('timeout', stderr.lower(),
                     "Should show error about timeout")

    def test_preset_service_redis(self):
        """Test that redis preset is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'redis',
            '--timeout', '0.1',
            '--format', 'json'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")

        try:
            data = json.loads(stdout)
            self.assertEqual(len(data['services']), 1)
            self.assertEqual(data['services'][0]['port'], 6379)
            self.assertEqual(data['services'][0]['name'], 'redis')
        except json.JSONDecodeError:
            self.fail("Output should be valid JSON")

    def test_preset_service_mysql(self):
        """Test that mysql preset is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'mysql',
            '--timeout', '0.1',
            '--format', 'json'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")

        try:
            data = json.loads(stdout)
            self.assertEqual(data['services'][0]['port'], 3306)
        except json.JSONDecodeError:
            self.fail("Output should be valid JSON")

    def test_preset_at_host(self):
        """Test preset@host format."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'redis@localhost',
            '--timeout', '0.1',
            '--format', 'json'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")

        try:
            data = json.loads(stdout)
            self.assertEqual(data['services'][0]['host'], 'localhost')
            self.assertEqual(data['services'][0]['port'], 6379)
        except json.JSONDecodeError:
            self.fail("Output should be valid JSON")

    def test_preset_at_host_custom_port(self):
        """Test preset@host:port format."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'http@localhost:8080',
            '--timeout', '0.1',
            '--format', 'json'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")

        try:
            data = json.loads(stdout)
            self.assertEqual(data['services'][0]['host'], 'localhost')
            self.assertEqual(data['services'][0]['port'], 8080)
        except json.JSONDecodeError:
            self.fail("Output should be valid JSON")

    def test_host_port_format(self):
        """Test host:port format."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'localhost:9999',
            '--timeout', '0.1',
            '--format', 'json'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")

        try:
            data = json.loads(stdout)
            self.assertEqual(data['services'][0]['host'], 'localhost')
            self.assertEqual(data['services'][0]['port'], 9999)
        except json.JSONDecodeError:
            self.fail("Output should be valid JSON")

    def test_host_port_protocol_format(self):
        """Test host:port:protocol format."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'localhost:53:udp',
            '--timeout', '0.1',
            '--format', 'json'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")

        try:
            data = json.loads(stdout)
            self.assertEqual(data['services'][0]['protocol'], 'udp')
        except json.JSONDecodeError:
            self.fail("Output should be valid JSON")

    def test_multiple_services(self):
        """Test checking multiple services."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'localhost:65534',
            'localhost:65533',
            '--timeout', '0.1',
            '--format', 'json'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")

        try:
            data = json.loads(stdout)
            self.assertEqual(len(data['services']), 2)
            self.assertEqual(data['summary']['total'], 2)
        except json.JSONDecodeError:
            self.fail("Output should be valid JSON")

    def test_unknown_preset(self):
        """Test that unknown preset is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'unknown_service@localhost'
        ])

        self.assertEqual(return_code, 2, "Unknown preset should return exit code 2")
        self.assertIn('unknown', stderr.lower(), "Should mention unknown preset")

    def test_short_options(self):
        """Test that short option flags work."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '-f', 'json',
            '-v',
            '-w',
            '-t', '0.1',
            'localhost:65534'
        ])

        self.assertIn(return_code, [0, 1],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Short options should be recognized")

    def test_json_output_structure(self):
        """Test that JSON output has expected structure."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--timeout', '0.1',
            'localhost:65534'
        ])

        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                # Check required top-level fields
                self.assertIn('services', data)
                self.assertIn('summary', data)
                self.assertIn('healthy', data)

                # Check summary structure
                summary = data['summary']
                self.assertIn('total', summary)
                self.assertIn('reachable', summary)
                self.assertIn('unreachable', summary)

                # Check service entry structure
                if data['services']:
                    service = data['services'][0]
                    self.assertIn('name', service)
                    self.assertIn('host', service)
                    self.assertIn('port', service)
                    self.assertIn('protocol', service)
                    self.assertIn('reachable', service)
            except json.JSONDecodeError:
                self.fail("Output should be valid JSON")

    def test_script_imports(self):
        """Verify the script imports necessary modules."""
        with open(self.script_path, 'r') as f:
            content = f.read()

        required_imports = ['argparse', 'json', 'socket', 'sys', 'time']
        for module in required_imports:
            self.assertIn(f'import {module}', content,
                         f"Script should import {module}")

    def test_unreachable_service_exit_code(self):
        """Test that unreachable service returns exit code 1."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'localhost:65534',  # Very unlikely to be listening
            '--timeout', '0.1'
        ])

        self.assertEqual(return_code, 1,
                        "Unreachable service should return exit code 1")
        self.assertIn('unreachable', stdout.lower(),
                     "Should show service as unreachable")

    def test_invalid_protocol(self):
        """Test that invalid protocol is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            'localhost:80:invalid'
        ])

        self.assertEqual(return_code, 2, "Invalid protocol should return exit code 2")
        self.assertIn('error', stderr.lower(), "Should show error message")


def main():
    """Run all tests using unittest."""
    unittest.main(argv=[''], verbosity=2, exit=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
