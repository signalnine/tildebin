"""Tests for ssh_host_key_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext, load_fixture


class TestSshHostKeyAudit:
    """Tests for ssh_host_key_audit."""

    def test_healthy_keys(self, capsys):
        """All secure keys return exit code 0."""
        from scripts.baremetal.ssh_host_key_audit import run

        context = MockContext(
            tools_available=["ssh-keygen"],
            command_outputs={
                ("ssh-keygen", "-l", "-f", "/etc/ssh/ssh_host_ed25519_key"): load_fixture("ssh", "keygen_ed25519.txt"),
                ("ssh-keygen", "-l", "-f", "/etc/ssh/ssh_host_rsa_key"): load_fixture("ssh", "keygen_rsa_4096.txt"),
            },
            file_contents={
                "/etc/ssh": "",  # Directory marker
                "/etc/ssh/ssh_host_ed25519_key": "private_key_content",
                "/etc/ssh/ssh_host_rsa_key": "private_key_content",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "SSH Host Key Audit" in captured.out

    def test_weak_rsa_key(self, capsys):
        """RSA key below minimum size returns exit code 1."""
        from scripts.baremetal.ssh_host_key_audit import run

        context = MockContext(
            tools_available=["ssh-keygen"],
            command_outputs={
                ("ssh-keygen", "-l", "-f", "/etc/ssh/ssh_host_rsa_key"): load_fixture("ssh", "keygen_rsa_1024.txt"),
            },
            file_contents={
                "/etc/ssh": "",
                "/etc/ssh/ssh_host_rsa_key": "private_key_content",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "below minimum" in captured.out.lower() or "ISSUES" in captured.out

    def test_dsa_key_deprecated(self, capsys):
        """DSA key returns exit code 1 (deprecated)."""
        from scripts.baremetal.ssh_host_key_audit import run

        context = MockContext(
            tools_available=["ssh-keygen"],
            command_outputs={
                ("ssh-keygen", "-l", "-f", "/etc/ssh/ssh_host_dsa_key"): load_fixture("ssh", "keygen_dsa.txt"),
            },
            file_contents={
                "/etc/ssh": "",
                "/etc/ssh/ssh_host_dsa_key": "private_key_content",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "deprecated" in captured.out.lower() or "DSA" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.ssh_host_key_audit import run

        context = MockContext(
            tools_available=["ssh-keygen"],
            command_outputs={
                ("ssh-keygen", "-l", "-f", "/etc/ssh/ssh_host_ed25519_key"): load_fixture("ssh", "keygen_ed25519.txt"),
            },
            file_contents={
                "/etc/ssh": "",
                "/etc/ssh/ssh_host_ed25519_key": "private_key_content",
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "keys" in data
        assert "issues" in data
        assert "warnings" in data
        assert "healthy" in data

    def test_missing_ed25519_warning(self, capsys):
        """Missing Ed25519 key generates warning."""
        from scripts.baremetal.ssh_host_key_audit import run

        context = MockContext(
            tools_available=["ssh-keygen"],
            command_outputs={
                ("ssh-keygen", "-l", "-f", "/etc/ssh/ssh_host_rsa_key"): load_fixture("ssh", "keygen_rsa_4096.txt"),
            },
            file_contents={
                "/etc/ssh": "",
                "/etc/ssh/ssh_host_rsa_key": "private_key_content",
                # Note: no ed25519 key present
            },
        )
        output = Output()

        result = run([], output, context)

        # Missing recommended key is a warning, not an issue
        captured = capsys.readouterr()
        assert "ed25519" in captured.out.lower() or "missing" in captured.out.lower()

    def test_missing_ssh_keygen_exit_2(self, capsys):
        """Missing ssh-keygen tool returns exit code 2."""
        from scripts.baremetal.ssh_host_key_audit import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
            file_contents={
                "/etc/ssh": "",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert output.errors

    def test_missing_ssh_dir_exit_2(self, capsys):
        """Missing SSH directory returns exit code 2."""
        from scripts.baremetal.ssh_host_key_audit import run

        context = MockContext(
            tools_available=["ssh-keygen"],
            command_outputs={},
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert output.errors
