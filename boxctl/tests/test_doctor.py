"""Tests for doctor command."""

import pytest
from pathlib import Path

from boxctl.cli import cmd_doctor, create_parser


SCRIPT_WITH_REQUIRES = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health]
#   requires: [smartctl, lsblk]
#   brief: Test script
'''

SCRIPT_WITH_PRIVILEGE = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health]
#   privilege: root
#   brief: Privileged script
'''

SCRIPT_NO_REQUIRES = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [health]
#   brief: No requirements
'''


class TestDoctorCommand:
    """Tests for doctor command."""

    def test_doctor_shows_tool_status(self, tmp_path, capsys):
        """Doctor shows required tools and their availability."""
        (tmp_path / "disk.py").write_text(SCRIPT_WITH_REQUIRES)

        parser = create_parser()
        args = parser.parse_args(["--scripts-dir", str(tmp_path), "doctor"])
        result = cmd_doctor(args)

        captured = capsys.readouterr()
        assert "smartctl" in captured.out
        assert "lsblk" in captured.out

    def test_doctor_shows_script_count(self, tmp_path, capsys):
        """Doctor shows script count by category."""
        (tmp_path / "disk1.py").write_text(SCRIPT_WITH_REQUIRES)
        (tmp_path / "disk2.py").write_text(SCRIPT_WITH_PRIVILEGE)
        (tmp_path / "mem.py").write_text(SCRIPT_NO_REQUIRES)

        parser = create_parser()
        args = parser.parse_args(["--scripts-dir", str(tmp_path), "doctor"])
        result = cmd_doctor(args)

        captured = capsys.readouterr()
        assert "baremetal/disk" in captured.out
        assert "baremetal/memory" in captured.out

    def test_doctor_shows_privilege_info(self, tmp_path, capsys):
        """Doctor shows scripts requiring privilege."""
        (tmp_path / "priv.py").write_text(SCRIPT_WITH_PRIVILEGE)

        parser = create_parser()
        args = parser.parse_args(["--scripts-dir", str(tmp_path), "doctor"])
        result = cmd_doctor(args)

        captured = capsys.readouterr()
        assert "root" in captured.out.lower() or "privilege" in captured.out.lower()

    def test_doctor_returns_zero_on_healthy(self, tmp_path):
        """Doctor returns 0 when all tools available."""
        # Script with no requirements - always healthy
        (tmp_path / "simple.py").write_text(SCRIPT_NO_REQUIRES)

        parser = create_parser()
        args = parser.parse_args(["--scripts-dir", str(tmp_path), "doctor"])
        result = cmd_doctor(args)

        assert result == 0

    def test_doctor_json_output(self, tmp_path, capsys):
        """Doctor supports JSON output."""
        (tmp_path / "disk.py").write_text(SCRIPT_WITH_REQUIRES)

        parser = create_parser()
        args = parser.parse_args([
            "--scripts-dir", str(tmp_path),
            "--format", "json",
            "doctor",
        ])
        result = cmd_doctor(args)

        captured = capsys.readouterr()
        assert "{" in captured.out  # JSON output

    def test_doctor_empty_directory(self, tmp_path, capsys):
        """Doctor handles empty scripts directory."""
        parser = create_parser()
        args = parser.parse_args(["--scripts-dir", str(tmp_path), "doctor"])
        result = cmd_doctor(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "0" in captured.out or "No scripts" in captured.out
