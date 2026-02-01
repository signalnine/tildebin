"""Tests for ext4_journal_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


PROC_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "proc"
EXT4_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "ext4"


def load_proc_fixture(name: str) -> str:
    """Load a proc fixture file."""
    return (PROC_FIXTURES / name).read_text()


def load_ext4_fixture(name: str) -> str:
    """Load an ext4 fixture file."""
    return (EXT4_FIXTURES / name).read_text()


class TestExt4JournalHealth:
    """Tests for ext4_journal_health script."""

    def test_missing_dumpe2fs(self, capsys):
        """Returns exit code 2 when dumpe2fs not available."""
        from scripts.baremetal.ext4_journal_health import run

        context = MockContext(
            tools_available=[],
            file_contents={
                "/proc/mounts": load_proc_fixture("mounts_ext4.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert any("dumpe2fs" in e.lower() for e in output.errors)

    def test_no_ext4_filesystems(self, capsys):
        """No ext4 filesystems returns exit code 0."""
        from scripts.baremetal.ext4_journal_health import run

        context = MockContext(
            tools_available=["dumpe2fs"],
            file_contents={
                "/proc/mounts": "/dev/sdb1 /data xfs rw,relatime 0 0\n",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_ext4_healthy(self, capsys):
        """Healthy ext4 filesystem returns exit code 0."""
        from scripts.baremetal.ext4_journal_health import run

        context = MockContext(
            tools_available=["dumpe2fs"],
            file_contents={
                "/proc/mounts": "/dev/sda1 / ext4 rw,relatime 0 0\n",
            },
            command_outputs={
                ("dumpe2fs", "-h", "/dev/sda1"): load_ext4_fixture("dumpe2fs_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert output.data["healthy"] == 1

    def test_ext4_with_errors(self, capsys):
        """Ext4 with errors returns exit code 1."""
        from scripts.baremetal.ext4_journal_health import run

        context = MockContext(
            tools_available=["dumpe2fs"],
            file_contents={
                "/proc/mounts": "/dev/sda1 / ext4 rw,relatime 0 0\n",
            },
            command_outputs={
                ("dumpe2fs", "-h", "/dev/sda1"): load_ext4_fixture("dumpe2fs_errors.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert any(f["status"] == "critical" for f in output.data["filesystems"])

    def test_ext4_max_mount_count(self, capsys):
        """Ext4 at max mount count returns exit code 1."""
        from scripts.baremetal.ext4_journal_health import run

        context = MockContext(
            tools_available=["dumpe2fs"],
            file_contents={
                "/proc/mounts": "/dev/sda1 / ext4 rw,relatime 0 0\n",
            },
            command_outputs={
                ("dumpe2fs", "-h", "/dev/sda1"): load_ext4_fixture("dumpe2fs_max_mount.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        # Should have warning about max mount count
        fs = output.data["filesystems"][0]
        assert any("mount count" in w["message"].lower() for w in fs["warnings"])

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.ext4_journal_health import run

        context = MockContext(
            tools_available=["dumpe2fs"],
            file_contents={
                "/proc/mounts": "/dev/sda1 / ext4 rw,relatime 0 0\n",
            },
            command_outputs={
                ("dumpe2fs", "-h", "/dev/sda1"): load_ext4_fixture("dumpe2fs_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "filesystems" in data
        assert "summary" in data
        assert "total" in data["summary"]

    def test_specific_device(self, capsys):
        """--device flag checks specific device."""
        from scripts.baremetal.ext4_journal_health import run

        context = MockContext(
            tools_available=["dumpe2fs"],
            file_contents={},
            command_outputs={
                ("dumpe2fs", "-h", "/dev/sda1"): load_ext4_fixture("dumpe2fs_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--device", "/dev/sda1"], output, context)

        assert result == 0
        assert output.data["total"] == 1

    def test_missing_proc_mounts(self, capsys):
        """Missing /proc/mounts returns exit code 2."""
        from scripts.baremetal.ext4_journal_health import run

        context = MockContext(
            tools_available=["dumpe2fs"],
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert len(output.errors) > 0
