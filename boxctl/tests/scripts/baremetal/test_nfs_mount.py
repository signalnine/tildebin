"""Tests for nfs_mount script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


PROC_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "proc"
FSTAB_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "fstab"


def load_proc_fixture(name: str) -> str:
    """Load a proc fixture file."""
    return (PROC_FIXTURES / name).read_text()


def load_fstab_fixture(name: str) -> str:
    """Load a fstab fixture file."""
    return (FSTAB_FIXTURES / name).read_text()


class TestNfsMount:
    """Tests for nfs_mount script."""

    def test_no_nfs_mounts(self, capsys):
        """No NFS mounts returns exit code 0."""
        from scripts.baremetal.nfs_mount import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_proc_fixture("mounts_no_nfs.txt"),
                "/etc/fstab": "",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert output.data["mount_count"] == 0

    def test_nfs_healthy(self, capsys):
        """Healthy NFS mounts return exit code 0."""
        from scripts.baremetal.nfs_mount import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_proc_fixture("mounts_nfs_healthy.txt"),
                "/etc/fstab": load_fstab_fixture("fstab_nfs.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert output.data["mount_count"] == 2
        assert output.data["healthy"] is True

    def test_soft_mount_warning(self, capsys):
        """Soft mount detected returns exit code 1."""
        from scripts.baremetal.nfs_mount import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_proc_fixture("mounts_nfs_soft.txt"),
                "/etc/fstab": "",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert any("soft" in i["type"] for i in output.data["issues"])

    def test_unmounted_fstab_entry(self, capsys):
        """Unmounted fstab entry detected returns exit code 1."""
        from scripts.baremetal.nfs_mount import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_proc_fixture("mounts_nfs_healthy.txt"),
                "/etc/fstab": load_fstab_fixture("fstab_unmounted_nfs.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert any("unmounted" in i["type"] for i in output.data["issues"])

    def test_no_fstab_flag_skips_check(self, capsys):
        """--no-fstab flag skips fstab check."""
        from scripts.baremetal.nfs_mount import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_proc_fixture("mounts_nfs_healthy.txt"),
                "/etc/fstab": load_fstab_fixture("fstab_unmounted_nfs.txt"),
            },
        )
        output = Output()

        result = run(["--no-fstab"], output, context)

        assert result == 0
        assert not any("unmounted" in i["type"] for i in output.data["issues"])

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.nfs_mount import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_proc_fixture("mounts_nfs_healthy.txt"),
                "/etc/fstab": "",
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "mount_count" in data
        assert "issues" in data
        assert "healthy" in data

    def test_missing_proc_mounts(self, capsys):
        """Missing /proc/mounts returns exit code 2."""
        from scripts.baremetal.nfs_mount import run

        context = MockContext(
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert len(output.errors) > 0
