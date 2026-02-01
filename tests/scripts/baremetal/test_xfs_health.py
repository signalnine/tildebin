"""Tests for xfs_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


PROC_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "proc"
XFS_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "xfs"
DF_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "df"


def load_proc_fixture(name: str) -> str:
    """Load a proc fixture file."""
    return (PROC_FIXTURES / name).read_text()


def load_xfs_fixture(name: str) -> str:
    """Load an XFS fixture file."""
    return (XFS_FIXTURES / name).read_text()


def load_df_fixture(name: str) -> str:
    """Load a df fixture file."""
    return (DF_FIXTURES / name).read_text()


class TestXfsHealth:
    """Tests for xfs_health script."""

    def test_missing_xfs_info(self, capsys):
        """Returns exit code 2 when xfs_info not available."""
        from scripts.baremetal.xfs_health import run

        context = MockContext(
            tools_available=[],
            file_contents={
                "/proc/mounts": load_proc_fixture("mounts_xfs.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert any("xfs_info" in e.lower() for e in output.errors)

    def test_no_xfs_filesystems(self, capsys):
        """No XFS filesystems returns exit code 0."""
        from scripts.baremetal.xfs_health import run

        context = MockContext(
            tools_available=["xfs_info"],
            file_contents={
                "/proc/mounts": "/dev/sda1 / ext4 rw,relatime 0 0\n",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_xfs_healthy(self, capsys):
        """Healthy XFS filesystem returns exit code 0."""
        from scripts.baremetal.xfs_health import run

        context = MockContext(
            tools_available=["xfs_info", "df"],
            file_contents={
                "/proc/mounts": "/dev/sdb1 /data xfs rw,relatime,attr2,inode64 0 0\n",
            },
            command_outputs={
                ("xfs_info", "/data"): load_xfs_fixture("xfs_info_healthy.txt"),
                ("df", "-B1", "/data"): load_df_fixture("df_xfs_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert output.data["healthy"] == 1

    def test_xfs_nobarrier_warning(self, capsys):
        """XFS with nobarrier option returns exit code 1."""
        from scripts.baremetal.xfs_health import run

        context = MockContext(
            tools_available=["xfs_info", "df"],
            file_contents={
                "/proc/mounts": "/dev/sdb1 /data xfs rw,relatime,nobarrier 0 0\n",
            },
            command_outputs={
                ("xfs_info", "/data"): load_xfs_fixture("xfs_info_healthy.txt"),
                ("df", "-B1", "/data"): load_df_fixture("df_xfs_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert any(f["status"] == "warning" for f in output.data["filesystems"])

    def test_xfs_full_filesystem(self, capsys):
        """XFS filesystem at 95% returns exit code 1."""
        from scripts.baremetal.xfs_health import run

        context = MockContext(
            tools_available=["xfs_info", "df"],
            file_contents={
                "/proc/mounts": "/dev/sdb1 /data xfs rw,relatime,attr2,inode64 0 0\n",
            },
            command_outputs={
                ("xfs_info", "/data"): load_xfs_fixture("xfs_info_healthy.txt"),
                ("df", "-B1", "/data"): load_df_fixture("df_xfs_full.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert any(f["status"] == "critical" for f in output.data["filesystems"])

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.xfs_health import run

        context = MockContext(
            tools_available=["xfs_info", "df"],
            file_contents={
                "/proc/mounts": "/dev/sdb1 /data xfs rw,relatime,attr2,inode64 0 0\n",
            },
            command_outputs={
                ("xfs_info", "/data"): load_xfs_fixture("xfs_info_healthy.txt"),
                ("df", "-B1", "/data"): load_df_fixture("df_xfs_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "filesystems" in data
        assert "summary" in data
        assert "total" in data["summary"]

    def test_specific_mount_point(self, capsys):
        """--mount flag filters to specific mount point."""
        from scripts.baremetal.xfs_health import run

        context = MockContext(
            tools_available=["xfs_info", "df"],
            file_contents={
                "/proc/mounts": load_proc_fixture("mounts_xfs.txt"),
            },
            command_outputs={
                ("xfs_info", "/data"): load_xfs_fixture("xfs_info_healthy.txt"),
                ("df", "-B1", "/data"): load_df_fixture("df_xfs_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--mount", "/data"], output, context)

        assert result == 0
        assert output.data["total"] == 1

    def test_missing_proc_mounts(self, capsys):
        """Missing /proc/mounts returns exit code 2."""
        from scripts.baremetal.xfs_health import run

        context = MockContext(
            tools_available=["xfs_info"],
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert len(output.errors) > 0
