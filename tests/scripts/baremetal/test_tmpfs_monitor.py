"""Tests for tmpfs_monitor script."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from boxctl.core.output import Output
from tests.conftest import MockContext


PROC_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "proc"
STATVFS_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "statvfs"


def load_proc_fixture(name: str) -> str:
    """Load a proc fixture file."""
    return (PROC_FIXTURES / name).read_text()


def load_statvfs_fixture(name: str) -> dict:
    """Load a statvfs fixture file."""
    return json.loads((STATVFS_FIXTURES / name).read_text())


class MockStatvfs:
    """Mock for os.statvfs results."""

    def __init__(self, data: dict):
        self.f_frsize = data["f_frsize"]
        self.f_blocks = data["f_blocks"]
        self.f_bfree = data["f_bfree"]
        self.f_bavail = data["f_bavail"]
        self.f_files = data["f_files"]
        self.f_ffree = data["f_ffree"]


class TestTmpfsMonitor:
    """Tests for tmpfs_monitor script."""

    def test_no_tmpfs_mounts(self, capsys):
        """No tmpfs mounts returns exit code 0."""
        from scripts.baremetal.tmpfs_monitor import run

        context = MockContext(
            file_contents={
                "/proc/mounts": "/dev/sda1 / ext4 rw,relatime 0 0\n",
            },
        )
        output = Output()

        with patch("os.statvfs"):
            result = run([], output, context)

        assert result == 0
        assert output.data["tmpfs_count"] == 0

    def test_tmpfs_healthy(self, capsys):
        """Healthy tmpfs returns exit code 0."""
        from scripts.baremetal.tmpfs_monitor import run

        statvfs_data = load_statvfs_fixture("tmpfs_healthy.json")

        def mock_statvfs(path):
            if path in statvfs_data:
                return MockStatvfs(statvfs_data[path])
            raise OSError(f"No mock data for {path}")

        context = MockContext(
            file_contents={
                "/proc/mounts": load_proc_fixture("mounts_tmpfs_healthy.txt"),
            },
        )
        output = Output()

        with patch("os.statvfs", mock_statvfs):
            result = run([], output, context)

        assert result == 0
        assert output.data["issues_count"] == 0

    def test_tmpfs_warning(self, capsys):
        """Tmpfs at warning threshold returns exit code 1."""
        from scripts.baremetal.tmpfs_monitor import run

        statvfs_data = load_statvfs_fixture("tmpfs_warning.json")

        def mock_statvfs(path):
            if path in statvfs_data:
                return MockStatvfs(statvfs_data[path])
            raise OSError(f"No mock data for {path}")

        mounts = "tmpfs /run tmpfs rw,nosuid,nodev 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"

        context = MockContext(
            file_contents={
                "/proc/mounts": mounts,
            },
        )
        output = Output()

        with patch("os.statvfs", mock_statvfs):
            result = run([], output, context)

        assert result == 1
        assert output.data["issues_count"] > 0
        # Find the /run entry which should be in WARNING status
        run_fs = next((f for f in output.data["filesystems"] if f["mountpoint"] == "/run"), None)
        assert run_fs is not None
        assert run_fs["status"] == "WARNING"

    def test_tmpfs_critical(self, capsys):
        """Tmpfs at critical threshold returns exit code 1."""
        from scripts.baremetal.tmpfs_monitor import run

        statvfs_data = load_statvfs_fixture("tmpfs_critical.json")

        def mock_statvfs(path):
            if path in statvfs_data:
                return MockStatvfs(statvfs_data[path])
            raise OSError(f"No mock data for {path}")

        mounts = "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"

        context = MockContext(
            file_contents={
                "/proc/mounts": mounts,
            },
        )
        output = Output()

        with patch("os.statvfs", mock_statvfs):
            result = run([], output, context)

        assert result == 1
        assert any(f["status"] == "CRITICAL" for f in output.data["filesystems"])

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.tmpfs_monitor import run

        statvfs_data = load_statvfs_fixture("tmpfs_healthy.json")

        def mock_statvfs(path):
            if path in statvfs_data:
                return MockStatvfs(statvfs_data[path])
            raise OSError(f"No mock data for {path}")

        context = MockContext(
            file_contents={
                "/proc/mounts": load_proc_fixture("mounts_tmpfs_healthy.txt"),
            },
        )
        output = Output()

        with patch("os.statvfs", mock_statvfs):
            result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "tmpfs_count" in data
        assert "issues_count" in data
        assert "filesystems" in data

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.tmpfs_monitor import run

        # With these stats, ~85% used: 409576 - 60000 = 349576 used / 409576 total
        statvfs_data = load_statvfs_fixture("tmpfs_warning.json")

        def mock_statvfs(path):
            if path in statvfs_data:
                return MockStatvfs(statvfs_data[path])
            raise OSError(f"No mock data for {path}")

        mounts = "tmpfs /run tmpfs rw,nosuid,nodev 0 0\n"

        context = MockContext(
            file_contents={
                "/proc/mounts": mounts,
            },
        )
        output = Output()

        # With --warn 90, 85% should be OK
        with patch("os.statvfs", mock_statvfs):
            result = run(["--warn", "90", "--critical", "95"], output, context)

        assert result == 0

    def test_missing_proc_mounts(self, capsys):
        """Missing /proc/mounts returns exit code 2."""
        from scripts.baremetal.tmpfs_monitor import run

        context = MockContext(
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert len(output.errors) > 0

    def test_invalid_thresholds(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.tmpfs_monitor import run

        context = MockContext(
            file_contents={
                "/proc/mounts": "tmpfs /run tmpfs rw 0 0\n",
            },
        )
        output = Output()

        result = run(["--warn", "90", "--critical", "80"], output, context)

        assert result == 2
        assert len(output.errors) > 0
