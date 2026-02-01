"""Tests for open_file_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestOpenFileMonitor:
    """Tests for open_file_monitor."""

    def test_healthy_no_warnings(self, capsys):
        """No warnings when processes have normal FD usage."""
        from scripts.baremetal.open_file_monitor import run

        # Process with 20/1024 FDs (1.9% usage - well below 80%)
        fd_files = {f"/proc/1234/fd/{i}": f"/tmp/file{i}\n" for i in range(20)}
        context = MockContext(
            file_contents={
                "/proc/sys/kernel/hostname": load_fixture("hostname.txt"),
                "/proc/1234/comm": "healthy_proc\n",
                "/proc/1234/limits": load_fixture("limits_normal.txt"),
                **fd_files,
            },
        )
        output = Output()

        result = run(["--min-fds", "1"], output, context)

        assert result == 0

    def test_warning_high_usage(self, capsys):
        """Warning when process has high FD usage."""
        from scripts.baremetal.open_file_monitor import run

        # Process with 85/100 FDs (85% usage - above 80%)
        fd_files = {f"/proc/5678/fd/{i}": f"/tmp/file{i}\n" for i in range(85)}
        context = MockContext(
            file_contents={
                "/proc/sys/kernel/hostname": load_fixture("hostname.txt"),
                "/proc/5678/comm": "high_usage_proc\n",
                "/proc/5678/limits": load_fixture("limits_high_usage.txt"),  # soft limit 100
                **fd_files,
            },
        )
        output = Output()

        result = run(["--min-fds", "1"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "High FD usage" in captured.out

    def test_warning_deleted_files(self, capsys):
        """Warning when process holds deleted files."""
        from scripts.baremetal.open_file_monitor import run

        fd_files = {
            "/proc/1234/fd/0": "/var/log/app.log (deleted)\n",
            "/proc/1234/fd/1": "/tmp/temp.txt (deleted)\n",
            "/proc/1234/fd/2": "/dev/null\n",
        }
        context = MockContext(
            file_contents={
                "/proc/sys/kernel/hostname": load_fixture("hostname.txt"),
                "/proc/1234/comm": "app_with_deleted\n",
                "/proc/1234/limits": load_fixture("limits_normal.txt"),
                **fd_files,
            },
        )
        output = Output()

        result = run(["--min-fds", "1"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "deleted" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.open_file_monitor import run

        fd_files = {f"/proc/1234/fd/{i}": f"/tmp/file{i}\n" for i in range(20)}
        context = MockContext(
            file_contents={
                "/proc/sys/kernel/hostname": load_fixture("hostname.txt"),
                "/proc/1234/comm": "test_proc\n",
                "/proc/1234/limits": load_fixture("limits_normal.txt"),
                **fd_files,
            },
        )
        output = Output()

        result = run(["--format", "json", "--min-fds", "1"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "hostname" in data
        assert "summary" in data
        assert "processes" in data
        assert "total_processes_checked" in data["summary"]
        assert "processes_with_warnings" in data["summary"]
        assert "processes_with_deleted_files" in data["summary"]

    def test_deleted_only_filter(self, capsys):
        """--deleted-only filter shows only processes with deleted files."""
        from scripts.baremetal.open_file_monitor import run

        fd_files_normal = {f"/proc/1234/fd/{i}": f"/tmp/file{i}\n" for i in range(20)}
        fd_files_deleted = {
            "/proc/5678/fd/0": "/var/log/deleted.log (deleted)\n",
            "/proc/5678/fd/1": "/tmp/normal.txt\n",
        }
        context = MockContext(
            file_contents={
                "/proc/sys/kernel/hostname": load_fixture("hostname.txt"),
                "/proc/1234/comm": "normal_proc\n",
                "/proc/1234/limits": load_fixture("limits_normal.txt"),
                "/proc/5678/comm": "deleted_holder\n",
                "/proc/5678/limits": load_fixture("limits_normal.txt"),
                **fd_files_normal,
                **fd_files_deleted,
            },
        )
        output = Output()

        result = run(["--deleted-only", "--min-fds", "1"], output, context)

        captured = capsys.readouterr()
        assert "deleted_holder" in captured.out
        # normal_proc should be filtered out
        assert "normal_proc" not in captured.out

    def test_verbose_shows_types(self, capsys):
        """Verbose mode shows FD type breakdown."""
        from scripts.baremetal.open_file_monitor import run

        fd_files = {
            "/proc/1234/fd/0": "/tmp/file.txt\n",
            "/proc/1234/fd/1": "socket:[12345]\n",
            "/proc/1234/fd/2": "pipe:[67890]\n",
        }
        context = MockContext(
            file_contents={
                "/proc/sys/kernel/hostname": load_fixture("hostname.txt"),
                "/proc/1234/comm": "mixed_proc\n",
                "/proc/1234/limits": load_fixture("limits_normal.txt"),
                **fd_files,
            },
        )
        output = Output()

        result = run(["--verbose", "--min-fds", "1"], output, context)

        captured = capsys.readouterr()
        assert "Types:" in captured.out

    def test_missing_proc_filesystem(self, capsys):
        """Missing /proc filesystem returns exit code 2."""
        from scripts.baremetal.open_file_monitor import run

        context = MockContext(
            file_contents={},  # No /proc files
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_filter_by_name(self, capsys):
        """--name filter works correctly."""
        from scripts.baremetal.open_file_monitor import run

        fd_files_nginx = {f"/proc/1234/fd/{i}": f"/tmp/file{i}\n" for i in range(20)}
        fd_files_apache = {f"/proc/5678/fd/{i}": f"/tmp/file{i}\n" for i in range(20)}
        context = MockContext(
            file_contents={
                "/proc/sys/kernel/hostname": load_fixture("hostname.txt"),
                "/proc/1234/comm": "nginx\n",
                "/proc/1234/limits": load_fixture("limits_normal.txt"),
                "/proc/5678/comm": "apache2\n",
                "/proc/5678/limits": load_fixture("limits_normal.txt"),
                **fd_files_nginx,
                **fd_files_apache,
            },
        )
        output = Output()

        result = run(["--name", "nginx", "--min-fds", "1"], output, context)

        captured = capsys.readouterr()
        assert "nginx" in captured.out
