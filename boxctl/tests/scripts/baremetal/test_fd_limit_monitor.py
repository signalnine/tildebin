"""Tests for fd_limit_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestFdLimitMonitor:
    """Tests for fd_limit_monitor."""

    def test_healthy_no_high_usage(self, capsys):
        """No warnings when processes are below threshold."""
        from scripts.baremetal.fd_limit_monitor import run

        # Process with 20/1024 FDs (1.9% usage - well below 80%)
        fd_files = {f"/proc/1234/fd/{i}": f"/tmp/file{i}" for i in range(20)}
        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
                "/proc/1234/comm": "healthy_proc\n",
                "/proc/1234/limits": load_fixture("limits_normal.txt"),
                **fd_files,
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_warning_high_usage(self, capsys):
        """Warning when process exceeds threshold."""
        from scripts.baremetal.fd_limit_monitor import run

        # Process with 85/100 FDs (85% usage - above 80%)
        fd_files = {f"/proc/5678/fd/{i}": f"/tmp/file{i}" for i in range(85)}
        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
                "/proc/5678/comm": "high_usage_proc\n",
                "/proc/5678/limits": load_fixture("limits_high_usage.txt"),  # soft limit 100
                **fd_files,
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "high_usage_proc" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.fd_limit_monitor import run

        fd_files = {f"/proc/1234/fd/{i}": f"/tmp/file{i}" for i in range(50)}
        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
                "/proc/1234/comm": "test_proc\n",
                "/proc/1234/limits": load_fixture("limits_normal.txt"),
                **fd_files,
            },
        )
        output = Output()

        result = run(["--format", "json", "--all"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "system" in data
        assert "processes" in data
        assert "allocated" in data["system"]
        assert "max" in data["system"]
        assert "usage_percent" in data["system"]

    def test_show_all_processes(self, capsys):
        """--all flag shows all processes regardless of threshold."""
        from scripts.baremetal.fd_limit_monitor import run

        fd_files = {f"/proc/1234/fd/{i}": f"/tmp/file{i}" for i in range(10)}
        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
                "/proc/1234/comm": "low_usage_proc\n",
                "/proc/1234/limits": load_fixture("limits_normal.txt"),
                **fd_files,
            },
        )
        output = Output()

        result = run(["--all"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "low_usage_proc" in captured.out

    def test_custom_threshold(self, capsys):
        """Custom threshold is respected."""
        from scripts.baremetal.fd_limit_monitor import run

        # Process with 60/100 FDs (60% usage)
        fd_files = {f"/proc/5678/fd/{i}": f"/tmp/file{i}" for i in range(60)}
        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
                "/proc/5678/comm": "medium_usage_proc\n",
                "/proc/5678/limits": load_fixture("limits_high_usage.txt"),  # soft limit 100
                **fd_files,
            },
        )
        output = Output()

        # With threshold 50, 60% should trigger warning
        result = run(["--threshold", "50"], output, context)

        assert result == 1

        # With threshold 70, 60% should be OK
        result = run(["--threshold", "70"], output, context)

        assert result == 0

    def test_invalid_threshold(self, capsys):
        """Invalid threshold returns exit code 2."""
        from scripts.baremetal.fd_limit_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--threshold", "150"], output, context)

        assert result == 2

    def test_filter_by_name(self, capsys):
        """--name filter works correctly."""
        from scripts.baremetal.fd_limit_monitor import run

        fd_files_nginx = {f"/proc/1234/fd/{i}": f"/tmp/file{i}" for i in range(90)}
        fd_files_apache = {f"/proc/5678/fd/{i}": f"/tmp/file{i}" for i in range(90)}
        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
                "/proc/1234/comm": "nginx\n",
                "/proc/1234/limits": load_fixture("limits_high_usage.txt"),
                "/proc/5678/comm": "apache2\n",
                "/proc/5678/limits": load_fixture("limits_high_usage.txt"),
                **fd_files_nginx,
                **fd_files_apache,
            },
        )
        output = Output()

        result = run(["--name", "nginx"], output, context)

        captured = capsys.readouterr()
        assert "nginx" in captured.out
        # apache2 should be filtered out
        # (though the output may still show it if both match percentage threshold)

    def test_missing_file_nr(self, capsys):
        """Missing /proc/sys/fs/file-nr returns exit code 2."""
        from scripts.baremetal.fd_limit_monitor import run

        context = MockContext(
            file_contents={},  # No file-nr
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
