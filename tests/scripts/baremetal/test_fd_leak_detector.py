"""Tests for fd_leak_detector script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestFdLeakDetector:
    """Tests for fd_leak_detector."""

    def test_no_issues_detected(self, capsys):
        """No issues when processes have low FD counts."""
        from scripts.baremetal.fd_leak_detector import run

        # Simulate a process with low FD count (below thresholds)
        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
                "/proc/1234/comm": "healthy_proc\n",
                "/proc/1234/limits": load_fixture("limits_normal.txt"),
                "/proc/1234/fd/0": "/dev/null",
                "/proc/1234/fd/1": "/dev/stdout",
                "/proc/1234/fd/2": "/dev/stderr",
            },
        )
        output = Output()

        result = run(["--min-fds", "1"], output, context)

        assert result == 0

    def test_warning_high_fd_count(self, capsys):
        """Warning when process has high FD count."""
        from scripts.baremetal.fd_leak_detector import run

        # Create mock files for a process with 1000+ FDs
        fd_files = {f"/proc/5678/fd/{i}": f"/tmp/file{i}" for i in range(1100)}
        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
                "/proc/5678/comm": "leaky_proc\n",
                "/proc/5678/limits": load_fixture("limits_normal.txt"),
                **fd_files,
            },
        )
        output = Output()

        result = run(["--min-fds", "1"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "[WARNING]" in captured.out

    def test_critical_high_fd_count(self, capsys):
        """Critical when process has very high FD count."""
        from scripts.baremetal.fd_leak_detector import run

        # Create mock files for a process with 5000+ FDs
        fd_files = {f"/proc/9999/fd/{i}": f"/tmp/file{i}" for i in range(5100)}
        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
                "/proc/9999/comm": "very_leaky_proc\n",
                "/proc/9999/limits": load_fixture("limits_normal.txt"),
                **fd_files,
            },
        )
        output = Output()

        result = run(["--min-fds", "1"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "[CRITICAL]" in captured.out

    def test_approaching_limit_warning(self, capsys):
        """Warning when process approaches FD limit."""
        from scripts.baremetal.fd_leak_detector import run

        # Process with 85 FDs and soft limit of 100 (85% usage)
        fd_files = {f"/proc/4321/fd/{i}": f"/tmp/file{i}" for i in range(85)}
        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
                "/proc/4321/comm": "near_limit_proc\n",
                "/proc/4321/limits": load_fixture("limits_high_usage.txt"),  # soft limit 100
                **fd_files,
            },
        )
        output = Output()

        result = run(["--min-fds", "1", "--fd-warning", "10000"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "approaching_limit" in captured.out.lower() or "% of FD limit" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.fd_leak_detector import run

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

        result = run(["--format", "json", "--min-fds", "1"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "processes" in data
        assert "total_processes_analyzed" in data["summary"]
        assert "processes_with_issues" in data["summary"]
        assert "critical_count" in data["summary"]
        assert "warning_count" in data["summary"]

    def test_warn_only_no_issues(self, capsys):
        """Warn-only mode produces no output when healthy."""
        from scripts.baremetal.fd_leak_detector import run

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

        result = run(["--warn-only", "--min-fds", "1"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_missing_proc_filesystem(self, capsys):
        """Missing /proc filesystem returns exit code 2."""
        from scripts.baremetal.fd_leak_detector import run

        context = MockContext(
            file_contents={},  # No /proc files
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
