"""Tests for fd_exhaustion_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestFdExhaustionMonitor:
    """Tests for fd_exhaustion_monitor."""

    def test_healthy_fd_usage(self, capsys):
        """Healthy FD usage returns exit code 0."""
        from scripts.baremetal.fd_exhaustion_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert "system" in output.data
        assert "allocated" in output.data["system"]
        assert "max" in output.data["system"]

    def test_warning_fd_usage(self, capsys):
        """Warning FD usage (75-90%) returns exit code 1."""
        from scripts.baremetal.fd_exhaustion_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_warning.txt"),
            },
        )
        output = Output()

        # 76800/102400 = 75% (at warn threshold)
        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "[WARNING]" in captured.out

    def test_critical_fd_usage(self, capsys):
        """Critical FD usage (>90%) returns exit code 1."""
        from scripts.baremetal.fd_exhaustion_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_critical.txt"),
            },
        )
        output = Output()

        # 92160/102400 = 90% (at crit threshold)
        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "[CRITICAL]" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.fd_exhaustion_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "system" in data
        assert "issues" in data
        assert "allocated" in data["system"]
        assert "max" in data["system"]
        assert "available" in data["system"]
        assert "usage_percent" in data["system"]

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.fd_exhaustion_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_warning.txt"),  # 75% used
            },
        )
        output = Output()

        # With higher thresholds (80/95), 75% should be OK
        result = run(["--warn", "80", "--crit", "95"], output, context)

        assert result == 0

    def test_invalid_thresholds(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.fd_exhaustion_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/fs/file-nr": load_fixture("file_nr_healthy.txt"),
            },
        )
        output = Output()

        # Warning >= critical is invalid
        result = run(["--warn", "90", "--crit", "80"], output, context)

        assert result == 2

    def test_missing_file_nr(self, capsys):
        """Missing /proc/sys/fs/file-nr returns exit code 2."""
        from scripts.baremetal.fd_exhaustion_monitor import run

        context = MockContext(
            file_contents={},  # No file-nr
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
