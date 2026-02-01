"""Tests for uptime script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestUptime:
    """Tests for uptime."""

    def test_normal_uptime(self, capsys):
        """Normal uptime returns exit code 0."""
        from scripts.baremetal.uptime import run

        context = MockContext(
            file_contents={
                "/proc/uptime": load_fixture("uptime_normal.txt"),
            },
        )
        output = Output()

        # 86400 seconds = 1 day (healthy)
        result = run([], output, context)

        assert result == 0

    def test_fresh_reboot_warning(self, capsys):
        """Fresh reboot returns warning (exit code 1)."""
        from scripts.baremetal.uptime import run

        context = MockContext(
            file_contents={
                "/proc/uptime": load_fixture("uptime_fresh.txt"),
            },
        )
        output = Output()

        # 3600 seconds = 1 hour (recent reboot)
        result = run(["--min-uptime", "2"], output, context)  # Warn if < 2 hours

        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.uptime import run

        context = MockContext(
            file_contents={
                "/proc/uptime": load_fixture("uptime_normal.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "uptime_seconds" in data
        assert "uptime_human" in data
        assert "status" in data

    def test_custom_threshold(self, capsys):
        """Custom threshold is respected."""
        from scripts.baremetal.uptime import run

        context = MockContext(
            file_contents={
                "/proc/uptime": load_fixture("uptime_fresh.txt"),  # 1 hour
            },
        )
        output = Output()

        # With 30 min threshold, should be OK
        result = run(["--min-uptime", "0.5"], output, context)

        assert result == 0

    def test_missing_uptime(self, capsys):
        """Missing /proc/uptime returns exit code 2."""
        from scripts.baremetal.uptime import run

        context = MockContext(
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
