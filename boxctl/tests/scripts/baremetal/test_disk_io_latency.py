"""Tests for disk_io_latency script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestDiskIoLatency:
    """Tests for disk_io_latency."""

    def test_normal_latency(self, capsys):
        """Normal disk latency returns exit code 0."""
        from scripts.baremetal.disk_io_latency import run

        context = MockContext(
            file_contents={
                "/proc/diskstats": load_fixture("diskstats_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_slow_disk_warning(self, capsys):
        """Slow disk latency returns warning (exit code 1)."""
        from scripts.baremetal.disk_io_latency import run

        context = MockContext(
            file_contents={
                "/proc/diskstats": load_fixture("diskstats_slow.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.disk_io_latency import run

        context = MockContext(
            file_contents={
                "/proc/diskstats": load_fixture("diskstats_normal.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "devices" in data
        assert "status" in data

    def test_custom_threshold(self, capsys):
        """Custom threshold is respected."""
        from scripts.baremetal.disk_io_latency import run

        context = MockContext(
            file_contents={
                "/proc/diskstats": load_fixture("diskstats_slow.txt"),  # High latency
            },
        )
        output = Output()

        # With very high threshold, should be OK
        result = run(["--warn-latency", "50", "--crit-latency", "100"], output, context)

        assert result == 0

    def test_verbose_shows_all(self, capsys):
        """Verbose mode shows all devices."""
        from scripts.baremetal.disk_io_latency import run

        context = MockContext(
            file_contents={
                "/proc/diskstats": load_fixture("diskstats_normal.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "sda" in captured.out or "nvme" in captured.out

    def test_missing_diskstats(self, capsys):
        """Missing /proc/diskstats returns exit code 2."""
        from scripts.baremetal.disk_io_latency import run

        context = MockContext(
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
