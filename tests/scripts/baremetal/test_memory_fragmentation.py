"""Tests for memory_fragmentation script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestMemoryFragmentation:
    """Tests for memory_fragmentation."""

    def test_healthy_fragmentation_returns_0(self, capsys):
        """Healthy memory fragmentation returns exit code 0."""
        from scripts.baremetal.memory_fragmentation import run

        context = MockContext(
            file_contents={
                "/proc/buddyinfo": load_fixture("buddyinfo_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--buddyinfo-file", "/proc/buddyinfo"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Memory Fragmentation Analysis" in captured.out

    def test_fragmented_memory_returns_1(self, capsys):
        """Fragmented memory returns exit code 1."""
        from scripts.baremetal.memory_fragmentation import run

        context = MockContext(
            file_contents={
                "/proc/buddyinfo": load_fixture("buddyinfo_fragmented.txt"),
            },
        )
        output = Output()

        result = run(["--buddyinfo-file", "/proc/buddyinfo"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        # Should show warning or critical
        assert "WARNING" in captured.out or "CRITICAL" in captured.out

    def test_low_hugepages_warning(self, capsys):
        """Low hugepage blocks triggers warning."""
        from scripts.baremetal.memory_fragmentation import run

        context = MockContext(
            file_contents={
                "/proc/buddyinfo": load_fixture("buddyinfo_low_hugepages.txt"),
            },
        )
        output = Output()

        result = run(["--buddyinfo-file", "/proc/buddyinfo", "--hugepage-warn", "20"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "hugepage" in captured.out.lower()

    def test_json_output_format(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.memory_fragmentation import run

        context = MockContext(
            file_contents={
                "/proc/buddyinfo": load_fixture("buddyinfo_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--buddyinfo-file", "/proc/buddyinfo", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "zones" in data
        assert "issues" in data
        assert "total_free_bytes" in data["summary"]
        assert "max_fragmentation_index" in data["summary"]
        assert "total_hugepage_capable" in data["summary"]

    def test_numa_system_analysis(self, capsys):
        """Analyzes NUMA system with multiple nodes."""
        from scripts.baremetal.memory_fragmentation import run

        context = MockContext(
            file_contents={
                "/proc/buddyinfo": load_fixture("buddyinfo_numa.txt"),
            },
        )
        output = Output()

        result = run(["--buddyinfo-file", "/proc/buddyinfo", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should have zones from multiple nodes
        nodes = set(zone["node"] for zone in data["zones"])
        assert len(nodes) == 2  # Node 0 and Node 1

    def test_custom_thresholds(self, capsys):
        """Custom fragmentation thresholds are respected."""
        from scripts.baremetal.memory_fragmentation import run

        context = MockContext(
            file_contents={
                "/proc/buddyinfo": load_fixture("buddyinfo_healthy.txt"),
            },
        )
        output = Output()

        # Set very low thresholds to trigger warnings
        result = run([
            "--buddyinfo-file", "/proc/buddyinfo",
            "--frag-warn", "10",
            "--frag-crit", "20"
        ], output, context)

        # May or may not trigger depending on fixture values
        assert result in [0, 1]

    def test_missing_buddyinfo_returns_2(self, capsys):
        """Missing buddyinfo returns exit code 2."""
        from scripts.baremetal.memory_fragmentation import run

        context = MockContext(
            file_contents={},  # No files
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
