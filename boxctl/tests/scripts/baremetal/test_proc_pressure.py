"""Tests for proc_pressure script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestProcPressure:
    """Tests for proc_pressure."""

    def test_healthy_pressure(self, capsys):
        """Healthy PSI metrics return exit code 0."""
        from scripts.baremetal.proc_pressure import run

        context = MockContext(
            file_contents={
                "/proc/pressure/cpu": load_fixture("pressure_cpu_healthy.txt"),
                "/proc/pressure/memory": load_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_fixture("pressure_io_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "[OK]" in captured.out

    def test_warning_pressure(self, capsys):
        """Warning level PSI metrics return exit code 0 (warnings only)."""
        from scripts.baremetal.proc_pressure import run

        context = MockContext(
            file_contents={
                "/proc/pressure/cpu": load_fixture("pressure_cpu_warning.txt"),
                "/proc/pressure/memory": load_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_fixture("pressure_io_healthy.txt"),
            },
        )
        output = Output()

        # avg10=15.50 is above warn threshold (10) but below crit (25)
        result = run([], output, context)

        # Warnings don't cause exit code 1, only critical issues do
        assert result == 0
        captured = capsys.readouterr()
        assert "WARN" in captured.out or "warning" in captured.out.lower()

    def test_critical_pressure(self, capsys):
        """Critical PSI metrics return exit code 1."""
        from scripts.baremetal.proc_pressure import run

        context = MockContext(
            file_contents={
                "/proc/pressure/cpu": load_fixture("pressure_cpu_critical.txt"),
                "/proc/pressure/memory": load_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_fixture("pressure_io_healthy.txt"),
            },
        )
        output = Output()

        # avg10=35.50 is above critical threshold (25)
        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.proc_pressure import run

        context = MockContext(
            file_contents={
                "/proc/pressure/cpu": load_fixture("pressure_cpu_healthy.txt"),
                "/proc/pressure/memory": load_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_fixture("pressure_io_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "psi_available" in data
        assert "metrics" in data
        assert "status" in data
        assert data["psi_available"] is True
        assert "cpu" in data["metrics"]
        assert "memory" in data["metrics"]
        assert "io" in data["metrics"]

    def test_single_resource(self, capsys):
        """Can monitor single resource."""
        from scripts.baremetal.proc_pressure import run

        context = MockContext(
            file_contents={
                "/proc/pressure/cpu": load_fixture("pressure_cpu_healthy.txt"),
                "/proc/pressure/memory": load_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_fixture("pressure_io_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--resource", "memory", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should only have memory metrics
        assert "memory" in data["metrics"]
        assert "cpu" not in data["metrics"]
        assert "io" not in data["metrics"]

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.proc_pressure import run

        context = MockContext(
            file_contents={
                "/proc/pressure/cpu": load_fixture("pressure_cpu_warning.txt"),  # 15.5%
                "/proc/pressure/memory": load_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_fixture("pressure_io_healthy.txt"),
            },
        )
        output = Output()

        # With higher thresholds, 15.5% should be OK
        result = run(["--warn-some", "20", "--crit-some", "40"], output, context)

        assert result == 0

    def test_psi_not_available(self, capsys):
        """Missing PSI returns exit code 2."""
        from scripts.baremetal.proc_pressure import run

        context = MockContext(
            file_contents={},  # No PSI files
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_table_format(self, capsys):
        """Table format output works correctly."""
        from scripts.baremetal.proc_pressure import run

        context = MockContext(
            file_contents={
                "/proc/pressure/cpu": load_fixture("pressure_cpu_healthy.txt"),
                "/proc/pressure/memory": load_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_fixture("pressure_io_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Resource" in captured.out
        assert "CPU" in captured.out
        assert "MEMORY" in captured.out
        assert "IO" in captured.out
