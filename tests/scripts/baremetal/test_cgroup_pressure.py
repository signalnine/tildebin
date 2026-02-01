"""Tests for cgroup_pressure script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


PROC_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "proc"
CGROUP_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "cgroup"


def load_proc_fixture(name: str) -> str:
    """Load a proc fixture file."""
    return (PROC_FIXTURES / name).read_text()


def load_cgroup_fixture(name: str) -> str:
    """Load a cgroup fixture file."""
    return (CGROUP_FIXTURES / name).read_text()


class TestCgroupPressure:
    """Tests for cgroup_pressure."""

    def test_healthy_pressure(self, capsys):
        """Healthy cgroup PSI metrics return exit code 0."""
        from scripts.baremetal.cgroup_pressure import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/proc/pressure/cpu": load_proc_fixture("pressure_cpu_healthy.txt"),
                "/proc/pressure/memory": load_proc_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_proc_fixture("pressure_io_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No pressure issues detected" in captured.out

    def test_warning_pressure(self, capsys):
        """Warning level PSI metrics return exit code 1."""
        from scripts.baremetal.cgroup_pressure import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/proc/pressure/cpu": load_proc_fixture("pressure_cpu_warning.txt"),
                "/proc/pressure/memory": load_proc_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_proc_fixture("pressure_io_healthy.txt"),
            },
        )
        output = Output()

        # avg10=15.50 is above warn threshold (10)
        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Warning" in captured.out or "CPU pressure" in captured.out

    def test_critical_pressure(self, capsys):
        """Critical PSI metrics return exit code 1."""
        from scripts.baremetal.cgroup_pressure import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/proc/pressure/cpu": load_proc_fixture("pressure_cpu_critical.txt"),
                "/proc/pressure/memory": load_proc_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_proc_fixture("pressure_io_healthy.txt"),
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
        from scripts.baremetal.cgroup_pressure import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/proc/pressure/cpu": load_proc_fixture("pressure_cpu_healthy.txt"),
                "/proc/pressure/memory": load_proc_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_proc_fixture("pressure_io_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "system_pressure" in data
        assert "issues" in data
        assert "summary" in data
        assert "cpu" in data["system_pressure"]
        assert "memory" in data["system_pressure"]
        assert "io" in data["system_pressure"]

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.cgroup_pressure import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/proc/pressure/cpu": load_proc_fixture("pressure_cpu_warning.txt"),  # 15.5%
                "/proc/pressure/memory": load_proc_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_proc_fixture("pressure_io_healthy.txt"),
            },
        )
        output = Output()

        # With higher thresholds, 15.5% should be OK
        result = run(["--warn", "20", "--crit", "40"], output, context)

        assert result == 0

    def test_cgroup_v2_not_available(self, capsys):
        """Missing cgroup v2 returns exit code 2."""
        from scripts.baremetal.cgroup_pressure import run

        context = MockContext(
            file_contents={
                "/proc/pressure/cpu": load_proc_fixture("pressure_cpu_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_psi_not_available(self, capsys):
        """Missing PSI returns exit code 2."""
        from scripts.baremetal.cgroup_pressure import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                # No /proc/pressure files
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_table_format(self, capsys):
        """Table format output works correctly."""
        from scripts.baremetal.cgroup_pressure import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/proc/pressure/cpu": load_proc_fixture("pressure_cpu_healthy.txt"),
                "/proc/pressure/memory": load_proc_fixture("pressure_memory_healthy.txt"),
                "/proc/pressure/io": load_proc_fixture("pressure_io_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Resource" in captured.out
        assert "Level" in captured.out
        assert "avg10" in captured.out
