"""Tests for cgroup_memory_limits script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


CGROUP_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "cgroup"


def load_cgroup_fixture(name: str) -> str:
    """Load a cgroup fixture file."""
    return (CGROUP_FIXTURES / name).read_text()


class TestCgroupMemoryLimits:
    """Tests for cgroup_memory_limits."""

    def test_healthy_memory(self, capsys):
        """Healthy memory usage returns exit code 0."""
        from scripts.baremetal.cgroup_memory_limits import run

        # 536870912 / 1073741824 = 50% usage (healthy)
        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/memory.current": load_cgroup_fixture("memory_current_healthy.txt"),
                "/sys/fs/cgroup/memory.max": load_cgroup_fixture("memory_max_1gb.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert len(output.data.get("issues", [])) == 0

    def test_high_memory_warning(self, capsys):
        """High memory usage returns exit code 1 with warning."""
        from scripts.baremetal.cgroup_memory_limits import run

        # 912680550 / 1073741824 = 85% usage (warning level)
        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/memory.current": load_cgroup_fixture("memory_current_high.txt"),
                "/sys/fs/cgroup/memory.max": load_cgroup_fixture("memory_max_1gb.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Warning" in captured.out or "85" in captured.out

    def test_critical_memory(self, capsys):
        """Critical memory usage returns exit code 1."""
        from scripts.baremetal.cgroup_memory_limits import run

        # 987842150 / 1073741824 = 92% usage (critical)
        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/memory.current": load_cgroup_fixture("memory_current_critical.txt"),
                "/sys/fs/cgroup/memory.max": load_cgroup_fixture("memory_max_1gb.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out

    def test_unlimited_memory(self, capsys):
        """Unlimited memory cgroups are handled correctly."""
        from scripts.baremetal.cgroup_memory_limits import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/memory.current": load_cgroup_fixture("memory_current_healthy.txt"),
                "/sys/fs/cgroup/memory.max": load_cgroup_fixture("memory_max_unlimited.txt"),
            },
        )
        output = Output()

        # Unlimited cgroups should not trigger issues
        result = run([], output, context)

        assert result == 0

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.cgroup_memory_limits import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/memory.current": load_cgroup_fixture("memory_current_healthy.txt"),
                "/sys/fs/cgroup/memory.max": load_cgroup_fixture("memory_max_1gb.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "cgroups" in data
        assert "issues" in data
        assert "summary" in data
        assert "total_cgroups" in data["summary"]
        assert "with_limits" in data["summary"]

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.cgroup_memory_limits import run

        # 912680550 / 1073741824 = 85% usage
        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/memory.current": load_cgroup_fixture("memory_current_high.txt"),
                "/sys/fs/cgroup/memory.max": load_cgroup_fixture("memory_max_1gb.txt"),
            },
        )
        output = Output()

        # With higher thresholds, 85% should be OK
        result = run(["--warn", "90", "--crit", "95"], output, context)

        assert result == 0

    def test_cgroup_v2_not_available(self, capsys):
        """Missing cgroup v2 returns exit code 2."""
        from scripts.baremetal.cgroup_memory_limits import run

        context = MockContext(
            file_contents={
                # No cgroup.controllers file
                "/sys/fs/cgroup/memory.current": load_cgroup_fixture("memory_current_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_table_format(self, capsys):
        """Table format output works correctly."""
        from scripts.baremetal.cgroup_memory_limits import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/memory.current": load_cgroup_fixture("memory_current_healthy.txt"),
                "/sys/fs/cgroup/memory.max": load_cgroup_fixture("memory_max_1gb.txt"),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Cgroup" in captured.out
        assert "Current" in captured.out
        assert "Limit" in captured.out
        assert "Status" in captured.out
