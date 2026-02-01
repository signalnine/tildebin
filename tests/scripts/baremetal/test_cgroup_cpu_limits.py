"""Tests for cgroup_cpu_limits script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


CGROUP_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "cgroup"


def load_cgroup_fixture(name: str) -> str:
    """Load a cgroup fixture file."""
    return (CGROUP_FIXTURES / name).read_text()


class TestCgroupCpuLimits:
    """Tests for cgroup_cpu_limits."""

    def test_healthy_cpu(self, capsys):
        """Healthy CPU usage returns exit code 0."""
        from scripts.baremetal.cgroup_cpu_limits import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/cpu.max": load_cgroup_fixture("cpu_max_limited.txt"),
                "/sys/fs/cgroup/cpu.weight": load_cgroup_fixture("cpu_weight_normal.txt"),
                "/sys/fs/cgroup/cpu.stat": load_cgroup_fixture("cpu_stat_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No CPU limit issues detected" in captured.out

    def test_throttled_cpu_warning(self, capsys):
        """Throttled CPU returns exit code 1 with warning."""
        from scripts.baremetal.cgroup_cpu_limits import run

        # cpu_stat_throttled has 30% throttling (3000/10000)
        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/cpu.max": load_cgroup_fixture("cpu_max_limited.txt"),
                "/sys/fs/cgroup/cpu.weight": load_cgroup_fixture("cpu_weight_normal.txt"),
                "/sys/fs/cgroup/cpu.stat": load_cgroup_fixture("cpu_stat_throttled.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "throttle" in captured.out.lower() or "CRITICAL" in captured.out

    def test_low_weight_warning(self, capsys):
        """Low CPU weight returns exit code 1 with warning."""
        from scripts.baremetal.cgroup_cpu_limits import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/cpu.max": load_cgroup_fixture("cpu_max_limited.txt"),
                "/sys/fs/cgroup/cpu.weight": load_cgroup_fixture("cpu_weight_low.txt"),  # weight=10
                "/sys/fs/cgroup/cpu.stat": load_cgroup_fixture("cpu_stat_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "weight" in captured.out.lower()

    def test_very_limited_cpu_warning(self, capsys):
        """Very restrictive CPU limit returns exit code 1 with warning."""
        from scripts.baremetal.cgroup_cpu_limits import run

        # cpu_max_very_limited has 5% limit (5000/100000)
        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/cpu.max": load_cgroup_fixture("cpu_max_very_limited.txt"),
                "/sys/fs/cgroup/cpu.weight": load_cgroup_fixture("cpu_weight_normal.txt"),
                "/sys/fs/cgroup/cpu.stat": load_cgroup_fixture("cpu_stat_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "restrictive" in captured.out.lower() or "limit" in captured.out.lower()

    def test_unlimited_cpu(self, capsys):
        """Unlimited CPU cgroups are handled correctly."""
        from scripts.baremetal.cgroup_cpu_limits import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/cpu.max": load_cgroup_fixture("cpu_max_unlimited.txt"),
                "/sys/fs/cgroup/cpu.weight": load_cgroup_fixture("cpu_weight_normal.txt"),
                "/sys/fs/cgroup/cpu.stat": load_cgroup_fixture("cpu_stat_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.cgroup_cpu_limits import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/cpu.max": load_cgroup_fixture("cpu_max_limited.txt"),
                "/sys/fs/cgroup/cpu.weight": load_cgroup_fixture("cpu_weight_normal.txt"),
                "/sys/fs/cgroup/cpu.stat": load_cgroup_fixture("cpu_stat_healthy.txt"),
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
        assert "throttled" in data["summary"]

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.cgroup_cpu_limits import run

        # 30% throttling - normally would trigger warning at 10%, critical at 25%
        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/cpu.max": load_cgroup_fixture("cpu_max_limited.txt"),
                "/sys/fs/cgroup/cpu.weight": load_cgroup_fixture("cpu_weight_normal.txt"),
                "/sys/fs/cgroup/cpu.stat": load_cgroup_fixture("cpu_stat_throttled.txt"),
            },
        )
        output = Output()

        # With higher thresholds, 30% should still be warning
        result = run(["--throttle-warn", "35", "--throttle-crit", "50"], output, context)

        assert result == 0

    def test_cgroup_v2_not_available(self, capsys):
        """Missing cgroup v2 returns exit code 2."""
        from scripts.baremetal.cgroup_cpu_limits import run

        context = MockContext(
            file_contents={
                # No cgroup.controllers file
                "/sys/fs/cgroup/cpu.max": load_cgroup_fixture("cpu_max_limited.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_table_format(self, capsys):
        """Table format output works correctly."""
        from scripts.baremetal.cgroup_cpu_limits import run

        context = MockContext(
            file_contents={
                "/sys/fs/cgroup/cgroup.controllers": "cpu memory io",
                "/sys/fs/cgroup/cpu.max": load_cgroup_fixture("cpu_max_limited.txt"),
                "/sys/fs/cgroup/cpu.weight": load_cgroup_fixture("cpu_weight_normal.txt"),
                "/sys/fs/cgroup/cpu.stat": load_cgroup_fixture("cpu_stat_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Cgroup" in captured.out
        assert "Limit" in captured.out
        assert "Weight" in captured.out
        assert "Status" in captured.out
