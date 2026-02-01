"""Tests for numa_balance_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "sys" / "numa"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


def make_balanced_context() -> MockContext:
    """Create context with balanced NUMA nodes."""
    return MockContext(
        file_contents={
            "/sys/devices/system/node": "",  # Directory marker
            "/sys/devices/system/node/node0": "",
            "/sys/devices/system/node/node1": "",
            "/sys/devices/system/node/node0/meminfo": load_fixture("node0_meminfo.txt"),
            "/sys/devices/system/node/node0/numastat": load_fixture("node0_numastat.txt"),
            "/sys/devices/system/node/node0/cpulist": load_fixture("node0_cpulist.txt"),
            "/sys/devices/system/node/node1/meminfo": load_fixture("node1_meminfo.txt"),
            "/sys/devices/system/node/node1/numastat": load_fixture("node1_numastat.txt"),
            "/sys/devices/system/node/node1/cpulist": load_fixture("node1_cpulist.txt"),
        },
    )


class TestNumaBalanceMonitor:
    """Tests for numa_balance_monitor."""

    def test_balanced_nodes_returns_0(self, capsys):
        """Balanced NUMA nodes return exit code 0."""
        from scripts.baremetal.numa_balance_monitor import run

        context = make_balanced_context()
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "NUMA Nodes: 2" in captured.out
        assert "[OK]" in captured.out

    def test_memory_imbalance_returns_1(self, capsys):
        """Memory imbalance returns exit code 1."""
        from scripts.baremetal.numa_balance_monitor import run

        context = MockContext(
            file_contents={
                "/sys/devices/system/node": "",
                "/sys/devices/system/node/node0": "",
                "/sys/devices/system/node/node1": "",
                "/sys/devices/system/node/node0/meminfo": load_fixture("node0_meminfo_imbalanced.txt"),
                "/sys/devices/system/node/node0/numastat": load_fixture("node0_numastat.txt"),
                "/sys/devices/system/node/node0/cpulist": load_fixture("node0_cpulist.txt"),
                "/sys/devices/system/node/node1/meminfo": load_fixture("node1_meminfo_imbalanced.txt"),
                "/sys/devices/system/node/node1/numastat": load_fixture("node1_numastat.txt"),
                "/sys/devices/system/node/node1/cpulist": load_fixture("node1_cpulist.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "memory_imbalance" in captured.out.lower() or "imbalance" in captured.out.lower()

    def test_high_numa_miss_returns_1(self, capsys):
        """High NUMA miss ratio returns exit code 1."""
        from scripts.baremetal.numa_balance_monitor import run

        context = MockContext(
            file_contents={
                "/sys/devices/system/node": "",
                "/sys/devices/system/node/node0": "",
                "/sys/devices/system/node/node1": "",
                "/sys/devices/system/node/node0/meminfo": load_fixture("node0_meminfo.txt"),
                "/sys/devices/system/node/node0/numastat": load_fixture("node0_numastat_high_miss.txt"),
                "/sys/devices/system/node/node0/cpulist": load_fixture("node0_cpulist.txt"),
                "/sys/devices/system/node/node1/meminfo": load_fixture("node1_meminfo.txt"),
                "/sys/devices/system/node/node1/numastat": load_fixture("node1_numastat.txt"),
                "/sys/devices/system/node/node1/cpulist": load_fixture("node1_cpulist.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "miss" in captured.out.lower()

    def test_low_free_memory_returns_1(self, capsys):
        """Low free memory on node returns exit code 1."""
        from scripts.baremetal.numa_balance_monitor import run

        context = MockContext(
            file_contents={
                "/sys/devices/system/node": "",
                "/sys/devices/system/node/node0": "",
                "/sys/devices/system/node/node1": "",
                "/sys/devices/system/node/node0/meminfo": load_fixture("node0_meminfo_low_free.txt"),
                "/sys/devices/system/node/node0/numastat": load_fixture("node0_numastat.txt"),
                "/sys/devices/system/node/node0/cpulist": load_fixture("node0_cpulist.txt"),
                "/sys/devices/system/node/node1/meminfo": load_fixture("node1_meminfo.txt"),
                "/sys/devices/system/node/node1/numastat": load_fixture("node1_numastat.txt"),
                "/sys/devices/system/node/node1/cpulist": load_fixture("node1_cpulist.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "free" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.numa_balance_monitor import run

        context = make_balanced_context()
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "nodes" in data
        assert "issues" in data
        assert data["summary"]["node_count"] == 2

    def test_no_numa_returns_2(self, capsys):
        """Missing NUMA sysfs returns exit code 2."""
        from scripts.baremetal.numa_balance_monitor import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_single_node_returns_2(self, capsys):
        """Single NUMA node returns exit code 2 (not applicable)."""
        from scripts.baremetal.numa_balance_monitor import run

        context = MockContext(
            file_contents={
                "/sys/devices/system/node": "",
                "/sys/devices/system/node/node0": "",
                "/sys/devices/system/node/node0/meminfo": load_fixture("node0_meminfo.txt"),
                "/sys/devices/system/node/node0/numastat": load_fixture("node0_numastat.txt"),
                "/sys/devices/system/node/node0/cpulist": load_fixture("node0_cpulist.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
