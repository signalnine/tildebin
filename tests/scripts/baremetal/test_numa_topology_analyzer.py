"""Tests for numa_topology_analyzer script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


NUMA_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "sys" / "numa"
PROC_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_numa_fixture(name: str) -> str:
    """Load a NUMA fixture file."""
    return (NUMA_FIXTURES / name).read_text()


def load_proc_fixture(name: str) -> str:
    """Load a proc fixture file."""
    return (PROC_FIXTURES / name).read_text()


def make_healthy_context() -> MockContext:
    """Create context with healthy NUMA topology."""
    return MockContext(
        file_contents={
            "/sys/devices/system/node": "",
            "/sys/devices/system/node/node0": "",
            "/sys/devices/system/node/node1": "",
            "/sys/devices/system/node/node0/meminfo": load_numa_fixture("node0_meminfo.txt"),
            "/sys/devices/system/node/node0/numastat": load_numa_fixture("node0_numastat.txt"),
            "/sys/devices/system/node/node0/cpulist": load_numa_fixture("node0_cpulist.txt"),
            "/sys/devices/system/node/node0/distance": load_numa_fixture("node0_distance.txt"),
            "/sys/devices/system/node/node1/meminfo": load_numa_fixture("node1_meminfo.txt"),
            "/sys/devices/system/node/node1/numastat": load_numa_fixture("node1_numastat.txt"),
            "/sys/devices/system/node/node1/cpulist": load_numa_fixture("node1_cpulist.txt"),
            "/sys/devices/system/node/node1/distance": load_numa_fixture("node1_distance.txt"),
            "/proc/sys/kernel/numa_balancing": load_proc_fixture("numa_balancing_enabled.txt"),
            "/proc/vmstat": load_proc_fixture("vmstat_numa.txt"),
        },
    )


class TestNumaTopologyAnalyzer:
    """Tests for numa_topology_analyzer."""

    def test_healthy_topology_returns_0(self, capsys):
        """Healthy NUMA topology returns exit code 0."""
        from scripts.baremetal.numa_topology_analyzer import run

        context = make_healthy_context()
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Numa Nodes: 2" in captured.out

    def test_disabled_balancing_returns_1(self, capsys):
        """Disabled NUMA balancing returns exit code 1 (warning)."""
        from scripts.baremetal.numa_topology_analyzer import run

        context = MockContext(
            file_contents={
                "/sys/devices/system/node": "",
                "/sys/devices/system/node/node0": "",
                "/sys/devices/system/node/node1": "",
                "/sys/devices/system/node/node0/meminfo": load_numa_fixture("node0_meminfo.txt"),
                "/sys/devices/system/node/node0/numastat": load_numa_fixture("node0_numastat.txt"),
                "/sys/devices/system/node/node0/cpulist": load_numa_fixture("node0_cpulist.txt"),
                "/sys/devices/system/node/node1/meminfo": load_numa_fixture("node1_meminfo.txt"),
                "/sys/devices/system/node/node1/numastat": load_numa_fixture("node1_numastat.txt"),
                "/sys/devices/system/node/node1/cpulist": load_numa_fixture("node1_cpulist.txt"),
                "/proc/sys/kernel/numa_balancing": load_proc_fixture("numa_balancing_disabled.txt"),
                "/proc/vmstat": load_proc_fixture("vmstat_numa.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "disabled" in captured.out.lower() or "balancing" in captured.out.lower()

    def test_high_migration_returns_1(self, capsys):
        """High NUMA page migration returns exit code 1."""
        from scripts.baremetal.numa_topology_analyzer import run

        context = MockContext(
            file_contents={
                "/sys/devices/system/node": "",
                "/sys/devices/system/node/node0": "",
                "/sys/devices/system/node/node1": "",
                "/sys/devices/system/node/node0/meminfo": load_numa_fixture("node0_meminfo.txt"),
                "/sys/devices/system/node/node0/numastat": load_numa_fixture("node0_numastat.txt"),
                "/sys/devices/system/node/node0/cpulist": load_numa_fixture("node0_cpulist.txt"),
                "/sys/devices/system/node/node1/meminfo": load_numa_fixture("node1_meminfo.txt"),
                "/sys/devices/system/node/node1/numastat": load_numa_fixture("node1_numastat.txt"),
                "/sys/devices/system/node/node1/cpulist": load_numa_fixture("node1_cpulist.txt"),
                "/proc/sys/kernel/numa_balancing": load_proc_fixture("numa_balancing_enabled.txt"),
                "/proc/vmstat": load_proc_fixture("vmstat_numa_high_migration.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "migration" in captured.out.lower() or "migrated" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.numa_topology_analyzer import run

        context = make_healthy_context()
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "numa_nodes" in data
        assert "nodes" in data
        assert "status" in data
        assert "balancing" in data
        assert data["numa_nodes"] == 2

    def test_table_output(self, capsys):
        """Table output format works correctly."""
        from scripts.baremetal.numa_topology_analyzer import run

        context = make_healthy_context()
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Node" in captured.out
        assert "CPUs" in captured.out
        assert "Memory" in captured.out

    def test_no_numa_returns_2(self, capsys):
        """Missing NUMA sysfs returns exit code 2."""
        from scripts.baremetal.numa_topology_analyzer import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_single_node_is_healthy(self, capsys):
        """Single NUMA node is considered healthy."""
        from scripts.baremetal.numa_topology_analyzer import run

        context = MockContext(
            file_contents={
                "/sys/devices/system/node": "",
                "/sys/devices/system/node/node0": "",
                "/sys/devices/system/node/node0/meminfo": load_numa_fixture("node0_meminfo.txt"),
                "/sys/devices/system/node/node0/numastat": load_numa_fixture("node0_numastat.txt"),
                "/sys/devices/system/node/node0/cpulist": load_numa_fixture("node0_cpulist.txt"),
                "/proc/sys/kernel/numa_balancing": load_proc_fixture("numa_balancing_enabled.txt"),
                "/proc/vmstat": load_proc_fixture("vmstat_numa.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Single NUMA node" in captured.out or "1" in captured.out
