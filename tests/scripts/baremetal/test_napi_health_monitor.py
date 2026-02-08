"""Tests for napi_health_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestNapiHealthMonitor:
    """Tests for napi_health_monitor."""

    def test_healthy_settings(self, capsys):
        """Healthy NAPI settings return exit code 0."""
        from scripts.baremetal.napi_health_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/core/netdev_budget": load_fixture("sys_net_core_netdev_budget.txt"),
                "/proc/sys/net/core/dev_weight": load_fixture("sys_net_core_dev_weight.txt"),
                "/proc/sys/net/core/gro_normal_batch": load_fixture("sys_net_core_gro_normal_batch.txt"),
                "/proc/sys/net/core/busy_poll": load_fixture("sys_net_core_busy_poll.txt"),
                "/proc/sys/net/core/busy_read": load_fixture("sys_net_core_busy_read.txt"),
                "/proc/softirqs": load_fixture("softirqs_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "healthy" in captured.out.lower() or "OK" in captured.out

    def test_low_netdev_budget_warning(self, capsys):
        """Low netdev_budget generates warning."""
        from scripts.baremetal.napi_health_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/core/netdev_budget": load_fixture("sys_net_core_netdev_budget_low.txt"),
                "/proc/sys/net/core/dev_weight": load_fixture("sys_net_core_dev_weight.txt"),
                "/proc/sys/net/core/gro_normal_batch": load_fixture("sys_net_core_gro_normal_batch.txt"),
                "/proc/sys/net/core/busy_poll": load_fixture("sys_net_core_busy_poll.txt"),
                "/proc/sys/net/core/busy_read": load_fixture("sys_net_core_busy_read.txt"),
                "/proc/softirqs": load_fixture("softirqs_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        # Low budget is a warning, not an issue, so should still be 0
        captured = capsys.readouterr()
        assert "netdev_budget" in captured.out.lower()

    def test_softirq_imbalance(self, capsys):
        """NET_RX softirq imbalance returns exit code 1."""
        from scripts.baremetal.napi_health_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/core/netdev_budget": load_fixture("sys_net_core_netdev_budget.txt"),
                "/proc/sys/net/core/dev_weight": load_fixture("sys_net_core_dev_weight.txt"),
                "/proc/sys/net/core/gro_normal_batch": load_fixture("sys_net_core_gro_normal_batch.txt"),
                "/proc/sys/net/core/busy_poll": load_fixture("sys_net_core_busy_poll.txt"),
                "/proc/sys/net/core/busy_read": load_fixture("sys_net_core_busy_read.txt"),
                "/proc/softirqs": load_fixture("softirqs_imbalanced.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "imbalance" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.napi_health_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/core/netdev_budget": load_fixture("sys_net_core_netdev_budget.txt"),
                "/proc/sys/net/core/dev_weight": load_fixture("sys_net_core_dev_weight.txt"),
                "/proc/sys/net/core/gro_normal_batch": load_fixture("sys_net_core_gro_normal_batch.txt"),
                "/proc/sys/net/core/busy_poll": load_fixture("sys_net_core_busy_poll.txt"),
                "/proc/sys/net/core/busy_read": load_fixture("sys_net_core_busy_read.txt"),
                "/proc/softirqs": load_fixture("softirqs_normal.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "settings" in data
        assert "softirq_stats" in data
        assert "status" in data
        assert "netdev_budget" in data["settings"]

    def test_verbose_shows_per_cpu(self, capsys):
        """Verbose mode shows per-CPU distribution."""
        from scripts.baremetal.napi_health_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/core/netdev_budget": load_fixture("sys_net_core_netdev_budget.txt"),
                "/proc/sys/net/core/dev_weight": load_fixture("sys_net_core_dev_weight.txt"),
                "/proc/sys/net/core/gro_normal_batch": load_fixture("sys_net_core_gro_normal_batch.txt"),
                "/proc/sys/net/core/busy_poll": load_fixture("sys_net_core_busy_poll.txt"),
                "/proc/sys/net/core/busy_read": load_fixture("sys_net_core_busy_read.txt"),
                "/proc/softirqs": load_fixture("softirqs_normal.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "Net Rx:" in captured.out and output.data["softirq_stats"]["net_rx"]

    def test_missing_settings_returns_error(self, capsys):
        """Missing NAPI settings return exit code 2."""
        from scripts.baremetal.napi_health_monitor import run

        context = MockContext(
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_low_gro_batch_warning(self, capsys):
        """Low gro_normal_batch generates warning."""
        from scripts.baremetal.napi_health_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/core/netdev_budget": load_fixture("sys_net_core_netdev_budget.txt"),
                "/proc/sys/net/core/dev_weight": load_fixture("sys_net_core_dev_weight.txt"),
                "/proc/sys/net/core/gro_normal_batch": load_fixture("sys_net_core_gro_normal_batch_low.txt"),
                "/proc/sys/net/core/busy_poll": load_fixture("sys_net_core_busy_poll.txt"),
                "/proc/sys/net/core/busy_read": load_fixture("sys_net_core_busy_read.txt"),
                "/proc/softirqs": load_fixture("softirqs_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert "gro_normal_batch" in captured.out.lower()
