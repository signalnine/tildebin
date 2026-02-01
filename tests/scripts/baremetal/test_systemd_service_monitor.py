"""Tests for systemd_service_monitor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "systemd"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestSystemdServiceMonitor:
    """Tests for systemd_service_monitor."""

    def test_missing_systemctl_returns_error(self):
        """Returns exit code 2 when systemctl not available."""
        from scripts.baremetal.systemd_service_monitor import run

        ctx = MockContext(tools_available=[])
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("systemctl" in e.lower() for e in output.errors)

    def test_healthy_system_returns_zero(self):
        """Returns 0 when system is running and no failed units."""
        from scripts.baremetal.systemd_service_monitor import run

        ctx = MockContext(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "is-system-running"): load_fixture("system_running.txt"),
                ("systemctl", "--failed", "--no-legend", "--no-pager"): load_fixture("no_failed_units.txt"),
                ("systemctl", "list-units", "--type=service", "--no-legend", "--no-pager", "--all"): load_fixture("all_services.txt"),
                ("systemctl", "show", "sshd.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "nginx.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "docker.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "cron.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
            },
        )
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        assert output.data["system_state"] == "running"
        assert len(output.data["failed_units"]) == 0

    def test_degraded_system_returns_one(self):
        """Returns 1 when system is degraded."""
        from scripts.baremetal.systemd_service_monitor import run

        ctx = MockContext(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "is-system-running"): load_fixture("system_degraded.txt"),
                ("systemctl", "--failed", "--no-legend", "--no-pager"): load_fixture("failed_units.txt"),
                ("systemctl", "list-units", "--type=service", "--no-legend", "--no-pager", "--all"): load_fixture("all_services.txt"),
                ("systemctl", "show", "sshd.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "nginx.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "docker.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "cron.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
            },
        )
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        assert output.data["system_state"] == "degraded"
        assert len(output.data["failed_units"]) == 2

    def test_failed_units_detected(self):
        """Detects and reports failed units."""
        from scripts.baremetal.systemd_service_monitor import run

        ctx = MockContext(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "is-system-running"): load_fixture("system_degraded.txt"),
                ("systemctl", "--failed", "--no-legend", "--no-pager"): load_fixture("failed_units.txt"),
                ("systemctl", "list-units", "--type=service", "--no-legend", "--no-pager", "--all"): load_fixture("all_services.txt"),
                ("systemctl", "show", "sshd.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "nginx.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "docker.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "cron.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
            },
        )
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        failed = output.data["failed_units"]
        assert len(failed) == 2
        assert any(u["unit"] == "nginx.service" for u in failed)
        assert any(u["unit"] == "mysql.service" for u in failed)

    def test_critical_service_check(self):
        """Checks specified critical services."""
        from scripts.baremetal.systemd_service_monitor import run

        ctx = MockContext(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "is-system-running"): load_fixture("system_running.txt"),
                ("systemctl", "--failed", "--no-legend", "--no-pager"): load_fixture("no_failed_units.txt"),
                ("systemctl", "is-active", "sshd.service"): load_fixture("is_active_active.txt"),
                ("systemctl", "is-active", "myapp.service"): load_fixture("is_active_inactive.txt"),
                ("systemctl", "show", "myapp.service", "--no-pager"): load_fixture("service_show_failed.txt"),
                ("systemctl", "list-units", "--type=service", "--no-legend", "--no-pager", "--all"): load_fixture("all_services.txt"),
                ("systemctl", "show", "sshd.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "nginx.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "docker.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "cron.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
            },
        )
        output = Output()

        exit_code = run(["--critical", "sshd,myapp"], output, ctx)

        assert exit_code == 1
        assert len(output.data["critical_issues"]) == 1
        assert output.data["critical_issues"][0]["service"] == "myapp.service"

    def test_high_restart_count_detected(self):
        """Detects services with high restart counts."""
        from scripts.baremetal.systemd_service_monitor import run

        ctx = MockContext(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "is-system-running"): load_fixture("system_running.txt"),
                ("systemctl", "--failed", "--no-legend", "--no-pager"): load_fixture("no_failed_units.txt"),
                ("systemctl", "list-units", "--type=service", "--no-legend", "--no-pager", "--all"): "flaky.service loaded active running Flaky Service\n",
                ("systemctl", "show", "flaky.service", "--no-pager"): load_fixture("service_show_high_restarts.txt"),
            },
        )
        output = Output()

        exit_code = run(["--restart-threshold", "3"], output, ctx)

        assert exit_code == 1
        assert len(output.data["restart_warnings"]) == 1
        assert output.data["restart_warnings"][0]["restart_count"] == 5

    def test_custom_restart_threshold(self):
        """Custom restart threshold is respected."""
        from scripts.baremetal.systemd_service_monitor import run

        ctx = MockContext(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "is-system-running"): load_fixture("system_running.txt"),
                ("systemctl", "--failed", "--no-legend", "--no-pager"): load_fixture("no_failed_units.txt"),
                ("systemctl", "list-units", "--type=service", "--no-legend", "--no-pager", "--all"): "flaky.service loaded active running Flaky Service\n",
                ("systemctl", "show", "flaky.service", "--no-pager"): load_fixture("service_show_high_restarts.txt"),
            },
        )
        output = Output()

        # With threshold of 10, 5 restarts should not trigger warning
        exit_code = run(["--restart-threshold", "10"], output, ctx)

        assert exit_code == 0
        assert len(output.data["restart_warnings"]) == 0
