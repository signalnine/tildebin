"""Tests for systemd_timer_monitor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "systemd"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestSystemdTimerMonitor:
    """Tests for systemd_timer_monitor."""

    def test_missing_systemctl_returns_error(self):
        """Returns exit code 2 when systemctl not available."""
        from scripts.baremetal.systemd_timer_monitor import run

        ctx = MockContext(tools_available=[])
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("systemctl" in e.lower() for e in output.errors)

    def test_no_timers_found(self):
        """Returns 0 when no timers found."""
        from scripts.baremetal.systemd_timer_monitor import run

        ctx = MockContext(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "list-timers", "--all", "--no-pager", "--no-legend"): load_fixture("timers_empty.txt"),
            },
        )
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total"] == 0

    def test_healthy_timers_returns_zero(self):
        """Returns 0 when all timers are healthy."""
        from scripts.baremetal.systemd_timer_monitor import run

        ctx = MockContext(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "list-timers", "--all", "--no-pager", "--no-legend"): load_fixture("timers_healthy.txt"),
                ("systemctl", "show", "logrotate.timer", "--no-pager"): load_fixture("timer_show_healthy.txt"),
                ("systemctl", "show", "logrotate.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "fstrim.timer", "--no-pager"): load_fixture("timer_show_healthy.txt"),
                ("systemctl", "show", "fstrim.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "apt-daily.timer", "--no-pager"): load_fixture("timer_show_healthy.txt"),
                ("systemctl", "show", "apt-daily.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
            },
        )
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["with_issues"] == 0

    def test_failed_timer_detected(self):
        """Returns 1 when a timer has failed."""
        from scripts.baremetal.systemd_timer_monitor import run

        ctx = MockContext(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "list-timers", "--all", "--no-pager", "--no-legend"): "backup.timer  backup.service\n",
                ("systemctl", "show", "backup.timer", "--no-pager"): load_fixture("timer_show_failed.txt"),
                ("systemctl", "show", "backup.service", "--no-pager"): load_fixture("service_show_failed.txt"),
            },
        )
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["critical"] >= 1
        assert any("failed" in t["issues"][0].lower() for t in output.data["timers"])

    def test_inactive_timer_detected(self):
        """Returns 1 when a timer is inactive."""
        from scripts.baremetal.systemd_timer_monitor import run

        ctx = MockContext(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "list-timers", "--all", "--no-pager", "--no-legend"): "cleanup.timer  cleanup.service\n",
                ("systemctl", "show", "cleanup.timer", "--no-pager"): load_fixture("timer_show_inactive.txt"),
                ("systemctl", "show", "cleanup.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
            },
        )
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["warning"] >= 1

    def test_invalid_max_age_format(self):
        """Returns 2 for invalid max-age format."""
        from scripts.baremetal.systemd_timer_monitor import run

        ctx = MockContext(
            tools_available=["systemctl"],
            command_outputs={},
        )
        output = Output()

        exit_code = run(["--max-age", "invalid"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_warn_only_filters_output(self):
        """--warn-only shows only problematic timers."""
        from scripts.baremetal.systemd_timer_monitor import run

        ctx = MockContext(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "list-timers", "--all", "--no-pager", "--no-legend"): "healthy.timer  healthy.service\nfailed.timer  failed.service\n",
                ("systemctl", "show", "healthy.timer", "--no-pager"): load_fixture("timer_show_healthy.txt"),
                ("systemctl", "show", "healthy.service", "--no-pager"): load_fixture("service_show_healthy.txt"),
                ("systemctl", "show", "failed.timer", "--no-pager"): load_fixture("timer_show_failed.txt"),
                ("systemctl", "show", "failed.service", "--no-pager"): load_fixture("service_show_failed.txt"),
            },
        )
        output = Output()

        exit_code = run(["--warn-only"], output, ctx)

        assert exit_code == 1
        # With warn-only, only problematic timers should be in the output
        timer_names = [t["name"] for t in output.data["timers"]]
        assert "failed.timer" in timer_names
        assert "healthy.timer" not in timer_names
