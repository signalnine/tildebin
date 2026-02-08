"""Tests for ksm_monitor script."""

import json

from boxctl.core.output import Output
from tests.conftest import MockContext


def _make_ksm_files(
    run_val="1",
    pages_shared="1000",
    pages_sharing="5000",
    pages_unshared="10000",
    pages_volatile="50",
    full_scans="42",
    sleep_millisecs="20",
):
    """Build a file_contents dict for KSM sysfs mock files."""
    base = "/sys/kernel/mm/ksm"
    return {
        f"{base}/run": run_val,
        f"{base}/pages_shared": pages_shared,
        f"{base}/pages_sharing": pages_sharing,
        f"{base}/pages_unshared": pages_unshared,
        f"{base}/pages_volatile": pages_volatile,
        f"{base}/full_scans": full_scans,
        f"{base}/sleep_millisecs": sleep_millisecs,
    }


class TestKsmMonitor:
    """Tests for ksm_monitor."""

    def test_ksm_not_available(self):
        """Missing /sys/kernel/mm/ksm/run returns exit code 2."""
        from scripts.baremetal.ksm_monitor import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_ksm_stopped(self, capsys):
        """KSM stopped (run=0) returns exit code 0 with INFO."""
        from scripts.baremetal.ksm_monitor import run

        context = MockContext(file_contents=_make_ksm_files(run_val="0"))
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "stopped" in captured.out.lower()
        assert "INFO" in captured.out

    def test_ksm_healthy(self, capsys):
        """KSM running with good sharing ratio returns exit code 0."""
        from scripts.baremetal.ksm_monitor import run

        # pages_sharing=5000, pages_unshared=10000
        # ratio = 5000 / (5000 + 10000) = 33.3% -- well above 1%
        context = MockContext(
            file_contents=_make_ksm_files(
                run_val="1",
                pages_sharing="5000",
                pages_unshared="10000",
            ),
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "KSM Monitor" in captured.out

    def test_ksm_low_efficiency(self, capsys):
        """KSM running with low sharing ratio returns exit code 1 WARNING."""
        from scripts.baremetal.ksm_monitor import run

        # pages_sharing=5, pages_unshared=50000
        # ratio = 5 / (5 + 50000) = 0.01% -- below 1% and unshared > 1000
        context = MockContext(
            file_contents=_make_ksm_files(
                run_val="1",
                pages_sharing="5",
                pages_unshared="50000",
            ),
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "wasting CPU" in captured.out.lower() or "low" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains all expected KSM metrics."""
        from scripts.baremetal.ksm_monitor import run

        context = MockContext(
            file_contents=_make_ksm_files(
                run_val="1",
                pages_shared="1000",
                pages_sharing="5000",
                pages_unshared="10000",
                pages_volatile="50",
                full_scans="42",
                sleep_millisecs="20",
            ),
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["run_state"] == 1
        assert data["run_state_name"] == "running"
        assert data["pages_shared"] == 1000
        assert data["pages_sharing"] == 5000
        assert data["pages_unshared"] == 10000
        assert data["pages_volatile"] == 50
        assert data["full_scans"] == 42
        assert data["sleep_millisecs"] == 20
        assert data["sharing_ratio"] is not None
        assert data["status"] == "healthy"
        assert "issues" in data
