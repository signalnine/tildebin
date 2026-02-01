"""Tests for kernel_limits_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestKernelLimitsMonitor:
    """Tests for kernel_limits_monitor."""

    def _create_limits_context(
        self,
        pid_max: str = "32768",
        threads_max: str = "63067",
        file_max: str = "9223372036854775807",
        file_nr: str = "5120\t0\t9223372036854775807",
        loadavg: str = "0.15 0.10 0.05 1/245 12345",
        aio_max: str = "1048576",
        aio_nr: str = "256",
        inotify_max: str = "524288",
    ) -> MockContext:
        """Create a mock context with kernel limit values."""
        file_contents = {
            "/proc/sys/kernel": "directory-marker",
            "/proc/sys/kernel/pid_max": pid_max,
            "/proc/sys/kernel/threads-max": threads_max,
            "/proc/sys/fs/file-max": file_max,
            "/proc/sys/fs/file-nr": file_nr,
            "/proc/loadavg": loadavg,
            "/proc/sys/fs/aio-max-nr": aio_max,
            "/proc/sys/fs/aio-nr": aio_nr,
            "/proc/sys/fs/inotify/max_user_watches": inotify_max,
        }
        return MockContext(file_contents=file_contents)

    def test_healthy_limits(self, capsys):
        """All limits OK returns exit code 0."""
        from scripts.baremetal.kernel_limits_monitor import run

        # 245 processes out of 32768 = 0.7% usage
        context = self._create_limits_context()
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_warning_threshold(self, capsys):
        """Warning when usage approaches threshold."""
        from scripts.baremetal.kernel_limits_monitor import run

        # 850 out of 1000 = 85% usage (above 80% default warning)
        context = self._create_limits_context(
            pid_max="1000",
            loadavg="0.15 0.10 0.05 1/850 12345",
        )
        output = Output()

        result = run([], output, context)

        assert result == 1

    def test_critical_threshold(self, capsys):
        """Critical when usage exceeds critical threshold."""
        from scripts.baremetal.kernel_limits_monitor import run

        # 970 out of 1000 = 97% usage (above 95% default critical)
        context = self._create_limits_context(
            pid_max="1000",
            loadavg="0.15 0.10 0.05 1/970 12345",
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.kernel_limits_monitor import run

        # 750 out of 1000 = 75% usage
        context = self._create_limits_context(
            pid_max="1000",
            loadavg="0.15 0.10 0.05 1/750 12345",
        )
        output = Output()

        # With warn=80, crit=95, 75% should be OK
        result = run(["--warn", "80", "--crit", "95"], output, context)
        assert result == 0

        # With warn=70, crit=90, 75% should be WARNING
        result = run(["--warn", "70", "--crit", "90"], output, context)
        assert result == 1

    def test_json_output_format(self, capsys):
        """JSON output contains expected structure."""
        from scripts.baremetal.kernel_limits_monitor import run

        context = self._create_limits_context()
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "status" in data
        assert "limits" in data
        assert "critical_count" in data
        assert "warning_count" in data
        assert isinstance(data["limits"], list)

    def test_table_output_format(self, capsys):
        """Table output has proper format."""
        from scripts.baremetal.kernel_limits_monitor import run

        context = self._create_limits_context()
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        # Should have header
        assert "Parameter" in captured.out
        assert "Limit" in captured.out
        assert "Status" in captured.out

    def test_verbose_shows_all(self, capsys):
        """Verbose mode shows all limits."""
        from scripts.baremetal.kernel_limits_monitor import run

        context = self._create_limits_context()
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "kernel.pid_max" in captured.out
        assert "fs.file-max" in captured.out

    def test_invalid_threshold_values(self, capsys):
        """Invalid threshold values return error."""
        from scripts.baremetal.kernel_limits_monitor import run

        context = self._create_limits_context()
        output = Output()

        # warn >= crit should fail
        result = run(["--warn", "90", "--crit", "80"], output, context)
        assert result == 2

        # Negative values should fail
        result = run(["--warn", "-10"], output, context)
        assert result == 2
