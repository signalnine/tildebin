"""Tests for hwclock_drift script."""

import subprocess

import pytest

from boxctl.core.output import Output


# Sample hwclock outputs for testing
HWCLOCK_HEALTHY = """hwclock from util-linux 2.37.2
System Time: 1699900800.123456
Trying to open: /dev/rtc0
Using the rtc interface to the clock.
Last drift adjustment done at 1699900000 seconds after 1969
Last calibration done at 1699900000 seconds after 1969
Hardware clock is on UTC time
Assuming hardware clock is kept in UTC time.
Waiting for clock tick...
...got clock tick
Time read from Hardware Clock: 2023/11/13 15:00:01
Hw clock time : 2023/11/13 15:00:01 = 1699887601 seconds since 1969
Time since last adjustment is 87601 seconds
Calculated Hardware Clock drift is 0.500000 seconds
2023-11-13 15:00:01.123456+00:00"""

HWCLOCK_WARNING_DRIFT = """hwclock from util-linux 2.37.2
Trying to open: /dev/rtc0
Using the rtc interface to the clock.
Hardware clock is on UTC time
Time read from Hardware Clock: 2023/11/13 15:00:01
Hw clock time : 2023/11/13 15:00:01 = 1699887601 seconds since 1969
Calculated Hardware Clock drift is 15.000000 seconds"""

HWCLOCK_CRITICAL_DRIFT = """hwclock from util-linux 2.37.2
Trying to open: /dev/rtc0
Using the rtc interface to the clock.
Hardware clock is on UTC time
Time read from Hardware Clock: 2023/11/13 15:00:01
Hw clock time : 2023/11/13 15:00:01 = 1699887601 seconds since 1969
Calculated Hardware Clock drift is 120.000000 seconds"""

HWCLOCK_LOCAL_TIME = """hwclock from util-linux 2.37.2
Trying to open: /dev/rtc0
Hardware clock is on local time
Time read from Hardware Clock: 2023/11/13 15:00:01
Calculated Hardware Clock drift is 0.100000 seconds"""


class TestHwclockDrift:
    """Tests for hwclock_drift script."""

    def test_hwclock_not_found_returns_error(self, mock_context):
        """Returns exit code 2 when hwclock command not found."""
        from scripts.baremetal import hwclock_drift

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = hwclock_drift.run([], output, ctx)

        assert exit_code == 2
        assert any("hwclock" in e.lower() for e in output.errors)

    def test_healthy_drift_returns_ok(self, mock_context):
        """Returns 0 when drift is within thresholds."""
        from scripts.baremetal import hwclock_drift

        ctx = mock_context(
            tools_available=["hwclock"],
            command_outputs={
                ("hwclock", "--show", "--verbose"): HWCLOCK_HEALTHY
            }
        )
        output = Output()

        exit_code = hwclock_drift.run([], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "OK"
        assert output.data["drift_seconds"] == 0.5

    def test_warning_drift_returns_issues(self, mock_context):
        """Returns 1 when drift exceeds warning threshold."""
        from scripts.baremetal import hwclock_drift

        ctx = mock_context(
            tools_available=["hwclock"],
            command_outputs={
                ("hwclock", "--show", "--verbose"): HWCLOCK_WARNING_DRIFT
            }
        )
        output = Output()

        exit_code = hwclock_drift.run([], output, ctx)

        assert exit_code == 1
        assert output.data["status"] == "WARNING"
        assert output.data["drift_seconds"] == 15.0

    def test_critical_drift_returns_issues(self, mock_context):
        """Returns 1 when drift exceeds critical threshold."""
        from scripts.baremetal import hwclock_drift

        ctx = mock_context(
            tools_available=["hwclock"],
            command_outputs={
                ("hwclock", "--show", "--verbose"): HWCLOCK_CRITICAL_DRIFT
            }
        )
        output = Output()

        exit_code = hwclock_drift.run([], output, ctx)

        assert exit_code == 1
        assert output.data["status"] == "CRITICAL"
        assert output.data["drift_seconds"] == 120.0

    def test_custom_thresholds(self, mock_context):
        """Custom thresholds are respected."""
        from scripts.baremetal import hwclock_drift

        ctx = mock_context(
            tools_available=["hwclock"],
            command_outputs={
                ("hwclock", "--show", "--verbose"): HWCLOCK_WARNING_DRIFT  # 15s drift
            }
        )
        output = Output()

        # With higher threshold, 15s should be OK
        exit_code = hwclock_drift.run(
            ["--warn-threshold", "20.0", "--crit-threshold", "120.0"],
            output,
            ctx
        )

        assert exit_code == 0
        assert output.data["status"] == "OK"

    def test_invalid_thresholds_returns_error(self, mock_context):
        """Returns error when thresholds are invalid."""
        from scripts.baremetal import hwclock_drift

        ctx = mock_context(tools_available=["hwclock"])
        output = Output()

        # Warning >= critical should error
        exit_code = hwclock_drift.run(
            ["--warn-threshold", "60.0", "--crit-threshold", "30.0"],
            output,
            ctx
        )

        assert exit_code == 2
        assert any("threshold" in e.lower() for e in output.errors)

    def test_negative_threshold_returns_error(self, mock_context):
        """Returns error when threshold is negative."""
        from scripts.baremetal import hwclock_drift

        ctx = mock_context(tools_available=["hwclock"])
        output = Output()

        exit_code = hwclock_drift.run(
            ["--warn-threshold", "-5.0", "--crit-threshold", "60.0"],
            output,
            ctx
        )

        assert exit_code == 2
        assert any("positive" in e.lower() for e in output.errors)

    def test_detects_local_time_mode(self, mock_context):
        """Correctly detects when RTC is in local time mode."""
        from scripts.baremetal import hwclock_drift

        ctx = mock_context(
            tools_available=["hwclock"],
            command_outputs={
                ("hwclock", "--show", "--verbose"): HWCLOCK_LOCAL_TIME
            }
        )
        output = Output()

        exit_code = hwclock_drift.run([], output, ctx)

        assert exit_code == 0
        assert output.data["is_utc"] is False

    def test_detects_utc_mode(self, mock_context):
        """Correctly detects when RTC is in UTC mode."""
        from scripts.baremetal import hwclock_drift

        ctx = mock_context(
            tools_available=["hwclock"],
            command_outputs={
                ("hwclock", "--show", "--verbose"): HWCLOCK_HEALTHY
            }
        )
        output = Output()

        exit_code = hwclock_drift.run([], output, ctx)

        assert exit_code == 0
        assert output.data["is_utc"] is True

    def test_verbose_includes_epoch(self, mock_context):
        """--verbose includes RTC epoch time."""
        from scripts.baremetal import hwclock_drift

        ctx = mock_context(
            tools_available=["hwclock"],
            command_outputs={
                ("hwclock", "--show", "--verbose"): HWCLOCK_HEALTHY
            }
        )
        output = Output()

        exit_code = hwclock_drift.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "rtc_epoch" in output.data
        assert output.data["rtc_epoch"] == 1699887601
