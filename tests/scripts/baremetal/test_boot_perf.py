"""Tests for boot_perf script."""

import pytest

from boxctl.core.output import Output


SYSTEMD_ANALYZE_NORMAL = """Startup finished in 4.234s (kernel) + 12.456s (userspace) = 16.690s
graphical.target reached after 12.345s in userspace.
"""

SYSTEMD_ANALYZE_WITH_FIRMWARE = """Startup finished in 2.1s (firmware) + 3.2s (loader) + 4.234s (kernel) + 12.456s (userspace) = 21.990s
graphical.target reached after 12.345s in userspace.
"""

SYSTEMD_ANALYZE_SLOW = """Startup finished in 10.0s (kernel) + 150.0s (userspace) = 160.0s
graphical.target reached after 149.0s in userspace.
"""

SYSTEMD_BLAME_OUTPUT = """ 12.456s docker.service
  5.123s NetworkManager-wait-online.service
  3.456s snapd.service
  2.100s systemd-udev-settle.service
  1.500s accounts-daemon.service
  0.800s systemd-journald.service
  0.500s ssh.service
  0.200s systemd-logind.service
"""


class TestBootPerf:
    """Tests for boot_perf script."""

    def test_missing_systemd_analyze(self, mock_context):
        """Returns exit code 2 when systemd-analyze not available."""
        from scripts.baremetal import boot_perf

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = boot_perf.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("systemd" in e.lower() for e in output.errors)

    def test_normal_boot_time(self, mock_context):
        """Returns 0 when boot time is within thresholds."""
        from scripts.baremetal import boot_perf

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze",): SYSTEMD_ANALYZE_NORMAL,
                ("systemd-analyze", "blame"): SYSTEMD_BLAME_OUTPUT,
            }
        )
        output = Output()

        exit_code = boot_perf.run([], output, ctx)

        assert exit_code == 0
        assert "boot_times" in output.data
        assert output.data["boot_times"]["total_sec"] == 16.69
        assert output.data["boot_times"]["kernel_sec"] == 4.23
        assert output.data["boot_times"]["userspace_sec"] == 12.46

    def test_slow_boot_time(self, mock_context):
        """Returns 1 when boot time exceeds thresholds."""
        from scripts.baremetal import boot_perf

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze",): SYSTEMD_ANALYZE_SLOW,
                ("systemd-analyze", "blame"): SYSTEMD_BLAME_OUTPUT,
            }
        )
        output = Output()

        exit_code = boot_perf.run([], output, ctx)

        assert exit_code == 1
        assert output.data["boot_times"]["total_sec"] == 160.0
        # Should have warnings
        assert any(i["severity"] == "warning" for i in output.data["issues"])

    def test_firmware_and_loader_times(self, mock_context):
        """Parses firmware and loader times when present."""
        from scripts.baremetal import boot_perf

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze",): SYSTEMD_ANALYZE_WITH_FIRMWARE,
                ("systemd-analyze", "blame"): SYSTEMD_BLAME_OUTPUT,
            }
        )
        output = Output()

        exit_code = boot_perf.run([], output, ctx)

        assert exit_code == 0
        assert "firmware_sec" in output.data["boot_times"]
        assert "loader_sec" in output.data["boot_times"]
        assert output.data["boot_times"]["firmware_sec"] == 2.1
        assert output.data["boot_times"]["loader_sec"] == 3.2

    def test_verbose_shows_services(self, mock_context):
        """--verbose includes slow services."""
        from scripts.baremetal import boot_perf

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze",): SYSTEMD_ANALYZE_NORMAL,
                ("systemd-analyze", "blame"): SYSTEMD_BLAME_OUTPUT,
            }
        )
        output = Output()

        exit_code = boot_perf.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "slow_services" in output.data
        assert len(output.data["slow_services"]) > 0
        assert output.data["slow_services"][0]["name"] == "docker.service"

    def test_custom_thresholds(self, mock_context):
        """Custom thresholds are respected."""
        from scripts.baremetal import boot_perf

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze",): SYSTEMD_ANALYZE_NORMAL,
                ("systemd-analyze", "blame"): SYSTEMD_BLAME_OUTPUT,
            }
        )
        output = Output()

        # Set threshold lower than actual boot time
        exit_code = boot_perf.run(["--boot-threshold", "10"], output, ctx)

        assert exit_code == 1
        assert any("total boot time" in i["message"].lower() for i in output.data["issues"])

    def test_userspace_threshold(self, mock_context):
        """Userspace threshold triggers warning."""
        from scripts.baremetal import boot_perf

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze",): SYSTEMD_ANALYZE_NORMAL,
                ("systemd-analyze", "blame"): SYSTEMD_BLAME_OUTPUT,
            }
        )
        output = Output()

        # Set userspace threshold lower than actual
        exit_code = boot_perf.run(["--userspace-threshold", "10"], output, ctx)

        assert exit_code == 1
        assert any("userspace" in i["message"].lower() for i in output.data["issues"])

    def test_service_threshold_info(self, mock_context):
        """Slow services generate info-level issues."""
        from scripts.baremetal import boot_perf

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze",): SYSTEMD_ANALYZE_NORMAL,
                ("systemd-analyze", "blame"): SYSTEMD_BLAME_OUTPUT,
            }
        )
        output = Output()

        # Set service threshold lower than docker.service
        exit_code = boot_perf.run(["--service-threshold", "5"], output, ctx)

        # Should be 0 because service issues are info-level, not warnings
        assert exit_code == 0
        # But should have info-level issues
        assert any(i["severity"] == "info" and "docker" in i["message"] for i in output.data["issues"])
