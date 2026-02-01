"""Tests for mce_monitor script."""

import pytest

from boxctl.core.output import Output


def make_mce_sysfs_files(cpus: list[dict]) -> dict[str, str]:
    """Build file_contents dict for MockContext with MCE sysfs data."""
    files = {
        "/sys/devices/system/machinecheck": ""  # Directory marker
    }

    for cpu in cpus:
        cpu_num = cpu["cpu"]
        base = f"/sys/devices/system/machinecheck/machinecheck{cpu_num}"
        files[base] = ""  # Directory marker

        if "tolerant" in cpu:
            files[f"{base}/tolerant"] = str(cpu["tolerant"])
        if "check_interval" in cpu:
            files[f"{base}/check_interval"] = str(cpu["check_interval"])
        if "monarch_timeout" in cpu:
            files[f"{base}/monarch_timeout"] = str(cpu["monarch_timeout"])
        if "trigger" in cpu:
            files[f"{base}/trigger"] = cpu["trigger"]

        # Add bank files
        for bank in cpu.get("banks", []):
            files[f"{base}/bank{bank['num']}"] = bank.get("control", "0xffffffffffffffff")

    return files


# Sample dmesg outputs for testing
DMESG_CLEAN = """[    0.000000] Linux version 5.15.0
[    0.001234] CPU0: Intel(R) Xeon(R) CPU
[    1.234567] eth0: link up"""

DMESG_CORRECTED_ERROR = """[    0.000000] Linux version 5.15.0
[   45.123456] mce: CPU 0: Machine Check Exception: Bank 4
[   45.123457] Corrected error: CPU 0 Bank 4
[   45.123458] MCE 0 events logged"""

DMESG_UNCORRECTED_ERROR = """[    0.000000] Linux version 5.15.0
[   45.123456] mce: CPU 0: Machine Check Exception: Bank 4
[   45.123457] Uncorrected error: CPU 0 Bank 4
[   45.123458] [Hardware Error]: fatal error detected"""

DMESG_CMCI_STORM = """[    0.000000] Linux version 5.15.0
[   45.123456] CMCI storm detected on CPU 0
[   45.123457] Corrected error: CPU 0 Bank 4"""


class TestMceMonitor:
    """Tests for mce_monitor script."""

    def test_no_mce_sysfs_healthy(self, mock_context):
        """Returns healthy when no MCE sysfs but also no errors."""
        from scripts.baremetal import mce_monitor

        ctx = mock_context(
            file_contents={},
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): DMESG_CLEAN
            }
        )
        output = Output()

        exit_code = mce_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "OK"

    def test_healthy_system(self, mock_context):
        """Returns healthy when MCE monitoring is OK."""
        from scripts.baremetal import mce_monitor

        files = make_mce_sysfs_files([
            {
                "cpu": 0,
                "tolerant": "1",
                "check_interval": "300",
                "banks": [
                    {"num": 0, "control": "0xffffffffffffffff"},
                    {"num": 1, "control": "0xffffffffffffffff"},
                ]
            },
            {
                "cpu": 1,
                "tolerant": "1",
                "check_interval": "300",
                "banks": [
                    {"num": 0, "control": "0xffffffffffffffff"},
                ]
            }
        ])

        ctx = mock_context(
            file_contents=files,
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): DMESG_CLEAN
            }
        )
        output = Output()

        exit_code = mce_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "OK"
        assert output.data["summary"]["cpus_monitored"] == 2

    def test_bad_pages_detected(self, mock_context):
        """Detects retired memory pages."""
        from scripts.baremetal import mce_monitor

        files = make_mce_sysfs_files([{"cpu": 0}])
        files["/sys/kernel/ras/bad_pages"] = "0x12340000\n0x56780000"

        ctx = mock_context(
            file_contents=files,
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): DMESG_CLEAN
            }
        )
        output = Output()

        exit_code = mce_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["status"] == "WARNING"
        assert output.data["summary"]["bad_pages"] == 2
        assert len(output.data["issues"]) > 0
        assert any("bad_pages" in i["type"] for i in output.data["issues"])

    def test_corrected_error_in_dmesg(self, mock_context):
        """Detects corrected MCE errors in dmesg."""
        from scripts.baremetal import mce_monitor

        files = make_mce_sysfs_files([{"cpu": 0}])

        ctx = mock_context(
            file_contents=files,
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): DMESG_CORRECTED_ERROR
            }
        )
        output = Output()

        exit_code = mce_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["status"] == "WARNING"
        assert output.data["summary"]["dmesg_events"] > 0

    def test_uncorrected_error_critical(self, mock_context):
        """Detects uncorrected MCE errors as critical."""
        from scripts.baremetal import mce_monitor

        files = make_mce_sysfs_files([{"cpu": 0}])

        ctx = mock_context(
            file_contents=files,
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): DMESG_UNCORRECTED_ERROR
            }
        )
        output = Output()

        exit_code = mce_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["status"] == "CRITICAL"
        # Should have a critical issue
        critical_issues = [i for i in output.data["issues"] if i["severity"] == "CRITICAL"]
        assert len(critical_issues) > 0

    def test_cmci_storm_detected(self, mock_context):
        """Detects CMCI storm events."""
        from scripts.baremetal import mce_monitor

        files = make_mce_sysfs_files([{"cpu": 0}])

        ctx = mock_context(
            file_contents=files,
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): DMESG_CMCI_STORM
            }
        )
        output = Output()

        exit_code = mce_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["dmesg_events"] > 0

    def test_verbose_includes_cpu_config(self, mock_context):
        """--verbose includes CPU MCE configuration."""
        from scripts.baremetal import mce_monitor

        files = make_mce_sysfs_files([
            {
                "cpu": 0,
                "tolerant": "1",
                "check_interval": "300",
                "banks": [{"num": 0}, {"num": 1}, {"num": 2}]
            }
        ])

        ctx = mock_context(
            file_contents=files,
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): DMESG_CLEAN
            }
        )
        output = Output()

        exit_code = mce_monitor.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "cpu_mce_config" in output.data
        assert len(output.data["cpu_mce_config"]) == 1
        assert output.data["cpu_mce_config"][0]["bank_count"] == 3

    def test_warn_only_suppresses_healthy(self, mock_context):
        """--warn-only suppresses output when healthy."""
        from scripts.baremetal import mce_monitor

        files = make_mce_sysfs_files([{"cpu": 0}])

        ctx = mock_context(
            file_contents=files,
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): DMESG_CLEAN
            }
        )
        output = Output()

        exit_code = mce_monitor.run(["--warn-only"], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "OK"
        assert len(output.data["issues"]) == 0
