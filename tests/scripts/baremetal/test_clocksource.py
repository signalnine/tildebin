"""Tests for clocksource script."""

import pytest

from boxctl.core.output import Output


CPUINFO_TSC_STABLE = """processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr constant_tsc nonstop_tsc tsc_reliable
"""

CPUINFO_TSC_UNSTABLE = """processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM)2 Duo CPU E8400
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr
"""

CPUINFO_TSC_PARTIAL = """processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr constant_tsc
"""


class TestClocksource:
    """Tests for clocksource script."""

    def test_missing_clocksource_sysfs(self, mock_context):
        """Returns exit code 2 when sysfs not available."""
        from scripts.baremetal import clocksource

        ctx = mock_context(
            tools_available=[],
            file_contents={}
        )
        output = Output()

        exit_code = clocksource.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_tsc_healthy(self, mock_context):
        """Returns 0 when TSC is stable and reliable."""
        from scripts.baremetal import clocksource

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/sys/devices/system/clocksource/clocksource0/current_clocksource": "tsc",
                "/sys/devices/system/clocksource/clocksource0/available_clocksource": "tsc hpet acpi_pm",
                "/proc/cpuinfo": CPUINFO_TSC_STABLE,
                "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda1",
            }
        )
        output = Output()

        exit_code = clocksource.run([], output, ctx)

        assert exit_code == 0
        assert output.data["clocksource"]["current"] == "tsc"
        assert output.data["tsc"]["constant"] is True
        assert output.data["tsc"]["nonstop"] is True
        assert output.data["status"] == "healthy"

    def test_tsc_not_constant(self, mock_context):
        """Returns 1 when TSC lacks constant_tsc flag."""
        from scripts.baremetal import clocksource

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/sys/devices/system/clocksource/clocksource0/current_clocksource": "tsc",
                "/sys/devices/system/clocksource/clocksource0/available_clocksource": "tsc hpet acpi_pm",
                "/proc/cpuinfo": CPUINFO_TSC_UNSTABLE,
                "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda1",
            }
        )
        output = Output()

        exit_code = clocksource.run([], output, ctx)

        assert exit_code == 1
        assert output.data["tsc"]["constant"] is False
        assert len(output.data["warnings"]) > 0

    def test_tsc_missing_nonstop(self, mock_context):
        """Returns 1 when TSC lacks nonstop_tsc flag."""
        from scripts.baremetal import clocksource

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/sys/devices/system/clocksource/clocksource0/current_clocksource": "tsc",
                "/sys/devices/system/clocksource/clocksource0/available_clocksource": "tsc hpet",
                "/proc/cpuinfo": CPUINFO_TSC_PARTIAL,
                "/proc/cmdline": "",
            }
        )
        output = Output()

        exit_code = clocksource.run([], output, ctx)

        assert exit_code == 1
        assert output.data["tsc"]["constant"] is True
        assert output.data["tsc"]["nonstop"] is False
        assert any("nonstop" in w.lower() for w in output.data["warnings"])

    def test_hpet_fallback(self, mock_context):
        """Warns when using HPET instead of TSC."""
        from scripts.baremetal import clocksource

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/sys/devices/system/clocksource/clocksource0/current_clocksource": "hpet",
                "/sys/devices/system/clocksource/clocksource0/available_clocksource": "tsc hpet acpi_pm",
                "/proc/cpuinfo": CPUINFO_TSC_STABLE,
                "/proc/cmdline": "",
            }
        )
        output = Output()

        exit_code = clocksource.run([], output, ctx)

        assert exit_code == 1
        assert output.data["clocksource"]["current"] == "hpet"
        assert any("hpet" in w.lower() or "tsc" in w.lower() for w in output.data["warnings"])

    def test_jiffies_critical(self, mock_context):
        """Returns 1 with critical issue when using jiffies."""
        from scripts.baremetal import clocksource

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/sys/devices/system/clocksource/clocksource0/current_clocksource": "jiffies",
                "/sys/devices/system/clocksource/clocksource0/available_clocksource": "jiffies",
                "/proc/cpuinfo": CPUINFO_TSC_UNSTABLE,
                "/proc/cmdline": "",
            }
        )
        output = Output()

        exit_code = clocksource.run([], output, ctx)

        assert exit_code == 1
        assert output.data["clocksource"]["current"] == "jiffies"
        assert output.data["status"] == "critical"
        assert len(output.data["issues"]) > 0

    def test_forced_clocksource_cmdline(self, mock_context):
        """Detects forced clock source in kernel cmdline."""
        from scripts.baremetal import clocksource

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/sys/devices/system/clocksource/clocksource0/current_clocksource": "hpet",
                "/sys/devices/system/clocksource/clocksource0/available_clocksource": "tsc hpet",
                "/proc/cpuinfo": CPUINFO_TSC_STABLE,
                "/proc/cmdline": "BOOT_IMAGE=/vmlinuz clocksource=hpet root=/dev/sda1",
            }
        )
        output = Output()

        exit_code = clocksource.run(["--verbose"], output, ctx)

        # Should have warnings about using HPET
        assert exit_code == 1
        assert "kernel_cmdline_params" in output.data
        assert output.data["kernel_cmdline_params"]["clocksource"] == "hpet"

    def test_verbose_includes_details(self, mock_context):
        """--verbose includes additional details."""
        from scripts.baremetal import clocksource

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/sys/devices/system/clocksource/clocksource0/current_clocksource": "tsc",
                "/sys/devices/system/clocksource/clocksource0/available_clocksource": "tsc hpet",
                "/proc/cpuinfo": CPUINFO_TSC_STABLE,
                "/proc/cmdline": "",
                "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor": "performance",
                "/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver": "intel_pstate",
            }
        )
        output = Output()

        exit_code = clocksource.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "cpu_frequency" in output.data
        assert "info" in output.data
