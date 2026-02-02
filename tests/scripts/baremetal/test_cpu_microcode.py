"""Tests for cpu_microcode script."""

import pytest

from boxctl.core.output import Output


CPUINFO_SINGLE_SOCKET = """processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
cpu family	: 6
model		: 79
stepping	: 1
microcode	: 0xb000040
physical id	: 0
core id		: 0

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
cpu family	: 6
model		: 79
stepping	: 1
microcode	: 0xb000040
physical id	: 0
core id		: 1

"""

CPUINFO_DUAL_SOCKET = """processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
cpu family	: 6
model		: 79
stepping	: 1
microcode	: 0xb000040
physical id	: 0
core id		: 0

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
cpu family	: 6
model		: 79
stepping	: 1
microcode	: 0xb000040
physical id	: 1
core id		: 0

"""

CPUINFO_INCONSISTENT = """processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
cpu family	: 6
model		: 79
stepping	: 1
microcode	: 0xb000040
physical id	: 0
core id		: 0

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
cpu family	: 6
model		: 79
stepping	: 1
microcode	: 0xb000038
physical id	: 0
core id		: 1

"""

CPUINFO_NO_MICROCODE = """processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU
cpu family	: 6
model		: 79
stepping	: 1
physical id	: 0
core id		: 0

"""


class TestCpuMicrocode:
    """Tests for cpu_microcode script."""

    def test_missing_cpuinfo(self, mock_context):
        """Returns exit code 2 when /proc/cpuinfo not available."""
        from scripts.baremetal import cpu_microcode

        ctx = mock_context(
            tools_available=[],
            file_contents={}
        )
        output = Output()

        exit_code = cpu_microcode.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_single_socket_healthy(self, mock_context):
        """Returns 0 when single socket has consistent microcode."""
        from scripts.baremetal import cpu_microcode

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/cpuinfo": CPUINFO_SINGLE_SOCKET,
            }
        )
        output = Output()

        exit_code = cpu_microcode.run([], output, ctx)

        assert exit_code == 0
        assert output.data["microcode"]["current"] == "0xb000040"
        assert output.data["microcode"]["consistent"] is True
        assert output.data["sockets"] == 1
        assert output.data["logical_cpus"] == 2

    def test_dual_socket_healthy(self, mock_context):
        """Returns 0 when dual socket has consistent microcode."""
        from scripts.baremetal import cpu_microcode

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/cpuinfo": CPUINFO_DUAL_SOCKET,
            }
        )
        output = Output()

        exit_code = cpu_microcode.run([], output, ctx)

        assert exit_code == 0
        assert output.data["sockets"] == 2
        assert output.data["microcode"]["consistent"] is True

    def test_inconsistent_microcode(self, mock_context):
        """Returns 1 when microcode versions are inconsistent."""
        from scripts.baremetal import cpu_microcode

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/cpuinfo": CPUINFO_INCONSISTENT,
            }
        )
        output = Output()

        exit_code = cpu_microcode.run([], output, ctx)

        assert exit_code == 1
        assert output.data["microcode"]["consistent"] is False
        assert output.data["microcode"]["current"] == "Mixed"
        assert len(output.data["issues"]) > 0

    def test_no_microcode_reported(self, mock_context):
        """Returns 1 when no microcode version reported."""
        from scripts.baremetal import cpu_microcode

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/cpuinfo": CPUINFO_NO_MICROCODE,
            }
        )
        output = Output()

        exit_code = cpu_microcode.run([], output, ctx)

        assert exit_code == 1
        assert any("no microcode" in i["message"].lower() for i in output.data["issues"])

    def test_min_version_check_pass(self, mock_context):
        """Returns 0 when microcode meets minimum version."""
        from scripts.baremetal import cpu_microcode

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/cpuinfo": CPUINFO_SINGLE_SOCKET,
            }
        )
        output = Output()

        exit_code = cpu_microcode.run(["--min-version", "0xb000030"], output, ctx)

        assert exit_code == 0
        # No critical issues
        assert not any(i["severity"] == "critical" for i in output.data["issues"])

    def test_min_version_check_fail(self, mock_context):
        """Returns 1 when microcode below minimum version."""
        from scripts.baremetal import cpu_microcode

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/cpuinfo": CPUINFO_SINGLE_SOCKET,
            }
        )
        output = Output()

        # Set min version higher than actual
        exit_code = cpu_microcode.run(["--min-version", "0xc000000"], output, ctx)

        assert exit_code == 1
        assert any(i["severity"] == "critical" for i in output.data["issues"])
        assert any("below minimum" in i["message"].lower() for i in output.data["issues"])

    def test_verbose_shows_per_socket(self, mock_context):
        """--verbose includes per-socket details."""
        from scripts.baremetal import cpu_microcode

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/cpuinfo": CPUINFO_DUAL_SOCKET,
            }
        )
        output = Output()

        exit_code = cpu_microcode.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "per_socket" in output.data
        assert len(output.data["per_socket"]) == 2

    def test_cpu_info_parsing(self, mock_context):
        """Correctly parses CPU information."""
        from scripts.baremetal import cpu_microcode

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/cpuinfo": CPUINFO_SINGLE_SOCKET,
            }
        )
        output = Output()

        exit_code = cpu_microcode.run([], output, ctx)

        assert exit_code == 0
        assert output.data["cpu"]["vendor"] == "GenuineIntel"
        assert "Xeon" in output.data["cpu"]["model_name"]
        assert output.data["cpu"]["family_model_stepping"] == "6/79/1"
