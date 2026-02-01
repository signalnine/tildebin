"""Tests for firmware_inventory script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def dmi_bios_vendor(fixtures_dir):
    """Load BIOS vendor fixture."""
    return (fixtures_dir / "boot" / "dmi_bios_vendor.txt").read_text()


@pytest.fixture
def dmi_bios_version(fixtures_dir):
    """Load BIOS version fixture."""
    return (fixtures_dir / "boot" / "dmi_bios_version.txt").read_text()


@pytest.fixture
def dmi_bios_date(fixtures_dir):
    """Load BIOS date fixture."""
    return (fixtures_dir / "boot" / "dmi_bios_date.txt").read_text()


@pytest.fixture
def dmi_sys_vendor(fixtures_dir):
    """Load system vendor fixture."""
    return (fixtures_dir / "boot" / "dmi_sys_vendor.txt").read_text()


@pytest.fixture
def dmi_product_name(fixtures_dir):
    """Load product name fixture."""
    return (fixtures_dir / "boot" / "dmi_product_name.txt").read_text()


@pytest.fixture
def cpuinfo_microcode(fixtures_dir):
    """Load cpuinfo with microcode fixture."""
    return (fixtures_dir / "boot" / "cpuinfo_microcode.txt").read_text()


@pytest.fixture
def ipmitool_mc_info(fixtures_dir):
    """Load ipmitool mc info fixture."""
    return (fixtures_dir / "boot" / "ipmitool_mc_info.txt").read_text()


@pytest.fixture
def ethtool_interface(fixtures_dir):
    """Load ethtool interface fixture."""
    return (fixtures_dir / "boot" / "ethtool_interface.txt").read_text()


class TestFirmwareInventory:
    """Tests for firmware_inventory script."""

    def test_missing_uname_returns_error(self, mock_context):
        """Returns exit code 2 when uname not available."""
        from scripts.baremetal import firmware_inventory

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = firmware_inventory.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_collects_bios_info(
        self, mock_context, dmi_bios_vendor, dmi_bios_version, dmi_bios_date
    ):
        """Collects BIOS information from DMI."""
        from scripts.baremetal import firmware_inventory

        ctx = mock_context(
            tools_available=["uname", "hostname"],
            file_contents={
                "/sys/class/dmi/id/bios_vendor": dmi_bios_vendor,
                "/sys/class/dmi/id/bios_version": dmi_bios_version,
                "/sys/class/dmi/id/bios_date": dmi_bios_date,
            },
            command_outputs={
                ("uname", "-r"): "5.15.0-91-generic\n",
                ("uname", "-m"): "x86_64\n",
                ("hostname", "-f"): "server.example.com\n",
            }
        )
        output = Output()

        exit_code = firmware_inventory.run([], output, ctx)

        assert exit_code == 0
        assert output.data["bios"]["vendor"] == "Dell Inc."
        assert output.data["bios"]["version"] == "2.18.0"
        assert output.data["bios"]["release_date"] == "01/15/2024"

    def test_collects_system_info(
        self, mock_context, dmi_sys_vendor, dmi_product_name
    ):
        """Collects system information from DMI."""
        from scripts.baremetal import firmware_inventory

        ctx = mock_context(
            tools_available=["uname", "hostname"],
            file_contents={
                "/sys/class/dmi/id/sys_vendor": dmi_sys_vendor,
                "/sys/class/dmi/id/product_name": dmi_product_name,
            },
            command_outputs={
                ("uname", "-r"): "5.15.0-91-generic\n",
                ("uname", "-m"): "x86_64\n",
                ("hostname", "-f"): "server.example.com\n",
            }
        )
        output = Output()

        exit_code = firmware_inventory.run([], output, ctx)

        assert exit_code == 0
        assert output.data["system"]["manufacturer"] == "Dell Inc."
        assert output.data["system"]["product_name"] == "PowerEdge R640"

    def test_collects_cpu_microcode(self, mock_context, cpuinfo_microcode):
        """Collects CPU microcode version."""
        from scripts.baremetal import firmware_inventory

        ctx = mock_context(
            tools_available=["uname", "hostname"],
            file_contents={
                "/proc/cpuinfo": cpuinfo_microcode,
                "/sys/class/dmi/id/bios_vendor": "Dell Inc.",
            },
            command_outputs={
                ("uname", "-r"): "5.15.0-91-generic\n",
                ("uname", "-m"): "x86_64\n",
                ("hostname", "-f"): "server.example.com\n",
            }
        )
        output = Output()

        exit_code = firmware_inventory.run([], output, ctx)

        assert exit_code == 0
        assert output.data["cpu_microcode"]["version"] == "0x5003604"

    def test_collects_bmc_info(
        self, mock_context, ipmitool_mc_info, dmi_bios_vendor
    ):
        """Collects BMC/IPMI information."""
        from scripts.baremetal import firmware_inventory

        ctx = mock_context(
            tools_available=["uname", "hostname", "ipmitool"],
            file_contents={
                "/sys/class/dmi/id/bios_vendor": dmi_bios_vendor,
            },
            command_outputs={
                ("uname", "-r"): "5.15.0-91-generic\n",
                ("uname", "-m"): "x86_64\n",
                ("hostname", "-f"): "server.example.com\n",
                ("ipmitool", "mc", "info"): ipmitool_mc_info,
            }
        )
        output = Output()

        exit_code = firmware_inventory.run([], output, ctx)

        assert exit_code == 0
        assert output.data["bmc"]["available"] is True
        assert output.data["bmc"]["version"] == "4.40"
        assert output.data["bmc"]["manufacturer"] == "Dell Inc."

    def test_collects_kernel_info(self, mock_context, dmi_bios_vendor):
        """Collects kernel version information."""
        from scripts.baremetal import firmware_inventory

        ctx = mock_context(
            tools_available=["uname", "hostname"],
            file_contents={
                "/sys/class/dmi/id/bios_vendor": dmi_bios_vendor,
            },
            command_outputs={
                ("uname", "-r"): "5.15.0-91-generic\n",
                ("uname", "-m"): "x86_64\n",
                ("hostname", "-f"): "server.example.com\n",
            }
        )
        output = Output()

        exit_code = firmware_inventory.run([], output, ctx)

        assert exit_code == 0
        assert output.data["kernel"]["release"] == "5.15.0-91-generic"
        assert output.data["kernel"]["machine"] == "x86_64"

    def test_returns_one_when_no_basic_info(self, mock_context):
        """Returns 1 when no BIOS or system info available."""
        from scripts.baremetal import firmware_inventory

        ctx = mock_context(
            tools_available=["uname", "hostname"],
            file_contents={},
            command_outputs={
                ("uname", "-r"): "5.15.0-91-generic\n",
                ("uname", "-m"): "x86_64\n",
                ("hostname", "-f"): "server.example.com\n",
            }
        )
        output = Output()

        exit_code = firmware_inventory.run([], output, ctx)

        assert exit_code == 1

    def test_sets_hostname(self, mock_context, dmi_bios_vendor):
        """Sets hostname in output."""
        from scripts.baremetal import firmware_inventory

        ctx = mock_context(
            tools_available=["uname", "hostname"],
            file_contents={
                "/sys/class/dmi/id/bios_vendor": dmi_bios_vendor,
            },
            command_outputs={
                ("uname", "-r"): "5.15.0-91-generic\n",
                ("uname", "-m"): "x86_64\n",
                ("hostname", "-f"): "server.example.com\n",
            }
        )
        output = Output()

        exit_code = firmware_inventory.run([], output, ctx)

        assert exit_code == 0
        assert output.data["hostname"] == "server.example.com"
