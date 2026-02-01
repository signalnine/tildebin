"""Tests for ptp_clock script."""

import pytest

from boxctl.core.output import Output


def make_ptp_device_files(devices: list[dict]) -> dict[str, str]:
    """Build file_contents dict for MockContext with PTP device data."""
    files = {
        "/sys/class/ptp": ""  # Directory marker
    }

    for dev in devices:
        name = dev["name"]
        base = f"/sys/class/ptp/{name}"
        files[base] = ""  # Directory marker

        if "clock_name" in dev:
            files[f"{base}/clock_name"] = dev["clock_name"]
        if "max_adjustment" in dev:
            files[f"{base}/max_adjustment"] = str(dev["max_adjustment"])
        if "n_alarms" in dev:
            files[f"{base}/n_alarms"] = str(dev["n_alarms"])
        if "n_pins" in dev:
            files[f"{base}/n_pins"] = str(dev["n_pins"])
        if "pps_available" in dev:
            files[f"{base}/pps_available"] = "1" if dev["pps_available"] else "0"

    return files


# Sample pmc command outputs
PMC_CURRENT_DATA_SLAVE = """CURRENT_DATA_SET
    stepsRemoved     1
    offsetFromMaster 250
    meanPathDelay    5000"""

PMC_CURRENT_DATA_HIGH_OFFSET = """CURRENT_DATA_SET
    stepsRemoved     1
    offsetFromMaster 5000
    meanPathDelay    5000"""

PMC_PORT_DATA_SLAVE = """PORT_DATA_SET
    portIdentity             00:11:22:ff:fe:33:44:55-1
    portState                SLAVE
    logMinDelayReqInterval   0"""

PMC_PORT_DATA_MASTER = """PORT_DATA_SET
    portIdentity             00:11:22:ff:fe:33:44:55-1
    portState                MASTER
    logMinDelayReqInterval   0"""

PMC_PORT_DATA_LISTENING = """PORT_DATA_SET
    portIdentity             00:11:22:ff:fe:33:44:55-1
    portState                LISTENING
    logMinDelayReqInterval   0"""

PMC_PARENT_DATA = """PARENT_DATA_SET
    parentPortIdentity       aa:bb:cc:ff:fe:dd:ee:ff-1"""


class TestPtpClock:
    """Tests for ptp_clock script."""

    def test_no_ptp_sysfs_returns_no_devices(self, mock_context):
        """Returns appropriate status when /sys/class/ptp doesn't exist."""
        from scripts.baremetal import ptp_clock

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = ptp_clock.run([], output, ctx)

        assert exit_code == 2
        assert output.data["status"] == "no_ptp"

    def test_ptp_devices_detected(self, mock_context):
        """Detects PTP devices from sysfs."""
        from scripts.baremetal import ptp_clock

        files = make_ptp_device_files([
            {
                "name": "ptp0",
                "clock_name": "igb",
                "max_adjustment": 600000000,
                "n_alarms": 0,
                "n_pins": 4,
                "pps_available": True,
            }
        ])

        ctx = mock_context(file_contents=files, tools_available=[])
        output = Output()

        exit_code = ptp_clock.run([], output, ctx)

        # Without pmc, status is unconfigured but devices are present
        assert exit_code == 0  # unconfigured is not an error
        assert output.data["device_count"] == 1

    def test_synchronized_status(self, mock_context):
        """Returns synchronized when ptp4l is in SLAVE state with low offset."""
        from scripts.baremetal import ptp_clock

        files = make_ptp_device_files([
            {"name": "ptp0", "clock_name": "igb", "pps_available": True}
        ])

        ctx = mock_context(
            file_contents=files,
            tools_available=["pmc"],
            command_outputs={
                ("pmc", "-u", "-b", "0", "GET CURRENT_DATA_SET"): PMC_CURRENT_DATA_SLAVE,
                ("pmc", "-u", "-b", "0", "GET PORT_DATA_SET"): PMC_PORT_DATA_SLAVE,
                ("pmc", "-u", "-b", "0", "GET PARENT_DATA_SET"): PMC_PARENT_DATA,
            }
        )
        output = Output()

        exit_code = ptp_clock.run([], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "synchronized"

    def test_master_status(self, mock_context):
        """Returns master when ptp4l is in MASTER state."""
        from scripts.baremetal import ptp_clock

        files = make_ptp_device_files([
            {"name": "ptp0", "clock_name": "igb"}
        ])

        ctx = mock_context(
            file_contents=files,
            tools_available=["pmc"],
            command_outputs={
                ("pmc", "-u", "-b", "0", "GET CURRENT_DATA_SET"): "",
                ("pmc", "-u", "-b", "0", "GET PORT_DATA_SET"): PMC_PORT_DATA_MASTER,
                ("pmc", "-u", "-b", "0", "GET PARENT_DATA_SET"): "",
            }
        )
        output = Output()

        exit_code = ptp_clock.run([], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "master"

    def test_high_offset_detected(self, mock_context):
        """Detects when offset exceeds threshold."""
        from scripts.baremetal import ptp_clock

        files = make_ptp_device_files([
            {"name": "ptp0", "clock_name": "igb"}
        ])

        ctx = mock_context(
            file_contents=files,
            tools_available=["pmc"],
            command_outputs={
                ("pmc", "-u", "-b", "0", "GET CURRENT_DATA_SET"): PMC_CURRENT_DATA_HIGH_OFFSET,
                ("pmc", "-u", "-b", "0", "GET PORT_DATA_SET"): PMC_PORT_DATA_SLAVE,
                ("pmc", "-u", "-b", "0", "GET PARENT_DATA_SET"): PMC_PARENT_DATA,
            }
        )
        output = Output()

        exit_code = ptp_clock.run(["--offset-threshold", "1000"], output, ctx)

        assert exit_code == 1
        assert output.data["status"] == "degraded"
        assert len(output.data["issues"]) > 0
        assert any("offset" in i.lower() for i in output.data["issues"])

    def test_acquiring_state(self, mock_context):
        """Detects when PTP is still acquiring sync."""
        from scripts.baremetal import ptp_clock

        files = make_ptp_device_files([
            {"name": "ptp0", "clock_name": "igb"}
        ])

        ctx = mock_context(
            file_contents=files,
            tools_available=["pmc"],
            command_outputs={
                ("pmc", "-u", "-b", "0", "GET CURRENT_DATA_SET"): "",
                ("pmc", "-u", "-b", "0", "GET PORT_DATA_SET"): PMC_PORT_DATA_LISTENING,
                ("pmc", "-u", "-b", "0", "GET PARENT_DATA_SET"): "",
            }
        )
        output = Output()

        exit_code = ptp_clock.run([], output, ctx)

        assert exit_code == 1
        assert output.data["status"] == "degraded"

    def test_custom_offset_threshold(self, mock_context):
        """Custom offset threshold is respected."""
        from scripts.baremetal import ptp_clock

        files = make_ptp_device_files([
            {"name": "ptp0", "clock_name": "igb"}
        ])

        ctx = mock_context(
            file_contents=files,
            tools_available=["pmc"],
            command_outputs={
                ("pmc", "-u", "-b", "0", "GET CURRENT_DATA_SET"): PMC_CURRENT_DATA_HIGH_OFFSET,
                ("pmc", "-u", "-b", "0", "GET PORT_DATA_SET"): PMC_PORT_DATA_SLAVE,
                ("pmc", "-u", "-b", "0", "GET PARENT_DATA_SET"): PMC_PARENT_DATA,
            }
        )
        output = Output()

        # With higher threshold, 5000ns should be OK
        exit_code = ptp_clock.run(["--offset-threshold", "10000"], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "synchronized"

    def test_warn_only_suppresses_healthy(self, mock_context):
        """--warn-only suppresses output when healthy."""
        from scripts.baremetal import ptp_clock

        files = make_ptp_device_files([
            {"name": "ptp0", "clock_name": "igb"}
        ])

        ctx = mock_context(
            file_contents=files,
            tools_available=["pmc"],
            command_outputs={
                ("pmc", "-u", "-b", "0", "GET CURRENT_DATA_SET"): PMC_CURRENT_DATA_SLAVE,
                ("pmc", "-u", "-b", "0", "GET PORT_DATA_SET"): PMC_PORT_DATA_SLAVE,
                ("pmc", "-u", "-b", "0", "GET PARENT_DATA_SET"): PMC_PARENT_DATA,
            }
        )
        output = Output()

        exit_code = ptp_clock.run(["--warn-only"], output, ctx)

        assert exit_code == 0
        assert len(output.data.get("devices", [])) == 0  # No device details in warn-only when healthy
