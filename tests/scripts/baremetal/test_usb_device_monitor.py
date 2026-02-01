"""Tests for usb_device_monitor script."""

import pytest

from boxctl.core.output import Output


def make_usb_device_files(devices: list[dict]) -> dict[str, str]:
    """Build file_contents dict for MockContext with USB device data."""
    files = {
        "/sys/bus/usb/devices": ""  # Directory marker
    }

    for dev in devices:
        name = dev["name"]
        base = f"/sys/bus/usb/devices/{name}"
        files[base] = ""  # Directory marker

        files[f"{base}/idVendor"] = dev.get("vendor_id", "0000")
        files[f"{base}/idProduct"] = dev.get("product_id", "0000")

        if "manufacturer" in dev:
            files[f"{base}/manufacturer"] = dev["manufacturer"]
        if "product" in dev:
            files[f"{base}/product"] = dev["product"]
        if "serial" in dev:
            files[f"{base}/serial"] = dev["serial"]
        if "device_class" in dev:
            files[f"{base}/bDeviceClass"] = dev["device_class"]
        if "busnum" in dev:
            files[f"{base}/busnum"] = dev["busnum"]
        if "devnum" in dev:
            files[f"{base}/devnum"] = dev["devnum"]
        if "speed" in dev:
            files[f"{base}/speed"] = dev["speed"]

        # Add interfaces
        for iface in dev.get("interfaces", []):
            iface_name = f"{name}:{iface['config']}.{iface['iface']}"
            iface_path = f"/sys/bus/usb/devices/{iface_name}"
            files[iface_path] = ""
            files[f"{iface_path}/bInterfaceClass"] = iface.get("class", "00")

    return files


class TestUsbDeviceMonitor:
    """Tests for usb_device_monitor script."""

    def test_no_usb_sysfs_returns_error(self, mock_context):
        """Returns exit code 2 when /sys/bus/usb/devices doesn't exist."""
        from scripts.baremetal import usb_device_monitor

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = usb_device_monitor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("usb" in e.lower() for e in output.errors)

    def test_no_devices_returns_healthy(self, mock_context):
        """Returns exit code 0 when no USB devices found."""
        from scripts.baremetal import usb_device_monitor

        ctx = mock_context(file_contents={
            "/sys/bus/usb/devices": ""
        })
        output = Output()

        exit_code = usb_device_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_devices"] == 0
        assert not output.data["has_issues"]

    def test_non_storage_device_is_healthy(self, mock_context):
        """Non-storage devices are reported as healthy."""
        from scripts.baremetal import usb_device_monitor

        files = make_usb_device_files([
            {
                "name": "1-1",
                "vendor_id": "046d",
                "product_id": "c52b",
                "manufacturer": "Logitech",
                "product": "USB Receiver",
                "device_class": "00",
                "busnum": "1",
                "devnum": "2",
                "interfaces": [
                    {"config": "1", "iface": "0", "class": "03"},  # HID
                ]
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = usb_device_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_devices"] == 1
        assert output.data["summary"]["storage_devices"] == 0
        assert not output.data["has_issues"]

    def test_storage_device_is_flagged(self, mock_context):
        """Mass storage devices are flagged by default."""
        from scripts.baremetal import usb_device_monitor

        files = make_usb_device_files([
            {
                "name": "1-2",
                "vendor_id": "0781",
                "product_id": "5567",
                "manufacturer": "SanDisk",
                "product": "Cruzer Blade",
                "device_class": "00",
                "busnum": "1",
                "devnum": "3",
                "interfaces": [
                    {"config": "1", "iface": "0", "class": "08"},  # Mass Storage
                ]
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = usb_device_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["storage_devices"] == 1
        assert output.data["has_issues"]
        assert len(output.data["issues"]) == 1
        assert "Mass storage" in output.data["issues"][0]["reason"]

    def test_no_flag_storage_option(self, mock_context):
        """--no-flag-storage prevents flagging storage devices."""
        from scripts.baremetal import usb_device_monitor

        files = make_usb_device_files([
            {
                "name": "1-2",
                "vendor_id": "0781",
                "product_id": "5567",
                "manufacturer": "SanDisk",
                "product": "Cruzer Blade",
                "device_class": "00",
                "busnum": "1",
                "devnum": "3",
                "interfaces": [
                    {"config": "1", "iface": "0", "class": "08"},
                ]
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = usb_device_monitor.run(["--no-flag-storage"], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["storage_devices"] == 1  # Still counted
        assert not output.data["has_issues"]  # But not flagged

    def test_whitelist_allows_devices(self, mock_context):
        """Devices in whitelist are not flagged."""
        from scripts.baremetal import usb_device_monitor

        files = make_usb_device_files([
            {
                "name": "1-2",
                "vendor_id": "0781",
                "product_id": "5567",
                "manufacturer": "SanDisk",
                "product": "Cruzer Blade",
                "device_class": "00",
                "interfaces": [
                    {"config": "1", "iface": "0", "class": "08"},
                ]
            }
        ])
        # Add whitelist file
        files["/etc/usb-whitelist.txt"] = "0781:5567  # SanDisk allowed\n"

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = usb_device_monitor.run(
            ["--whitelist", "/etc/usb-whitelist.txt", "--no-flag-storage"],
            output,
            ctx
        )

        assert exit_code == 0
        assert not output.data["has_issues"]

    def test_whitelist_missing_returns_error(self, mock_context):
        """Returns error when whitelist file is missing."""
        from scripts.baremetal import usb_device_monitor

        files = make_usb_device_files([])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = usb_device_monitor.run(
            ["--whitelist", "/nonexistent/whitelist.txt"],
            output,
            ctx
        )

        assert exit_code == 2
        assert any("whitelist" in e.lower() for e in output.errors)

    def test_verbose_includes_device_details(self, mock_context):
        """--verbose includes full device information."""
        from scripts.baremetal import usb_device_monitor

        files = make_usb_device_files([
            {
                "name": "1-1",
                "vendor_id": "046d",
                "product_id": "c52b",
                "manufacturer": "Logitech",
                "product": "USB Receiver",
                "serial": "ABC123",
                "device_class": "00",
                "busnum": "1",
                "devnum": "2",
                "speed": "12",
                "interfaces": [
                    {"config": "1", "iface": "0", "class": "03"},
                ]
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = usb_device_monitor.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "devices" in output.data
        assert len(output.data["devices"]) == 1
        assert output.data["devices"][0]["serial"] == "ABC123"
        assert output.data["devices"][0]["speed"] == "12"
