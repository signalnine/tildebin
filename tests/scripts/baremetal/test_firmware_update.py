"""Tests for firmware_update script."""

import json
import pytest

from boxctl.core.output import Output


class TestFirmwareUpdate:
    """Tests for firmware_update script."""

    def test_missing_fwupdmgr_returns_error(self, mock_context):
        """Returns exit code 2 when fwupdmgr not available."""
        from scripts.baremetal import firmware_update

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = firmware_update.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("fwupdmgr" in e.lower() for e in output.errors)

    def test_no_updates_returns_zero(self, mock_context):
        """Returns 0 when no firmware updates available."""
        from scripts.baremetal import firmware_update

        devices_json = json.dumps({"Devices": []})

        ctx = mock_context(
            tools_available=["fwupdmgr", "systemctl"],
            command_outputs={
                ("systemctl", "is-active", "fwupd"): "",
                ("systemctl", "show", "fwupd", "--property=ActiveState,SubState"): (
                    "ActiveState=active\nSubState=running"
                ),
                ("fwupdmgr", "get-devices", "--json"): devices_json,
                ("fwupdmgr", "get-updates", "--json"): "",
            },
        )
        output = Output()

        exit_code = firmware_update.run([], output, ctx)

        assert exit_code == 0

    def test_pending_updates_returns_one(self, mock_context):
        """Returns 1 when firmware updates are pending."""
        from scripts.baremetal import firmware_update

        devices_json = json.dumps({
            "Devices": [
                {
                    "Name": "System Firmware",
                    "Vendor": "Dell",
                    "Version": "1.0.0",
                    "DeviceId": "system-firmware",
                    "Flags": ["updatable", "internal"],
                    "Releases": [
                        {
                            "Version": "1.1.0",
                            "Urgency": "high",
                            "Summary": "Security update",
                            "IsSecurityRisk": True,
                        }
                    ],
                }
            ]
        })

        ctx = mock_context(
            tools_available=["fwupdmgr", "systemctl"],
            command_outputs={
                ("systemctl", "is-active", "fwupd"): "",
                ("systemctl", "show", "fwupd", "--property=ActiveState,SubState"): (
                    "ActiveState=active\nSubState=running"
                ),
                ("fwupdmgr", "get-devices", "--json"): devices_json,
                ("fwupdmgr", "get-updates", "--json"): "",
            },
        )
        output = Output()

        exit_code = firmware_update.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["pending_updates"] == 1
        assert output.data["summary"]["security_updates"] == 1

    def test_security_only_filter(self, mock_context):
        """--security-only filters to only security updates."""
        from scripts.baremetal import firmware_update

        devices_json = json.dumps({
            "Devices": [
                {
                    "Name": "System Firmware",
                    "Vendor": "Dell",
                    "Version": "1.0.0",
                    "Flags": ["updatable"],
                    "Releases": [
                        {
                            "Version": "1.1.0",
                            "IsSecurityRisk": True,
                        }
                    ],
                },
                {
                    "Name": "BIOS Update",
                    "Vendor": "Dell",
                    "Version": "2.0.0",
                    "Flags": ["updatable"],
                    "Releases": [
                        {
                            "Version": "2.1.0",
                            "IsSecurityRisk": False,
                        }
                    ],
                },
            ]
        })

        ctx = mock_context(
            tools_available=["fwupdmgr", "systemctl"],
            command_outputs={
                ("systemctl", "is-active", "fwupd"): "",
                ("systemctl", "show", "fwupd", "--property=ActiveState,SubState"): (
                    "ActiveState=active\nSubState=running"
                ),
                ("fwupdmgr", "get-devices", "--json"): devices_json,
                ("fwupdmgr", "get-updates", "--json"): "",
            },
        )
        output = Output()

        exit_code = firmware_update.run(["--security-only"], output, ctx)

        assert exit_code == 1
        # Only security update should be in the list
        assert len(output.data["devices"]) == 1
        assert output.data["devices"][0]["name"] == "System Firmware"

    def test_device_analysis(self, mock_context):
        """Test device analysis with various flags."""
        from scripts.baremetal import firmware_update

        devices_json = json.dumps({
            "Devices": [
                {
                    "Name": "Test Device",
                    "Vendor": "Test Vendor",
                    "Version": "1.0.0",
                    "DeviceId": "test-device-123",
                    "Flags": ["updatable", "needs-reboot", "internal"],
                    "Releases": [],
                }
            ]
        })

        ctx = mock_context(
            tools_available=["fwupdmgr", "systemctl"],
            command_outputs={
                ("systemctl", "is-active", "fwupd"): "",
                ("systemctl", "show", "fwupd", "--property=ActiveState,SubState"): (
                    "ActiveState=active\nSubState=running"
                ),
                ("fwupdmgr", "get-devices", "--json"): devices_json,
                ("fwupdmgr", "get-updates", "--json"): "",
            },
        )
        output = Output()

        exit_code = firmware_update.run([], output, ctx)

        assert exit_code == 0
        device = output.data["devices"][0]
        assert device["name"] == "Test Device"
        assert device["vendor"] == "Test Vendor"
        assert device["can_update"] is True
        assert device["needs_reboot"] is True
        assert device["is_internal"] is True
        assert device["has_update"] is False

    def test_json_output_format(self, mock_context, capsys):
        """Test JSON output format."""
        from scripts.baremetal import firmware_update

        devices_json = json.dumps({"Devices": []})

        ctx = mock_context(
            tools_available=["fwupdmgr", "systemctl"],
            command_outputs={
                ("systemctl", "is-active", "fwupd"): "",
                ("systemctl", "show", "fwupd", "--property=ActiveState,SubState"): (
                    "ActiveState=active\nSubState=running"
                ),
                ("fwupdmgr", "get-devices", "--json"): devices_json,
                ("fwupdmgr", "get-updates", "--json"): "",
            },
        )
        output = Output()

        exit_code = firmware_update.run(["--format", "json"], output, ctx)

        assert exit_code == 0
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "service" in result
        assert "devices" in result
        assert "summary" in result
