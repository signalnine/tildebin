"""Tests for acpi_events script."""

import json
import subprocess

import pytest

from boxctl.core.output import Output


DMESG_CLEAN = "Linux version 5.4.0\nInitializing cgroup subsys cpuset\nrandom: systemd: uninitialized urandom read\n"

DMESG_ACPI_ERRORS = (
    "Linux version 5.4.0\n"
    "ACPI BIOS Error (bug): Could not resolve symbol\n"
    "ACPI Error: AE_NOT_FOUND evaluating _SB.PCI0\n"
    "Normal log line here\n"
    "ACPI fault: method failed with status AE_NOT_FOUND\n"
)


def make_thermal_files(zones, dmesg_output=DMESG_CLEAN):
    """Build file_contents and command_outputs for MockContext."""
    files = {}
    if zones is not None:
        files["/sys/class/thermal"] = ""  # Directory marker
        for i, zone in enumerate(zones):
            base = f"/sys/class/thermal/thermal_zone{i}"
            files[base] = ""  # Directory marker
            files[f"{base}/type"] = zone.get("type", "unknown")
            files[f"{base}/temp"] = str(zone.get("temp", 45000))
            for j, trip in enumerate(zone.get("trips", [])):
                files[f"{base}/trip_point_{j}_type"] = trip["type"]
                files[f"{base}/trip_point_{j}_temp"] = str(trip["temp"])

    cmd_outputs = {}
    if dmesg_output is not None:
        cmd_outputs[("dmesg",)] = dmesg_output

    return files, cmd_outputs


class TestAcpiEvents:
    """Tests for acpi_events script."""

    def test_no_thermal_zones_no_dmesg(self, mock_context):
        """Returns exit code 2 when no zones and dmesg fails."""
        from scripts.baremetal import acpi_events

        ctx = mock_context(
            tools_available=[],
            command_outputs={("dmesg",): KeyError("No mock output for command: ['dmesg']")},
            file_contents={},
        )
        output = Output()

        exit_code = acpi_events.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_thermal_zones_clean_dmesg(self, mock_context):
        """Returns exit code 0 when no zones but dmesg is clean."""
        from scripts.baremetal import acpi_events

        ctx = mock_context(
            tools_available=[],
            command_outputs={("dmesg",): DMESG_CLEAN},
            file_contents={},
        )
        output = Output()

        exit_code = acpi_events.run([], output, ctx)

        assert exit_code == 0
        assert "no acpi errors" in output.summary.lower()

    def test_healthy_temps(self, mock_context):
        """Returns 0 when temps are well below trip points."""
        from scripts.baremetal import acpi_events

        files, cmd_outputs = make_thermal_files([
            {
                "type": "x86_pkg_temp",
                "temp": 45000,  # 45C
                "trips": [
                    {"type": "passive", "temp": 80000},   # 80C
                    {"type": "critical", "temp": 100000},  # 100C
                ],
            },
        ])

        ctx = mock_context(
            tools_available=[],
            command_outputs=cmd_outputs,
            file_contents=files,
        )
        output = Output()

        exit_code = acpi_events.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["thermal_zones"]) == 1
        assert output.data["thermal_zones"][0]["temp_c"] == 45.0
        assert output.data["thermal_zones"][0]["alerts"] == []

    def test_near_critical_trip(self, mock_context):
        """Returns 1 CRITICAL when temp is within 10C of critical trip."""
        from scripts.baremetal import acpi_events

        files, cmd_outputs = make_thermal_files([
            {
                "type": "x86_pkg_temp",
                "temp": 92000,  # 92C - within 10C of 100C critical
                "trips": [
                    {"type": "passive", "temp": 80000},
                    {"type": "critical", "temp": 100000},
                ],
            },
        ])

        ctx = mock_context(
            tools_available=[],
            command_outputs=cmd_outputs,
            file_contents=files,
        )
        output = Output()

        exit_code = acpi_events.run([], output, ctx)

        assert exit_code == 1
        alerts = output.data["thermal_zones"][0]["alerts"]
        critical_alerts = [a for a in alerts if a["severity"] == "CRITICAL"]
        assert len(critical_alerts) > 0
        assert critical_alerts[0]["trip_type"] == "critical"
        assert critical_alerts[0]["margin_c"] == 8.0

    def test_near_passive_trip(self, mock_context):
        """Returns 1 WARNING when temp is within 20C of passive trip."""
        from scripts.baremetal import acpi_events

        files, cmd_outputs = make_thermal_files([
            {
                "type": "acpitz",
                "temp": 65000,  # 65C - within 20C of 80C passive
                "trips": [
                    {"type": "passive", "temp": 80000},
                    {"type": "critical", "temp": 110000},
                ],
            },
        ])

        ctx = mock_context(
            tools_available=[],
            command_outputs=cmd_outputs,
            file_contents=files,
        )
        output = Output()

        exit_code = acpi_events.run([], output, ctx)

        assert exit_code == 1
        alerts = output.data["thermal_zones"][0]["alerts"]
        warning_alerts = [a for a in alerts if a["severity"] == "WARNING"]
        assert len(warning_alerts) > 0
        assert warning_alerts[0]["trip_type"] == "passive"
        assert warning_alerts[0]["margin_c"] == 15.0

    def test_acpi_dmesg_errors(self, mock_context):
        """Returns 1 WARNING when dmesg contains ACPI errors."""
        from scripts.baremetal import acpi_events

        files, _ = make_thermal_files([
            {
                "type": "x86_pkg_temp",
                "temp": 45000,  # 45C - healthy
                "trips": [
                    {"type": "critical", "temp": 100000},
                ],
            },
        ])

        ctx = mock_context(
            tools_available=[],
            command_outputs={("dmesg",): DMESG_ACPI_ERRORS},
            file_contents=files,
        )
        output = Output()

        exit_code = acpi_events.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["acpi_errors"]) == 3
        assert "WARNING" in output.summary

    def test_json_output(self, mock_context):
        """Verify thermal zone data structure in JSON output."""
        from scripts.baremetal import acpi_events

        files, cmd_outputs = make_thermal_files([
            {
                "type": "x86_pkg_temp",
                "temp": 55000,  # 55C
                "trips": [
                    {"type": "passive", "temp": 80000},
                    {"type": "critical", "temp": 100000},
                ],
            },
            {
                "type": "acpitz",
                "temp": 40000,  # 40C
                "trips": [
                    {"type": "critical", "temp": 110000},
                ],
            },
        ])

        ctx = mock_context(
            tools_available=[],
            command_outputs=cmd_outputs,
            file_contents=files,
        )
        output = Output()

        exit_code = acpi_events.run(["--format", "json"], output, ctx)

        assert exit_code == 0
        assert "thermal_zones" in output.data
        assert "acpi_errors" in output.data
        assert len(output.data["thermal_zones"]) == 2

        zone0 = output.data["thermal_zones"][0]
        assert zone0["name"] == "thermal_zone0"
        assert zone0["type"] == "x86_pkg_temp"
        assert zone0["temp_c"] == 55.0
        assert isinstance(zone0["alerts"], list)

        zone1 = output.data["thermal_zones"][1]
        assert zone1["name"] == "thermal_zone1"
        assert zone1["type"] == "acpitz"
        assert zone1["temp_c"] == 40.0
