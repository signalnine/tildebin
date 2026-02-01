"""Tests for thermal_zone script."""

import pytest

from boxctl.core.output import Output


def make_thermal_file_contents(zones: list[dict], cooling: list[dict] = None) -> dict[str, str]:
    """Build file_contents dict for MockContext with thermal zone data."""
    files = {
        "/sys/class/thermal": ""  # Directory marker
    }

    for i, zone in enumerate(zones):
        base = f"/sys/class/thermal/thermal_zone{i}"
        files[base] = ""  # Directory marker
        files[f"{base}/type"] = zone.get("type", "unknown")
        files[f"{base}/temp"] = str(zone.get("temp", 45000))

        for j, trip in enumerate(zone.get("trips", [])):
            files[f"{base}/trip_point_{j}_type"] = trip["type"]
            files[f"{base}/trip_point_{j}_temp"] = str(trip["temp"])

    for i, dev in enumerate(cooling or []):
        base = f"/sys/class/thermal/cooling_device{i}"
        files[base] = ""  # Directory marker
        files[f"{base}/type"] = dev.get("type", "Processor")
        files[f"{base}/cur_state"] = str(dev.get("cur_state", 0))
        files[f"{base}/max_state"] = str(dev.get("max_state", 10))

    return files


class TestThermalZone:
    """Tests for thermal_zone script."""

    def test_no_thermal_sysfs_returns_error(self, mock_context):
        """Returns exit code 2 when /sys/class/thermal doesn't exist."""
        from scripts.baremetal import thermal_zone

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = thermal_zone.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("thermal" in e.lower() for e in output.errors)

    def test_no_zones_found_returns_error(self, mock_context):
        """Returns exit code 2 when thermal sysfs exists but no zones."""
        from scripts.baremetal import thermal_zone

        ctx = mock_context(file_contents={
            "/sys/class/thermal": ""
        })
        output = Output()

        exit_code = thermal_zone.run([], output, ctx)

        assert exit_code == 2
        assert any("no thermal zones" in e.lower() for e in output.errors)

    def test_all_zones_healthy(self, mock_context):
        """Returns 0 when all zones are below thresholds."""
        from scripts.baremetal import thermal_zone

        files = make_thermal_file_contents([
            {
                "type": "x86_pkg_temp",
                "temp": 45000,  # 45C
                "trips": [
                    {"type": "passive", "temp": 80000},
                    {"type": "critical", "temp": 100000}
                ]
            },
            {
                "type": "acpitz",
                "temp": 35000,  # 35C
                "trips": [
                    {"type": "critical", "temp": 110000}
                ]
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = thermal_zone.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["thermal_zones"]) == 2
        assert all(z["status"] == "OK" for z in output.data["thermal_zones"])

    def test_zone_throttling_status(self, mock_context):
        """Returns 1 when zone exceeds passive threshold (throttling)."""
        from scripts.baremetal import thermal_zone

        files = make_thermal_file_contents([
            {
                "type": "x86_pkg_temp",
                "temp": 82000,  # 82C - above passive
                "trips": [
                    {"type": "passive", "temp": 80000},
                    {"type": "critical", "temp": 100000}
                ]
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = thermal_zone.run([], output, ctx)

        assert exit_code == 1
        assert output.data["thermal_zones"][0]["status"] == "THROTTLING"

    def test_zone_critical_status(self, mock_context):
        """Returns 1 when zone exceeds critical threshold."""
        from scripts.baremetal import thermal_zone

        files = make_thermal_file_contents([
            {
                "type": "x86_pkg_temp",
                "temp": 102000,  # 102C - above critical!
                "trips": [
                    {"type": "passive", "temp": 80000},
                    {"type": "critical", "temp": 100000}
                ]
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = thermal_zone.run([], output, ctx)

        assert exit_code == 1
        assert output.data["thermal_zones"][0]["status"] == "CRITICAL"

    def test_headroom_calculation(self, mock_context):
        """Correctly calculates headroom to critical threshold."""
        from scripts.baremetal import thermal_zone

        files = make_thermal_file_contents([
            {
                "type": "x86_pkg_temp",
                "temp": 45000,  # 45C
                "trips": [
                    {"type": "critical", "temp": 100000}  # 100C
                ]
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = thermal_zone.run([], output, ctx)

        assert exit_code == 0
        # Headroom should be 100 - 45 = 55C
        assert output.data["thermal_zones"][0]["headroom_to_critical"] == 55.0

    def test_cooling_devices_detected(self, mock_context):
        """Detects and reports cooling devices."""
        from scripts.baremetal import thermal_zone

        files = make_thermal_file_contents(
            zones=[{
                "type": "x86_pkg_temp",
                "temp": 45000,
                "trips": [{"type": "critical", "temp": 100000}]
            }],
            cooling=[
                {"type": "Processor", "cur_state": 0, "max_state": 10},
                {"type": "intel_powerclamp", "cur_state": 5, "max_state": 50}
            ]
        )

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = thermal_zone.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["cooling_devices"]) == 2
        assert output.data["cooling_devices"][0]["active"] is False
        assert output.data["cooling_devices"][1]["active"] is True

    def test_warn_only_filters_output(self, mock_context):
        """--warn-only filters to only zones with issues."""
        from scripts.baremetal import thermal_zone

        files = make_thermal_file_contents(
            zones=[
                {
                    "type": "x86_pkg_temp",
                    "temp": 45000,  # Healthy
                    "trips": [{"type": "critical", "temp": 100000}]
                },
                {
                    "type": "acpitz",
                    "temp": 85000,  # Above passive
                    "trips": [
                        {"type": "passive", "temp": 80000},
                        {"type": "critical", "temp": 100000}
                    ]
                }
            ],
            cooling=[
                {"type": "Processor", "cur_state": 0, "max_state": 10},  # Inactive
                {"type": "Fan", "cur_state": 5, "max_state": 10}  # Active
            ]
        )

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = thermal_zone.run(["--warn-only"], output, ctx)

        assert exit_code == 1
        # Only throttling zone should be shown
        assert len(output.data["thermal_zones"]) == 1
        assert output.data["thermal_zones"][0]["status"] == "THROTTLING"
        # Only active cooling device
        assert len(output.data["cooling_devices"]) == 1
        assert output.data["cooling_devices"][0]["active"] is True
