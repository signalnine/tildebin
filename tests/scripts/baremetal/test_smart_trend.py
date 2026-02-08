"""Tests for smart_trend script."""

import json
import pytest

from boxctl.core.output import Output


SCAN_ONE_DRIVE = json.dumps({
    "devices": [{"name": "/dev/sda", "type": "sat", "protocol": "ATA"}]
})

SCAN_EMPTY = json.dumps({"devices": []})

SMART_HEALTHY = json.dumps({
    "ata_smart_attributes": {
        "table": [
            {"id": 5, "name": "Reallocated_Sector_Ct", "value": 100, "worst": 100, "thresh": 10, "raw": {"value": 0}},
            {"id": 197, "name": "Current_Pending_Sector", "value": 100, "worst": 100, "thresh": 0, "raw": {"value": 0}},
            {"id": 198, "name": "Offline_Uncorrectable", "value": 100, "worst": 100, "thresh": 0, "raw": {"value": 0}},
        ]
    }
})

SMART_REALLOC_WARN = json.dumps({
    "ata_smart_attributes": {
        "table": [
            {"id": 5, "name": "Reallocated_Sector_Ct", "value": 98, "worst": 98, "thresh": 10, "raw": {"value": 5}},
            {"id": 197, "name": "Current_Pending_Sector", "value": 100, "worst": 100, "thresh": 0, "raw": {"value": 0}},
        ]
    }
})

SMART_REALLOC_CRIT = json.dumps({
    "ata_smart_attributes": {
        "table": [
            {"id": 5, "name": "Reallocated_Sector_Ct", "value": 80, "worst": 80, "thresh": 10, "raw": {"value": 150}},
        ]
    }
})

SMART_PENDING = json.dumps({
    "ata_smart_attributes": {
        "table": [
            {"id": 197, "name": "Current_Pending_Sector", "value": 100, "worst": 100, "thresh": 0, "raw": {"value": 3}},
        ]
    }
})

SMART_NEAR_THRESH = json.dumps({
    "ata_smart_attributes": {
        "table": [
            {"id": 1, "name": "Raw_Read_Error_Rate", "value": 15, "worst": 15, "thresh": 10, "raw": {"value": 500}},
        ]
    }
})


class TestSmartTrend:
    """Tests for smart_trend script."""

    def test_smartctl_missing(self, mock_context):
        """Returns 2 when smartctl not available."""
        from scripts.baremetal.smart_trend import run

        ctx = mock_context(tools_available=[])
        output = Output()

        assert run([], output, ctx) == 2

    def test_no_drives(self, mock_context):
        """Returns 0 when no drives found."""
        from scripts.baremetal.smart_trend import run

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan', '--json'): SCAN_EMPTY,
            },
        )
        output = Output()

        assert run([], output, ctx) == 0

    def test_healthy_drives(self, mock_context):
        """Returns 0 when all attributes clean."""
        from scripts.baremetal.smart_trend import run

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan', '--json'): SCAN_ONE_DRIVE,
                ('smartctl', '-A', '/dev/sda', '--json'): SMART_HEALTHY,
            },
        )
        output = Output()

        assert run([], output, ctx) == 0

    def test_reallocated_sectors_warning(self, mock_context):
        """Returns 1 when Reallocated_Sector_Ct has non-zero raw."""
        from scripts.baremetal.smart_trend import run

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan', '--json'): SCAN_ONE_DRIVE,
                ('smartctl', '-A', '/dev/sda', '--json'): SMART_REALLOC_WARN,
            },
        )
        output = Output()

        assert run([], output, ctx) == 1
        assert any(i['severity'] == 'WARNING' for i in output.data['issues'])

    def test_reallocated_sectors_critical(self, mock_context):
        """Returns 1 when Reallocated_Sector_Ct raw > 100."""
        from scripts.baremetal.smart_trend import run

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan', '--json'): SCAN_ONE_DRIVE,
                ('smartctl', '-A', '/dev/sda', '--json'): SMART_REALLOC_CRIT,
            },
        )
        output = Output()

        assert run([], output, ctx) == 1
        assert any(i['severity'] == 'CRITICAL' for i in output.data['issues'])

    def test_pending_sectors(self, mock_context):
        """Returns 1 when Current_Pending_Sector raw > 0."""
        from scripts.baremetal.smart_trend import run

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan', '--json'): SCAN_ONE_DRIVE,
                ('smartctl', '-A', '/dev/sda', '--json'): SMART_PENDING,
            },
        )
        output = Output()

        assert run([], output, ctx) == 1
        assert any('pending' in i['type'] for i in output.data['issues'])

    def test_attribute_near_threshold(self, mock_context):
        """Returns 1 when attribute value approaches threshold."""
        from scripts.baremetal.smart_trend import run

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan', '--json'): SCAN_ONE_DRIVE,
                ('smartctl', '-A', '/dev/sda', '--json'): SMART_NEAR_THRESH,
            },
        )
        output = Output()

        assert run([], output, ctx) == 1
        assert any(i['type'] == 'near_threshold' for i in output.data['issues'])

    def test_json_output(self, mock_context):
        """Verify JSON data structure."""
        from scripts.baremetal.smart_trend import run

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan', '--json'): SCAN_ONE_DRIVE,
                ('smartctl', '-A', '/dev/sda', '--json'): SMART_HEALTHY,
            },
        )
        output = Output()

        run(["--format", "json"], output, ctx)

        assert 'drives' in output.data
        assert 'issues' in output.data
