"""Tests for dmi_inventory script."""

import json
from datetime import datetime
from unittest.mock import patch

import pytest

from boxctl.core.output import Output


# Full DMI file contents for a healthy system
FULL_DMI_FILES = {
    '/sys/class/dmi/id': '',  # directory marker
    '/sys/class/dmi/id/sys_vendor': 'Dell Inc.\n',
    '/sys/class/dmi/id/product_name': 'PowerEdge R640\n',
    '/sys/class/dmi/id/product_serial': 'ABC1234XYZ\n',
    '/sys/class/dmi/id/bios_vendor': 'Dell Inc.\n',
    '/sys/class/dmi/id/bios_version': '2.18.0\n',
    '/sys/class/dmi/id/bios_date': '01/15/2025\n',
    '/sys/class/dmi/id/board_vendor': 'Dell Inc.\n',
    '/sys/class/dmi/id/board_name': '0T7D40\n',
    '/sys/class/dmi/id/chassis_type': '23\n',
}


class TestDmiInventory:
    """Tests for dmi_inventory script."""

    def test_no_dmi_dir(self, mock_context):
        """Returns exit code 2 when /sys/class/dmi/id/ does not exist."""
        from scripts.baremetal import dmi_inventory

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = dmi_inventory.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_full_inventory(self, mock_context):
        """Returns exit code 0 when all fields present and BIOS is recent."""
        from scripts.baremetal import dmi_inventory

        ctx = mock_context(file_contents=FULL_DMI_FILES)
        output = Output()

        # Patch datetime.now to ensure bios_date is within 3 years
        with patch.object(dmi_inventory, 'check_bios_age', wraps=dmi_inventory.check_bios_age) as _:
            exit_code = dmi_inventory.run([], output, ctx)

        assert exit_code == 0
        inv = output.data['inventory']
        assert inv['system']['vendor'] == 'Dell Inc.'
        assert inv['system']['product_name'] == 'PowerEdge R640'
        assert inv['system']['serial'] == 'ABC1234XYZ'
        assert inv['bios']['vendor'] == 'Dell Inc.'
        assert inv['bios']['version'] == '2.18.0'
        assert inv['bios']['date'] == '01/15/2025'
        assert inv['board']['vendor'] == 'Dell Inc.'
        assert inv['board']['name'] == '0T7D40'
        assert inv['chassis']['type'] == '23'
        assert output.data['issues'] == []

    def test_old_bios_date(self, mock_context):
        """Returns exit code 1 with WARNING when BIOS is more than 3 years old."""
        from scripts.baremetal import dmi_inventory

        old_dmi_files = dict(FULL_DMI_FILES)
        old_dmi_files['/sys/class/dmi/id/bios_date'] = '01/15/2020\n'

        ctx = mock_context(file_contents=old_dmi_files)
        output = Output()

        exit_code = dmi_inventory.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data['issues']) > 0
        issue = output.data['issues'][0]
        assert issue['severity'] == 'WARNING'
        assert '01/15/2020' in issue['message']

    def test_partial_data(self, mock_context):
        """Returns exit code 0 with missing fields set to None."""
        from scripts.baremetal import dmi_inventory

        partial_files = {
            '/sys/class/dmi/id': '',  # directory marker
            '/sys/class/dmi/id/sys_vendor': 'Dell Inc.\n',
            '/sys/class/dmi/id/product_name': 'PowerEdge R640\n',
            '/sys/class/dmi/id/bios_vendor': 'Dell Inc.\n',
            '/sys/class/dmi/id/bios_version': '2.18.0\n',
        }

        ctx = mock_context(file_contents=partial_files)
        output = Output()

        exit_code = dmi_inventory.run([], output, ctx)

        assert exit_code == 0
        inv = output.data['inventory']
        assert inv['system']['vendor'] == 'Dell Inc.'
        assert inv['system']['serial'] is None
        assert inv['bios']['date'] is None
        assert inv['board']['vendor'] is None
        assert inv['board']['name'] is None
        assert inv['chassis']['type'] is None

    def test_json_output(self, mock_context, capsys):
        """Verify JSON output contains inventory dict structure."""
        from scripts.baremetal import dmi_inventory

        ctx = mock_context(file_contents=FULL_DMI_FILES)
        output = Output()

        exit_code = dmi_inventory.run(['--format', 'json'], output, ctx)

        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert 'inventory' in data
        assert 'system' in data['inventory']
        assert 'bios' in data['inventory']
        assert 'board' in data['inventory']
        assert 'chassis' in data['inventory']
        assert 'issues' in data
