"""Tests for ups_health script."""

import pytest

from boxctl.core.output import Output


class TestUpsHealth:
    """Tests for UPS health monitor."""

    def test_no_ups_tools_returns_error(self, mock_context):
        """Returns exit code 2 when no UPS tools available."""
        from scripts.baremetal import ups_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = ups_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_ups_found(self, mock_context):
        """Returns 0 when no UPS devices found."""
        from scripts.baremetal import ups_health

        ctx = mock_context(
            tools_available=['upsc'],
            command_outputs={
                ('upsc', '-l'): '',
            }
        )
        output = Output()

        exit_code = ups_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['total_ups'] == 0

    def test_nut_ups_healthy(self, mock_context):
        """Returns 0 when NUT UPS is healthy."""
        from scripts.baremetal import ups_health

        list_output = "myups"

        ups_output = """battery.charge: 100
battery.runtime: 3600
ups.load: 25
ups.status: OL
input.voltage: 120.0
output.voltage: 120.0"""

        ctx = mock_context(
            tools_available=['upsc'],
            command_outputs={
                ('upsc', '-l'): list_output,
                ('upsc', 'myups'): ups_output,
            }
        )
        output = Output()

        exit_code = ups_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['ok'] == 1
        assert output.data['ups_units'][0]['health']['status'] == 'OK'

    def test_nut_ups_on_battery_warning(self, mock_context):
        """Returns 1 when UPS is on battery."""
        from scripts.baremetal import ups_health

        list_output = "myups"

        ups_output = """battery.charge: 85
battery.runtime: 1800
ups.load: 40
ups.status: OB
input.voltage: 0.0
output.voltage: 120.0"""

        ctx = mock_context(
            tools_available=['upsc'],
            command_outputs={
                ('upsc', '-l'): list_output,
                ('upsc', 'myups'): ups_output,
            }
        )
        output = Output()

        exit_code = ups_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data['ups_units'][0]['health']['on_battery'] is True
        assert 'Running on battery' in str(output.data['ups_units'][0]['health']['warnings'])

    def test_nut_ups_low_battery_critical(self, mock_context):
        """Returns 1 when battery is critically low."""
        from scripts.baremetal import ups_health

        list_output = "myups"

        ups_output = """battery.charge: 15
battery.runtime: 300
ups.load: 50
ups.status: OB LB
input.voltage: 0.0
output.voltage: 120.0"""

        ctx = mock_context(
            tools_available=['upsc'],
            command_outputs={
                ('upsc', '-l'): list_output,
                ('upsc', 'myups'): ups_output,
            }
        )
        output = Output()

        exit_code = ups_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data['ups_units'][0]['health']['status'] == 'CRITICAL'
        assert any('Critical battery' in i for i in output.data['ups_units'][0]['health']['issues'])

    def test_apcaccess_ups_healthy(self, mock_context):
        """Returns 0 when APC UPS is healthy."""
        from scripts.baremetal import ups_health

        apc_output = """STATUS   : ONLINE
BCHARGE  : 100.0 Percent
TIMELEFT : 60.0 Minutes
LOADPCT  : 30.0 Percent
LINEV    : 120.0 Volts
OUTPUTV  : 120.0 Volts"""

        ctx = mock_context(
            tools_available=['apcaccess'],
            command_outputs={
                ('apcaccess',): apc_output,
            }
        )
        output = Output()

        exit_code = ups_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data['ups_units'][0]['health']['status'] == 'OK'
        assert output.data['ups_units'][0]['source'] == 'apcaccess'

    def test_apcaccess_on_battery(self, mock_context):
        """Returns 1 when APC UPS is on battery."""
        from scripts.baremetal import ups_health

        apc_output = """STATUS   : ONBATT
BCHARGE  : 75.0 Percent
TIMELEFT : 30.0 Minutes
LOADPCT  : 45.0 Percent
LINEV    : 0.0 Volts
OUTPUTV  : 120.0 Volts"""

        ctx = mock_context(
            tools_available=['apcaccess'],
            command_outputs={
                ('apcaccess',): apc_output,
            }
        )
        output = Output()

        exit_code = ups_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data['ups_units'][0]['health']['on_battery'] is True

    def test_high_load_warning(self, mock_context):
        """Returns 1 when UPS load is high."""
        from scripts.baremetal import ups_health

        list_output = "myups"

        ups_output = """battery.charge: 100
battery.runtime: 1200
ups.load: 80
ups.status: OL
input.voltage: 120.0
output.voltage: 120.0"""

        ctx = mock_context(
            tools_available=['upsc'],
            command_outputs={
                ('upsc', '-l'): list_output,
                ('upsc', 'myups'): ups_output,
            }
        )
        output = Output()

        exit_code = ups_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data['ups_units'][0]['health']['status'] == 'WARNING'
        assert any('High UPS load' in w for w in output.data['ups_units'][0]['health']['warnings'])

    def test_critical_load(self, mock_context):
        """Returns 1 when UPS load is critical."""
        from scripts.baremetal import ups_health

        list_output = "myups"

        ups_output = """battery.charge: 100
battery.runtime: 600
ups.load: 95
ups.status: OL
input.voltage: 120.0
output.voltage: 120.0"""

        ctx = mock_context(
            tools_available=['upsc'],
            command_outputs={
                ('upsc', '-l'): list_output,
                ('upsc', 'myups'): ups_output,
            }
        )
        output = Output()

        exit_code = ups_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data['ups_units'][0]['health']['status'] == 'CRITICAL'
        assert any('near capacity' in i for i in output.data['ups_units'][0]['health']['issues'])

    def test_warn_only_filters_healthy(self, mock_context):
        """--warn-only filters out healthy UPS units."""
        from scripts.baremetal import ups_health

        list_output = "ups1\nups2"

        healthy_output = """battery.charge: 100
battery.runtime: 3600
ups.load: 25
ups.status: OL
input.voltage: 120.0
output.voltage: 120.0"""

        warning_output = """battery.charge: 40
battery.runtime: 900
ups.load: 50
ups.status: OL
input.voltage: 120.0
output.voltage: 120.0"""

        ctx = mock_context(
            tools_available=['upsc'],
            command_outputs={
                ('upsc', '-l'): list_output,
                ('upsc', 'ups1'): healthy_output,
                ('upsc', 'ups2'): warning_output,
            }
        )
        output = Output()

        exit_code = ups_health.run(['--warn-only'], output, ctx)

        assert exit_code == 1
        # Only the warning UPS should be included
        assert len(output.data['ups_units']) == 1
        assert output.data['ups_units'][0]['name'] == 'ups2'

    def test_replace_battery_warning(self, mock_context):
        """Detects replace battery flag."""
        from scripts.baremetal import ups_health

        list_output = "myups"

        ups_output = """battery.charge: 100
battery.runtime: 3600
ups.load: 25
ups.status: OL RB
input.voltage: 120.0
output.voltage: 120.0"""

        ctx = mock_context(
            tools_available=['upsc'],
            command_outputs={
                ('upsc', '-l'): list_output,
                ('upsc', 'myups'): ups_output,
            }
        )
        output = Output()

        exit_code = ups_health.run([], output, ctx)

        assert exit_code == 1
        assert any('Replace battery' in w for w in output.data['ups_units'][0]['health']['warnings'])

    def test_low_runtime_warning(self, mock_context):
        """Warns when runtime is low."""
        from scripts.baremetal import ups_health

        list_output = "myups"

        # 600 seconds = 10 minutes runtime
        ups_output = """battery.charge: 90
battery.runtime: 600
ups.load: 50
ups.status: OL
input.voltage: 120.0
output.voltage: 120.0"""

        ctx = mock_context(
            tools_available=['upsc'],
            command_outputs={
                ('upsc', '-l'): list_output,
                ('upsc', 'myups'): ups_output,
            }
        )
        output = Output()

        exit_code = ups_health.run([], output, ctx)

        assert exit_code == 1
        assert any('Low runtime' in w for w in output.data['ups_units'][0]['health']['warnings'])
