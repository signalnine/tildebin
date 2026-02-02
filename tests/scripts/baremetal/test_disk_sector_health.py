"""Tests for disk_sector_health script."""

import pytest

from boxctl.core.output import Output


class TestDiskSectorHealth:
    """Tests for disk_sector_health script."""

    def test_missing_smartctl_returns_error(self, mock_context):
        """Returns exit code 2 when smartctl not available."""
        from scripts.baremetal import disk_sector_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = disk_sector_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("smartctl" in e.lower() for e in output.errors)

    def test_all_disks_healthy(self, mock_context):
        """Returns 0 when all disks have no sector issues."""
        from scripts.baremetal import disk_sector_health

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan'): '/dev/sda -d sat # /dev/sda\n',
                ('smartctl', '-i', '-A', '-H', '/dev/sda'): (
                    'Device Model:     Samsung SSD 860\n'
                    'Serial Number:    S123456\n'
                    'Rotation Rate:    Solid State Device\n'
                    'SMART overall-health self-assessment test result: PASSED\n'
                    '\n'
                    'ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n'
                    '  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0\n'
                    '197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       0\n'
                    '198 Offline_Uncorrectable   0x0010   100   100   000    Old_age   Offline      -       0\n'
                ),
            }
        )
        output = Output()

        exit_code = disk_sector_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['healthy'] == 1
        assert output.data['summary']['issues'] == 0

    def test_reallocated_sectors_warning(self, mock_context):
        """Returns 1 when reallocated sectors found."""
        from scripts.baremetal import disk_sector_health

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan'): '/dev/sda -d sat\n',
                ('smartctl', '-i', '-A', '-H', '/dev/sda'): (
                    'Device Model:     WD Blue\n'
                    'Serial Number:    WD123456\n'
                    'SMART overall-health self-assessment test result: PASSED\n'
                    '\n'
                    'ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n'
                    '  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       8\n'
                    '197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       0\n'
                ),
            }
        )
        output = Output()

        exit_code = disk_sector_health.run([], output, ctx)

        assert exit_code == 1
        disk = output.data['disks'][0]
        assert disk['healthy'] is False
        assert any('Reallocated' in i['attribute'] for i in disk['issues'])

    def test_pending_sectors_warning(self, mock_context):
        """Returns 1 when pending sectors found."""
        from scripts.baremetal import disk_sector_health

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan'): '/dev/sda -d sat\n',
                ('smartctl', '-i', '-A', '-H', '/dev/sda'): (
                    'Device Model:     Seagate Barracuda\n'
                    'SMART overall-health self-assessment test result: PASSED\n'
                    '\n'
                    'ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n'
                    '  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0\n'
                    '197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       3\n'
                ),
            }
        )
        output = Output()

        exit_code = disk_sector_health.run([], output, ctx)

        assert exit_code == 1
        disk = output.data['disks'][0]
        assert any('Pending' in i['attribute'] for i in disk['issues'])

    def test_smart_failed_critical(self, mock_context):
        """Returns 1 with critical issue when SMART failed."""
        from scripts.baremetal import disk_sector_health

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan'): '/dev/sda -d sat\n',
                ('smartctl', '-i', '-A', '-H', '/dev/sda'): (
                    'Device Model:     Failing Drive\n'
                    'SMART overall-health self-assessment test result: FAILED!\n'
                ),
            }
        )
        output = Output()

        exit_code = disk_sector_health.run([], output, ctx)

        assert exit_code == 1
        disk = output.data['disks'][0]
        assert disk['healthy'] is False
        assert any(i['severity'] == 'CRITICAL' for i in disk['issues'])

    def test_nvme_media_errors(self, mock_context):
        """Detects NVMe media errors."""
        from scripts.baremetal import disk_sector_health

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan'): '/dev/nvme0n1 -d nvme\n',
                ('smartctl', '-i', '-A', '-H', '/dev/nvme0n1'): (
                    'Model Number:     Samsung SSD 970 EVO\n'
                    'Serial Number:    NVM123\n'
                    'NVMe Version:     1.3\n'
                    'SMART overall-health self-assessment test result: PASSED\n'
                    'Media and Data Integrity Errors:            5\n'
                    'Available Spare:                            100%\n'
                ),
            }
        )
        output = Output()

        exit_code = disk_sector_health.run([], output, ctx)

        assert exit_code == 1
        disk = output.data['disks'][0]
        assert disk['type'] == 'nvme'
        assert any('media_errors' in i['attribute'] for i in disk['issues'])

    def test_nvme_low_spare(self, mock_context):
        """Detects NVMe low available spare."""
        from scripts.baremetal import disk_sector_health

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan'): '/dev/nvme0n1 -d nvme\n',
                ('smartctl', '-i', '-A', '-H', '/dev/nvme0n1'): (
                    'Model Number:     Samsung SSD 970 EVO\n'
                    'NVMe Version:     1.3\n'
                    'SMART overall-health self-assessment test result: PASSED\n'
                    'Media and Data Integrity Errors:            0\n'
                    'Available Spare:                            8%\n'
                ),
            }
        )
        output = Output()

        exit_code = disk_sector_health.run([], output, ctx)

        assert exit_code == 1
        disk = output.data['disks'][0]
        assert any('available_spare' in i['attribute'] for i in disk['issues'])
        assert any(i['severity'] == 'CRITICAL' for i in disk['issues'])

    def test_specific_device(self, mock_context):
        """--device flag checks specific device only."""
        from scripts.baremetal import disk_sector_health

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '-i', '-A', '-H', '/dev/sdb'): (
                    'Device Model:     Specific Drive\n'
                    'SMART overall-health self-assessment test result: PASSED\n'
                    '\n'
                    'ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n'
                    '  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0\n'
                ),
            }
        )
        output = Output()

        exit_code = disk_sector_health.run(['-d', '/dev/sdb'], output, ctx)

        assert exit_code == 0
        assert len(output.data['disks']) == 1
        assert output.data['disks'][0]['device'] == '/dev/sdb'

    def test_verbose_includes_serial(self, mock_context):
        """--verbose includes serial number."""
        from scripts.baremetal import disk_sector_health

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan'): '/dev/sda -d sat\n',
                ('smartctl', '-i', '-A', '-H', '/dev/sda'): (
                    'Device Model:     Test Drive\n'
                    'Serial Number:    ABC123XYZ\n'
                    'SMART overall-health self-assessment test result: PASSED\n'
                    '\n'
                    'ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n'
                    '  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0\n'
                ),
            }
        )
        output = Output()

        exit_code = disk_sector_health.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert output.data['disks'][0]['serial'] == 'ABC123XYZ'

    def test_high_reallocated_is_critical(self, mock_context):
        """High reallocated sector count is CRITICAL severity."""
        from scripts.baremetal import disk_sector_health

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '--scan'): '/dev/sda -d sat\n',
                ('smartctl', '-i', '-A', '-H', '/dev/sda'): (
                    'Device Model:     Dying Drive\n'
                    'SMART overall-health self-assessment test result: PASSED\n'
                    '\n'
                    'ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n'
                    '  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       100\n'
                ),
            }
        )
        output = Output()

        exit_code = disk_sector_health.run([], output, ctx)

        assert exit_code == 1
        disk = output.data['disks'][0]
        critical_issues = [i for i in disk['issues'] if i['severity'] == 'CRITICAL']
        assert len(critical_issues) >= 1
