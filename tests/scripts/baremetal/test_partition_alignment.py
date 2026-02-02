"""Tests for partition_alignment script."""

import pytest

from boxctl.core.output import Output


class TestPartitionAlignment:
    """Tests for partition_alignment script."""

    def test_missing_lsblk_returns_error(self, mock_context):
        """Returns 2 when lsblk not available."""
        from scripts.baremetal import partition_alignment

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = partition_alignment.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any('lsblk' in e.lower() for e in output.errors)

    def test_no_devices_found(self, mock_context):
        """Returns 1 with warning when no devices found."""
        from scripts.baremetal import partition_alignment

        ctx = mock_context(
            tools_available=['lsblk'],
            command_outputs={
                ('lsblk', '-d', '-n', '-o', 'NAME,TYPE'): '',
            }
        )
        output = Output()

        exit_code = partition_alignment.run([], output, ctx)

        assert exit_code == 1
        assert len(output.warnings) > 0

    def test_properly_aligned_partitions(self, mock_context):
        """Returns 0 when all partitions are properly aligned."""
        from scripts.baremetal import partition_alignment

        ctx = mock_context(
            tools_available=['lsblk', 'sfdisk'],
            command_outputs={
                ('lsblk', '-d', '-n', '-o', 'NAME,TYPE'): 'sda disk\n',
                ('lsblk', '-n', '-o', 'SIZE,MODEL', '/dev/sda'): '500G Samsung SSD 870',
                ('sfdisk', '-d', '/dev/sda'): '/dev/sda1 : start=     2048, size=   1048576, type=83\n/dev/sda2 : start=  1050624, size= 976773120, type=83\n',
            },
            file_contents={
                '/sys/block/sda/queue/logical_block_size': '512',
                '/sys/block/sda/queue/physical_block_size': '4096',
                '/sys/block/sda/queue/rotational': '0',
                '/sys/block/sda/queue/optimal_io_size': '0',
                '/sys/block/sda/queue/minimum_io_size': '4096',
            }
        )
        output = Output()

        exit_code = partition_alignment.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data['devices']) == 1
        device = output.data['devices'][0]
        assert device['status'] == 'OK'
        assert all(p['aligned'] for p in device['partitions'])

    def test_misaligned_partition_detected(self, mock_context):
        """Returns 1 when misaligned partition detected."""
        from scripts.baremetal import partition_alignment

        ctx = mock_context(
            tools_available=['lsblk', 'sfdisk'],
            command_outputs={
                ('lsblk', '-d', '-n', '-o', 'NAME,TYPE'): 'sda disk\n',
                ('lsblk', '-n', '-o', 'SIZE,MODEL', '/dev/sda'): '500G WDC WD5000',
                ('sfdisk', '-d', '/dev/sda'): '/dev/sda1 : start=       63, size=   1048576, type=83\n',  # Legacy sector 63
            },
            file_contents={
                '/sys/block/sda/queue/logical_block_size': '512',
                '/sys/block/sda/queue/physical_block_size': '4096',
                '/sys/block/sda/queue/rotational': '1',
                '/sys/block/sda/queue/optimal_io_size': '0',
                '/sys/block/sda/queue/minimum_io_size': '4096',
            }
        )
        output = Output()

        exit_code = partition_alignment.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data['devices']) == 1
        device = output.data['devices'][0]
        assert device['status'] in ['WARNING', 'ERROR']
        assert any(not p['aligned'] or len(p['issues']) > 0 for p in device['partitions'])

    def test_ssd_detected_correctly(self, mock_context):
        """SSD is correctly identified."""
        from scripts.baremetal import partition_alignment

        ctx = mock_context(
            tools_available=['lsblk', 'sfdisk'],
            command_outputs={
                ('lsblk', '-d', '-n', '-o', 'NAME,TYPE'): 'nvme0n1 disk\n',
                ('lsblk', '-n', '-o', 'SIZE,MODEL', '/dev/nvme0n1'): '1T Samsung 980 PRO',
                ('sfdisk', '-d', '/dev/nvme0n1'): '/dev/nvme0n1p1 : start=     2048, size=   1048576, type=83\n',
            },
            file_contents={
                '/sys/block/nvme0n1/queue/logical_block_size': '512',
                '/sys/block/nvme0n1/queue/physical_block_size': '512',
                '/sys/block/nvme0n1/queue/rotational': '0',
                '/sys/block/nvme0n1/queue/optimal_io_size': '0',
                '/sys/block/nvme0n1/queue/minimum_io_size': '512',
            }
        )
        output = Output()

        exit_code = partition_alignment.run([], output, ctx)

        assert exit_code == 0
        device = output.data['devices'][0]
        assert device['type'] == 'SSD'

    def test_specific_device_option(self, mock_context):
        """--device option checks only specified device."""
        from scripts.baremetal import partition_alignment

        ctx = mock_context(
            tools_available=['lsblk', 'sfdisk'],
            command_outputs={
                ('lsblk', '-n', '-o', 'SIZE,MODEL', '/dev/sdb'): '1T Seagate HDD',
                ('sfdisk', '-d', '/dev/sdb'): '/dev/sdb1 : start=     2048, size=   1048576, type=83\n',
            },
            file_contents={
                '/sys/block/sdb/queue/logical_block_size': '512',
                '/sys/block/sdb/queue/physical_block_size': '512',
                '/sys/block/sdb/queue/rotational': '1',
                '/sys/block/sdb/queue/optimal_io_size': '0',
                '/sys/block/sdb/queue/minimum_io_size': '512',
            }
        )
        output = Output()

        exit_code = partition_alignment.run(['--device', 'sdb'], output, ctx)

        assert exit_code == 0
        assert len(output.data['devices']) == 1
        assert output.data['devices'][0]['device'] == 'sdb'

    def test_advanced_format_drive_detected(self, mock_context):
        """Advanced Format (4K physical, 512B logical) is detected."""
        from scripts.baremetal import partition_alignment

        ctx = mock_context(
            tools_available=['lsblk', 'sfdisk'],
            command_outputs={
                ('lsblk', '-d', '-n', '-o', 'NAME,TYPE'): 'sda disk\n',
                ('lsblk', '-n', '-o', 'SIZE,MODEL', '/dev/sda'): '2T WD Red',
                ('sfdisk', '-d', '/dev/sda'): '/dev/sda1 : start=     2048, size=   1048576, type=83\n',
            },
            file_contents={
                '/sys/block/sda/queue/logical_block_size': '512',
                '/sys/block/sda/queue/physical_block_size': '4096',  # 4K physical
                '/sys/block/sda/queue/rotational': '1',
                '/sys/block/sda/queue/optimal_io_size': '0',
                '/sys/block/sda/queue/minimum_io_size': '4096',
            }
        )
        output = Output()

        exit_code = partition_alignment.run([], output, ctx)

        assert exit_code == 0
        device = output.data['devices'][0]
        assert device['advanced_format'] is True
