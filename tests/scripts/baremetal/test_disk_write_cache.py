"""Tests for disk_write_cache script."""

import pytest

from boxctl.core.output import Output


class TestDiskWriteCache:
    """Tests for disk_write_cache script."""

    def test_no_devices_found(self, mock_context):
        """Returns exit code 2 when no devices found."""
        from scripts.baremetal import disk_write_cache

        ctx = mock_context(
            file_contents={}
        )
        output = Output()

        exit_code = disk_write_cache.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_write_cache_enabled(self, mock_context):
        """Detects write cache enabled on device."""
        from scripts.baremetal import disk_write_cache

        ctx = mock_context(
            tools_available=['hdparm'],
            file_contents={
                '/sys/block/sda': '',
                '/sys/block/sda/device': '',
                '/sys/block/sda/queue/rotational': '0',
                '/sys/block/sda/device/model': 'Samsung SSD 860',
                '/sys/block/sda/size': '1000000000',
            },
            command_outputs={
                ('hdparm', '-W', '/dev/sda'): ' write-caching =  1 (on)\n',
            }
        )
        output = Output()

        exit_code = disk_write_cache.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['write_cache_enabled'] == 1
        device = output.data['devices'][0]
        assert device['write_cache']['enabled'] is True

    def test_write_cache_disabled(self, mock_context):
        """Detects write cache disabled on device."""
        from scripts.baremetal import disk_write_cache

        ctx = mock_context(
            tools_available=['hdparm'],
            file_contents={
                '/sys/block/sda': '',
                '/sys/block/sda/device': '',
                '/sys/block/sda/queue/rotational': '1',
                '/sys/block/sda/device/model': 'WD Blue',
                '/sys/block/sda/size': '500000000',
            },
            command_outputs={
                ('hdparm', '-W', '/dev/sda'): ' write-caching =  0 (off)\n',
            }
        )
        output = Output()

        exit_code = disk_write_cache.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['write_cache_disabled'] == 1
        device = output.data['devices'][0]
        assert device['write_cache']['enabled'] is False

    def test_require_disabled_flag(self, mock_context):
        """--require-disabled flags enabled write caches as issues."""
        from scripts.baremetal import disk_write_cache

        ctx = mock_context(
            tools_available=['hdparm'],
            file_contents={
                '/sys/block/sda': '',
                '/sys/block/sda/device': '',
                '/sys/block/sda/queue/rotational': '0',
                '/sys/block/sda/device/model': 'Samsung SSD',
                '/sys/block/sda/size': '500000000',
            },
            command_outputs={
                ('hdparm', '-W', '/dev/sda'): ' write-caching =  1 (on)\n',
            }
        )
        output = Output()

        # Without flag - should pass
        exit_code = disk_write_cache.run([], output, ctx)
        assert exit_code == 0

        # With flag - should fail
        output = Output()
        exit_code = disk_write_cache.run(['--require-disabled'], output, ctx)
        assert exit_code == 1
        assert output.data['summary']['devices_with_issues'] == 1

    def test_specific_device(self, mock_context):
        """--device flag checks specific device only."""
        from scripts.baremetal import disk_write_cache

        ctx = mock_context(
            tools_available=['hdparm'],
            file_contents={
                '/sys/block/sda': '',
                '/sys/block/sda/device': '',
                '/sys/block/sda/size': '500000000',
                '/sys/block/sdb': '',
                '/sys/block/sdb/device': '',
                '/sys/block/sdb/size': '1000000000',
            },
            command_outputs={
                ('hdparm', '-W', '/dev/sdb'): ' write-caching =  1 (on)\n',
            }
        )
        output = Output()

        exit_code = disk_write_cache.run(['-d', 'sdb'], output, ctx)

        assert exit_code == 0
        assert len(output.data['devices']) == 1
        assert output.data['devices'][0]['device'] == 'sdb'

    def test_device_not_found(self, mock_context):
        """Returns 2 when specified device not found."""
        from scripts.baremetal import disk_write_cache

        ctx = mock_context(
            file_contents={}
        )
        output = Output()

        exit_code = disk_write_cache.run(['-d', 'nonexistent'], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_nvme_device_type(self, mock_context):
        """Correctly identifies NVMe devices."""
        from scripts.baremetal import disk_write_cache

        ctx = mock_context(
            tools_available=['hdparm'],
            file_contents={
                '/sys/block/nvme0n1': '',
                '/sys/block/nvme0n1/device': '',
                '/sys/block/nvme0n1/queue/rotational': '0',
                '/sys/block/nvme0n1/device/model': 'Samsung SSD 970',
                '/sys/block/nvme0n1/size': '500000000',
            }
        )
        output = Output()

        exit_code = disk_write_cache.run([], output, ctx)

        assert exit_code == 0
        device = output.data['devices'][0]
        assert device['is_nvme'] is True
        assert device['type'] == 'NVMe SSD'

    def test_hdd_device_type(self, mock_context):
        """Correctly identifies HDD devices."""
        from scripts.baremetal import disk_write_cache

        ctx = mock_context(
            tools_available=['hdparm'],
            file_contents={
                '/sys/block/sda': '',
                '/sys/block/sda/device': '',
                '/sys/block/sda/queue/rotational': '1',  # rotational = HDD
                '/sys/block/sda/device/model': 'WD Blue',
                '/sys/block/sda/size': '2000000000',
            },
            command_outputs={
                ('hdparm', '-W', '/dev/sda'): ' write-caching =  1 (on)\n',
            }
        )
        output = Output()

        exit_code = disk_write_cache.run([], output, ctx)

        assert exit_code == 0
        device = output.data['devices'][0]
        assert device['rotational'] is True
        assert device['type'] == 'HDD'

    def test_ssd_device_type(self, mock_context):
        """Correctly identifies SSD devices."""
        from scripts.baremetal import disk_write_cache

        ctx = mock_context(
            tools_available=['hdparm'],
            file_contents={
                '/sys/block/sda': '',
                '/sys/block/sda/device': '',
                '/sys/block/sda/queue/rotational': '0',  # non-rotational = SSD
                '/sys/block/sda/device/model': 'Samsung SSD',
                '/sys/block/sda/size': '500000000',
            },
            command_outputs={
                ('hdparm', '-W', '/dev/sda'): ' write-caching =  0 (off)\n',
            }
        )
        output = Output()

        exit_code = disk_write_cache.run([], output, ctx)

        assert exit_code == 0
        device = output.data['devices'][0]
        assert device['rotational'] is False
        assert device['type'] == 'SSD'

    def test_skips_virtual_devices(self, mock_context):
        """Skips virtual devices like dm- and loop."""
        from scripts.baremetal import disk_write_cache

        ctx = mock_context(
            tools_available=['hdparm'],
            file_contents={
                '/sys/block/sda': '',
                '/sys/block/sda/device': '',
                '/sys/block/sda/size': '500000000',
                '/sys/block/dm-0': '',  # Should be skipped
                '/sys/block/dm-0/device': '',
                '/sys/block/loop0': '',  # Should be skipped
                '/sys/block/loop0/device': '',
            },
            command_outputs={
                ('hdparm', '-W', '/dev/sda'): ' write-caching =  1 (on)\n',
            }
        )
        output = Output()

        exit_code = disk_write_cache.run([], output, ctx)

        assert exit_code == 0
        # Only real device should be included
        assert len(output.data['devices']) == 1
        assert output.data['devices'][0]['device'] == 'sda'

    def test_hdparm_not_available(self, mock_context):
        """Handles missing hdparm gracefully."""
        from scripts.baremetal import disk_write_cache

        ctx = mock_context(
            tools_available=[],  # No hdparm
            file_contents={
                '/sys/block/sda': '',
                '/sys/block/sda/device': '',
                '/sys/block/sda/size': '500000000',
            }
        )
        output = Output()

        exit_code = disk_write_cache.run([], output, ctx)

        # Should report unknown, but still issue a warning about being unable to determine
        # The script reports issues when it can't determine write cache status
        assert output.data['summary']['write_cache_unknown'] == 1
