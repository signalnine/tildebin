"""Tests for disk_encryption script."""

import pytest

from boxctl.core.output import Output


class TestDiskEncryption:
    """Tests for disk_encryption script."""

    def test_missing_cryptsetup_returns_error(self, mock_context):
        """Returns exit code 2 when cryptsetup not available."""
        from scripts.baremetal import disk_encryption

        ctx = mock_context(tools_available=[])  # No cryptsetup
        output = Output()

        exit_code = disk_encryption.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("cryptsetup" in e.lower() for e in output.errors)

    def test_all_encrypted(self, mock_context):
        """Returns 0 when all data partitions are encrypted."""
        from scripts.baremetal import disk_encryption

        ctx = mock_context(
            tools_available=['cryptsetup', 'lsblk'],
            command_outputs={
                ('lsblk', '-n', '-o', 'NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE', '-l'): (
                    'sda disk 500G\n'
                    'sda1 part 500M /boot ext4\n'
                    'sda2 part 499G crypto_LUKS\n'
                    'dm-0 crypt 499G / ext4\n'
                ),
                ('cryptsetup', 'isLuks', '/dev/sda1'): Exception("Not LUKS"),
                ('cryptsetup', 'isLuks', '/dev/sda2'): '',
                ('cryptsetup', 'luksDump', '/dev/sda2'): (
                    'LUKS header information\n'
                    'Version:        2\n'
                    'Cipher name:    aes\n'
                    'Cipher mode:    xts-plain64\n'
                    'Hash spec:      sha256\n'
                    'Key Slot 0: ENABLED\n'
                ),
            },
            file_contents={
                '/sys/block/dm-0/dm/uuid': 'CRYPT-LUKS2-abc123',
            }
        )

        # Override run to handle exceptions
        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            key = tuple(cmd)
            if key in ctx.command_outputs:
                val = ctx.command_outputs[key]
                if isinstance(val, Exception):
                    import subprocess
                    return subprocess.CompletedProcess(cmd, returncode=1, stdout='', stderr=str(val))
                import subprocess
                return subprocess.CompletedProcess(cmd, returncode=0, stdout=val, stderr='')
            return original_run(cmd, **kwargs)
        ctx.run = mock_run

        output = Output()
        exit_code = disk_encryption.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['encrypted'] >= 1

    def test_unencrypted_data_partition(self, mock_context):
        """Returns 1 when unencrypted data partition found."""
        from scripts.baremetal import disk_encryption

        ctx = mock_context(
            tools_available=['cryptsetup', 'lsblk'],
            command_outputs={
                ('lsblk', '-n', '-o', 'NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE', '-l'): (
                    'sda disk 500G\n'
                    'sda1 part 500G /data ext4\n'  # Unencrypted data
                ),
                ('cryptsetup', 'isLuks', '/dev/sda1'): Exception("Not LUKS"),
            },
            file_contents={}
        )

        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            key = tuple(cmd)
            if key in ctx.command_outputs:
                val = ctx.command_outputs[key]
                if isinstance(val, Exception):
                    import subprocess
                    return subprocess.CompletedProcess(cmd, returncode=1, stdout='', stderr=str(val))
                import subprocess
                return subprocess.CompletedProcess(cmd, returncode=0, stdout=val, stderr='')
            return original_run(cmd, **kwargs)
        ctx.run = mock_run

        output = Output()
        exit_code = disk_encryption.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['unencrypted_data'] >= 1
        assert output.data['summary']['has_issues'] is True

    def test_swap_not_flagged(self, mock_context):
        """Swap partitions are not flagged as needing encryption."""
        from scripts.baremetal import disk_encryption

        ctx = mock_context(
            tools_available=['cryptsetup', 'lsblk'],
            command_outputs={
                ('lsblk', '-n', '-o', 'NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE', '-l'): (
                    'sda disk 500G\n'
                    'sda1 part 8G [SWAP] swap\n'
                ),
                ('cryptsetup', 'isLuks', '/dev/sda1'): Exception("Not LUKS"),
            },
            file_contents={}
        )

        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            key = tuple(cmd)
            if key in ctx.command_outputs:
                val = ctx.command_outputs[key]
                if isinstance(val, Exception):
                    import subprocess
                    return subprocess.CompletedProcess(cmd, returncode=1, stdout='', stderr=str(val))
                import subprocess
                return subprocess.CompletedProcess(cmd, returncode=0, stdout=val, stderr='')
            return original_run(cmd, **kwargs)
        ctx.run = mock_run

        output = Output()
        exit_code = disk_encryption.run([], output, ctx)

        # Should not flag swap as unencrypted data
        assert exit_code == 0

    def test_boot_partition_not_flagged(self, mock_context):
        """Boot partitions are not flagged as needing encryption."""
        from scripts.baremetal import disk_encryption

        ctx = mock_context(
            tools_available=['cryptsetup', 'lsblk'],
            command_outputs={
                ('lsblk', '-n', '-o', 'NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE', '-l'): (
                    'sda disk 500G\n'
                    'sda1 part 500M /boot ext4\n'
                    'sda2 part 100M /boot/efi vfat\n'
                ),
                ('cryptsetup', 'isLuks', '/dev/sda1'): Exception("Not LUKS"),
                ('cryptsetup', 'isLuks', '/dev/sda2'): Exception("Not LUKS"),
            },
            file_contents={}
        )

        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            key = tuple(cmd)
            if key in ctx.command_outputs:
                val = ctx.command_outputs[key]
                if isinstance(val, Exception):
                    import subprocess
                    return subprocess.CompletedProcess(cmd, returncode=1, stdout='', stderr=str(val))
                import subprocess
                return subprocess.CompletedProcess(cmd, returncode=0, stdout=val, stderr='')
            return original_run(cmd, **kwargs)
        ctx.run = mock_run

        output = Output()
        exit_code = disk_encryption.run([], output, ctx)

        # Boot partitions should not be flagged
        assert exit_code == 0
        assert output.data['summary']['unencrypted_data'] == 0

    def test_verbose_includes_cipher_details(self, mock_context):
        """--verbose includes cipher details."""
        from scripts.baremetal import disk_encryption

        ctx = mock_context(
            tools_available=['cryptsetup', 'lsblk'],
            command_outputs={
                ('lsblk', '-n', '-o', 'NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE', '-l'): (
                    'sda disk 500G\n'
                    'sda1 part 500G crypto_LUKS\n'
                ),
                ('cryptsetup', 'isLuks', '/dev/sda1'): '',
                ('cryptsetup', 'luksDump', '/dev/sda1'): (
                    'Version:        2\n'
                    'Cipher name:    aes\n'
                    'Cipher mode:    xts-plain64\n'
                    'Hash spec:      sha256\n'
                    'Key Slot 0: ENABLED\n'
                    'Key Slot 1: ENABLED\n'
                ),
            },
            file_contents={}
        )

        output = Output()
        exit_code = disk_encryption.run(['--verbose'], output, ctx)

        assert exit_code == 0
        device = output.data['devices'][0]
        assert device['encryption']['cipher'] == 'aes'
        assert device['encryption']['cipher_mode'] == 'xts-plain64'
        assert device['encryption']['key_slots_used'] == 2

    def test_dm_crypt_detected(self, mock_context):
        """Detects dm-crypt mapped devices."""
        from scripts.baremetal import disk_encryption

        ctx = mock_context(
            tools_available=['cryptsetup', 'lsblk'],
            command_outputs={
                ('lsblk', '-n', '-o', 'NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE', '-l'): (
                    'dm-0 crypt 500G / ext4\n'
                ),
            },
            file_contents={
                '/sys/block/dm-0/dm/uuid': 'CRYPT-LUKS2-abcd1234',
            }
        )

        output = Output()
        exit_code = disk_encryption.run(['--all'], output, ctx)

        assert exit_code == 0
        dm_device = next((d for d in output.data['devices'] if d['name'] == 'dm-0'), None)
        assert dm_device is not None
        assert dm_device['encryption'] is not None
        assert dm_device['encryption']['type'] == 'dm-crypt'

    def test_crypto_luks_not_flagged(self, mock_context):
        """crypto_LUKS partition type is not flagged as unencrypted."""
        from scripts.baremetal import disk_encryption

        ctx = mock_context(
            tools_available=['cryptsetup', 'lsblk'],
            command_outputs={
                # crypto_LUKS partitions are LUKS containers, not unencrypted data
                ('lsblk', '-n', '-o', 'NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE', '-l'): (
                    'sda disk 500G\n'
                    'sda1 part 500G crypto_LUKS\n'
                ),
                ('cryptsetup', 'isLuks', '/dev/sda1'): '',
                ('cryptsetup', 'luksDump', '/dev/sda1'): 'Version: 2\n',
            },
            file_contents={}
        )

        output = Output()
        exit_code = disk_encryption.run([], output, ctx)

        # crypto_LUKS is a LUKS container, not unencrypted data
        assert exit_code == 0
        assert output.data['summary']['encrypted'] == 1
        assert output.data['summary']['unencrypted_data'] == 0
