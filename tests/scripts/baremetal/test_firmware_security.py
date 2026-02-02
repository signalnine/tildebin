"""Tests for firmware_security script."""

import pytest

from boxctl.core.output import Output


class TestFirmwareSecurity:
    """Tests for firmware_security script."""

    def test_all_security_features_enabled(self, mock_context):
        """Returns 0 when all security features are enabled."""
        from scripts.baremetal import firmware_security

        ctx = mock_context(
            tools_available=['mokutil'],
            file_contents={
                '/sys/firmware/efi': '',  # UEFI mode
                '/dev/tpm0': '',
                '/sys/class/tpm/tpm0': '',
                '/sys/class/tpm/tpm0/tpm_version_major': '2',
                '/sys/kernel/iommu_groups': '',
                '/sys/kernel/iommu_groups/0': '',
                '/sys/kernel/iommu_groups/1': '',
                '/sys/kernel/security/lockdown': '[integrity] none confidentiality',
                '/proc/cmdline': 'root=/dev/sda1 intel_iommu=on',
            },
            command_outputs={
                ('mokutil', '--sb-state'): 'SecureBoot enabled\n',
            }
        )
        output = Output()

        exit_code = firmware_security.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['secure_boot'] == 'enabled'
        assert output.data['summary']['tpm'] == 'present'
        assert output.data['summary']['boot_mode'] == 'uefi'
        assert output.data['summary']['iommu'] == 'enabled'

    def test_secure_boot_disabled_warning(self, mock_context):
        """Returns 1 with warning when Secure Boot disabled."""
        from scripts.baremetal import firmware_security

        ctx = mock_context(
            tools_available=['mokutil'],
            file_contents={
                '/sys/firmware/efi': '',
            },
            command_outputs={
                ('mokutil', '--sb-state'): 'SecureBoot disabled\n',
            }
        )
        output = Output()

        exit_code = firmware_security.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['secure_boot'] == 'disabled'
        assert 'Secure Boot is disabled' in output.data['warnings']

    def test_require_secure_boot_flag(self, mock_context):
        """--require-secure-boot makes disabled Secure Boot an issue."""
        from scripts.baremetal import firmware_security

        ctx = mock_context(
            tools_available=['mokutil'],
            file_contents={
                '/sys/firmware/efi': '',
            },
            command_outputs={
                ('mokutil', '--sb-state'): 'SecureBoot disabled\n',
            }
        )
        output = Output()

        exit_code = firmware_security.run(['--require-secure-boot'], output, ctx)

        assert exit_code == 1
        assert 'Secure Boot is disabled' in output.data['issues']

    def test_no_tpm_warning(self, mock_context):
        """Returns 1 with warning when TPM not found."""
        from scripts.baremetal import firmware_security

        ctx = mock_context(
            tools_available=['mokutil'],
            file_contents={
                '/sys/firmware/efi': '',
            },
            command_outputs={
                ('mokutil', '--sb-state'): 'SecureBoot enabled\n',
            }
        )
        output = Output()

        exit_code = firmware_security.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['tpm'] == 'not_found'
        assert 'No TPM device found' in output.data['warnings']

    def test_require_tpm_flag(self, mock_context):
        """--require-tpm makes missing TPM an issue."""
        from scripts.baremetal import firmware_security

        ctx = mock_context(
            tools_available=['mokutil'],
            file_contents={
                '/sys/firmware/efi': '',
            },
            command_outputs={
                ('mokutil', '--sb-state'): 'SecureBoot enabled\n',
            }
        )
        output = Output()

        exit_code = firmware_security.run(['--require-tpm'], output, ctx)

        assert exit_code == 1
        assert 'No TPM device found' in output.data['issues']

    def test_legacy_bios_warning(self, mock_context):
        """Returns 1 with warning for Legacy BIOS mode."""
        from scripts.baremetal import firmware_security

        ctx = mock_context(
            file_contents={
                # No /sys/firmware/efi = Legacy BIOS
                '/dev/tpm0': '',
                '/sys/class/tpm/tpm0': '',
                '/sys/kernel/iommu_groups': '',
                '/sys/kernel/iommu_groups/0': '',
            }
        )
        output = Output()

        exit_code = firmware_security.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['boot_mode'] == 'legacy'
        assert 'Legacy BIOS' in str(output.data['warnings'])

    def test_iommu_disabled_warning(self, mock_context):
        """Returns 1 with warning when IOMMU disabled."""
        from scripts.baremetal import firmware_security

        ctx = mock_context(
            tools_available=['mokutil'],
            file_contents={
                '/sys/firmware/efi': '',
                '/dev/tpm0': '',
                '/sys/class/tpm/tpm0': '',
                # No IOMMU groups
            },
            command_outputs={
                ('mokutil', '--sb-state'): 'SecureBoot enabled\n',
            }
        )
        output = Output()

        exit_code = firmware_security.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['iommu'] == 'disabled'
        assert 'IOMMU' in str(output.data['warnings'])

    def test_require_iommu_flag(self, mock_context):
        """--require-iommu makes disabled IOMMU an issue."""
        from scripts.baremetal import firmware_security

        ctx = mock_context(
            tools_available=['mokutil'],
            file_contents={
                '/sys/firmware/efi': '',
                '/dev/tpm0': '',
                '/sys/class/tpm/tpm0': '',
            },
            command_outputs={
                ('mokutil', '--sb-state'): 'SecureBoot enabled\n',
            }
        )
        output = Output()

        exit_code = firmware_security.run(['--require-iommu'], output, ctx)

        assert exit_code == 1
        assert 'IOMMU' in str(output.data['issues'])

    def test_require_all_flag(self, mock_context):
        """--require-all enables all requirements."""
        from scripts.baremetal import firmware_security

        ctx = mock_context(
            tools_available=['mokutil'],
            file_contents={
                '/sys/firmware/efi': '',
            },
            command_outputs={
                ('mokutil', '--sb-state'): 'SecureBoot disabled\n',
            }
        )
        output = Output()

        exit_code = firmware_security.run(['--require-all'], output, ctx)

        assert exit_code == 1
        # Should have issues for all missing requirements
        assert len(output.data['issues']) >= 3  # SB, TPM, IOMMU

    def test_kernel_lockdown_disabled_warning(self, mock_context):
        """Returns 1 with warning when kernel lockdown disabled."""
        from scripts.baremetal import firmware_security

        ctx = mock_context(
            tools_available=['mokutil'],
            file_contents={
                '/sys/firmware/efi': '',
                '/dev/tpm0': '',
                '/sys/class/tpm/tpm0': '',
                '/sys/kernel/iommu_groups': '',
                '/sys/kernel/iommu_groups/0': '',
                '/sys/kernel/security/lockdown': '[none] integrity confidentiality',
            },
            command_outputs={
                ('mokutil', '--sb-state'): 'SecureBoot enabled\n',
            }
        )
        output = Output()

        exit_code = firmware_security.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['kernel_lockdown'] == 'none'
        assert 'lockdown' in str(output.data['warnings']).lower()

    def test_tpm_version_detected(self, mock_context):
        """Detects TPM version correctly."""
        from scripts.baremetal import firmware_security

        ctx = mock_context(
            tools_available=['mokutil'],
            file_contents={
                '/sys/firmware/efi': '',
                '/dev/tpm0': '',
                '/sys/class/tpm/tpm0': '',
                '/sys/class/tpm/tpm0/tpm_version_major': '2',
                '/sys/kernel/iommu_groups': '',
                '/sys/kernel/iommu_groups/0': '',
                '/sys/kernel/security/lockdown': '[integrity] none confidentiality',
            },
            command_outputs={
                ('mokutil', '--sb-state'): 'SecureBoot enabled\n',
            }
        )
        output = Output()

        exit_code = firmware_security.run([], output, ctx)

        assert exit_code == 0
        assert output.data['checks']['tpm']['version'] == 'TPM 2.0'

    def test_iommu_groups_counted(self, mock_context):
        """Counts IOMMU groups correctly."""
        from scripts.baremetal import firmware_security

        ctx = mock_context(
            tools_available=['mokutil'],
            file_contents={
                '/sys/firmware/efi': '',
                '/dev/tpm0': '',
                '/sys/class/tpm/tpm0': '',
                '/sys/kernel/iommu_groups': '',
                '/sys/kernel/iommu_groups/0': '',
                '/sys/kernel/iommu_groups/1': '',
                '/sys/kernel/iommu_groups/2': '',
                '/sys/kernel/security/lockdown': '[integrity] none confidentiality',
            },
            command_outputs={
                ('mokutil', '--sb-state'): 'SecureBoot enabled\n',
            }
        )
        output = Output()

        exit_code = firmware_security.run([], output, ctx)

        assert exit_code == 0
        assert output.data['checks']['iommu']['groups'] == 3
