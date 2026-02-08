"""Tests for iommu_status script."""

import json

import pytest

from boxctl.core.output import Output


class TestIommuStatus:
    """Tests for iommu_status script."""

    def test_no_iommu_hardware(self, mock_context):
        """Returns exit 0 with INFO issue when no DMAR/IVRS and no iommu entries."""
        from scripts.baremetal import iommu_status

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1 quiet',
                # No DMAR, no IVRS, no /sys/class/iommu entries
            }
        )
        output = Output()

        exit_code = iommu_status.run([], output, ctx)

        assert exit_code == 0
        assert output.data['iommu_enabled'] is False
        assert output.data['has_dmar'] is False
        assert output.data['has_ivrs'] is False
        issues = output.data['issues']
        assert len(issues) >= 1
        assert issues[0]['severity'] == 'INFO'
        assert 'No IOMMU hardware detected' in issues[0]['message']

    def test_iommu_enabled_healthy(self, mock_context):
        """Returns exit 0 when DMAR exists, iommu active, cmdline has intel_iommu=on."""
        from scripts.baremetal import iommu_status

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1 intel_iommu=on iommu=pt quiet',
                '/sys/firmware/acpi/tables/DMAR': '',
                '/sys/class/iommu/dmar0/placeholder': '',
                '/sys/class/iommu/dmar1/placeholder': '',
                '/sys/kernel/iommu_groups/0/devices/0000:00:02.0': '',
                '/sys/kernel/iommu_groups/1/devices/0000:00:1f.0': '',
            }
        )
        output = Output()

        exit_code = iommu_status.run([], output, ctx)

        assert exit_code == 0
        assert output.data['iommu_enabled'] is True
        assert output.data['has_dmar'] is True
        assert output.data['hardware_type'] == 'Intel VT-d (DMAR)'
        assert output.data['iommu_instance_count'] == 2
        assert output.data['iommu_group_count'] == 2
        assert 'intel_iommu=on' in output.data['cmdline_params']
        assert 'iommu=pt' in output.data['cmdline_params']
        # No CRITICAL issues
        for issue in output.data['issues']:
            assert issue['severity'] != 'CRITICAL'

    def test_iommu_hardware_not_enabled(self, mock_context):
        """Returns exit 1 CRITICAL when DMAR exists but no iommu entries."""
        from scripts.baremetal import iommu_status

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1 quiet',
                '/sys/firmware/acpi/tables/DMAR': '',
                # No /sys/class/iommu entries - IOMMU not enabled
            }
        )
        output = Output()

        exit_code = iommu_status.run([], output, ctx)

        assert exit_code == 1
        issues = output.data['issues']
        critical_issues = [i for i in issues if i['severity'] == 'CRITICAL']
        assert len(critical_issues) == 1
        assert 'not enabled' in critical_issues[0]['message']
        assert 'Intel VT-d (DMAR)' in critical_issues[0]['message']

    def test_iommu_groups_enumerated(self, mock_context):
        """IOMMU groups with devices show up in output data."""
        from scripts.baremetal import iommu_status

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1 intel_iommu=on',
                '/sys/firmware/acpi/tables/DMAR': '',
                '/sys/class/iommu/dmar0/placeholder': '',
                '/sys/kernel/iommu_groups/0/devices/0000:00:02.0': '',
                '/sys/kernel/iommu_groups/1/devices/0000:00:1f.0': '',
                '/sys/kernel/iommu_groups/1/devices/0000:00:1f.3': '',
                '/sys/kernel/iommu_groups/2/devices/0000:01:00.0': '',
            }
        )
        output = Output()

        exit_code = iommu_status.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert output.data['iommu_group_count'] == 3
        groups = output.data['iommu_groups']
        assert len(groups) == 3

        # Group 0: single device
        group0 = next(g for g in groups if g['group_id'] == '0')
        assert group0['device_count'] == 1
        assert '0000:00:02.0' in group0['devices']

        # Group 1: two devices (mixed group)
        group1 = next(g for g in groups if g['group_id'] == '1')
        assert group1['device_count'] == 2
        assert '0000:00:1f.0' in group1['devices']
        assert '0000:00:1f.3' in group1['devices']

        # Group 2: single device
        group2 = next(g for g in groups if g['group_id'] == '2')
        assert group2['device_count'] == 1

        # Mixed group should produce INFO issue
        info_issues = [i for i in output.data['issues'] if i['severity'] == 'INFO']
        assert len(info_issues) >= 1
        assert any('group 1' in i['message'] for i in info_issues)

    def test_missing_cmdline(self, mock_context):
        """Returns exit 2 when /proc/cmdline is not available."""
        from scripts.baremetal import iommu_status

        ctx = mock_context(
            file_contents={
                # No /proc/cmdline at all
                '/sys/firmware/acpi/tables/DMAR': '',
            }
        )
        output = Output()

        exit_code = iommu_status.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any('cmdline' in e.lower() for e in output.errors)

    def test_json_output(self, mock_context):
        """Verify data structure has expected keys for JSON output."""
        from scripts.baremetal import iommu_status

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1 intel_iommu=on iommu=pt',
                '/sys/firmware/acpi/tables/DMAR': '',
                '/sys/class/iommu/dmar0/placeholder': '',
                '/sys/kernel/iommu_groups/0/devices/0000:00:02.0': '',
            }
        )
        output = Output()

        exit_code = iommu_status.run(['--format', 'json'], output, ctx)

        assert exit_code == 0
        # Verify all expected top-level keys are present
        expected_keys = {
            'iommu_enabled',
            'hardware_type',
            'has_dmar',
            'has_ivrs',
            'iommu_instance_count',
            'iommu_group_count',
            'cmdline_params',
            'issues',
        }
        assert expected_keys.issubset(set(output.data.keys()))

        # Verify data is JSON-serializable
        json_str = json.dumps(output.data)
        parsed = json.loads(json_str)
        assert parsed['iommu_enabled'] is True
        assert parsed['has_dmar'] is True
        assert parsed['has_ivrs'] is False
        assert isinstance(parsed['cmdline_params'], list)
        assert isinstance(parsed['issues'], list)

    def test_amd_iommu_hardware(self, mock_context):
        """Detects AMD-Vi (IVRS) hardware correctly."""
        from scripts.baremetal import iommu_status

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1 amd_iommu=on',
                '/sys/firmware/acpi/tables/IVRS': '',
                '/sys/class/iommu/ivhd0/placeholder': '',
                '/sys/kernel/iommu_groups/0/devices/0000:00:02.0': '',
            }
        )
        output = Output()

        exit_code = iommu_status.run([], output, ctx)

        assert exit_code == 0
        assert output.data['has_ivrs'] is True
        assert output.data['has_dmar'] is False
        assert output.data['hardware_type'] == 'AMD-Vi (IVRS)'

    def test_verbose_includes_details(self, mock_context):
        """--verbose adds iommu_instances, iommu_groups, and cmdline_detail."""
        from scripts.baremetal import iommu_status

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1 intel_iommu=on iommu=pt',
                '/sys/firmware/acpi/tables/DMAR': '',
                '/sys/class/iommu/dmar0/placeholder': '',
                '/sys/kernel/iommu_groups/0/devices/0000:00:02.0': '',
            }
        )
        output = Output()

        exit_code = iommu_status.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert 'iommu_instances' in output.data
        assert 'dmar0' in output.data['iommu_instances']
        assert 'iommu_groups' in output.data
        assert 'cmdline_detail' in output.data
        assert output.data['cmdline_detail']['intel_iommu'] == 'on'
        assert output.data['cmdline_detail']['iommu'] == 'pt'

    def test_amd_hardware_not_enabled(self, mock_context):
        """Returns exit 1 CRITICAL for AMD IVRS present but not enabled."""
        from scripts.baremetal import iommu_status

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1 quiet',
                '/sys/firmware/acpi/tables/IVRS': '',
                # No /sys/class/iommu entries
            }
        )
        output = Output()

        exit_code = iommu_status.run([], output, ctx)

        assert exit_code == 1
        critical_issues = [i for i in output.data['issues'] if i['severity'] == 'CRITICAL']
        assert len(critical_issues) == 1
        assert 'AMD-Vi (IVRS)' in critical_issues[0]['message']
