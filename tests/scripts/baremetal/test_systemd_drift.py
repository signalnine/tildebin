"""Tests for systemd_drift script."""

import pytest

from boxctl.core.output import Output


class TestSystemdDrift:
    """Tests for systemd unit drift detector."""

    def test_missing_systemctl_returns_error(self, mock_context):
        """Returns exit code 2 when systemctl not available."""
        from scripts.baremetal import systemd_drift

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = systemd_drift.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any('systemctl' in e.lower() for e in output.errors)

    def test_no_units_found(self, mock_context):
        """Returns 0 when no units found."""
        from scripts.baremetal import systemd_drift

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-unit-files', '--no-pager', '--no-legend'): '',
            }
        )
        output = Output()

        exit_code = systemd_drift.run([], output, ctx)

        assert exit_code == 0
        assert output.data.get('units') == []

    def test_clean_unit_no_drift(self, mock_context):
        """Returns 0 when unit has no drift."""
        from scripts.baremetal import systemd_drift

        list_output = "sshd.service enabled"

        show_output = """UnitFileState=enabled
UnitFilePreset=enabled
FragmentPath=/usr/lib/systemd/system/sshd.service
DropInPaths="""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-unit-files', '--no-pager', '--no-legend'): list_output,
                ('systemctl', 'show', 'sshd.service',
                 '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'): show_output,
                ('systemctl', 'show', 'sshd.service', '--property=LoadState'): 'LoadState=loaded',
            },
            file_contents={
                '/usr/lib/systemd/system/sshd.service': '[Unit]\nDescription=SSH Daemon\n',
            }
        )
        output = Output()

        exit_code = systemd_drift.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data['units']) == 1
        assert output.data['units'][0]['has_drift'] is False

    def test_local_override_detected(self, mock_context):
        """Returns 1 when local override exists."""
        from scripts.baremetal import systemd_drift

        list_output = "sshd.service enabled"

        show_output = """UnitFileState=enabled
UnitFilePreset=enabled
FragmentPath=/etc/systemd/system/sshd.service
DropInPaths="""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-unit-files', '--no-pager', '--no-legend'): list_output,
                ('systemctl', 'show', 'sshd.service',
                 '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'): show_output,
                ('systemctl', 'show', 'sshd.service', '--property=LoadState'): 'LoadState=loaded',
            },
            file_contents={
                '/etc/systemd/system/sshd.service': '[Unit]\nDescription=Custom SSH\n',
                '/usr/lib/systemd/system/sshd.service': '[Unit]\nDescription=SSH Daemon\n',
            }
        )
        output = Output()

        exit_code = systemd_drift.run([], output, ctx)

        assert exit_code == 1
        assert output.data['units'][0]['has_drift'] is True
        assert 'local_override' in output.data['units'][0]['drift_reasons']

    def test_drop_in_detected(self, mock_context):
        """Returns 1 when drop-in files exist."""
        from scripts.baremetal import systemd_drift

        list_output = "docker.service enabled"

        show_output = """UnitFileState=enabled
UnitFilePreset=enabled
FragmentPath=/usr/lib/systemd/system/docker.service
DropInPaths=/etc/systemd/system/docker.service.d/override.conf"""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-unit-files', '--no-pager', '--no-legend'): list_output,
                ('systemctl', 'show', 'docker.service',
                 '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'): show_output,
                ('systemctl', 'show', 'docker.service', '--property=LoadState'): 'LoadState=loaded',
            },
            file_contents={
                '/usr/lib/systemd/system/docker.service': '[Unit]\nDescription=Docker\n',
                '/etc/systemd/system/docker.service.d': '',  # directory marker
                '/etc/systemd/system/docker.service.d/override.conf': '[Service]\nEnvironment=FOO=bar\n',
            }
        )
        output = Output()

        exit_code = systemd_drift.run([], output, ctx)

        assert exit_code == 1
        assert output.data['units'][0]['has_drift'] is True
        assert 'has_drop_ins' in output.data['units'][0]['drift_reasons']

    def test_masked_unit_detected(self, mock_context):
        """Returns 1 when unit is masked."""
        from scripts.baremetal import systemd_drift

        list_output = "cups.service masked"

        show_output = """UnitFileState=masked
UnitFilePreset=enabled
FragmentPath=/etc/systemd/system/cups.service
DropInPaths="""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-unit-files', '--no-pager', '--no-legend'): list_output,
                ('systemctl', 'show', 'cups.service',
                 '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'): show_output,
                ('systemctl', 'show', 'cups.service', '--property=LoadState'): 'LoadState=masked',
            },
            file_contents={
                '/etc/systemd/system/cups.service': '/dev/null',  # symlink target
            }
        )
        output = Output()

        exit_code = systemd_drift.run([], output, ctx)

        assert exit_code == 1
        assert output.data['units'][0]['has_drift'] is True
        assert 'masked' in output.data['units'][0]['drift_reasons']

    def test_specific_unit_check(self, mock_context):
        """Can check a specific unit."""
        from scripts.baremetal import systemd_drift

        show_output = """UnitFileState=enabled
UnitFilePreset=enabled
FragmentPath=/usr/lib/systemd/system/nginx.service
DropInPaths="""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'show', 'nginx.service',
                 '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'): show_output,
                ('systemctl', 'show', 'nginx.service', '--property=LoadState'): 'LoadState=loaded',
            },
            file_contents={
                '/usr/lib/systemd/system/nginx.service': '[Unit]\nDescription=Nginx\n',
            }
        )
        output = Output()

        exit_code = systemd_drift.run(['--unit', 'nginx.service'], output, ctx)

        assert exit_code == 0
        assert len(output.data['units']) == 1
        assert output.data['units'][0]['unit'] == 'nginx.service'

    def test_filter_by_type(self, mock_context):
        """Can filter by unit type."""
        from scripts.baremetal import systemd_drift

        list_output = "sshd.service enabled\nnginx.service enabled"

        show_sshd = """UnitFileState=enabled
UnitFilePreset=enabled
FragmentPath=/usr/lib/systemd/system/sshd.service
DropInPaths="""

        show_nginx = """UnitFileState=enabled
UnitFilePreset=enabled
FragmentPath=/usr/lib/systemd/system/nginx.service
DropInPaths="""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-unit-files', '--no-pager', '--no-legend',
                 '--type=service'): list_output,
                ('systemctl', 'show', 'sshd.service',
                 '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'): show_sshd,
                ('systemctl', 'show', 'sshd.service', '--property=LoadState'): 'LoadState=loaded',
                ('systemctl', 'show', 'nginx.service',
                 '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'): show_nginx,
                ('systemctl', 'show', 'nginx.service', '--property=LoadState'): 'LoadState=loaded',
            },
            file_contents={
                '/usr/lib/systemd/system/sshd.service': '[Unit]\nDescription=SSH\n',
                '/usr/lib/systemd/system/nginx.service': '[Unit]\nDescription=Nginx\n',
            }
        )
        output = Output()

        exit_code = systemd_drift.run(['--type', 'service'], output, ctx)

        assert exit_code == 0
        assert len(output.data['units']) == 2

    def test_warn_only_filters_clean_units(self, mock_context):
        """--warn-only filters out clean units."""
        from scripts.baremetal import systemd_drift

        list_output = "clean.service enabled\ndrifted.service enabled"

        show_clean = """UnitFileState=enabled
UnitFilePreset=enabled
FragmentPath=/usr/lib/systemd/system/clean.service
DropInPaths="""

        show_drifted = """UnitFileState=enabled
UnitFilePreset=enabled
FragmentPath=/etc/systemd/system/drifted.service
DropInPaths="""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-unit-files', '--no-pager', '--no-legend'): list_output,
                ('systemctl', 'show', 'clean.service',
                 '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'): show_clean,
                ('systemctl', 'show', 'clean.service', '--property=LoadState'): 'LoadState=loaded',
                ('systemctl', 'show', 'drifted.service',
                 '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'): show_drifted,
                ('systemctl', 'show', 'drifted.service', '--property=LoadState'): 'LoadState=loaded',
            },
            file_contents={
                '/usr/lib/systemd/system/clean.service': '[Unit]\nDescription=Clean\n',
                '/etc/systemd/system/drifted.service': '[Unit]\nDescription=Drifted\n',
                '/usr/lib/systemd/system/drifted.service': '[Unit]\nDescription=Original\n',
            }
        )
        output = Output()

        exit_code = systemd_drift.run(['--warn-only'], output, ctx)

        assert exit_code == 1
        # Only the drifted unit should be included
        assert len(output.data['units']) == 1
        assert output.data['units'][0]['unit'] == 'drifted.service'

    def test_summary_statistics(self, mock_context):
        """Summary includes drift statistics."""
        from scripts.baremetal import systemd_drift

        list_output = "a.service enabled\nb.service masked"

        show_a = """UnitFileState=enabled
UnitFilePreset=enabled
FragmentPath=/usr/lib/systemd/system/a.service
DropInPaths="""

        show_b = """UnitFileState=masked
UnitFilePreset=enabled
FragmentPath=/etc/systemd/system/b.service
DropInPaths="""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-unit-files', '--no-pager', '--no-legend'): list_output,
                ('systemctl', 'show', 'a.service',
                 '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'): show_a,
                ('systemctl', 'show', 'a.service', '--property=LoadState'): 'LoadState=loaded',
                ('systemctl', 'show', 'b.service',
                 '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'): show_b,
                ('systemctl', 'show', 'b.service', '--property=LoadState'): 'LoadState=masked',
            },
            file_contents={
                '/usr/lib/systemd/system/a.service': '[Unit]\nDescription=A\n',
                '/etc/systemd/system/b.service': '/dev/null',
            }
        )
        output = Output()

        exit_code = systemd_drift.run([], output, ctx)

        assert exit_code == 1
        summary = output.data['summary']
        assert summary['total_checked'] == 2
        assert summary['units_with_drift'] == 1
        assert summary['clean_units'] == 1
        assert 'masked' in summary['drift_by_reason']
