"""Tests for systemd_socket script."""

import pytest

from boxctl.core.output import Output


class TestSystemdSocket:
    """Tests for systemd socket activation monitor."""

    def test_missing_systemctl_returns_error(self, mock_context):
        """Returns exit code 2 when systemctl not available."""
        from scripts.baremetal import systemd_socket

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = systemd_socket.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any('systemctl' in e.lower() for e in output.errors)

    def test_no_socket_units_found(self, mock_context):
        """Returns 0 when no socket units are found."""
        from scripts.baremetal import systemd_socket

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--type=socket', '--all',
                 '--no-legend', '--no-pager'): '',
            }
        )
        output = Output()

        exit_code = systemd_socket.run([], output, ctx)

        assert exit_code == 0
        assert output.data.get('sockets') == []

    def test_all_sockets_healthy(self, mock_context):
        """Returns 0 when all sockets are healthy."""
        from scripts.baremetal import systemd_socket

        list_output = """sshd.socket loaded active listening OpenSSH Server Socket
dbus.socket loaded active running D-Bus System Message Bus Socket"""

        show_sshd = """Listen=/run/sshd.sock
Triggers=sshd.service
NAccepted=5
NConnections=0
NRefused=0
ActiveState=active
SubState=listening
Result=success
Accept=no"""

        show_dbus = """Listen=/run/dbus/system_bus_socket
Triggers=dbus.service
NAccepted=100
NConnections=2
NRefused=0
ActiveState=active
SubState=running
Result=success
Accept=no"""

        sshd_service_status = """ActiveState=inactive
SubState=dead"""

        dbus_service_status = """ActiveState=active
SubState=running"""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--type=socket', '--all',
                 '--no-legend', '--no-pager'): list_output,
                ('systemctl', 'show', 'sshd.socket',
                 '--property=Listen', '--property=Triggers',
                 '--property=NAccepted', '--property=NConnections',
                 '--property=NRefused', '--property=ActiveState',
                 '--property=SubState', '--property=Result',
                 '--property=Backlog', '--property=MaxConnections',
                 '--property=Accept'): show_sshd,
                ('systemctl', 'show', 'dbus.socket',
                 '--property=Listen', '--property=Triggers',
                 '--property=NAccepted', '--property=NConnections',
                 '--property=NRefused', '--property=ActiveState',
                 '--property=SubState', '--property=Result',
                 '--property=Backlog', '--property=MaxConnections',
                 '--property=Accept'): show_dbus,
                ('systemctl', 'show', 'sshd.service',
                 '--property=ActiveState', '--property=SubState'): sshd_service_status,
                ('systemctl', 'show', 'dbus.service',
                 '--property=ActiveState', '--property=SubState'): dbus_service_status,
            }
        )
        output = Output()

        exit_code = systemd_socket.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data['sockets']) == 2
        assert all(s['status'] == 'healthy' for s in output.data['sockets'])

    def test_failed_socket_detected(self, mock_context):
        """Returns 1 when socket is in failed state."""
        from scripts.baremetal import systemd_socket

        list_output = """myapp.socket loaded failed failed My App Socket"""

        show_output = """Listen=/run/myapp.sock
Triggers=myapp.service
NAccepted=0
NConnections=0
NRefused=0
ActiveState=failed
SubState=failed
Result=start-limit-hit
Accept=no"""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--type=socket', '--all',
                 '--no-legend', '--no-pager'): list_output,
                ('systemctl', 'show', 'myapp.socket',
                 '--property=Listen', '--property=Triggers',
                 '--property=NAccepted', '--property=NConnections',
                 '--property=NRefused', '--property=ActiveState',
                 '--property=SubState', '--property=Result',
                 '--property=Backlog', '--property=MaxConnections',
                 '--property=Accept'): show_output,
                ('systemctl', 'show', 'myapp.service',
                 '--property=ActiveState', '--property=SubState'): "ActiveState=failed\nSubState=failed",
            }
        )
        output = Output()

        exit_code = systemd_socket.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data['sockets']) == 1
        assert output.data['sockets'][0]['status'] == 'critical'
        assert any(i['type'] == 'socket_failed' for i in output.data['sockets'][0]['issues'])

    def test_high_refused_connections_warning(self, mock_context):
        """Returns 1 when socket has many refused connections."""
        from scripts.baremetal import systemd_socket

        list_output = """nginx.socket loaded active listening Nginx Socket"""

        show_output = """Listen=0.0.0.0:80
Triggers=nginx.service
NAccepted=1000
NConnections=50
NRefused=100
ActiveState=active
SubState=listening
Result=success
Accept=no"""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--type=socket', '--all',
                 '--no-legend', '--no-pager'): list_output,
                ('systemctl', 'show', 'nginx.socket',
                 '--property=Listen', '--property=Triggers',
                 '--property=NAccepted', '--property=NConnections',
                 '--property=NRefused', '--property=ActiveState',
                 '--property=SubState', '--property=Result',
                 '--property=Backlog', '--property=MaxConnections',
                 '--property=Accept'): show_output,
                ('systemctl', 'show', 'nginx.service',
                 '--property=ActiveState', '--property=SubState'): "ActiveState=active\nSubState=running",
            }
        )
        output = Output()

        exit_code = systemd_socket.run([], output, ctx)

        assert exit_code == 1
        assert output.data['sockets'][0]['status'] == 'warning'
        assert any(w['type'] == 'connections_refused' for w in output.data['sockets'][0]['warnings'])

    def test_specific_unit_check(self, mock_context):
        """Can check a specific socket unit."""
        from scripts.baremetal import systemd_socket

        show_load = """LoadState=loaded
ActiveState=active
SubState=listening"""

        show_details = """Listen=/run/sshd.sock
Triggers=sshd.service
NAccepted=10
NConnections=0
NRefused=0
ActiveState=active
SubState=listening
Result=success
Accept=no"""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'show', 'sshd.socket', '--property=LoadState'): 'LoadState=loaded',
                ('systemctl', 'show', 'sshd.socket',
                 '--property=LoadState', '--property=ActiveState', '--property=SubState'): show_load,
                ('systemctl', 'show', 'sshd.socket',
                 '--property=Listen', '--property=Triggers',
                 '--property=NAccepted', '--property=NConnections',
                 '--property=NRefused', '--property=ActiveState',
                 '--property=SubState', '--property=Result',
                 '--property=Backlog', '--property=MaxConnections',
                 '--property=Accept'): show_details,
                ('systemctl', 'show', 'sshd.service',
                 '--property=ActiveState', '--property=SubState'): "ActiveState=inactive\nSubState=dead",
            }
        )
        output = Output()

        exit_code = systemd_socket.run(['--unit', 'sshd'], output, ctx)

        assert exit_code == 0
        assert len(output.data['sockets']) == 1
        assert output.data['sockets'][0]['unit'] == 'sshd.socket'

    def test_unit_not_found_error(self, mock_context):
        """Returns 2 when specified unit is not found."""
        from scripts.baremetal import systemd_socket

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'show', 'nonexistent.socket', '--property=LoadState'): 'LoadState=not-found',
            }
        )
        output = Output()

        exit_code = systemd_socket.run(['--unit', 'nonexistent'], output, ctx)

        assert exit_code == 2
        assert any('not found' in e.lower() for e in output.errors)

    def test_triggered_service_failed(self, mock_context):
        """Detects when triggered service is in failed state."""
        from scripts.baremetal import systemd_socket

        list_output = """myapp.socket loaded active listening My App Socket"""

        show_output = """Listen=/run/myapp.sock
Triggers=myapp.service
NAccepted=5
NConnections=0
NRefused=0
ActiveState=active
SubState=listening
Result=success
Accept=no"""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--type=socket', '--all',
                 '--no-legend', '--no-pager'): list_output,
                ('systemctl', 'show', 'myapp.socket',
                 '--property=Listen', '--property=Triggers',
                 '--property=NAccepted', '--property=NConnections',
                 '--property=NRefused', '--property=ActiveState',
                 '--property=SubState', '--property=Result',
                 '--property=Backlog', '--property=MaxConnections',
                 '--property=Accept'): show_output,
                ('systemctl', 'show', 'myapp.service',
                 '--property=ActiveState', '--property=SubState'): "ActiveState=failed\nSubState=failed",
            }
        )
        output = Output()

        exit_code = systemd_socket.run([], output, ctx)

        assert exit_code == 1
        assert output.data['sockets'][0]['status'] == 'critical'
        assert any(i['type'] == 'triggered_service_failed' for i in output.data['sockets'][0]['issues'])

    def test_warn_only_filters_healthy(self, mock_context):
        """--warn-only filters out healthy sockets."""
        from scripts.baremetal import systemd_socket

        list_output = """healthy.socket loaded active listening Healthy Socket
broken.socket loaded failed failed Broken Socket"""

        show_healthy = """Listen=/run/healthy.sock
Triggers=healthy.service
NAccepted=10
NConnections=0
NRefused=0
ActiveState=active
SubState=listening
Result=success
Accept=no"""

        show_broken = """Listen=/run/broken.sock
Triggers=broken.service
NAccepted=0
NConnections=0
NRefused=0
ActiveState=failed
SubState=failed
Result=start-limit-hit
Accept=no"""

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--type=socket', '--all',
                 '--no-legend', '--no-pager'): list_output,
                ('systemctl', 'show', 'healthy.socket',
                 '--property=Listen', '--property=Triggers',
                 '--property=NAccepted', '--property=NConnections',
                 '--property=NRefused', '--property=ActiveState',
                 '--property=SubState', '--property=Result',
                 '--property=Backlog', '--property=MaxConnections',
                 '--property=Accept'): show_healthy,
                ('systemctl', 'show', 'broken.socket',
                 '--property=Listen', '--property=Triggers',
                 '--property=NAccepted', '--property=NConnections',
                 '--property=NRefused', '--property=ActiveState',
                 '--property=SubState', '--property=Result',
                 '--property=Backlog', '--property=MaxConnections',
                 '--property=Accept'): show_broken,
                ('systemctl', 'show', 'healthy.service',
                 '--property=ActiveState', '--property=SubState'): "ActiveState=active\nSubState=running",
                ('systemctl', 'show', 'broken.service',
                 '--property=ActiveState', '--property=SubState'): "ActiveState=failed\nSubState=failed",
            }
        )
        output = Output()

        exit_code = systemd_socket.run(['--warn-only'], output, ctx)

        assert exit_code == 1
        # Only the broken socket should be included
        assert len(output.data['sockets']) == 1
        assert output.data['sockets'][0]['unit'] == 'broken.socket'
