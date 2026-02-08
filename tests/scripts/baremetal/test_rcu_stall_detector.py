"""Tests for rcu_stall_detector script."""

import pytest

from boxctl.core.output import Output


class TestRcuStallDetector:
    """Tests for rcu_stall_detector script."""

    def test_dmesg_fails(self, mock_context):
        """Returns exit code 2 when dmesg fails."""
        from scripts.baremetal.rcu_stall_detector import run

        ctx = mock_context(
            command_outputs={
                ('dmesg',): RuntimeError("dmesg failed"),
            },
        )
        output = Output()

        assert run([], output, ctx) == 2

    def test_no_stalls(self, mock_context):
        """Returns 0 when dmesg has no RCU issues."""
        from scripts.baremetal.rcu_stall_detector import run

        ctx = mock_context(
            command_outputs={
                ('dmesg',): "[ 0.000000] Linux version 6.1.0\n[ 1.234567] Normal boot messages\n",
            },
        )
        output = Output()

        assert run([], output, ctx) == 0
        assert output.data['stall_count'] == 0

    def test_rcu_stall_detected(self, mock_context):
        """Returns 1 when RCU stall is detected in dmesg."""
        from scripts.baremetal.rcu_stall_detector import run

        ctx = mock_context(
            command_outputs={
                ('dmesg',): (
                    "[ 0.000000] Linux version 6.1.0\n"
                    "[12345.678] rcu_sched self-detected stall on CPU 3\n"
                ),
            },
        )
        output = Output()

        assert run([], output, ctx) == 1
        assert output.data['stall_count'] == 1
        assert any(i['severity'] == 'CRITICAL' for i in output.data['issues'])

    def test_rcu_kthread_starved(self, mock_context):
        """Returns 1 when RCU kthread starvation is detected."""
        from scripts.baremetal.rcu_stall_detector import run

        ctx = mock_context(
            command_outputs={
                ('dmesg',): (
                    "[ 0.000000] Linux version 6.1.0\n"
                    "[99999.123] rcu_sched kthread starved for 26001 jiffies\n"
                ),
            },
        )
        output = Output()

        assert run([], output, ctx) == 1
        assert any(i['severity'] == 'WARNING' for i in output.data['issues'])

    def test_expedited_mode(self, mock_context):
        """Notes when rcu_expedited is enabled."""
        from scripts.baremetal.rcu_stall_detector import run

        ctx = mock_context(
            command_outputs={
                ('dmesg',): "[ 0.000000] Clean boot\n",
            },
            file_contents={
                '/proc/sys/kernel/rcu_expedited': '1\n',
            },
        )
        output = Output()

        assert run([], output, ctx) == 0
        assert output.data['rcu_expedited'] == '1'
        assert any(i['type'] == 'rcu_expedited' for i in output.data['issues'])

    def test_multiple_stalls(self, mock_context):
        """Captures multiple stall types."""
        from scripts.baremetal.rcu_stall_detector import run

        ctx = mock_context(
            command_outputs={
                ('dmesg',): (
                    "[100.0] rcu_sched self-detected stall on CPU 0\n"
                    "[200.0] rcu_sched self-detected stall on CPU 1\n"
                    "[300.0] rcu_preempt kthread starved for 5000 jiffies\n"
                ),
            },
        )
        output = Output()

        assert run([], output, ctx) == 1
        assert output.data['stall_count'] == 3
