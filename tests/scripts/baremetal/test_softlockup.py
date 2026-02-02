"""Tests for softlockup script."""

import pytest

from boxctl.core.output import Output


DMESG_CLEAN = """[    0.000000] Linux version 5.4.0
[    0.000001] Command line: BOOT_IMAGE=/boot/vmlinuz
[    1.000000] Initializing cgroup subsys cpuset
[   10.000000] random: systemd: uninitialized urandom read
"""

DMESG_SOFTLOCKUP = """[    0.000000] Linux version 5.4.0
[12345.678901] watchdog: BUG: soft lockup - CPU#0 stuck for 22s! [kworker/0:0:1234]
[12345.678910] Modules linked in: nvidia
[12345.678920] CPU: 0 PID: 1234 Comm: kworker/0:0 Tainted: P
"""

DMESG_HUNG_TASK = """[    0.000000] Linux version 5.4.0
[12345.678901] INFO: task kworker/0:0:1234 blocked for more than 120 seconds.
[12345.678910]       Not tainted 5.4.0-generic
[12345.678920] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
"""

DMESG_RCU_STALL = """[    0.000000] Linux version 5.4.0
[12345.678901] rcu: INFO: rcu_sched self-detected stall on CPU
[12345.678910] rcu:     0-....: (1 GPs behind) idle=2e2/1/0x40000000000002
"""

DMESG_HARDLOCKUP = """[    0.000000] Linux version 5.4.0
[12345.678901] NMI watchdog: Watchdog detected hard LOCKUP on cpu 0
[12345.678910] Modules linked in: nvidia
"""

DMESG_MULTIPLE = """[    0.000000] Linux version 5.4.0
[12345.678901] watchdog: BUG: soft lockup - CPU#0 stuck for 22s! [kworker/0:0:1234]
[12346.678901] INFO: task kworker/0:0:1234 blocked for more than 120 seconds.
[12347.678901] rcu: INFO: rcu_sched self-detected stall on CPU
"""

PS_NO_D_STATE = """    1 S -              systemd
 1234 S -              sshd
 5678 R 0              bash
"""

PS_WITH_D_STATE = """    1 S -              systemd
 1234 D nfs_wait_request    mount.nfs
 5678 D io_schedule         dd
 9999 S -              bash
"""


class TestSoftlockup:
    """Tests for softlockup script."""

    def test_missing_dmesg_returns_error(self, mock_context):
        """Returns exit code 2 when dmesg not available."""
        from scripts.baremetal import softlockup

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = softlockup.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("dmesg" in e.lower() for e in output.errors)

    def test_clean_dmesg(self, mock_context):
        """Returns 0 when dmesg shows no issues."""
        from scripts.baremetal import softlockup

        ctx = mock_context(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T", "--nopager"): DMESG_CLEAN,
                ("ps", "axo", "pid,state,wchan:32,comm", "--no-headers"): PS_NO_D_STATE,
            }
        )
        output = Output()

        exit_code = softlockup.run([], output, ctx)

        assert exit_code == 0
        assert output.data['status'] == 'ok'
        assert output.data['summary']['total_events'] == 0

    def test_softlockup_detected(self, mock_context):
        """Returns 1 when softlockup detected."""
        from scripts.baremetal import softlockup

        ctx = mock_context(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T", "--nopager"): DMESG_SOFTLOCKUP,
                ("ps", "axo", "pid,state,wchan:32,comm", "--no-headers"): PS_NO_D_STATE,
            }
        )
        output = Output()

        exit_code = softlockup.run([], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'critical'
        assert output.data['summary']['softlockups'] > 0

    def test_hung_task_detected(self, mock_context):
        """Returns 1 when hung task detected."""
        from scripts.baremetal import softlockup

        ctx = mock_context(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T", "--nopager"): DMESG_HUNG_TASK,
                ("ps", "axo", "pid,state,wchan:32,comm", "--no-headers"): PS_NO_D_STATE,
            }
        )
        output = Output()

        exit_code = softlockup.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['hung_tasks'] > 0

    def test_rcu_stall_detected(self, mock_context):
        """Returns 1 when RCU stall detected."""
        from scripts.baremetal import softlockup

        ctx = mock_context(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T", "--nopager"): DMESG_RCU_STALL,
                ("ps", "axo", "pid,state,wchan:32,comm", "--no-headers"): PS_NO_D_STATE,
            }
        )
        output = Output()

        exit_code = softlockup.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['rcu_stalls'] > 0

    def test_hardlockup_detected(self, mock_context):
        """Returns 1 when hardlockup detected."""
        from scripts.baremetal import softlockup

        ctx = mock_context(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T", "--nopager"): DMESG_HARDLOCKUP,
                ("ps", "axo", "pid,state,wchan:32,comm", "--no-headers"): PS_NO_D_STATE,
            }
        )
        output = Output()

        exit_code = softlockup.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['hardlockups'] > 0

    def test_multiple_events(self, mock_context):
        """Multiple event types are detected."""
        from scripts.baremetal import softlockup

        ctx = mock_context(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T", "--nopager"): DMESG_MULTIPLE,
                ("ps", "axo", "pid,state,wchan:32,comm", "--no-headers"): PS_NO_D_STATE,
            }
        )
        output = Output()

        exit_code = softlockup.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['total_events'] >= 3

    def test_d_state_processes_detected(self, mock_context):
        """D-state processes are detected."""
        from scripts.baremetal import softlockup

        ctx = mock_context(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T", "--nopager"): DMESG_CLEAN,
                ("ps", "axo", "pid,state,wchan:32,comm", "--no-headers"): PS_WITH_D_STATE,
            }
        )
        output = Output()

        exit_code = softlockup.run([], output, ctx)

        assert output.data['summary']['current_d_state_procs'] == 2

    def test_many_d_state_processes_triggers_issue(self, mock_context):
        """Returns 1 when many D-state processes are detected."""
        from scripts.baremetal import softlockup

        # Create many D-state processes
        many_d_state = "\n".join([f"  {i} D wait_func    process_{i}" for i in range(10)])

        ctx = mock_context(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T", "--nopager"): DMESG_CLEAN,
                ("ps", "axo", "pid,state,wchan:32,comm", "--no-headers"): many_d_state,
            }
        )
        output = Output()

        exit_code = softlockup.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['current_d_state_procs'] > 5

    def test_verbose_output(self, mock_context):
        """--verbose includes detailed information."""
        from scripts.baremetal import softlockup

        ctx = mock_context(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T", "--nopager"): DMESG_CLEAN,
                ("ps", "axo", "pid,state,wchan:32,comm", "--no-headers"): PS_WITH_D_STATE,
            }
        )
        output = Output()

        exit_code = softlockup.run(["--verbose"], output, ctx)

        assert 'stuck_processes' in output.data
        assert len(output.data['stuck_processes']) > 0
