"""Tests for sysv_ipc script."""

import pytest

from boxctl.core.output import Output


class TestSysvIpc:
    """Tests for System V IPC monitor."""

    def test_missing_ipcs_returns_error(self, mock_context):
        """Returns exit code 2 when ipcs not available."""
        from scripts.baremetal import sysv_ipc

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = sysv_ipc.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any('ipcs' in e.lower() for e in output.errors)

    def test_healthy_usage(self, mock_context):
        """Returns 0 when IPC usage is healthy."""
        from scripts.baremetal import sysv_ipc

        sem_output = """------ Semaphore Arrays --------
key        semid      owner      perms      nsems
0x00000001 0          root       600        1
0x00000002 1          postgres   600        17"""

        shm_output = """------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch
0x00000001 0          root       600        1048576    2
0x00000002 1          postgres   600        8388608    4"""

        msg_output = """------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages"""

        ctx = mock_context(
            tools_available=['ipcs'],
            command_outputs={
                ('ipcs', '-s'): sem_output,
                ('ipcs', '-m'): shm_output,
                ('ipcs', '-q'): msg_output,
            },
            file_contents={
                '/proc/sys/kernel/sem': '250 32000 32 128',
                '/proc/sys/kernel/shmmax': '68719476736',
                '/proc/sys/kernel/shmall': '4294967296',
                '/proc/sys/kernel/shmmni': '4096',
                '/proc/sys/kernel/msgmax': '8192',
                '/proc/sys/kernel/msgmnb': '16384',
                '/proc/sys/kernel/msgmni': '32000',
            }
        )
        output = Output()

        exit_code = sysv_ipc.run([], output, ctx)

        assert exit_code == 0
        assert output.data['has_issues'] is False
        assert output.data['usage']['semaphores']['arrays'] == 2
        assert output.data['usage']['shared_memory']['segments'] == 2

    def test_high_semaphore_usage_warning(self, mock_context):
        """Returns 1 when semaphore usage exceeds warning threshold."""
        from scripts.baremetal import sysv_ipc

        # Generate many semaphore arrays (80% of limit of 10)
        sem_lines = []
        for i in range(8):
            sem_lines.append(f"0x0000000{i} {i}          root       600        1")

        sem_output = """------ Semaphore Arrays --------
key        semid      owner      perms      nsems
""" + "\n".join(sem_lines)

        shm_output = """------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch"""

        msg_output = """------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages"""

        ctx = mock_context(
            tools_available=['ipcs'],
            command_outputs={
                ('ipcs', '-s'): sem_output,
                ('ipcs', '-m'): shm_output,
                ('ipcs', '-q'): msg_output,
            },
            file_contents={
                '/proc/sys/kernel/sem': '250 32000 32 10',  # Only 10 arrays allowed
                '/proc/sys/kernel/shmmax': '68719476736',
                '/proc/sys/kernel/shmall': '4294967296',
                '/proc/sys/kernel/shmmni': '4096',
                '/proc/sys/kernel/msgmax': '8192',
                '/proc/sys/kernel/msgmnb': '16384',
                '/proc/sys/kernel/msgmni': '32000',
            }
        )
        output = Output()

        exit_code = sysv_ipc.run([], output, ctx)

        assert exit_code == 1
        assert output.data['has_issues'] is True
        assert any(i['resource'] == 'semaphore_arrays' for i in output.data['issues'])

    def test_critical_shared_memory_usage(self, mock_context):
        """Returns 1 when shared memory usage is critical."""
        from scripts.baremetal import sysv_ipc

        sem_output = """------ Semaphore Arrays --------
key        semid      owner      perms      nsems"""

        # Generate 9 of 10 segments (90%+)
        shm_lines = []
        for i in range(9):
            shm_lines.append(f"0x0000000{i} {i}          root       600        1048576    2")

        shm_output = """------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch
""" + "\n".join(shm_lines)

        msg_output = """------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages"""

        ctx = mock_context(
            tools_available=['ipcs'],
            command_outputs={
                ('ipcs', '-s'): sem_output,
                ('ipcs', '-m'): shm_output,
                ('ipcs', '-q'): msg_output,
            },
            file_contents={
                '/proc/sys/kernel/sem': '250 32000 32 128',
                '/proc/sys/kernel/shmmax': '68719476736',
                '/proc/sys/kernel/shmall': '4294967296',
                '/proc/sys/kernel/shmmni': '10',  # Only 10 segments allowed
                '/proc/sys/kernel/msgmax': '8192',
                '/proc/sys/kernel/msgmnb': '16384',
                '/proc/sys/kernel/msgmni': '32000',
            }
        )
        output = Output()

        exit_code = sysv_ipc.run([], output, ctx)

        assert exit_code == 1
        assert output.data['has_issues'] is True
        assert any(i['severity'] == 'CRITICAL' and i['resource'] == 'shm_segments'
                   for i in output.data['issues'])

    def test_orphaned_shared_memory_detected(self, mock_context):
        """Detects shared memory with no attachments."""
        from scripts.baremetal import sysv_ipc

        sem_output = """------ Semaphore Arrays --------
key        semid      owner      perms      nsems"""

        # Segment with nattch=0 is orphaned
        shm_output = """------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch
0x00000001 0          root       600        1048576    0
0x00000002 1          postgres   600        8388608    4"""

        msg_output = """------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages"""

        ctx = mock_context(
            tools_available=['ipcs'],
            command_outputs={
                ('ipcs', '-s'): sem_output,
                ('ipcs', '-m'): shm_output,
                ('ipcs', '-q'): msg_output,
            },
            file_contents={
                '/proc/sys/kernel/sem': '250 32000 32 128',
                '/proc/sys/kernel/shmmax': '68719476736',
                '/proc/sys/kernel/shmall': '4294967296',
                '/proc/sys/kernel/shmmni': '4096',
                '/proc/sys/kernel/msgmax': '8192',
                '/proc/sys/kernel/msgmnb': '16384',
                '/proc/sys/kernel/msgmni': '32000',
            }
        )
        output = Output()

        exit_code = sysv_ipc.run([], output, ctx)

        assert exit_code == 1
        assert any(i['resource'] == 'orphaned_shm' for i in output.data['issues'])

    def test_custom_thresholds(self, mock_context):
        """Custom warning/critical thresholds work."""
        from scripts.baremetal import sysv_ipc

        sem_output = """------ Semaphore Arrays --------
key        semid      owner      perms      nsems
0x00000001 0          root       600        1"""

        shm_output = """------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch
0x00000001 0          root       600        1048576    2"""

        msg_output = """------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages"""

        ctx = mock_context(
            tools_available=['ipcs'],
            command_outputs={
                ('ipcs', '-s'): sem_output,
                ('ipcs', '-m'): shm_output,
                ('ipcs', '-q'): msg_output,
            },
            file_contents={
                '/proc/sys/kernel/sem': '250 32000 32 2',  # 1/2 = 50%
                '/proc/sys/kernel/shmmax': '68719476736',
                '/proc/sys/kernel/shmall': '4294967296',
                '/proc/sys/kernel/shmmni': '4096',
                '/proc/sys/kernel/msgmax': '8192',
                '/proc/sys/kernel/msgmnb': '16384',
                '/proc/sys/kernel/msgmni': '32000',
            }
        )
        output = Output()

        # With default 75% warn, 50% should be fine
        exit_code = sysv_ipc.run([], output, ctx)
        assert exit_code == 0

        # With 40% warn threshold, 50% should trigger warning
        output2 = Output()
        exit_code2 = sysv_ipc.run(['--warn', '40', '--crit', '60'], output2, ctx)
        assert exit_code2 == 1
        assert any(i['resource'] == 'semaphore_arrays' for i in output2.data['issues'])

    def test_invalid_threshold_returns_error(self, mock_context):
        """Returns 2 for invalid threshold arguments."""
        from scripts.baremetal import sysv_ipc

        ctx = mock_context(tools_available=['ipcs'])
        output = Output()

        # warn >= crit is invalid
        exit_code = sysv_ipc.run(['--warn', '90', '--crit', '80'], output, ctx)

        assert exit_code == 2
        assert any('crit' in e.lower() for e in output.errors)

    def test_verbose_includes_details(self, mock_context):
        """--verbose includes detailed resource breakdown."""
        from scripts.baremetal import sysv_ipc

        sem_output = """------ Semaphore Arrays --------
key        semid      owner      perms      nsems
0x00000001 0          root       600        1"""

        shm_output = """------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch
0x00000001 0          root       600        1048576    2"""

        msg_output = """------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages"""

        ctx = mock_context(
            tools_available=['ipcs'],
            command_outputs={
                ('ipcs', '-s'): sem_output,
                ('ipcs', '-m'): shm_output,
                ('ipcs', '-q'): msg_output,
            },
            file_contents={
                '/proc/sys/kernel/sem': '250 32000 32 128',
                '/proc/sys/kernel/shmmax': '68719476736',
                '/proc/sys/kernel/shmall': '4294967296',
                '/proc/sys/kernel/shmmni': '4096',
                '/proc/sys/kernel/msgmax': '8192',
                '/proc/sys/kernel/msgmnb': '16384',
                '/proc/sys/kernel/msgmni': '32000',
            }
        )
        output = Output()

        exit_code = sysv_ipc.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert 'semaphores' in output.data
        assert 'shared_memory' in output.data
        assert len(output.data['semaphores']) == 1
        assert len(output.data['shared_memory']) == 1
