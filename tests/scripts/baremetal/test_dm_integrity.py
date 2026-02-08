"""Tests for dm_integrity script."""

import pytest

from boxctl.core.output import Output


class TestDmIntegrity:
    """Tests for dm_integrity script."""

    def test_dmsetup_missing(self, mock_context):
        """Returns 2 when dmsetup not available."""
        from scripts.baremetal.dm_integrity import run

        ctx = mock_context(tools_available=[])
        output = Output()

        assert run([], output, ctx) == 2

    def test_no_dm_devices(self, mock_context):
        """Returns 0 when no integrity/verity targets found."""
        from scripts.baremetal.dm_integrity import run

        ctx = mock_context(
            tools_available=['dmsetup'],
            command_outputs={
                ('dmsetup', 'table'): 'root: 0 1048576 linear 8:1 0\nswap: 0 524288 linear 8:2 0\n',
            },
        )
        output = Output()

        assert run([], output, ctx) == 0
        assert len(output.data['devices']) == 0

    def test_healthy_integrity(self, mock_context):
        """Returns 0 when integrity device has 0 mismatches."""
        from scripts.baremetal.dm_integrity import run

        ctx = mock_context(
            tools_available=['dmsetup'],
            command_outputs={
                ('dmsetup', 'table'): 'data-integrity: 0 1048576 integrity 8:1 0 32 J 0\n',
                ('dmsetup', 'status', 'data-integrity'): 'data-integrity: 0 1048576 integrity 0 mismatches\n',
            },
        )
        output = Output()

        assert run([], output, ctx) == 0
        assert output.data['devices'][0]['mismatches'] == 0

    def test_integrity_mismatches(self, mock_context):
        """Returns 1 when integrity device has mismatches."""
        from scripts.baremetal.dm_integrity import run

        ctx = mock_context(
            tools_available=['dmsetup'],
            command_outputs={
                ('dmsetup', 'table'): 'data-integrity: 0 1048576 integrity 8:1 0 32 J 0\n',
                ('dmsetup', 'status', 'data-integrity'): 'data-integrity: 0 1048576 integrity 5 mismatches\n',
            },
        )
        output = Output()

        assert run([], output, ctx) == 1
        assert any(i['severity'] == 'CRITICAL' for i in output.data['issues'])

    def test_healthy_verity(self, mock_context):
        """Returns 0 when verity device is verified."""
        from scripts.baremetal.dm_integrity import run

        ctx = mock_context(
            tools_available=['dmsetup'],
            command_outputs={
                ('dmsetup', 'table'): 'root-verity: 0 2097152 verity 1 8:1 8:2 4096 4096\n',
                ('dmsetup', 'status', 'root-verity'): 'root-verity: 0 2097152 verity V\n',
            },
        )
        output = Output()

        assert run([], output, ctx) == 0

    def test_corrupted_verity(self, mock_context):
        """Returns 1 when verity device shows corruption."""
        from scripts.baremetal.dm_integrity import run

        ctx = mock_context(
            tools_available=['dmsetup'],
            command_outputs={
                ('dmsetup', 'table'): 'root-verity: 0 2097152 verity 1 8:1 8:2 4096 4096\n',
                ('dmsetup', 'status', 'root-verity'): 'root-verity: 0 2097152 verity C\n',
            },
        )
        output = Output()

        assert run([], output, ctx) == 1
        assert any(i['type'] == 'verity_corruption' for i in output.data['issues'])

    def test_json_output(self, mock_context):
        """Verify JSON data structure."""
        from scripts.baremetal.dm_integrity import run

        ctx = mock_context(
            tools_available=['dmsetup'],
            command_outputs={
                ('dmsetup', 'table'): 'data: 0 100 integrity 8:1 0 32\n',
                ('dmsetup', 'status', 'data'): 'data: 0 100 integrity 0 mismatches\n',
            },
        )
        output = Output()

        run(["--format", "json"], output, ctx)

        assert 'devices' in output.data
        assert 'issues' in output.data
