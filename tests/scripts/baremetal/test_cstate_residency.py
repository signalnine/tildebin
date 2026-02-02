"""Tests for cstate_residency script."""

import pytest

from boxctl.core.output import Output


class TestCstateResidency:
    """Tests for cstate_residency script."""

    def test_cpuidle_not_available(self, mock_context):
        """Returns exit code 2 when cpuidle not available."""
        from scripts.baremetal import cstate_residency

        ctx = mock_context(
            file_contents={}  # No cpuidle interface
        )
        output = Output()

        exit_code = cstate_residency.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("idle" in e.lower() for e in output.errors)

    def test_healthy_cstate_residency(self, mock_context):
        """Returns 0 when C-state residency is healthy."""
        from scripts.baremetal import cstate_residency

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/cpu/cpu0/cpuidle': '',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/name': 'POLL',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/time': '1000000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/usage': '100',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/disable': '0',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/name': 'C1',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/time': '5000000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/usage': '500',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/disable': '0',
                '/sys/devices/system/cpu/cpu0/cpuidle/state2/name': 'C6',
                '/sys/devices/system/cpu/cpu0/cpuidle/state2/time': '50000000',  # High deep state
                '/sys/devices/system/cpu/cpu0/cpuidle/state2/usage': '1000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state2/disable': '0',
                '/sys/devices/system/cpu/cpuidle/current_driver': 'intel_idle',
                '/sys/devices/system/cpu/cpuidle/current_governor': 'menu',
                '/sys/devices/system/cpu/cpu0': '',  # For CPU count
            }
        )
        output = Output()

        exit_code = cstate_residency.run([], output, ctx)

        assert exit_code == 0
        assert output.data['driver'] == 'intel_idle'
        assert output.data['governor'] == 'menu'
        assert output.data['cpu_count'] == 1

    def test_low_deep_residency_warning(self, mock_context):
        """Returns 1 when deep C-state residency is too low."""
        from scripts.baremetal import cstate_residency

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/cpu/cpu0/cpuidle': '',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/name': 'POLL',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/time': '50000000',  # 50%
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/usage': '100',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/disable': '0',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/name': 'C1',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/time': '45000000',  # 45%
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/usage': '500',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/disable': '0',
                '/sys/devices/system/cpu/cpu0/cpuidle/state2/name': 'C6',
                '/sys/devices/system/cpu/cpu0/cpuidle/state2/time': '5000000',  # 5% - too low
                '/sys/devices/system/cpu/cpu0/cpuidle/state2/usage': '100',
                '/sys/devices/system/cpu/cpu0/cpuidle/state2/disable': '0',
                '/sys/devices/system/cpu/cpuidle/current_driver': 'intel_idle',
                '/sys/devices/system/cpu/cpuidle/current_governor': 'menu',
                '/sys/devices/system/cpu/cpu0': '',
            }
        )
        output = Output()

        exit_code = cstate_residency.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data['issues']) > 0
        assert any('low_deep_residency' in i['type'] for i in output.data['issues'])

    def test_disabled_state_warning(self, mock_context):
        """Returns 1 when C-states are disabled."""
        from scripts.baremetal import cstate_residency

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/cpu/cpu0/cpuidle': '',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/name': 'POLL',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/time': '10000000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/usage': '100',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/disable': '0',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/name': 'C6',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/time': '90000000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/usage': '1000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/disable': '1',  # Disabled
                '/sys/devices/system/cpu/cpuidle/current_driver': 'intel_idle',
                '/sys/devices/system/cpu/cpuidle/current_governor': 'menu',
                '/sys/devices/system/cpu/cpu0': '',
            }
        )
        output = Output()

        exit_code = cstate_residency.run([], output, ctx)

        assert exit_code == 1
        assert any('disabled_states' in i['type'] for i in output.data['issues'])

    def test_verbose_includes_cpu_details(self, mock_context):
        """--verbose includes per-CPU details."""
        from scripts.baremetal import cstate_residency

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/cpu/cpu0/cpuidle': '',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/name': 'C1',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/time': '10000000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/usage': '100',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/disable': '0',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/name': 'C6',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/time': '90000000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/usage': '1000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/disable': '0',
                '/sys/devices/system/cpu/cpuidle/current_driver': 'intel_idle',
                '/sys/devices/system/cpu/cpuidle/current_governor': 'menu',
                '/sys/devices/system/cpu/cpu0': '',
            }
        )
        output = Output()

        exit_code = cstate_residency.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert 'cpus' in output.data
        assert len(output.data['cpus']) == 1
        assert output.data['cpus'][0]['cpu'] == 0

    def test_custom_min_deep_residency(self, mock_context):
        """--min-deep-residency changes the threshold."""
        from scripts.baremetal import cstate_residency

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/cpu/cpu0/cpuidle': '',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/name': 'C1',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/time': '90000000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/usage': '100',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/disable': '0',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/name': 'C6',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/time': '8000000',  # 8%
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/usage': '100',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/disable': '0',
                '/sys/devices/system/cpu/cpuidle/current_driver': 'intel_idle',
                '/sys/devices/system/cpu/cpuidle/current_governor': 'menu',
                '/sys/devices/system/cpu/cpu0': '',
            }
        )
        output = Output()

        # With default 10% threshold, should warn (8% < 10%)
        exit_code = cstate_residency.run([], output, ctx)
        assert exit_code == 1

        # With 5% threshold, should pass (8% > 5%)
        output = Output()
        exit_code = cstate_residency.run(['--min-deep-residency', '5'], output, ctx)
        assert exit_code == 0

    def test_average_residency_calculated(self, mock_context):
        """Average residency is calculated across all CPUs."""
        from scripts.baremetal import cstate_residency

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/cpu/cpu0/cpuidle': '',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/name': 'C1',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/time': '50000000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/disable': '0',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/name': 'C6',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/time': '50000000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state1/disable': '0',
                '/sys/devices/system/cpu/cpuidle/current_driver': 'intel_idle',
                '/sys/devices/system/cpu/cpuidle/current_governor': 'menu',
                '/sys/devices/system/cpu/cpu0': '',
            }
        )
        output = Output()

        exit_code = cstate_residency.run([], output, ctx)

        assert 'average_residency' in output.data
        assert 'C1' in output.data['average_residency']
        assert 'C6' in output.data['average_residency']
        # Each should be ~50%
        assert 45 <= output.data['average_residency']['C1'] <= 55
        assert 45 <= output.data['average_residency']['C6'] <= 55

    def test_multiple_cpus(self, mock_context):
        """Handles multiple CPUs correctly."""
        from scripts.baremetal import cstate_residency

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/cpu/cpu0/cpuidle': '',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/name': 'C6',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/time': '100000000',
                '/sys/devices/system/cpu/cpu0/cpuidle/state0/disable': '0',
                '/sys/devices/system/cpu/cpu1/cpuidle': '',
                '/sys/devices/system/cpu/cpu1/cpuidle/state0/name': 'C6',
                '/sys/devices/system/cpu/cpu1/cpuidle/state0/time': '100000000',
                '/sys/devices/system/cpu/cpu1/cpuidle/state0/disable': '0',
                '/sys/devices/system/cpu/cpuidle/current_driver': 'intel_idle',
                '/sys/devices/system/cpu/cpuidle/current_governor': 'menu',
                '/sys/devices/system/cpu/cpu0': '',
                '/sys/devices/system/cpu/cpu1': '',
            }
        )
        output = Output()

        exit_code = cstate_residency.run([], output, ctx)

        assert exit_code == 0
        assert output.data['cpu_count'] == 2
