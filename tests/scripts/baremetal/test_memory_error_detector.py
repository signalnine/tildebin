"""Tests for memory_error_detector script."""

import pytest

from boxctl.core.output import Output


class TestMemoryErrorDetector:
    """Tests for memory_error_detector script."""

    def test_no_edac_returns_healthy(self, mock_context):
        """Returns 0 when EDAC is not available (no ECC support)."""
        from scripts.baremetal import memory_error_detector

        ctx = mock_context(
            tools_available=[],
            file_contents={}
        )
        output = Output()

        exit_code = memory_error_detector.run([], output, ctx)

        assert exit_code == 0
        assert output.data['edac_available'] is False

    def test_edac_no_errors(self, mock_context):
        """Returns 0 when EDAC available but no errors."""
        from scripts.baremetal import memory_error_detector

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/sys/devices/system/edac/mc': '',
                '/sys/devices/system/edac/mc/mc0': '',
                '/sys/devices/system/edac/mc/mc0/mc_name': 'Intel EDAC\n',
                '/sys/devices/system/edac/mc/mc0/size_mb': '16384\n',
                '/sys/devices/system/edac/mc/mc0/seconds_since_reset': '86400\n',
                '/sys/devices/system/edac/mc/mc0/ue_count': '0\n',
                '/sys/devices/system/edac/mc/mc0/ce_count': '0\n',
            }
        )
        output = Output()

        exit_code = memory_error_detector.run([], output, ctx)

        assert exit_code == 0
        assert output.data['edac_available'] is True
        assert output.data['summary']['total_ce'] == 0
        assert output.data['summary']['total_ue'] == 0

    def test_correctable_errors_returns_warning(self, mock_context):
        """Returns 1 when correctable errors detected."""
        from scripts.baremetal import memory_error_detector

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/sys/devices/system/edac/mc': '',
                '/sys/devices/system/edac/mc/mc0': '',
                '/sys/devices/system/edac/mc/mc0/mc_name': 'Intel EDAC\n',
                '/sys/devices/system/edac/mc/mc0/size_mb': '16384\n',
                '/sys/devices/system/edac/mc/mc0/seconds_since_reset': '86400\n',
                '/sys/devices/system/edac/mc/mc0/ue_count': '0\n',
                '/sys/devices/system/edac/mc/mc0/ce_count': '50\n',
            }
        )
        output = Output()

        exit_code = memory_error_detector.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['total_ce'] == 50
        assert output.data['summary']['severity'] == 'info'

    def test_high_correctable_errors_returns_warning(self, mock_context):
        """Returns 1 with warning severity for high CE count."""
        from scripts.baremetal import memory_error_detector

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/sys/devices/system/edac/mc': '',
                '/sys/devices/system/edac/mc/mc0': '',
                '/sys/devices/system/edac/mc/mc0/mc_name': 'Intel EDAC\n',
                '/sys/devices/system/edac/mc/mc0/size_mb': '16384\n',
                '/sys/devices/system/edac/mc/mc0/seconds_since_reset': '86400\n',
                '/sys/devices/system/edac/mc/mc0/ue_count': '0\n',
                '/sys/devices/system/edac/mc/mc0/ce_count': '150\n',  # > 100
            }
        )
        output = Output()

        exit_code = memory_error_detector.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['severity'] == 'warning'

    def test_uncorrectable_errors_returns_critical(self, mock_context):
        """Returns 1 with critical severity for UE errors."""
        from scripts.baremetal import memory_error_detector

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/sys/devices/system/edac/mc': '',
                '/sys/devices/system/edac/mc/mc0': '',
                '/sys/devices/system/edac/mc/mc0/mc_name': 'Intel EDAC\n',
                '/sys/devices/system/edac/mc/mc0/size_mb': '16384\n',
                '/sys/devices/system/edac/mc/mc0/seconds_since_reset': '86400\n',
                '/sys/devices/system/edac/mc/mc0/ue_count': '1\n',
                '/sys/devices/system/edac/mc/mc0/ce_count': '0\n',
            }
        )
        output = Output()

        exit_code = memory_error_detector.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['severity'] == 'critical'
        assert output.data['summary']['total_ue'] == 1

    def test_dimm_level_errors(self, mock_context):
        """Tracks errors at DIMM level when available."""
        from scripts.baremetal import memory_error_detector

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/sys/devices/system/edac/mc': '',
                '/sys/devices/system/edac/mc/mc0': '',
                '/sys/devices/system/edac/mc/mc0/mc_name': 'Intel EDAC\n',
                '/sys/devices/system/edac/mc/mc0/size_mb': '16384\n',
                '/sys/devices/system/edac/mc/mc0/seconds_since_reset': '86400\n',
                '/sys/devices/system/edac/mc/mc0/ue_count': '0\n',
                '/sys/devices/system/edac/mc/mc0/ce_count': '10\n',
                '/sys/devices/system/edac/mc/mc0/dimm0': '',
                '/sys/devices/system/edac/mc/mc0/dimm0/size': '8192 MB\n',
                '/sys/devices/system/edac/mc/mc0/dimm0/dimm_label': 'DIMM_A1\n',
                '/sys/devices/system/edac/mc/mc0/dimm0/dimm_ce_count': '10\n',
                '/sys/devices/system/edac/mc/mc0/dimm0/dimm_ue_count': '0\n',
            }
        )
        output = Output()

        exit_code = memory_error_detector.run(['--verbose'], output, ctx)

        assert exit_code == 1
        assert len(output.data['dimms_with_errors']) == 1
        assert output.data['dimms_with_errors'][0]['label'] == 'DIMM_A1'

    def test_multiple_controllers(self, mock_context):
        """Handles multiple memory controllers."""
        from scripts.baremetal import memory_error_detector

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/sys/devices/system/edac/mc': '',
                '/sys/devices/system/edac/mc/mc0': '',
                '/sys/devices/system/edac/mc/mc0/mc_name': 'Intel EDAC\n',
                '/sys/devices/system/edac/mc/mc0/size_mb': '8192\n',
                '/sys/devices/system/edac/mc/mc0/seconds_since_reset': '86400\n',
                '/sys/devices/system/edac/mc/mc0/ue_count': '0\n',
                '/sys/devices/system/edac/mc/mc0/ce_count': '5\n',
                '/sys/devices/system/edac/mc/mc1': '',
                '/sys/devices/system/edac/mc/mc1/mc_name': 'Intel EDAC\n',
                '/sys/devices/system/edac/mc/mc1/size_mb': '8192\n',
                '/sys/devices/system/edac/mc/mc1/seconds_since_reset': '86400\n',
                '/sys/devices/system/edac/mc/mc1/ue_count': '0\n',
                '/sys/devices/system/edac/mc/mc1/ce_count': '3\n',
            }
        )
        output = Output()

        exit_code = memory_error_detector.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['total_ce'] == 8
        assert output.data['summary']['controller_count'] == 2
