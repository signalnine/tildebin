"""Tests for systemd_security script."""

import pytest

from boxctl.core.output import Output


SECURITY_OVERVIEW_HEALTHY = """UNIT                      EXPOSURE PREDICATE HAPPY
sshd.service              2.0      OK        :)
systemd-journald.service  1.5      OK        :)
nginx.service             3.5      MEDIUM    :|
"""

SECURITY_OVERVIEW_ISSUES = """UNIT                      EXPOSURE PREDICATE HAPPY
sshd.service              2.0      OK        :)
docker.service            7.5      UNSAFE    :(
app.service               8.5      UNSAFE    :(
nginx.service             5.5      EXPOSED   :|
"""

SECURITY_OVERVIEW_ALL_OK = """UNIT                      EXPOSURE PREDICATE HAPPY
sshd.service              1.5      OK        :)
systemd-journald.service  1.2      OK        :)
nginx.service             2.0      OK        :)
"""

SECURITY_OVERVIEW_EMPTY = """UNIT                      EXPOSURE PREDICATE HAPPY
"""

SECURITY_SERVICE_DETAIL = """\u2713 PrivateTmp=                           Service has access to other software's temporary files
\u2717 ProtectSystem=                        Service has full access to the OS file hierarchy
\u2717 ProtectHome=                          Service has full access to home directories
\u25cb User=/DynamicUser=                     Service runs as root user
\u2192 Overall exposure level for test.service: 7.5 UNSAFE
"""


class TestSystemdSecurity:
    """Tests for systemd_security script."""

    def test_missing_systemd_analyze_returns_error(self, mock_context):
        """Returns exit code 2 when systemd-analyze not available."""
        from scripts.baremetal import systemd_security

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = systemd_security.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("systemd-analyze" in e.lower() for e in output.errors)

    def test_security_subcommand_not_available(self, mock_context):
        """Returns exit code 2 when security subcommand not available."""
        from scripts.baremetal import systemd_security
        import subprocess

        # Return a CompletedProcess with non-zero returncode to simulate
        # the security subcommand not being available
        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze", "security", "--help"): subprocess.CompletedProcess(
                    ["systemd-analyze", "security", "--help"],
                    returncode=1,
                    stdout="",
                    stderr="Unknown command 'security'",
                ),
            }
        )
        output = Output()

        exit_code = systemd_security.run([], output, ctx)

        assert exit_code == 2

    def test_all_services_healthy(self, mock_context):
        """Returns 0 when all services are below threshold."""
        from scripts.baremetal import systemd_security

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze", "security", "--help"): "Usage: systemd-analyze security",
                ("systemd-analyze", "security", "--no-pager"): SECURITY_OVERVIEW_ALL_OK,
            }
        )
        output = Output()

        exit_code = systemd_security.run([], output, ctx)

        assert exit_code == 0
        assert output.data['services_above_threshold'] == 0

    def test_services_above_threshold(self, mock_context):
        """Returns 1 when services exceed threshold."""
        from scripts.baremetal import systemd_security

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze", "security", "--help"): "Usage: systemd-analyze security",
                ("systemd-analyze", "security", "--no-pager"): SECURITY_OVERVIEW_ISSUES,
            }
        )
        output = Output()

        exit_code = systemd_security.run([], output, ctx)

        assert exit_code == 1
        assert output.data['services_above_threshold'] > 0
        assert output.data['by_rating']['UNSAFE'] > 0

    def test_custom_threshold(self, mock_context):
        """Custom threshold can be specified."""
        from scripts.baremetal import systemd_security

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze", "security", "--help"): "Usage: systemd-analyze security",
                ("systemd-analyze", "security", "--no-pager"): SECURITY_OVERVIEW_HEALTHY,
            }
        )
        output = Output()

        # With threshold of 3.0, nginx (3.5) should be flagged
        exit_code = systemd_security.run(["--threshold", "3.0"], output, ctx)

        assert exit_code == 1
        assert output.data['services_above_threshold'] > 0

    def test_higher_threshold_passes(self, mock_context):
        """Higher threshold allows more services to pass."""
        from scripts.baremetal import systemd_security

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze", "security", "--help"): "Usage: systemd-analyze security",
                ("systemd-analyze", "security", "--no-pager"): SECURITY_OVERVIEW_HEALTHY,
            }
        )
        output = Output()

        # With threshold of 5.0, all services should pass
        exit_code = systemd_security.run(["--threshold", "5.0"], output, ctx)

        assert exit_code == 0
        assert output.data['services_above_threshold'] == 0

    def test_single_service_analysis(self, mock_context):
        """Single service analysis works."""
        from scripts.baremetal import systemd_security

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze", "security", "--help"): "Usage: systemd-analyze security",
                ("systemd-analyze", "security", "--no-pager", "test.service"): SECURITY_SERVICE_DETAIL,
            }
        )
        output = Output()

        exit_code = systemd_security.run(["--service", "test.service"], output, ctx)

        assert exit_code == 1  # 7.5 > default threshold 6.5
        assert output.data['service'] == 'test.service'
        assert output.data['exposure'] == 7.5
        assert output.data['rating'] == 'UNSAFE'

    def test_single_service_verbose(self, mock_context):
        """--verbose shows findings for single service."""
        from scripts.baremetal import systemd_security

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze", "security", "--help"): "Usage: systemd-analyze security",
                ("systemd-analyze", "security", "--no-pager", "test.service"): SECURITY_SERVICE_DETAIL,
            }
        )
        output = Output()

        exit_code = systemd_security.run(["--service", "test.service", "--verbose"], output, ctx)

        assert 'findings' in output.data
        assert len(output.data['findings']) > 0

    def test_rating_counts(self, mock_context):
        """Rating counts are calculated correctly."""
        from scripts.baremetal import systemd_security

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze", "security", "--help"): "Usage: systemd-analyze security",
                ("systemd-analyze", "security", "--no-pager"): SECURITY_OVERVIEW_ISSUES,
            }
        )
        output = Output()

        exit_code = systemd_security.run([], output, ctx)

        assert 'by_rating' in output.data
        assert output.data['by_rating']['UNSAFE'] == 2
        assert output.data['by_rating']['EXPOSED'] == 1
        assert output.data['by_rating']['OK'] == 1

    def test_services_sorted_by_exposure(self, mock_context):
        """Services are sorted by exposure score (highest first)."""
        from scripts.baremetal import systemd_security

        ctx = mock_context(
            tools_available=["systemd-analyze"],
            command_outputs={
                ("systemd-analyze", "security", "--help"): "Usage: systemd-analyze security",
                ("systemd-analyze", "security", "--no-pager"): SECURITY_OVERVIEW_ISSUES,
            }
        )
        output = Output()

        exit_code = systemd_security.run([], output, ctx)

        services = output.data['services']
        exposures = [s['exposure'] for s in services]
        assert exposures == sorted(exposures, reverse=True)
