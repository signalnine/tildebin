"""Tests for smt_status script."""

import pytest

from boxctl.core.output import Output


class TestSmtStatus:
    """Tests for smt_status script."""

    def test_sysfs_not_available_returns_error(self, mock_context, monkeypatch):
        """Returns exit code 2 when sysfs not available."""
        from scripts.baremetal import smt_status

        monkeypatch.setattr("os.path.exists", lambda p: False)

        ctx = mock_context()
        output = Output()

        exit_code = smt_status.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_smt_not_supported(self, mock_context, monkeypatch):
        """Returns 0 when SMT is not supported."""
        from scripts.baremetal import smt_status

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr("os.path.isdir", lambda p: True)
        monkeypatch.setattr(smt_status, "get_smt_control", lambda: "notsupported")
        monkeypatch.setattr(smt_status, "get_smt_active", lambda: None)
        monkeypatch.setattr(smt_status, "get_cpu_topology", lambda: {
            'num_packages': 1,
            'num_physical_cores': 4,
            'num_logical_cpus': 4,
            'threads_per_core': 1,
            'core_mapping': {},
        })
        monkeypatch.setattr(smt_status, "get_cpu_vulnerabilities", lambda: {})

        ctx = mock_context()
        output = Output()

        exit_code = smt_status.run([], output, ctx)

        assert exit_code == 0
        assert output.data["smt"]["control"] == "notsupported"

    def test_smt_disabled(self, mock_context, monkeypatch):
        """Returns 0 when SMT is disabled."""
        from scripts.baremetal import smt_status

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr("os.path.isdir", lambda p: True)
        monkeypatch.setattr(smt_status, "get_smt_control", lambda: "off")
        monkeypatch.setattr(smt_status, "get_smt_active", lambda: False)
        monkeypatch.setattr(smt_status, "get_cpu_topology", lambda: {
            'num_packages': 1,
            'num_physical_cores': 4,
            'num_logical_cpus': 4,
            'threads_per_core': 1,
            'core_mapping': {},
        })
        monkeypatch.setattr(smt_status, "get_cpu_vulnerabilities", lambda: {})

        ctx = mock_context()
        output = Output()

        exit_code = smt_status.run([], output, ctx)

        assert exit_code == 0
        assert output.data["smt"]["active"] is False

    def test_smt_enabled(self, mock_context, monkeypatch):
        """Returns 0 when SMT is enabled (no warnings by default)."""
        from scripts.baremetal import smt_status

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr("os.path.isdir", lambda p: True)
        monkeypatch.setattr(smt_status, "get_smt_control", lambda: "on")
        monkeypatch.setattr(smt_status, "get_smt_active", lambda: True)
        monkeypatch.setattr(smt_status, "get_cpu_topology", lambda: {
            'num_packages': 1,
            'num_physical_cores': 4,
            'num_logical_cpus': 8,
            'threads_per_core': 2,
            'core_mapping': {},
        })
        monkeypatch.setattr(smt_status, "get_cpu_vulnerabilities", lambda: {})

        ctx = mock_context()
        output = Output()

        exit_code = smt_status.run([], output, ctx)

        assert exit_code == 0
        assert output.data["smt"]["active"] is True
        assert output.data["topology"]["threads_per_core"] == 2

    def test_require_disabled_with_smt_enabled(self, mock_context, monkeypatch):
        """Returns 1 when --require-disabled but SMT is enabled."""
        from scripts.baremetal import smt_status

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr("os.path.isdir", lambda p: True)
        monkeypatch.setattr(smt_status, "get_smt_control", lambda: "on")
        monkeypatch.setattr(smt_status, "get_smt_active", lambda: True)
        monkeypatch.setattr(smt_status, "get_cpu_topology", lambda: {
            'num_packages': 1,
            'num_physical_cores': 4,
            'num_logical_cpus': 8,
            'threads_per_core': 2,
            'core_mapping': {},
        })
        monkeypatch.setattr(smt_status, "get_cpu_vulnerabilities", lambda: {})

        ctx = mock_context()
        output = Output()

        exit_code = smt_status.run(["--require-disabled"], output, ctx)

        assert exit_code == 1
        assert any(i["type"] == "smt_enabled" for i in output.data["issues"])

    def test_vulnerability_detection(self, mock_context, monkeypatch):
        """Detects SMT-related vulnerabilities."""
        from scripts.baremetal import smt_status

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr("os.path.isdir", lambda p: True)
        monkeypatch.setattr(smt_status, "get_smt_control", lambda: "on")
        monkeypatch.setattr(smt_status, "get_smt_active", lambda: True)
        monkeypatch.setattr(smt_status, "get_cpu_topology", lambda: {
            'num_packages': 1,
            'num_physical_cores': 4,
            'num_logical_cpus': 8,
            'threads_per_core': 2,
            'core_mapping': {},
        })
        monkeypatch.setattr(smt_status, "get_cpu_vulnerabilities", lambda: {
            'mds': 'Vulnerable; SMT vulnerable',
            'l1tf': 'Mitigation: PTE Inversion; VMX: SMT vulnerable',
        })

        ctx = mock_context()
        output = Output()

        exit_code = smt_status.run([], output, ctx)

        assert exit_code == 1
        assert any(i["type"] == "vulnerability" for i in output.data["issues"])

    def test_verbose_includes_details(self, mock_context, monkeypatch):
        """Verbose mode includes vulnerability and mapping details."""
        from scripts.baremetal import smt_status

        mock_vulns = {'spectre_v1': 'Mitigation: usercopy/swapgs barriers'}
        mock_mapping = {'0:0': [0, 4], '0:1': [1, 5]}

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr("os.path.isdir", lambda p: True)
        monkeypatch.setattr(smt_status, "get_smt_control", lambda: "on")
        monkeypatch.setattr(smt_status, "get_smt_active", lambda: True)
        monkeypatch.setattr(smt_status, "get_cpu_topology", lambda: {
            'num_packages': 1,
            'num_physical_cores': 2,
            'num_logical_cpus': 4,
            'threads_per_core': 2,
            'core_mapping': mock_mapping,
        })
        monkeypatch.setattr(smt_status, "get_cpu_vulnerabilities", lambda: mock_vulns)

        ctx = mock_context()
        output = Output()

        exit_code = smt_status.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "vulnerabilities" in output.data
        assert "core_mapping" in output.data
        assert output.data["core_mapping"] == mock_mapping

    def test_topology_output(self, mock_context, monkeypatch):
        """Output includes correct topology information."""
        from scripts.baremetal import smt_status

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr("os.path.isdir", lambda p: True)
        monkeypatch.setattr(smt_status, "get_smt_control", lambda: "on")
        monkeypatch.setattr(smt_status, "get_smt_active", lambda: True)
        monkeypatch.setattr(smt_status, "get_cpu_topology", lambda: {
            'num_packages': 2,
            'num_physical_cores': 8,
            'num_logical_cpus': 16,
            'threads_per_core': 2,
            'core_mapping': {},
        })
        monkeypatch.setattr(smt_status, "get_cpu_vulnerabilities", lambda: {})

        ctx = mock_context()
        output = Output()

        exit_code = smt_status.run([], output, ctx)

        assert exit_code == 0
        assert output.data["topology"]["num_packages"] == 2
        assert output.data["topology"]["num_physical_cores"] == 8
        assert output.data["topology"]["num_logical_cpus"] == 16
        assert output.data["topology"]["threads_per_core"] == 2
