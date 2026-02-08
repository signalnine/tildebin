"""Tests for shared_library_audit script."""

import pytest

from boxctl.core.output import Output


class TestSharedLibraryAudit:
    """Tests for shared_library_audit script."""

    def test_no_ldconfig(self, mock_context):
        """Returns 2 when /etc/ld.so.conf not found."""
        from scripts.baremetal.shared_library_audit import run

        ctx = mock_context(file_contents={})
        output = Output()

        assert run([], output, ctx) == 2

    def test_clean_config(self, mock_context):
        """Returns 0 when config is clean with standard paths."""
        from scripts.baremetal.shared_library_audit import run

        ctx = mock_context(file_contents={
            '/etc/ld.so.conf': 'include /etc/ld.so.conf.d/*.conf\n',
            '/etc/ld.so.conf.d/libc.conf': '/usr/local/lib\n',
        })
        output = Output()

        assert run([], output, ctx) == 0
        assert len(output.data['preload_entries']) == 0

    def test_preload_exists(self, mock_context):
        """Returns 1 when ld.so.preload has entries."""
        from scripts.baremetal.shared_library_audit import run

        ctx = mock_context(file_contents={
            '/etc/ld.so.conf': 'include /etc/ld.so.conf.d/*.conf\n',
            '/etc/ld.so.preload': '/usr/lib/libevil.so\n',
        })
        output = Output()

        assert run([], output, ctx) == 1
        assert any(i['severity'] == 'WARNING' for i in output.data['issues'])
        assert '/usr/lib/libevil.so' in output.data['preload_entries']

    def test_preload_empty_comments(self, mock_context):
        """Returns 0 when preload file has only comments."""
        from scripts.baremetal.shared_library_audit import run

        ctx = mock_context(file_contents={
            '/etc/ld.so.conf': '/usr/lib\n',
            '/etc/ld.so.preload': '# This is a comment\n\n',
        })
        output = Output()

        assert run([], output, ctx) == 0

    def test_non_standard_paths(self, mock_context):
        """Reports INFO for non-standard library paths."""
        from scripts.baremetal.shared_library_audit import run

        ctx = mock_context(file_contents={
            '/etc/ld.so.conf': '/opt/custom/lib\n/usr/lib\n',
        })
        output = Output()

        assert run([], output, ctx) == 0
        info_issues = [i for i in output.data['issues'] if i['severity'] == 'INFO']
        assert any('/opt/custom/lib' in i['path'] for i in info_issues)

    def test_json_output(self, mock_context):
        """Verify JSON data structure."""
        from scripts.baremetal.shared_library_audit import run

        ctx = mock_context(file_contents={
            '/etc/ld.so.conf': '/usr/lib\n',
        })
        output = Output()

        run(["--format", "json"], output, ctx)

        assert 'preload_entries' in output.data
        assert 'library_paths' in output.data
        assert 'config_files' in output.data
