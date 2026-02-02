"""Tests for process_tree script."""

import pytest

from boxctl.core.output import Output


class TestProcessTree:
    """Tests for process_tree script."""

    def test_no_processes_returns_error(self, mock_context, monkeypatch):
        """Returns exit code 2 when no processes can be read."""
        from scripts.baremetal import process_tree

        # Mock get_all_processes to return empty dict
        monkeypatch.setattr(process_tree, "get_all_processes", lambda: {})

        ctx = mock_context()
        output = Output()

        exit_code = process_tree.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_invalid_max_depth(self, mock_context, monkeypatch):
        """Returns exit code 2 for invalid --max-depth."""
        from scripts.baremetal import process_tree

        ctx = mock_context()
        output = Output()

        exit_code = process_tree.run(["--max-depth", "0"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_invalid_max_children(self, mock_context, monkeypatch):
        """Returns exit code 2 for invalid --max-children."""
        from scripts.baremetal import process_tree

        ctx = mock_context()
        output = Output()

        exit_code = process_tree.run(["--max-children", "0"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_invalid_orphan_age(self, mock_context, monkeypatch):
        """Returns exit code 2 for invalid --orphan-age."""
        from scripts.baremetal import process_tree

        ctx = mock_context()
        output = Output()

        exit_code = process_tree.run(["--orphan-age", "-1"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_healthy_process_tree(self, mock_context, monkeypatch):
        """Returns 0 when process tree is healthy."""
        from scripts.baremetal import process_tree

        # Mock a simple healthy process tree
        mock_processes = {
            1: {'pid': 1, 'ppid': 0, 'comm': 'systemd', 'cmdline': '/sbin/init',
                'state': 'S', 'start_time': 0, 'uid': 0},
            100: {'pid': 100, 'ppid': 1, 'comm': 'sshd', 'cmdline': '/usr/sbin/sshd',
                  'state': 'S', 'start_time': 100, 'uid': 0},
        }

        monkeypatch.setattr(process_tree, "get_all_processes", lambda: mock_processes)
        monkeypatch.setattr(process_tree, "get_boot_time", lambda: 1000000)

        ctx = mock_context()
        output = Output()

        exit_code = process_tree.run([], output, ctx)

        assert exit_code == 0
        assert output.data["total_processes"] == 2
        assert output.data["orphan_count"] == 0
        assert len(output.data["issues"]) == 0

    def test_build_process_tree(self, mock_context):
        """Test building parent-child relationships."""
        from scripts.baremetal.process_tree import build_process_tree

        processes = {
            1: {'pid': 1, 'ppid': 0},
            10: {'pid': 10, 'ppid': 1},
            11: {'pid': 11, 'ppid': 1},
            100: {'pid': 100, 'ppid': 10},
        }

        children = build_process_tree(processes)

        assert 10 in children[1]
        assert 11 in children[1]
        assert 100 in children[10]
        assert children[11] == []  # leaf node (defaultdict returns [] for missing keys)

    def test_calculate_tree_depth(self, mock_context):
        """Test tree depth calculation."""
        from scripts.baremetal.process_tree import calculate_tree_depth

        # Simple tree: 1 -> 10 -> 100 -> 1000
        children = {
            1: [10],
            10: [100],
            100: [1000],
            1000: [],
        }

        assert calculate_tree_depth(1000, children) == 0  # leaf
        assert calculate_tree_depth(100, children) == 1   # parent of leaf
        assert calculate_tree_depth(10, children) == 2
        assert calculate_tree_depth(1, children) == 3

    def test_verbose_includes_depth_distribution(self, mock_context, monkeypatch):
        """Verbose mode includes depth distribution."""
        from scripts.baremetal import process_tree

        mock_processes = {
            1: {'pid': 1, 'ppid': 0, 'comm': 'systemd', 'cmdline': '/sbin/init',
                'state': 'S', 'start_time': 0, 'uid': 0},
        }

        monkeypatch.setattr(process_tree, "get_all_processes", lambda: mock_processes)
        monkeypatch.setattr(process_tree, "get_boot_time", lambda: 1000000)

        ctx = mock_context()
        output = Output()

        exit_code = process_tree.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "depth_distribution" in output.data

    def test_known_init_children_not_flagged(self, mock_context):
        """Known system processes are not flagged as orphans."""
        from scripts.baremetal.process_tree import KNOWN_INIT_CHILDREN

        # Verify expected system processes are in the list
        assert 'systemd' in KNOWN_INIT_CHILDREN
        assert 'sshd' in KNOWN_INIT_CHILDREN
        assert 'cron' in KNOWN_INIT_CHILDREN
        assert 'dockerd' in KNOWN_INIT_CHILDREN
