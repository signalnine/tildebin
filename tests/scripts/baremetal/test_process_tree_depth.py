"""Tests for process_tree_depth script."""

import pytest

from boxctl.core.output import Output


class TestProcessTreeDepth:
    """Tests for process_tree_depth script."""

    def test_no_processes_returns_error(self, mock_context, monkeypatch):
        """Returns exit code 2 when no processes can be read."""
        from scripts.baremetal import process_tree_depth

        monkeypatch.setattr(process_tree_depth, "get_all_processes", lambda: ({}, {}))

        ctx = mock_context()
        output = Output()

        exit_code = process_tree_depth.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_invalid_depth_thresholds(self, mock_context):
        """Returns exit code 2 when depth-warning >= depth-critical."""
        from scripts.baremetal import process_tree_depth

        ctx = mock_context()
        output = Output()

        exit_code = process_tree_depth.run(
            ["--depth-warning", "30", "--depth-critical", "30"],
            output,
            ctx
        )

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_invalid_child_thresholds(self, mock_context):
        """Returns exit code 2 when child-warning >= child-critical."""
        from scripts.baremetal import process_tree_depth

        ctx = mock_context()
        output = Output()

        exit_code = process_tree_depth.run(
            ["--child-warning", "200", "--child-critical", "100"],
            output,
            ctx
        )

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_negative_thresholds(self, mock_context):
        """Returns exit code 2 for negative thresholds."""
        from scripts.baremetal import process_tree_depth

        ctx = mock_context()
        output = Output()

        exit_code = process_tree_depth.run(["--depth-warning", "0"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_healthy_tree(self, mock_context, monkeypatch):
        """Returns 0 for a healthy process tree."""
        from scripts.baremetal import process_tree_depth

        mock_processes = {
            1: {'pid': 1, 'ppid': 0, 'comm': 'init', 'state': 'S'},
            10: {'pid': 10, 'ppid': 1, 'comm': 'sshd', 'state': 'S'},
        }
        mock_children = {0: [1], 1: [10], 10: []}

        monkeypatch.setattr(
            process_tree_depth,
            "get_all_processes",
            lambda: (mock_processes, mock_children)
        )

        ctx = mock_context()
        output = Output()

        exit_code = process_tree_depth.run([], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "healthy"
        assert output.data["max_depth"] <= 15  # below warning threshold

    def test_deep_tree_warning(self, mock_context, monkeypatch):
        """Returns 0 with warning for moderately deep tree."""
        from scripts.baremetal import process_tree_depth

        # Create a tree with depth 16 (above default warning of 15)
        mock_processes = {}
        mock_children = {}
        for i in range(17):
            mock_processes[i] = {'pid': i, 'ppid': max(0, i-1), 'comm': f'proc{i}', 'state': 'S'}
            if i > 0:
                mock_children[i-1] = [i]
            mock_children[i] = []

        monkeypatch.setattr(
            process_tree_depth,
            "get_all_processes",
            lambda: (mock_processes, mock_children)
        )

        ctx = mock_context()
        output = Output()

        exit_code = process_tree_depth.run([], output, ctx)

        # Should be 0 because it's just a warning, not critical
        assert exit_code == 0
        assert output.data["status"] == "warning"
        assert len(output.data["warnings"]) > 0

    def test_calculate_tree_depth(self, mock_context):
        """Test tree depth calculation function."""
        from scripts.baremetal.process_tree_depth import calculate_tree_depth

        processes = {1: {}, 10: {}, 100: {}, 1000: {}}
        children = {1: [10], 10: [100], 100: [1000], 1000: []}

        assert calculate_tree_depth(1000, processes, children) == 0
        assert calculate_tree_depth(100, processes, children) == 1
        assert calculate_tree_depth(10, processes, children) == 2
        assert calculate_tree_depth(1, processes, children) == 3

    def test_get_ancestry_chain(self, mock_context):
        """Test ancestry chain extraction."""
        from scripts.baremetal.process_tree_depth import get_ancestry_chain

        processes = {
            1: {'pid': 1, 'ppid': 0, 'comm': 'init', 'state': 'S'},
            10: {'pid': 10, 'ppid': 1, 'comm': 'bash', 'state': 'S'},
            100: {'pid': 100, 'ppid': 10, 'comm': 'python', 'state': 'S'},
        }

        chain = get_ancestry_chain(100, processes)

        assert len(chain) == 3
        assert chain[0]['comm'] == 'init'
        assert chain[1]['comm'] == 'bash'
        assert chain[2]['comm'] == 'python'

    def test_verbose_includes_chains(self, mock_context, monkeypatch):
        """Verbose mode includes deepest chains."""
        from scripts.baremetal import process_tree_depth

        mock_processes = {
            1: {'pid': 1, 'ppid': 0, 'comm': 'init', 'state': 'S'},
        }
        mock_children = {0: [1], 1: []}

        monkeypatch.setattr(
            process_tree_depth,
            "get_all_processes",
            lambda: (mock_processes, mock_children)
        )

        ctx = mock_context()
        output = Output()

        exit_code = process_tree_depth.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "deepest_chains" in output.data
