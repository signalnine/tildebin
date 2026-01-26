#!/usr/bin/env python3
"""
Tests for k8s_volume_snapshot_monitor.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and core functions.
"""

import subprocess
import sys
import unittest
from unittest.mock import patch
import json
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_volume_snapshot_monitor as snapshot_monitor


def run_command(cmd_args, input_data=None):
    """Run the k8s_volume_snapshot_monitor.py script with given arguments."""
    cmd = [sys.executable, 'k8s_volume_snapshot_monitor.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sVolumeSnapshotMonitor(unittest.TestCase):
    """Test cases for k8s_volume_snapshot_monitor.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('VolumeSnapshot', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('--retention-days', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('VolumeSnapshot', stdout)

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Either exits 2 (no kubectl/CRDs) or 1 (kubectl error)
        self.assertIn(returncode, [1, 2])

    def test_format_option_json(self):
        """Test --format json option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [1, 2])

    def test_format_option_short(self):
        """Test -f short option works."""
        returncode, stdout, stderr = run_command(['-f', 'json'])
        self.assertIn(returncode, [1, 2])

    def test_invalid_format(self):
        """Test that invalid format values are rejected."""
        returncode, stdout, stderr = run_command(['--format', 'invalid'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid choice', stderr)

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'default'])
        self.assertIn(returncode, [1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'kube-system'])
        self.assertIn(returncode, [1, 2])

    def test_warn_only_option(self):
        """Test --warn-only option is accepted."""
        returncode, stdout, stderr = run_command(['--warn-only'])
        self.assertIn(returncode, [1, 2])

    def test_warn_only_short(self):
        """Test -w short option works."""
        returncode, stdout, stderr = run_command(['-w'])
        self.assertIn(returncode, [1, 2])

    def test_retention_days_option(self):
        """Test --retention-days option is accepted."""
        returncode, stdout, stderr = run_command(['--retention-days', '30'])
        self.assertIn(returncode, [1, 2])

    def test_retention_days_short(self):
        """Test -r short option works."""
        returncode, stdout, stderr = run_command(['-r', '7'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-n', 'default', '-r', '30'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command([
            '--format', 'plain',
            '--warn-only',
            '--namespace', 'kube-system',
            '--retention-days', '14'
        ])
        self.assertIn(returncode, [1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        returncode, stdout, stderr = run_command([])
        # Should exit with error code 1 or 2
        self.assertNotEqual(returncode, 0)
        # Error message should be helpful
        if returncode == 2:
            self.assertTrue(
                'kubectl' in stderr.lower() or
                'volumesnapshot' in stderr.lower() or
                'resource type' in stderr.lower()
            )

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (will fail without kubectl/CRDs, but args are valid)
        self.assertIn(returncode, [1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_volume_snapshot_monitor.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_volume_snapshot_monitor.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('VolumeSnapshot', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_volume_snapshot_monitor.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)


class TestParseAge(unittest.TestCase):
    """Test parse_age function."""

    def test_parse_valid_timestamp(self):
        """Test parsing a valid ISO 8601 timestamp."""
        # Use a recent timestamp
        from datetime import datetime, timezone, timedelta
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        timestamp = yesterday.strftime('%Y-%m-%dT%H:%M:%SZ')

        age = snapshot_monitor.parse_age(timestamp)
        self.assertEqual(age, 1)

    def test_parse_empty_timestamp(self):
        """Test parsing empty timestamp returns 0."""
        age = snapshot_monitor.parse_age('')
        self.assertEqual(age, 0)

    def test_parse_none_timestamp(self):
        """Test parsing None timestamp returns 0."""
        age = snapshot_monitor.parse_age(None)
        self.assertEqual(age, 0)

    def test_parse_invalid_timestamp(self):
        """Test parsing invalid timestamp returns 0."""
        age = snapshot_monitor.parse_age('not-a-date')
        self.assertEqual(age, 0)


class TestFormatAge(unittest.TestCase):
    """Test format_age function."""

    def test_format_zero_days(self):
        """Test formatting 0 days."""
        result = snapshot_monitor.format_age(0)
        self.assertEqual(result, '<1d')

    def test_format_days(self):
        """Test formatting days."""
        result = snapshot_monitor.format_age(3)
        self.assertEqual(result, '3d')

    def test_format_weeks(self):
        """Test formatting weeks."""
        result = snapshot_monitor.format_age(14)
        self.assertEqual(result, '2w')

    def test_format_months(self):
        """Test formatting months."""
        result = snapshot_monitor.format_age(60)
        self.assertEqual(result, '2mo')

    def test_format_years(self):
        """Test formatting years."""
        result = snapshot_monitor.format_age(400)
        self.assertEqual(result, '1y')


class TestCheckSnapshotHealth(unittest.TestCase):
    """Test check_snapshot_health function."""

    def test_healthy_snapshot(self):
        """Test status checking for healthy snapshot."""
        snapshot = {
            'metadata': {
                'name': 'test-snapshot',
                'namespace': 'default',
                'creationTimestamp': '2024-01-01T00:00:00Z'
            },
            'spec': {
                'source': {'persistentVolumeClaimName': 'test-pvc'},
                'volumeSnapshotClassName': 'csi-hostpath-snapclass'
            },
            'status': {
                'readyToUse': True,
                'boundVolumeSnapshotContentName': 'snapcontent-123',
                'restoreSize': '10Gi'
            }
        }

        is_healthy, issues, warnings, status_info = snapshot_monitor.check_snapshot_health(snapshot, 0)

        self.assertTrue(is_healthy)
        self.assertEqual(len(issues), 0)
        self.assertTrue(status_info['readyToUse'])
        self.assertEqual(status_info['restoreSize'], '10Gi')

    def test_snapshot_not_ready(self):
        """Test snapshot that is not ready."""
        snapshot = {
            'metadata': {
                'name': 'pending-snapshot',
                'namespace': 'default',
                'creationTimestamp': '2024-01-01T00:00:00Z'
            },
            'spec': {
                'source': {'persistentVolumeClaimName': 'test-pvc'}
            },
            'status': {
                'readyToUse': False
            }
        }

        is_healthy, issues, warnings, status_info = snapshot_monitor.check_snapshot_health(snapshot, 0)

        self.assertFalse(is_healthy)
        self.assertGreater(len(issues), 0)
        self.assertTrue(any('not ready' in issue.lower() for issue in issues))

    def test_snapshot_with_error(self):
        """Test snapshot with error status."""
        snapshot = {
            'metadata': {
                'name': 'failed-snapshot',
                'namespace': 'default',
                'creationTimestamp': '2024-01-01T00:00:00Z'
            },
            'spec': {
                'source': {'persistentVolumeClaimName': 'test-pvc'}
            },
            'status': {
                'readyToUse': False,
                'error': {
                    'message': 'Failed to create snapshot: volume not found'
                }
            }
        }

        is_healthy, issues, warnings, status_info = snapshot_monitor.check_snapshot_health(snapshot, 0)

        self.assertFalse(is_healthy)
        self.assertGreater(len(issues), 0)
        self.assertTrue(any('error' in issue.lower() for issue in issues))
        self.assertTrue(any('volume not found' in issue for issue in issues))

    def test_snapshot_exceeds_retention(self):
        """Test snapshot exceeding retention threshold."""
        from datetime import datetime, timezone, timedelta
        old_date = datetime.now(timezone.utc) - timedelta(days=45)
        timestamp = old_date.strftime('%Y-%m-%dT%H:%M:%SZ')

        snapshot = {
            'metadata': {
                'name': 'old-snapshot',
                'namespace': 'default',
                'creationTimestamp': timestamp
            },
            'spec': {
                'source': {'persistentVolumeClaimName': 'test-pvc'}
            },
            'status': {
                'readyToUse': True,
                'boundVolumeSnapshotContentName': 'snapcontent-123'
            }
        }

        is_healthy, issues, warnings, status_info = snapshot_monitor.check_snapshot_health(snapshot, 30)

        self.assertTrue(is_healthy)  # Still healthy, just a warning
        self.assertGreater(len(warnings), 0)
        self.assertTrue(any('retention' in warning.lower() for warning in warnings))

    def test_snapshot_no_source(self):
        """Test snapshot with no source reference."""
        snapshot = {
            'metadata': {
                'name': 'no-source-snapshot',
                'namespace': 'default',
                'creationTimestamp': '2024-01-01T00:00:00Z'
            },
            'spec': {
                'source': {}
            },
            'status': {
                'readyToUse': True,
                'boundVolumeSnapshotContentName': 'snapcontent-123'
            }
        }

        is_healthy, issues, warnings, status_info = snapshot_monitor.check_snapshot_health(snapshot, 0)

        self.assertTrue(is_healthy)  # Still healthy, just a warning
        self.assertGreater(len(warnings), 0)
        self.assertTrue(any('source' in warning.lower() for warning in warnings))


class TestFindOrphanedContents(unittest.TestCase):
    """Test find_orphaned_contents function."""

    def test_no_orphaned_contents(self):
        """Test when there are no orphaned contents."""
        snapshots = {
            'items': [{
                'metadata': {'name': 'snap1', 'namespace': 'default'},
                'status': {'boundVolumeSnapshotContentName': 'snapcontent-1'}
            }]
        }
        contents = {
            'items': [{
                'metadata': {'name': 'snapcontent-1'},
                'spec': {
                    'volumeSnapshotRef': {'name': 'snap1', 'namespace': 'default'},
                    'deletionPolicy': 'Delete',
                    'driver': 'hostpath.csi.k8s.io'
                },
                'status': {}
            }]
        }

        orphaned = snapshot_monitor.find_orphaned_contents(snapshots, contents)

        self.assertEqual(len(orphaned), 0)

    def test_orphaned_content_found(self):
        """Test finding orphaned content."""
        snapshots = {'items': []}  # No snapshots
        contents = {
            'items': [{
                'metadata': {'name': 'orphaned-content'},
                'spec': {
                    'volumeSnapshotRef': {'name': 'deleted-snapshot', 'namespace': 'default'},
                    'deletionPolicy': 'Retain',
                    'driver': 'hostpath.csi.k8s.io'
                },
                'status': {'restoreSize': '5Gi'}
            }]
        }

        orphaned = snapshot_monitor.find_orphaned_contents(snapshots, contents)

        self.assertEqual(len(orphaned), 1)
        self.assertEqual(orphaned[0]['name'], 'orphaned-content')
        self.assertEqual(orphaned[0]['deletionPolicy'], 'Retain')
        self.assertIn('deleted-snapshot', orphaned[0]['referencedSnapshot'])

    def test_content_without_snapshot_ref(self):
        """Test content without snapshot reference is not orphaned."""
        snapshots = {'items': []}
        contents = {
            'items': [{
                'metadata': {'name': 'content-no-ref'},
                'spec': {
                    'deletionPolicy': 'Delete',
                    'driver': 'hostpath.csi.k8s.io'
                },
                'status': {}
            }]
        }

        orphaned = snapshot_monitor.find_orphaned_contents(snapshots, contents)

        # Content without volumeSnapshotRef is not considered orphaned
        self.assertEqual(len(orphaned), 0)


class TestGetVolumeSnapshots(unittest.TestCase):
    """Test get_volume_snapshots function with mocking."""

    @patch('k8s_volume_snapshot_monitor.run_kubectl')
    def test_get_snapshots_all_namespaces(self, mock_run):
        """Test getting snapshots from all namespaces."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'snap1', 'namespace': 'default'}},
                {'metadata': {'name': 'snap2', 'namespace': 'production'}}
            ]
        })

        snapshots = snapshot_monitor.get_volume_snapshots()

        self.assertEqual(len(snapshots['items']), 2)
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        self.assertIn('--all-namespaces', call_args)

    @patch('k8s_volume_snapshot_monitor.run_kubectl')
    def test_get_snapshots_specific_namespace(self, mock_run):
        """Test getting snapshots from specific namespace."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'snap1', 'namespace': 'production'}}
            ]
        })

        snapshots = snapshot_monitor.get_volume_snapshots('production')

        self.assertEqual(len(snapshots['items']), 1)
        call_args = mock_run.call_args[0][0]
        self.assertIn('-n', call_args)
        self.assertIn('production', call_args)


class TestPrintStatus(unittest.TestCase):
    """Test print_status function."""

    def test_print_status_json_format(self):
        """Test print_status with JSON format."""
        snapshots = {
            'items': [{
                'metadata': {
                    'name': 'test-snapshot',
                    'namespace': 'default',
                    'creationTimestamp': '2024-01-01T00:00:00Z'
                },
                'spec': {
                    'source': {'persistentVolumeClaimName': 'test-pvc'},
                    'volumeSnapshotClassName': 'csi-class'
                },
                'status': {
                    'readyToUse': True,
                    'boundVolumeSnapshotContentName': 'content-1',
                    'restoreSize': '10Gi'
                }
            }]
        }
        contents = {'items': []}
        classes = {'items': [{'metadata': {'name': 'csi-class'}, 'driver': 'csi.example.com', 'deletionPolicy': 'Delete'}]}

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = snapshot_monitor.print_status(
                snapshots, contents, classes, 'json', False, 0
            )

        output = f.getvalue()
        self.assertFalse(has_issues)

        # Verify JSON is valid
        data = json.loads(output)
        self.assertIn('volumeSnapshots', data)
        self.assertIn('summary', data)
        self.assertEqual(len(data['volumeSnapshots']), 1)
        self.assertEqual(data['volumeSnapshots'][0]['name'], 'test-snapshot')

    def test_print_status_plain_format(self):
        """Test print_status with plain format."""
        snapshots = {
            'items': [{
                'metadata': {
                    'name': 'test-snapshot',
                    'namespace': 'default',
                    'creationTimestamp': '2024-01-01T00:00:00Z'
                },
                'spec': {
                    'source': {'persistentVolumeClaimName': 'test-pvc'}
                },
                'status': {
                    'readyToUse': True,
                    'boundVolumeSnapshotContentName': 'content-1'
                }
            }]
        }
        contents = {'items': []}
        classes = {'items': []}

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = snapshot_monitor.print_status(
                snapshots, contents, classes, 'plain', False, 0
            )

        output = f.getvalue()
        self.assertIn('test-snapshot', output)
        self.assertIn('default', output)
        self.assertIn('VolumeSnapshot', output)

    def test_print_status_warn_only(self):
        """Test print_status with warn_only flag."""
        snapshots = {
            'items': [
                {
                    'metadata': {
                        'name': 'healthy-snapshot',
                        'namespace': 'default',
                        'creationTimestamp': '2024-01-01T00:00:00Z'
                    },
                    'spec': {'source': {'persistentVolumeClaimName': 'pvc1'}},
                    'status': {
                        'readyToUse': True,
                        'boundVolumeSnapshotContentName': 'content-1'
                    }
                },
                {
                    'metadata': {
                        'name': 'failed-snapshot',
                        'namespace': 'default',
                        'creationTimestamp': '2024-01-01T00:00:00Z'
                    },
                    'spec': {'source': {'persistentVolumeClaimName': 'pvc2'}},
                    'status': {
                        'readyToUse': False,
                        'error': {'message': 'Snapshot failed'}
                    }
                }
            ]
        }
        contents = {'items': []}
        classes = {'items': []}

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = snapshot_monitor.print_status(
                snapshots, contents, classes, 'json', True, 0
            )

        output = f.getvalue()
        data = json.loads(output)

        # Only failed snapshot should be in output
        self.assertEqual(len(data['volumeSnapshots']), 1)
        self.assertEqual(data['volumeSnapshots'][0]['name'], 'failed-snapshot')
        self.assertTrue(has_issues)

    def test_print_status_with_orphaned_contents(self):
        """Test print_status detecting orphaned contents."""
        snapshots = {'items': []}
        contents = {
            'items': [{
                'metadata': {'name': 'orphaned-content'},
                'spec': {
                    'volumeSnapshotRef': {'name': 'deleted-snap', 'namespace': 'default'},
                    'deletionPolicy': 'Retain',
                    'driver': 'csi.example.com'
                },
                'status': {}
            }]
        }
        classes = {'items': []}

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = snapshot_monitor.print_status(
                snapshots, contents, classes, 'json', False, 0
            )

        output = f.getvalue()
        data = json.loads(output)

        self.assertTrue(has_issues)
        self.assertEqual(len(data['orphanedContents']), 1)
        self.assertEqual(data['orphanedContents'][0]['name'], 'orphaned-content')


if __name__ == '__main__':
    # Run tests with custom runner to report results in expected format
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)

    # Print results in expected format
    passed = result.testsRun - len(result.failures) - len(result.errors)
    print(f"\nTest Results: {passed}/{result.testsRun} tests passed")

    sys.exit(0 if result.wasSuccessful() else 1)
