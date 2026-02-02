"""Tests for cron_monitor script."""

import pytest

from boxctl.core.output import Output


class TestCronMonitor:
    """Tests for cron_monitor script."""

    def test_no_crontab_files(self, mock_context):
        """Returns 0 when no crontab files exist."""
        from scripts.baremetal import cron_monitor

        ctx = mock_context(
            file_contents={}
        )
        output = Output()

        exit_code = cron_monitor.run([], output, ctx)

        assert exit_code == 0

    def test_healthy_system_crontab(self, mock_context):
        """Returns 0 when system crontab is healthy."""
        from scripts.baremetal import cron_monitor

        ctx = mock_context(
            file_contents={
                '/etc/crontab': '''SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin

# Run daily jobs
0 3 * * * root /usr/local/bin/backup.sh
*/15 * * * * root /usr/local/bin/check-health.sh
''',
            }
        )
        output = Output()

        exit_code = cron_monitor.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data['system_crontab']['jobs']) == 2
        assert all(j['severity'] == 'OK' for j in output.data['system_crontab']['jobs'])

    def test_invalid_schedule_detected(self, mock_context):
        """Returns 1 when cron schedule is invalid."""
        from scripts.baremetal import cron_monitor

        ctx = mock_context(
            file_contents={
                # System crontab (with user field): schedule user command
                # Use an invalid special schedule that's not recognized
                '/etc/crontab': '''# Invalid special schedule
@invalid root /usr/local/bin/backup.sh
''',
            }
        )
        output = Output()

        exit_code = cron_monitor.run(['--system-only'], output, ctx)

        # The schedule "@invalid" is not a valid special schedule
        assert exit_code == 1
        jobs = output.data['system_crontab']['jobs']
        assert len(jobs) == 1
        assert jobs[0]['severity'] == 'CRITICAL'
        assert any('schedule' in i.lower() for i in jobs[0]['issues'])

    def test_special_schedules_valid(self, mock_context):
        """Special schedules like @daily are valid."""
        from scripts.baremetal import cron_monitor

        ctx = mock_context(
            file_contents={
                '/etc/crontab': '''@daily root /usr/local/bin/daily-task.sh
@reboot root /usr/local/bin/startup.sh
@hourly root /usr/local/bin/hourly-check.sh
''',
            }
        )
        output = Output()

        exit_code = cron_monitor.run([], output, ctx)

        assert exit_code == 0
        jobs = output.data['system_crontab']['jobs']
        assert len(jobs) == 3
        assert all(j['severity'] == 'OK' for j in jobs)

    def test_cron_d_directory(self, mock_context):
        """Analyzes /etc/cron.d files."""
        from scripts.baremetal import cron_monitor

        ctx = mock_context(
            file_contents={
                '/etc/cron.d': '',  # dir marker
                '/etc/cron.d/backup': '''# Backup job
0 2 * * * root /usr/local/bin/backup.sh
''',
                '/etc/cron.d/monitoring': '''# Monitoring
*/5 * * * * root /usr/local/bin/monitor.sh
''',
            }
        )
        output = Output()

        exit_code = cron_monitor.run([], output, ctx)

        assert exit_code == 0
        cron_d = next(d for d in output.data['cron_directories'] if d['path'] == '/etc/cron.d')
        assert len(cron_d['files']) == 2

    def test_user_crontabs(self, mock_context):
        """Analyzes user crontabs."""
        from scripts.baremetal import cron_monitor

        ctx = mock_context(
            file_contents={
                '/var/spool/cron/crontabs': '',  # dir marker
                '/var/spool/cron/crontabs/alice': '''0 9 * * * /home/alice/bin/morning.sh
''',
                '/var/spool/cron/crontabs/bob': '''30 18 * * 5 /home/bob/bin/friday.sh
''',
            }
        )
        output = Output()

        exit_code = cron_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data['user_crontabs'] is not None
        users = output.data['user_crontabs']['users']
        assert len(users) == 2
        usernames = [u['username'] for u in users]
        assert 'alice' in usernames
        assert 'bob' in usernames

    def test_system_only_flag(self, mock_context):
        """--system-only skips user crontabs."""
        from scripts.baremetal import cron_monitor

        ctx = mock_context(
            file_contents={
                '/etc/crontab': '0 0 * * * root /bin/true\n',
                '/var/spool/cron/crontabs': '',
                '/var/spool/cron/crontabs/alice': '0 9 * * * /bin/echo\n',
            }
        )
        output = Output()

        exit_code = cron_monitor.run(['--system-only'], output, ctx)

        assert exit_code == 0
        assert output.data['user_crontabs'] is None

    def test_user_only_flag(self, mock_context):
        """--user-only skips system crontabs."""
        from scripts.baremetal import cron_monitor

        ctx = mock_context(
            file_contents={
                '/etc/crontab': '0 0 * * * root /bin/true\n',
                '/var/spool/cron/crontabs': '',
                '/var/spool/cron/crontabs/alice': '0 9 * * * /bin/echo\n',
            }
        )
        output = Output()

        exit_code = cron_monitor.run(['--user-only'], output, ctx)

        assert exit_code == 0
        assert output.data['system_crontab'] is None
        assert output.data['user_crontabs'] is not None

    def test_both_flags_error(self, mock_context):
        """Returns 2 when both --system-only and --user-only specified."""
        from scripts.baremetal import cron_monitor

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = cron_monitor.run(['--system-only', '--user-only'], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_comments_and_variables_skipped(self, mock_context):
        """Comments and variable assignments are not parsed as jobs."""
        from scripts.baremetal import cron_monitor

        ctx = mock_context(
            file_contents={
                '/etc/crontab': '''# This is a comment
SHELL=/bin/bash
PATH=/usr/bin:/bin
MAILTO=admin@example.com

# The actual job
0 3 * * * root /usr/local/bin/backup.sh
''',
            }
        )
        output = Output()

        exit_code = cron_monitor.run([], output, ctx)

        assert exit_code == 0
        jobs = output.data['system_crontab']['jobs']
        # Only the actual job should be parsed, not comments or variables
        assert len(jobs) == 1
        assert jobs[0]['command'] == '/usr/local/bin/backup.sh'

    def test_skip_backup_files(self, mock_context):
        """Backup files (.bak, ~, .dpkg-old) are skipped."""
        from scripts.baremetal import cron_monitor

        ctx = mock_context(
            file_contents={
                '/etc/cron.d': '',
                '/etc/cron.d/backup': '0 2 * * * root /bin/backup\n',
                '/etc/cron.d/backup.bak': '0 2 * * * root /bin/old-backup\n',
                '/etc/cron.d/backup~': '0 2 * * * root /bin/temp-backup\n',
                '/etc/cron.d/backup.dpkg-old': '0 2 * * * root /bin/dpkg-backup\n',
            }
        )
        output = Output()

        exit_code = cron_monitor.run([], output, ctx)

        assert exit_code == 0
        cron_d = next(d for d in output.data['cron_directories'] if d['path'] == '/etc/cron.d')
        # Only the main backup file should be included
        assert len(cron_d['files']) == 1
        assert cron_d['files'][0]['name'] == 'backup'
