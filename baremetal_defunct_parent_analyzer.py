#!/usr/bin/env python3
"""
Analyze processes with defunct or reparented parent relationships.

This script identifies processes that have been orphaned (reparented to init/systemd)
which may indicate their original parent process crashed or was killed unexpectedly.
This is different from zombie processes - these are live processes whose parent died.

Useful for detecting:
- Service crashes that left child workers running
- Application instability patterns
- Resource leaks from orphaned processes
- Long-running processes that lost supervision

Exit codes:
    0 - No orphaned processes with issues detected
    1 - Orphaned processes found that may need attention
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
import time
from datetime import datetime


# Common init/supervisor process names that legitimately parent processes
KNOWN_INIT_PROCESSES = {
    'systemd', 'init', 'launchd', 'upstart', 'runit', 'openrc-init',
    's6-svscan', 'supervisord', 'containerd-shim', 'docker-init',
    'tini', 'dumb-init', 'catatonit'
}

# Processes that are expected to be reparented (not concerning)
# These are daemons/services normally started by init
EXPECTED_REPARENTED = {
    # Kernel threads
    'kthreadd', 'migration', 'ksoftirqd', 'kworker', 'rcu_sched',
    'watchdog', 'cpuhp', 'idle_inject', 'kcompactd', 'khugepaged',
    'oom_reaper', 'writeback', 'kblockd', 'ata_sff', 'md', 'edac-poller',
    'devfreq_wq', 'kswapd', 'ecryptfs', 'kthrotld', 'acpi_thermal_pm',
    'nvme-wq', 'scsi_eh', 'kpsmoused', 'ipv6_addrconf', 'kstrp',
    'zswap', 'charger_manager', 'kintegrityd', 'bioset', 'kmemleak',
    'jbd2', 'ext4', 'xfs', 'btrfs', 'nfsiod', 'rpciod',
    # System daemons commonly started by init
    'sshd', 'cron', 'rsyslogd', 'systemd-journal', 'systemd-logind',
    'systemd-udevd', 'dbus-daemon', 'polkitd', 'accounts-daemon',
    'NetworkManager', 'wpa_supplicant', 'avahi-daemon', 'cupsd',
    'gdm', 'lightdm', 'sddm', 'login', 'agetty', 'getty',
    'smartd', 'chronyd', 'ntpd', 'dhclient', 'dhcpcd',
    'postgres', 'mysqld', 'mariadbd', 'mongod', 'redis-server',
    'nginx', 'apache2', 'httpd', 'caddy', 'haproxy', 'envoy',
    'dockerd', 'containerd', 'kubelet', 'podman',
    'sshfs', 'screen', 'tmux', 'ssh-agent',
    # Common background processes
    'ssh', 'gpg-agent', 'agent', 'at-spi-bus-launc', 'at-spi2-registr',
    'pulseaudio', 'pipewire', 'wireplumber', 'dconf-service',
    'gvfsd', 'gvfs-daemon', 'tracker', 'gnome-keyring-d',
    # Container/VM related
    'lxcfs', 'lxc-monitord', 'qemu', 'libvirtd', 'virtlogd',
    'pve', 'pmxcfs', 'proxmox', 'corosync', 'pacemaker',
    'netavark', 'aardvark-dns', 'conmon',
    # Other common services
    'snapd', 'flatpak', 'packagekitd', 'fwupd', 'udisksd',
    'colord', 'geoclue', 'ModemManager', 'bluetoothd',
    'rpcbind', 'rpc.statd', 'rpc.mountd', 'nfsd', 'blkmapd',
    'zed', 'postfix', 'master', 'qmgr', 'pickup',
    'rrdcached', 'collectd', 'telegraf', 'prometheus',
}


# Cache for boot time (read once)
_boot_time_cache = None


def get_boot_time():
    """Get system boot time in seconds since epoch."""
    global _boot_time_cache
    if _boot_time_cache is not None:
        return _boot_time_cache
    try:
        with open('/proc/stat', 'r') as f:
            for line in f:
                if line.startswith('btime'):
                    _boot_time_cache = int(line.split()[1])
                    return _boot_time_cache
    except (IOError, OSError, ValueError, IndexError):
        pass
    return None


def get_process_list():
    """Get list of all process PIDs from /proc."""
    pids = []
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pids.append(int(entry))
    except OSError:
        pass
    return pids


def get_process_info(pid):
    """Get detailed process information from /proc/[pid]/stat."""
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            stat = f.read()

        # Parse stat file - handle comm field with spaces/parens
        # Format: pid (comm) state ppid pgrp session tty_nr tpgid ...
        first_paren = stat.index('(')
        last_paren = stat.rindex(')')

        comm = stat[first_paren + 1:last_paren]
        fields = stat[last_paren + 2:].split()

        # Fields after (comm):
        # 0=state, 1=ppid, 2=pgrp, 3=session, 4=tty_nr, 5=tpgid, 6=flags,
        # 7=minflt, 8=cminflt, 9=majflt, 10=cmajflt, 11=utime, 12=stime,
        # 13=cutime, 14=cstime, 15=priority, 16=nice, 17=num_threads,
        # 18=itrealvalue, 19=starttime, ...

        ppid = int(fields[1])
        state = fields[0]
        starttime_ticks = int(fields[19])

        # Convert starttime to epoch seconds
        boot_time = get_boot_time()
        clock_ticks = os.sysconf('SC_CLK_TCK')
        if boot_time and clock_ticks:
            start_epoch = boot_time + (starttime_ticks / clock_ticks)
        else:
            start_epoch = None

        return {
            'pid': pid,
            'comm': comm,
            'state': state,
            'ppid': ppid,
            'starttime': start_epoch
        }
    except (IOError, OSError, ValueError, IndexError):
        return None


def get_process_cmdline(pid):
    """Get process command line."""
    try:
        with open(f'/proc/{pid}/cmdline', 'r') as f:
            cmdline = f.read()
            return cmdline.replace('\x00', ' ').strip()
    except (IOError, OSError):
        return None


def get_process_uid(pid):
    """Get UID of process owner."""
    try:
        stat_info = os.stat(f'/proc/{pid}')
        return stat_info.st_uid
    except OSError:
        return None


def get_username(uid):
    """Get username for a UID."""
    if uid is None:
        return None
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return str(uid)


def is_kernel_thread(pid):
    """Check if a process is a kernel thread (no cmdline)."""
    try:
        with open(f'/proc/{pid}/cmdline', 'r') as f:
            return f.read().strip() == ''
    except (IOError, OSError):
        return True


def analyze_orphans(min_age_seconds=0, include_expected=False, user_filter=None):
    """Find processes that have been reparented to init (PID 1).

    Args:
        min_age_seconds: Only include processes older than this
        include_expected: Include processes that are expected to be reparented
        user_filter: Only include processes owned by this user

    Returns:
        list of orphaned process info dicts
    """
    orphans = []
    pids = get_process_list()
    now = time.time()

    for pid in pids:
        if pid == 1:
            continue

        info = get_process_info(pid)
        if info is None:
            continue

        # Check if reparented to init (ppid == 1)
        if info['ppid'] != 1:
            continue

        # Skip kernel threads
        if is_kernel_thread(pid):
            continue

        # Skip expected reparented processes unless requested
        if not include_expected:
            comm_lower = info['comm'].lower()
            comm_base = info['comm'].split('/')[0].split('-')[0]
            # Check various matching patterns
            if comm_base in EXPECTED_REPARENTED:
                continue
            if info['comm'] in EXPECTED_REPARENTED:
                continue
            if any(exp in comm_lower for exp in EXPECTED_REPARENTED):
                continue
            # Skip common daemon patterns
            if comm_lower.endswith('d') and len(info['comm']) > 3:
                # Likely a daemon (sshd, crond, etc.)
                continue

        # Check age filter
        if info['starttime']:
            age_seconds = now - info['starttime']
            if age_seconds < min_age_seconds:
                continue
        else:
            age_seconds = None

        # Get additional info
        uid = get_process_uid(pid)
        username = get_username(uid)
        cmdline = get_process_cmdline(pid)

        # Apply user filter
        if user_filter and username != user_filter:
            continue

        # Determine if this is likely problematic
        is_init_like = info['comm'] in KNOWN_INIT_PROCESSES
        issues = []

        if not is_init_like:
            # This process has init as parent but isn't a known init-spawned process
            issues.append({
                'severity': 'WARNING',
                'type': 'orphaned_process',
                'message': f"Process was reparented to init (original parent likely crashed)"
            })

            # Check for long-running orphans
            if age_seconds and age_seconds > 86400:  # > 1 day
                issues.append({
                    'severity': 'INFO',
                    'type': 'long_running_orphan',
                    'message': f"Orphaned process running for {age_seconds / 86400:.1f} days"
                })

        orphan_info = {
            'pid': pid,
            'comm': info['comm'],
            'state': info['state'],
            'cmdline': cmdline[:200] if cmdline else '',
            'uid': uid,
            'user': username,
            'age_seconds': int(age_seconds) if age_seconds else None,
            'age_human': format_age(age_seconds) if age_seconds else 'unknown',
            'starttime': datetime.fromtimestamp(info['starttime']).isoformat() if info['starttime'] else None,
            'is_init_like': is_init_like,
            'issues': issues
        }

        orphans.append(orphan_info)

    # Sort by age (oldest first)
    orphans.sort(key=lambda x: -(x['age_seconds'] or 0))

    return orphans


def format_age(seconds):
    """Format age in human-readable form."""
    if seconds is None:
        return 'unknown'
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds / 60)}m"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    else:
        return f"{seconds / 86400:.1f}d"


def generate_summary(orphans):
    """Generate summary statistics."""
    summary = {
        'total_orphans': len(orphans),
        'with_issues': sum(1 for o in orphans if o['issues']),
        'long_running': sum(1 for o in orphans if (o['age_seconds'] or 0) > 86400),
        'init_like': sum(1 for o in orphans if o['is_init_like']),
        'by_user': {},
        'by_process': {}
    }

    for orphan in orphans:
        user = orphan['user'] or 'unknown'
        comm = orphan['comm']

        summary['by_user'][user] = summary['by_user'].get(user, 0) + 1
        summary['by_process'][comm] = summary['by_process'].get(comm, 0) + 1

    return summary


def output_plain(orphans, summary, verbose=False, warn_only=False):
    """Output results in plain text format."""
    has_issues = summary['with_issues'] > 0

    if warn_only and not has_issues:
        return

    print("Defunct Parent Analyzer - Orphaned Process Report")
    print("=" * 60)
    print(f"Total orphaned processes (ppid=1): {summary['total_orphans']}")
    print(f"Processes with issues: {summary['with_issues']}")
    print(f"Long-running (>1 day): {summary['long_running']}")
    print()

    if orphans:
        print("Orphaned Processes:")
        print("-" * 60)

        for orphan in orphans:
            status = "[ISSUE]" if orphan['issues'] else "[OK]"
            print(f"{status} PID {orphan['pid']}: {orphan['comm']}")
            print(f"    User: {orphan['user']}, Age: {orphan['age_human']}, State: {orphan['state']}")

            if verbose and orphan['cmdline']:
                print(f"    Cmd: {orphan['cmdline'][:60]}...")

            for issue in orphan['issues']:
                print(f"    [{issue['severity']}] {issue['message']}")

            print()

    if summary['by_user']:
        print("By User:")
        for user, count in sorted(summary['by_user'].items(), key=lambda x: -x[1])[:5]:
            print(f"  {user}: {count}")

    if summary['by_process']:
        print("\nBy Process Name:")
        for proc, count in sorted(summary['by_process'].items(), key=lambda x: -x[1])[:5]:
            print(f"  {proc}: {count}")


def output_json(orphans, summary):
    """Output results in JSON format."""
    output = {
        'summary': summary,
        'orphans': orphans
    }
    print(json.dumps(output, indent=2))


def output_table(orphans, summary, warn_only=False):
    """Output results in table format."""
    has_issues = summary['with_issues'] > 0

    if warn_only and not has_issues:
        return

    print("=" * 90)
    print("ORPHANED PROCESS REPORT")
    print("=" * 90)
    print()

    # Summary table
    print(f"{'Metric':<40} {'Count':<10}")
    print("-" * 50)
    print(f"{'Total orphaned processes':<40} {summary['total_orphans']:<10}")
    print(f"{'Processes with issues':<40} {summary['with_issues']:<10}")
    print(f"{'Long-running (>1 day)':<40} {summary['long_running']:<10}")
    print()

    if orphans:
        print("=" * 90)
        print(f"{'PID':<8} {'Process':<20} {'User':<12} {'Age':<10} {'State':<6} {'Issues':<20}")
        print("-" * 90)

        for orphan in orphans:
            issue_count = len(orphan['issues'])
            issue_str = f"{issue_count} issue(s)" if issue_count else "OK"
            user = (orphan['user'] or 'N/A')[:12]
            comm = orphan['comm'][:20]

            print(f"{orphan['pid']:<8} {comm:<20} {user:<12} "
                  f"{orphan['age_human']:<10} {orphan['state']:<6} {issue_str:<20}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze processes orphaned/reparented to init (PID 1)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Show orphaned processes with issues
  %(prog)s --all               # Show all orphaned processes
  %(prog)s --min-age 3600      # Only show processes orphaned > 1 hour
  %(prog)s --user root         # Filter by user
  %(prog)s --format json       # JSON output for automation

Exit codes:
  0 - No orphaned processes with issues detected
  1 - Orphaned processes found that may need attention
  2 - Usage error

Notes:
  - Processes reparented to init (ppid=1) may indicate crashed parents
  - Kernel threads are excluded from results
  - Known init/supervisor processes are marked as expected
  - Long-running orphans (>1 day) may indicate resource leaks
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed process information including command line'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only produce output if orphaned processes with issues are found'
    )

    parser.add_argument(
        '-a', '--all',
        action='store_true',
        help='Include all orphaned processes, even expected ones'
    )

    parser.add_argument(
        '-u', '--user',
        help='Only show processes owned by specified user'
    )

    parser.add_argument(
        '--min-age',
        type=int,
        default=0,
        metavar='SECONDS',
        help='Only show processes orphaned for at least this many seconds'
    )

    args = parser.parse_args()

    # Check if /proc is accessible
    if not os.path.isdir('/proc'):
        print("Error: /proc filesystem not accessible", file=sys.stderr)
        print("This tool requires Linux with procfs mounted", file=sys.stderr)
        sys.exit(2)

    # Analyze orphaned processes
    orphans = analyze_orphans(
        min_age_seconds=args.min_age,
        include_expected=args.all,
        user_filter=args.user
    )

    # Generate summary
    summary = generate_summary(orphans)

    # Check for issues
    has_issues = summary['with_issues'] > 0

    if args.warn_only and not has_issues:
        sys.exit(0)

    # Output results
    if args.format == 'json':
        output_json(orphans, summary)
    elif args.format == 'table':
        output_table(orphans, summary, args.warn_only)
    else:
        output_plain(orphans, summary, args.verbose, args.warn_only)

    # Exit code based on findings
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
