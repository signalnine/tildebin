#!/usr/bin/env python3
"""
Monitor active login sessions on baremetal systems.

This script tracks currently logged-in users, their session sources, and idle times.
Critical for security auditing in large-scale baremetal environments to detect:
- Unauthorized or unexpected user sessions
- Idle sessions that may indicate abandoned connections
- Root logins (potential security concern)
- Sessions from unusual source IPs or hostnames

Key features:
- List all active user sessions with details
- Detect idle sessions exceeding threshold
- Flag root/privileged user sessions
- Track session sources (local, SSH, etc.)
- Support filtering by user, source, or session type

Exit codes:
    0 - No issues detected (or below warning thresholds)
    1 - Issues detected (idle sessions, root logins, threshold exceeded)
    2 - Usage error or required tools not available
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime


def run_command(cmd):
    """Execute shell command and return result."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd.split()[0]}"
    except Exception as e:
        return -1, "", str(e)


def parse_idle_time(idle_str):
    """
    Parse idle time string to seconds.

    Formats:
    - '.' or 'old' = 0 (just logged in or very old)
    - '00:05' = 5 seconds
    - '5:30' = 5 minutes 30 seconds
    - '1:05m' = 1 hour 5 minutes (some systems)
    - '2days' = 2 days
    """
    if not idle_str or idle_str == '.' or idle_str == 'old':
        return 0

    idle_str = idle_str.strip().lower()

    # Handle days format
    if 'days' in idle_str or 'day' in idle_str:
        match = re.match(r'(\d+)\s*days?', idle_str)
        if match:
            return int(match.group(1)) * 86400

    # Handle hours:minutes format (e.g., "1:05m" or "2:30")
    if 'm' in idle_str:
        idle_str = idle_str.replace('m', '')
        parts = idle_str.split(':')
        if len(parts) == 2:
            try:
                return int(parts[0]) * 3600 + int(parts[1]) * 60
            except ValueError:
                pass

    # Handle MM:SS or HH:MM format
    if ':' in idle_str:
        parts = idle_str.split(':')
        try:
            if len(parts) == 2:
                # Could be MM:SS or HH:MM - assume MM:SS for shorter times
                val1, val2 = int(parts[0]), int(parts[1])
                if val1 > 59:
                    # Likely HH:MM
                    return val1 * 3600 + val2 * 60
                else:
                    # Likely MM:SS
                    return val1 * 60 + val2
            elif len(parts) == 3:
                # HH:MM:SS
                return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        except ValueError:
            pass

    # Handle plain number (seconds or minutes depending on system)
    try:
        val = int(idle_str)
        # If less than 100, likely minutes; otherwise seconds
        return val * 60 if val < 100 else val
    except ValueError:
        pass

    return 0


def format_idle_time(seconds):
    """Format idle time as human-readable string."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m"
    elif seconds < 86400:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}d {hours}h"


def get_sessions_from_who():
    """Get session information using 'who' command."""
    sessions = []

    # Try 'who -u' for idle time information
    returncode, stdout, stderr = run_command(['who', '-u'])

    if returncode != 0:
        # Fallback to plain 'who'
        returncode, stdout, stderr = run_command(['who'])
        if returncode != 0:
            return sessions, f"Failed to run 'who': {stderr}"

    for line in stdout.strip().split('\n'):
        if not line:
            continue

        # Parse who output
        # Format: username tty login_date login_time (idle) (source)
        # Example: root     pts/0        2025-01-20 10:30   .          (192.168.1.100)
        parts = line.split()
        if len(parts) < 3:
            continue

        username = parts[0]
        tty = parts[1]

        # Find login time - look for date/time patterns
        login_time = None
        idle_time = '.'
        source = 'local'

        # Parse remaining fields
        idx = 2
        date_parts = []
        while idx < len(parts):
            part = parts[idx]

            # Check if it's a source (in parentheses)
            if part.startswith('(') and part.endswith(')'):
                source = part[1:-1]
                idx += 1
                continue

            # Check if it looks like a date component
            if re.match(r'\d{4}-\d{2}-\d{2}', part) or re.match(r'\w{3}\s+\d+', part):
                date_parts.append(part)
            elif re.match(r'\d{2}:\d{2}', part):
                date_parts.append(part)
            elif part == '.' or part == 'old' or re.match(r'\d+:\d+', part):
                idle_time = part

            idx += 1

        # Parse login time
        if date_parts:
            try:
                date_str = ' '.join(date_parts)
                # Try various formats
                for fmt in [
                    '%Y-%m-%d %H:%M',
                    '%b %d %H:%M',
                    '%Y-%m-%d',
                ]:
                    try:
                        login_time = datetime.strptime(date_str, fmt)
                        if login_time.year == 1900:
                            login_time = login_time.replace(year=datetime.now().year)
                        break
                    except ValueError:
                        continue
            except Exception:
                pass

        # Determine session type
        if tty.startswith('pts/'):
            session_type = 'pty'
            if source != 'local' and source != ':0':
                session_type = 'ssh'
        elif tty.startswith('tty'):
            session_type = 'console'
        elif tty.startswith(':'):
            session_type = 'x11'
        else:
            session_type = 'unknown'

        sessions.append({
            'username': username,
            'tty': tty,
            'login_time': login_time.isoformat() if login_time else None,
            'idle_seconds': parse_idle_time(idle_time),
            'idle_formatted': format_idle_time(parse_idle_time(idle_time)),
            'source': source,
            'session_type': session_type,
        })

    return sessions, None


def get_sessions_from_w():
    """Get session information using 'w' command (includes more detail)."""
    sessions = []

    returncode, stdout, stderr = run_command(['w', '-h'])

    if returncode != 0:
        return sessions, f"Failed to run 'w': {stderr}"

    for line in stdout.strip().split('\n'):
        if not line:
            continue

        # Parse w output
        # Format: user tty from login@ idle jcpu pcpu what
        # Example: root pts/0 192.168.1.1 10:30 5:00 0.10s 0.02s bash
        parts = line.split()
        if len(parts) < 4:
            continue

        username = parts[0]
        tty = parts[1]
        source = parts[2] if len(parts) > 2 else 'local'

        # Handle login time and idle
        login_at = parts[3] if len(parts) > 3 else ''
        idle = parts[4] if len(parts) > 4 else '.'

        # Get the command being run
        what = ' '.join(parts[7:]) if len(parts) > 7 else ''

        # Determine session type
        if source == '-' or source == ':0' or source == ':0.0':
            source = 'local'

        if tty.startswith('pts/'):
            session_type = 'ssh' if source not in ['local', ':0', ':0.0', '-'] else 'pty'
        elif tty.startswith('tty'):
            session_type = 'console'
        else:
            session_type = 'unknown'

        sessions.append({
            'username': username,
            'tty': tty,
            'login_time': login_at,
            'idle_seconds': parse_idle_time(idle),
            'idle_formatted': format_idle_time(parse_idle_time(idle)),
            'source': source,
            'session_type': session_type,
            'command': what,
        })

    return sessions, None


def get_active_sessions():
    """Get active sessions using available tools."""
    # Try 'w' first as it gives more info
    sessions, error = get_sessions_from_w()
    if sessions:
        return sessions, None

    # Fallback to 'who'
    sessions, error = get_sessions_from_who()
    return sessions, error


def check_thresholds(sessions, max_idle_seconds, max_sessions, warn_root):
    """Check sessions against thresholds and return issues."""
    issues = []

    # Check for idle sessions
    for session in sessions:
        idle = session.get('idle_seconds', 0)
        if idle > max_idle_seconds:
            issues.append({
                'severity': 'WARNING',
                'type': 'idle_session',
                'user': session['username'],
                'tty': session['tty'],
                'message': f"Session for {session['username']} on {session['tty']} idle for {session['idle_formatted']}"
            })

    # Check for root sessions
    if warn_root:
        root_sessions = [s for s in sessions if s['username'] == 'root']
        for session in root_sessions:
            issues.append({
                'severity': 'WARNING',
                'type': 'root_session',
                'user': 'root',
                'tty': session['tty'],
                'source': session.get('source', 'unknown'),
                'message': f"Root session active on {session['tty']} from {session.get('source', 'unknown')}"
            })

    # Check total session count
    if max_sessions > 0 and len(sessions) > max_sessions:
        issues.append({
            'severity': 'WARNING',
            'type': 'session_count',
            'count': len(sessions),
            'threshold': max_sessions,
            'message': f"Session count ({len(sessions)}) exceeds threshold ({max_sessions})"
        })

    return issues


def get_hostname():
    """Get system hostname."""
    try:
        with open('/etc/hostname', 'r') as f:
            return f.read().strip()
    except IOError:
        pass

    returncode, stdout, stderr = run_command(['hostname'])
    if returncode == 0:
        return stdout.strip()

    return os.uname().nodename


def output_plain(data, verbose=False, warn_only=False):
    """Output results in plain text format."""
    if warn_only and not data['issues']:
        return

    print(f"Host: {data['hostname']}")
    print(f"Active Sessions: {data['session_count']}")
    print(f"Unique Users: {len(data['unique_users'])}")
    print()

    if data['sessions']:
        print("Sessions:")
        for session in data['sessions']:
            source = session.get('source', 'local')
            idle = session.get('idle_formatted', '0s')
            cmd = session.get('command', '')
            if cmd and verbose:
                print(f"  {session['username']:<12} {session['tty']:<10} {source:<20} idle: {idle:<10} {cmd}")
            else:
                print(f"  {session['username']:<12} {session['tty']:<10} {source:<20} idle: {idle}")

    if data['issues']:
        print("\nIssues:")
        for issue in data['issues']:
            print(f"  [{issue['severity']}] {issue['message']}")


def output_json(data):
    """Output results in JSON format."""
    print(json.dumps(data, indent=2, default=str))


def output_table(data, verbose=False, warn_only=False):
    """Output results in table format."""
    if warn_only and not data['issues']:
        return

    print("=" * 80)
    print(f"Active Sessions Report: {data['hostname']}")
    print("=" * 80)
    print(f"Total Sessions: {data['session_count']}  |  Unique Users: {len(data['unique_users'])}")
    print("=" * 80)

    if data['sessions']:
        print(f"\n{'USER':<12} {'TTY':<10} {'SOURCE':<20} {'IDLE':<10} {'TYPE':<8}")
        print("-" * 70)
        for session in data['sessions']:
            source = session.get('source', 'local')[:18]
            idle = session.get('idle_formatted', '0s')
            stype = session.get('session_type', 'unknown')
            print(f"{session['username']:<12} {session['tty']:<10} {source:<20} {idle:<10} {stype:<8}")

    if data['issues']:
        print("\n" + "=" * 80)
        print("Issues Detected:")
        print("-" * 80)
        for issue in data['issues']:
            print(f"[{issue['severity']}] {issue['message']}")

    print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor active login sessions on baremetal systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all active sessions
  baremetal_active_sessions_monitor.py

  # Check for sessions idle more than 30 minutes
  baremetal_active_sessions_monitor.py --max-idle 1800

  # Warn on root logins
  baremetal_active_sessions_monitor.py --warn-root

  # JSON output for monitoring integration
  baremetal_active_sessions_monitor.py --format json

  # Filter by user
  baremetal_active_sessions_monitor.py --user admin

  # Show only issues
  baremetal_active_sessions_monitor.py --warn-only
        """
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed session information"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only output if issues are detected"
    )

    parser.add_argument(
        "--max-idle",
        type=int,
        default=3600,
        metavar="SECONDS",
        help="Maximum idle time before warning (default: 3600 seconds / 1 hour)"
    )

    parser.add_argument(
        "--max-sessions",
        type=int,
        default=0,
        metavar="COUNT",
        help="Maximum session count before warning (default: 0 = no limit)"
    )

    parser.add_argument(
        "--warn-root",
        action="store_true",
        help="Warn on active root sessions"
    )

    parser.add_argument(
        "--user",
        metavar="USERNAME",
        help="Filter sessions by username"
    )

    parser.add_argument(
        "--type",
        choices=["ssh", "console", "pty", "x11"],
        metavar="TYPE",
        help="Filter sessions by type"
    )

    args = parser.parse_args()

    # Get active sessions
    sessions, error = get_active_sessions()
    if error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)

    # Apply filters
    if args.user:
        sessions = [s for s in sessions if s['username'] == args.user]

    if args.type:
        sessions = [s for s in sessions if s.get('session_type') == args.type]

    # Check thresholds
    issues = check_thresholds(
        sessions,
        args.max_idle,
        args.max_sessions,
        args.warn_root
    )

    # Prepare output data
    unique_users = list(set(s['username'] for s in sessions))

    data = {
        'hostname': get_hostname(),
        'timestamp': datetime.now().isoformat(),
        'session_count': len(sessions),
        'unique_users': unique_users,
        'sessions': sessions,
        'issues': issues,
    }

    # Handle warn-only mode
    if args.warn_only and not issues:
        sys.exit(0)

    # Output results
    if args.format == "json":
        output_json(data)
    elif args.format == "table":
        output_table(data, args.verbose, args.warn_only)
    else:  # plain
        output_plain(data, args.verbose, args.warn_only)

    # Exit based on findings
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
