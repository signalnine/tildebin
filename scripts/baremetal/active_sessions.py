#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, users, sessions, login, monitoring]
#   brief: Monitor active login sessions on baremetal systems

"""
Monitor active login sessions on baremetal systems.

Tracks currently logged-in users, their session sources, and idle times.
Critical for security auditing in large-scale baremetal environments to detect:
- Unauthorized or unexpected user sessions
- Idle sessions that may indicate abandoned connections
- Root logins (potential security concern)
- Sessions from unusual source IPs or hostnames

Exit codes:
    0: No issues detected (or below warning thresholds)
    1: Issues detected (idle sessions, root logins, threshold exceeded)
    2: Usage error or required tools not available
"""

import argparse
import json
import re
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_idle_time(idle_str: str) -> int:
    """
    Parse idle time string to seconds.

    Formats:
    - '.' or 'old' = 0 (just logged in or very old)
    - '00:05' = 5 seconds
    - '5:30' = 5 minutes 30 seconds
    - '1:05m' = 1 hour 5 minutes (some systems)
    - '2days' = 2 days
    - '2:30:00' = 2 hours 30 minutes (w command format)
    """
    if not idle_str or idle_str == "." or idle_str == "old":
        return 0

    idle_str = idle_str.strip().lower()

    # Handle days format
    if "days" in idle_str or "day" in idle_str:
        match = re.match(r"(\d+)\s*days?", idle_str)
        if match:
            return int(match.group(1)) * 86400

    # Handle hours:minutes format (e.g., "1:05m" or "2:30")
    if "m" in idle_str:
        idle_str = idle_str.replace("m", "")
        parts = idle_str.split(":")
        if len(parts) == 2:
            try:
                return int(parts[0]) * 3600 + int(parts[1]) * 60
            except ValueError:
                pass

    # Handle HH:MM:SS or MM:SS format
    if ":" in idle_str:
        parts = idle_str.split(":")
        try:
            if len(parts) == 3:
                # HH:MM:SS
                return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
            elif len(parts) == 2:
                val1, val2 = int(parts[0]), int(parts[1])
                if val1 > 59:
                    # Likely HH:MM
                    return val1 * 3600 + val2 * 60
                else:
                    # Likely MM:SS
                    return val1 * 60 + val2
        except ValueError:
            pass

    # Handle plain number (seconds or minutes)
    try:
        val = int(idle_str)
        return val * 60 if val < 100 else val
    except ValueError:
        pass

    return 0


def format_idle_time(seconds: int) -> str:
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


def parse_who_output(stdout: str) -> list[dict]:
    """Parse 'who' command output into session list."""
    sessions = []

    for line in stdout.strip().split("\n"):
        if not line:
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        username = parts[0]
        tty = parts[1]

        # Find source (in parentheses)
        source = "local"
        idle_time = "."
        for part in parts:
            if part.startswith("(") and part.endswith(")"):
                source = part[1:-1]
            elif part in (".", "old") or re.match(r"\d+:\d+", part):
                idle_time = part

        # Determine session type
        if tty.startswith("pts/"):
            session_type = "ssh" if source not in ("local", ":0", ":0.0") else "pty"
        elif tty.startswith("tty"):
            session_type = "console"
        elif tty.startswith(":"):
            session_type = "x11"
        else:
            session_type = "unknown"

        sessions.append({
            "username": username,
            "tty": tty,
            "idle_seconds": parse_idle_time(idle_time),
            "idle_formatted": format_idle_time(parse_idle_time(idle_time)),
            "source": source,
            "session_type": session_type,
        })

    return sessions


def parse_w_output(stdout: str) -> list[dict]:
    """Parse 'w -h' command output into session list."""
    sessions = []

    for line in stdout.strip().split("\n"):
        if not line:
            continue

        # Format: user tty from login@ idle jcpu pcpu what
        parts = line.split()
        if len(parts) < 4:
            continue

        username = parts[0]
        tty = parts[1]
        source = parts[2] if len(parts) > 2 else "local"
        idle = parts[4] if len(parts) > 4 else "."
        what = " ".join(parts[7:]) if len(parts) > 7 else ""

        if source in ("-", ":0", ":0.0"):
            source = "local"

        if tty.startswith("pts/"):
            session_type = "ssh" if source not in ("local", ":0", ":0.0", "-") else "pty"
        elif tty.startswith("tty"):
            session_type = "console"
        else:
            session_type = "unknown"

        sessions.append({
            "username": username,
            "tty": tty,
            "idle_seconds": parse_idle_time(idle),
            "idle_formatted": format_idle_time(parse_idle_time(idle)),
            "source": source,
            "session_type": session_type,
            "command": what,
        })

    return sessions


def check_thresholds(
    sessions: list[dict],
    max_idle_seconds: int,
    max_sessions: int,
    warn_root: bool,
) -> list[dict]:
    """Check sessions against thresholds and return issues."""
    issues = []

    # Check for idle sessions
    for session in sessions:
        idle = session.get("idle_seconds", 0)
        if idle > max_idle_seconds:
            issues.append({
                "severity": "WARNING",
                "type": "idle_session",
                "user": session["username"],
                "tty": session["tty"],
                "message": f"Session for {session['username']} on {session['tty']} idle for {session['idle_formatted']}",
            })

    # Check for root sessions
    if warn_root:
        root_sessions = [s for s in sessions if s["username"] == "root"]
        for session in root_sessions:
            issues.append({
                "severity": "WARNING",
                "type": "root_session",
                "user": "root",
                "tty": session["tty"],
                "source": session.get("source", "unknown"),
                "message": f"Root session active on {session['tty']} from {session.get('source', 'unknown')}",
            })

    # Check total session count
    if max_sessions > 0 and len(sessions) > max_sessions:
        issues.append({
            "severity": "WARNING",
            "type": "session_count",
            "count": len(sessions),
            "threshold": max_sessions,
            "message": f"Session count ({len(sessions)}) exceeds threshold ({max_sessions})",
        })

    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor active login sessions on baremetal systems"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed session information",
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only output if issues are detected",
    )
    parser.add_argument(
        "--max-idle",
        type=int,
        default=3600,
        metavar="SECONDS",
        help="Maximum idle time before warning (default: 3600 seconds / 1 hour)",
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=0,
        metavar="COUNT",
        help="Maximum session count before warning (default: 0 = no limit)",
    )
    parser.add_argument(
        "--warn-root",
        action="store_true",
        help="Warn on active root sessions",
    )
    parser.add_argument(
        "--user",
        metavar="USERNAME",
        help="Filter sessions by username",
    )
    parser.add_argument(
        "--type",
        dest="session_type",
        choices=["ssh", "console", "pty", "x11"],
        metavar="TYPE",
        help="Filter sessions by type",
    )

    opts = parser.parse_args(args)

    # Check for required tools
    if not context.check_tool("w") and not context.check_tool("who"):
        output.error("Neither 'w' nor 'who' command available")
        return 2

    # Get active sessions (try 'w' first, fallback to 'who')
    sessions = []
    error_msg = None

    if context.check_tool("w"):
        try:
            result = context.run(["w", "-h"])
            if result.returncode == 0:
                sessions = parse_w_output(result.stdout)
        except Exception as e:
            error_msg = str(e)

    if not sessions and context.check_tool("who"):
        try:
            result = context.run(["who"])
            if result.returncode == 0:
                sessions = parse_who_output(result.stdout)
        except Exception as e:
            error_msg = str(e)

    if error_msg and not sessions:
        output.error(f"Failed to get sessions: {error_msg}")
        return 2

    # Apply filters
    if opts.user:
        sessions = [s for s in sessions if s["username"] == opts.user]

    if opts.session_type:
        sessions = [s for s in sessions if s.get("session_type") == opts.session_type]

    # Check thresholds
    issues = check_thresholds(
        sessions,
        opts.max_idle,
        opts.max_sessions,
        opts.warn_root,
    )

    # Get unique users
    unique_users = list(set(s["username"] for s in sessions))

    # Get hostname
    hostname = "unknown"
    try:
        result = context.run(["hostname"])
        if result.returncode == 0:
            hostname = result.stdout.strip()
    except Exception:
        pass

    # Prepare output data
    data = {
        "hostname": hostname,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_count": len(sessions),
        "unique_users": unique_users,
        "sessions": sessions,
        "issues": issues,
        "healthy": len(issues) == 0,
    }

    # Handle warn-only mode
    if opts.warn_only and not issues:
        return 0

    # Output based on format
    if opts.format == "json":
        print(json.dumps(data, indent=2, default=str))
    elif opts.format == "table":
        _output_table(data, opts.verbose)
    else:
        _output_plain(data, opts.verbose)

    # Set summary
    if issues:
        output.set_summary(f"Found {len(issues)} issue(s) in {len(sessions)} session(s)")
    else:
        output.set_summary(f"No issues in {len(sessions)} active session(s)")

    return 1 if issues else 0


def _output_plain(data: dict, verbose: bool) -> None:
    """Output results in plain text format."""
    print(f"Host: {data['hostname']}")
    print(f"Active Sessions: {data['session_count']}")
    print(f"Unique Users: {len(data['unique_users'])}")
    print()

    if data["sessions"]:
        print("Sessions:")
        for session in data["sessions"]:
            source = session.get("source", "local")
            idle = session.get("idle_formatted", "0s")
            cmd = session.get("command", "")
            if cmd and verbose:
                print(f"  {session['username']:<12} {session['tty']:<10} {source:<20} idle: {idle:<10} {cmd}")
            else:
                print(f"  {session['username']:<12} {session['tty']:<10} {source:<20} idle: {idle}")

    if data["issues"]:
        print("\nIssues:")
        for issue in data["issues"]:
            print(f"  [{issue['severity']}] {issue['message']}")


def _output_table(data: dict, verbose: bool) -> None:
    """Output results in table format."""
    print("=" * 80)
    print(f"Active Sessions Report: {data['hostname']}")
    print("=" * 80)
    print(f"Total Sessions: {data['session_count']}  |  Unique Users: {len(data['unique_users'])}")
    print("=" * 80)

    if data["sessions"]:
        print(f"\n{'USER':<12} {'TTY':<10} {'SOURCE':<20} {'IDLE':<10} {'TYPE':<8}")
        print("-" * 70)
        for session in data["sessions"]:
            source = session.get("source", "local")[:18]
            idle = session.get("idle_formatted", "0s")
            stype = session.get("session_type", "unknown")
            print(f"{session['username']:<12} {session['tty']:<10} {source:<20} {idle:<10} {stype:<8}")

    if data["issues"]:
        print("\n" + "=" * 80)
        print("Issues Detected:")
        print("-" * 80)
        for issue in data["issues"]:
            print(f"[{issue['severity']}] {issue['message']}")

    print()


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
