#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, users, audit, compliance, login]
#   brief: Audit user accounts and login history to identify dormant accounts

"""
Audit user accounts and login history to identify dormant accounts.

Analyzes user accounts from /etc/passwd and login history from lastlog
to identify accounts that haven't logged in recently. Useful for security
compliance and identifying stale accounts that should be disabled.

Key features:
- Reports last login time for each user account
- Identifies accounts that have never logged in
- Detects dormant accounts exceeding configurable thresholds
- Supports filtering by UID range (system vs human users)

Use cases:
- Security compliance audits (SOC2, PCI-DSS, HIPAA)
- Identifying accounts to disable during offboarding reviews
- Detecting service accounts that may be abandoned
- Pre-audit preparation for access reviews

Exit codes:
    0: No dormant or problematic accounts found
    1: Dormant or suspicious accounts detected
    2: Usage error or required tools not available
"""

import argparse
import json
import re
from datetime import datetime, timezone
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Shells that indicate no login capability
NOLOGIN_SHELLS = [
    "/sbin/nologin",
    "/usr/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
]


def parse_passwd_file(content: str, min_uid: int, max_uid: int, include_system: bool) -> list[dict]:
    """Parse /etc/passwd content into user list."""
    users = []

    for line in content.strip().split("\n"):
        if not line or line.startswith("#"):
            continue

        parts = line.split(":")
        if len(parts) < 7:
            continue

        try:
            uid = int(parts[2])
            gid = int(parts[3])
        except ValueError:
            continue

        # Filter by UID range
        if not include_system:
            if uid < min_uid or uid > max_uid:
                continue
        else:
            if uid > max_uid:
                continue

        user_info = {
            "username": parts[0],
            "uid": uid,
            "gid": gid,
            "gecos": parts[4],
            "home": parts[5],
            "shell": parts[6],
            "is_system": uid < min_uid,
            "has_login_shell": parts[6] not in NOLOGIN_SHELLS,
        }
        users.append(user_info)

    return users


def parse_lastlog_output(content: str) -> dict[str, datetime | None]:
    """Parse lastlog output to get last login times per user."""
    lastlog_data: dict[str, datetime | None] = {}

    lines = content.strip().split("\n")
    if len(lines) < 2:
        return lastlog_data

    # Skip header line
    for line in lines[1:]:
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) < 1:
            continue

        username = parts[0]

        # Check if user has never logged in
        if "**Never logged in**" in line:
            lastlog_data[username] = None
            continue

        # Try to parse the date
        # Look for month abbreviation
        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

        date_str = None
        for i, part in enumerate(parts):
            if part in months and i + 3 < len(parts):
                # Found month, construct date string
                # Format varies, try to capture 4-5 parts
                date_parts = parts[i-1:i+5] if i > 0 else parts[i:i+5]
                date_str = " ".join(date_parts)
                break

        if date_str:
            for fmt in [
                "%a %b %d %H:%M:%S %z %Y",
                "%a %b %d %H:%M:%S %Y",
                "%b %d %H:%M:%S %Y",
            ]:
                try:
                    lastlog_data[username] = datetime.strptime(date_str.strip(), fmt)
                    break
                except ValueError:
                    continue

        # If we couldn't parse the date but there's login info, mark as recent
        if username not in lastlog_data and "Never" not in line:
            lastlog_data[username] = datetime.now(timezone.utc)

    return lastlog_data


def analyze_user(
    user: dict[str, Any],
    lastlog: dict[str, datetime | None],
    dormant_days: int,
) -> dict[str, Any]:
    """Analyze a single user account for issues."""
    username = user["username"]
    now = datetime.now(timezone.utc)

    analysis = {
        **user,
        "last_login": None,
        "days_since_login": None,
        "never_logged_in": False,
        "is_dormant": False,
        "issues": [],
    }

    # Get last login info
    if username in lastlog:
        last_login = lastlog[username]
        if last_login is None:
            analysis["never_logged_in"] = True
            if user["has_login_shell"]:
                analysis["issues"].append("Has login shell but never logged in")
        else:
            # Make last_login timezone-aware if it isn't
            if last_login.tzinfo is None:
                last_login = last_login.replace(tzinfo=timezone.utc)
            analysis["last_login"] = last_login.isoformat()
            days_since = (now - last_login).days
            analysis["days_since_login"] = days_since

            if days_since > dormant_days:
                analysis["is_dormant"] = True
                analysis["issues"].append(f"Dormant for {days_since} days")

    return analysis


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit user accounts and login history"
    )
    parser.add_argument(
        "--dormant-days", "-d",
        type=int,
        default=90,
        metavar="DAYS",
        help="Days since login to consider account dormant (default: 90)",
    )
    parser.add_argument(
        "--min-uid",
        type=int,
        default=1000,
        metavar="UID",
        help="Minimum UID to check (default: 1000)",
    )
    parser.add_argument(
        "--max-uid",
        type=int,
        default=65533,
        metavar="UID",
        help="Maximum UID to check (default: 65533)",
    )
    parser.add_argument(
        "--include-system", "-s",
        action="store_true",
        help="Include system accounts (UID < min-uid)",
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
        help="Show detailed user information",
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show accounts with issues",
    )

    opts = parser.parse_args(args)

    # Check if lastlog is available
    if not context.check_tool("lastlog"):
        output.error("'lastlog' command not found")
        return 2

    # Read /etc/passwd
    try:
        passwd_content = context.read_file("/etc/passwd")
    except FileNotFoundError:
        output.error("Cannot read /etc/passwd")
        return 2

    # Get user accounts
    users = parse_passwd_file(
        passwd_content,
        opts.min_uid,
        opts.max_uid,
        opts.include_system,
    )

    if not users:
        if opts.format == "json":
            print(json.dumps({"summary": {"total_users": 0}, "users": []}))
        else:
            print("No user accounts found matching criteria")
        return 0

    # Get lastlog data
    try:
        result = context.run(["lastlog"])
        lastlog = parse_lastlog_output(result.stdout) if result.returncode == 0 else {}
    except Exception:
        lastlog = {}

    # Analyze each user
    results = []
    for user in users:
        analysis = analyze_user(user, lastlog, opts.dormant_days)
        results.append(analysis)

    # Calculate summary
    summary = {
        "total_users": len(results),
        "dormant_count": sum(1 for r in results if r["is_dormant"]),
        "never_logged_in": sum(1 for r in results if r["never_logged_in"]),
        "issues_count": sum(1 for r in results if r["issues"]),
        "dormant_threshold_days": opts.dormant_days,
    }

    # Output results
    if opts.format == "json":
        output_data = results if opts.verbose else [r for r in results if r["issues"]] if opts.warn_only else results
        print(json.dumps({"summary": summary, "users": output_data}, indent=2, default=str))
    elif opts.format == "table":
        _output_table(results, summary, opts.warn_only, opts.verbose)
    else:
        _output_plain(results, summary, opts.warn_only, opts.verbose)

    # Set output summary
    if summary["issues_count"] > 0:
        output.set_summary(
            f"Found {summary['issues_count']} account(s) with issues "
            f"({summary['dormant_count']} dormant, {summary['never_logged_in']} never logged in)"
        )
    else:
        output.set_summary(f"All {summary['total_users']} user accounts are healthy")

    return 1 if summary["issues_count"] > 0 else 0


def _output_plain(results: list[dict], summary: dict, warn_only: bool, verbose: bool) -> None:
    """Output results in plain text format."""
    if not warn_only:
        print("User Account Login Audit")
        print("=" * 60)
        print(f"Total accounts analyzed: {summary['total_users']}")
        print(f"Dormant accounts: {summary['dormant_count']}")
        print(f"Never logged in: {summary['never_logged_in']}")
        print(f"Accounts with issues: {summary['issues_count']}")
        print()

    # Filter if warn_only
    if warn_only:
        results = [r for r in results if r["issues"]]

    if not results:
        if not warn_only:
            print("No issues detected.")
        return

    # Print results
    for user in sorted(results, key=lambda x: (not x["issues"], x["username"])):
        if warn_only and not user["issues"]:
            continue

        status = "!" if user["issues"] else " "
        login_str = user.get("last_login", "Never")
        if login_str and login_str != "Never":
            login_str = login_str[:10]  # Just the date

        print(f"[{status}] {user['username']:<20} UID:{user['uid']:<6} Last Login: {login_str}")

        if user["issues"]:
            for issue in user["issues"]:
                print(f"    - {issue}")

        if verbose:
            print(f"    Shell: {user['shell']}")
            print(f"    Home: {user['home']}")
            if user.get("gecos"):
                print(f"    GECOS: {user['gecos']}")

    print()


def _output_table(results: list[dict], summary: dict, warn_only: bool, verbose: bool) -> None:
    """Output results in table format."""
    if warn_only:
        results = [r for r in results if r["issues"]]

    print(f"{'Username':<20} {'UID':<8} {'Last Login':<12} {'Days':<8} {'Issues'}")
    print("-" * 80)

    for user in sorted(
        results,
        key=lambda x: (x["days_since_login"] or 99999, x["username"]),
        reverse=True,
    ):
        login_str = user.get("last_login", "Never")
        if login_str and login_str != "Never":
            login_str = login_str[:10]

        days = user.get("days_since_login", "N/A")
        if days == "N/A" or days is None:
            days = "Never"

        issues = ", ".join(user["issues"]) if user["issues"] else "-"
        if len(issues) > 30:
            issues = issues[:27] + "..."

        print(f"{user['username']:<20} {user['uid']:<8} {login_str:<12} {str(days):<8} {issues}")

    print()
    print(f"Total: {summary['total_users']} | Dormant: {summary['dormant_count']} | "
          f"Never logged in: {summary['never_logged_in']} | With issues: {summary['issues_count']}")


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
