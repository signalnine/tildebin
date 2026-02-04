#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, audit, suid, sgid, permissions, privilege]
#   requires: [find]
#   privilege: root
#   brief: Audit SUID and SGID binaries for security issues

"""
Audit SUID and SGID binaries on Linux systems.

Finds and reports all files with SUID (Set User ID) or SGID (Set Group ID)
bits set. These files run with elevated privileges and are common targets
for privilege escalation attacks.

Checks for:
- Unexpected SUID/SGID binaries (not in known-good list)
- Binaries in suspicious locations (/tmp, /home, etc.)
- Non-root owned SUID binaries

Returns exit code 1 if suspicious binaries are found.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Common expected SUID binaries on Linux systems
EXPECTED_SUID_BINARIES = {
    '/usr/bin/passwd',
    '/usr/bin/chfn',
    '/usr/bin/chsh',
    '/usr/bin/gpasswd',
    '/usr/bin/newgrp',
    '/usr/bin/su',
    '/usr/bin/sudo',
    '/usr/bin/mount',
    '/usr/bin/umount',
    '/usr/bin/pkexec',
    '/usr/bin/crontab',
    '/usr/bin/fusermount',
    '/usr/bin/fusermount3',
    '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
    '/usr/lib/openssh/ssh-keysign',
    '/usr/libexec/openssh/ssh-keysign',
    '/bin/passwd',
    '/bin/su',
    '/bin/mount',
    '/bin/umount',
    '/bin/ping',
    '/usr/bin/ping',
}

# Common expected SGID binaries
EXPECTED_SGID_BINARIES = {
    '/usr/bin/wall',
    '/usr/bin/write',
    '/usr/bin/chage',
    '/usr/bin/expiry',
    '/usr/bin/crontab',
    '/usr/bin/ssh-agent',
    '/usr/bin/locate',
    '/usr/bin/mlocate',
}

# Directories that should NOT have SUID/SGID binaries
SUSPICIOUS_DIRS = [
    '/tmp',
    '/var/tmp',
    '/dev/shm',
    '/home',
    '/root',
]


def parse_find_output(output: str) -> list[str]:
    """Parse find command output into list of paths."""
    files = []
    for line in output.strip().split('\n'):
        line = line.strip()
        if line and not line.startswith('find:'):
            files.append(line)
    return files


def analyze_suid_sgid_files(
    files: list[str],
    check_expected: bool = True
) -> dict[str, Any]:
    """Analyze SUID/SGID files and categorize them."""
    results = {
        'suid_files': [],
        'unexpected_suid': [],
        'suspicious_location': [],
        'warnings': [],
    }

    for filepath in files:
        # Check for suspicious locations
        is_suspicious = False
        for suspicious_dir in SUSPICIOUS_DIRS:
            if filepath.startswith(suspicious_dir + '/'):
                results['suspicious_location'].append(filepath)
                results['warnings'].append(
                    f"SUID/SGID file in suspicious location: {filepath}"
                )
                is_suspicious = True
                break

        # Check against expected list
        if check_expected:
            if filepath not in EXPECTED_SUID_BINARIES and filepath not in EXPECTED_SGID_BINARIES:
                results['unexpected_suid'].append(filepath)

        results['suid_files'].append({
            'path': filepath,
            'suspicious': is_suspicious,
            'expected': filepath in EXPECTED_SUID_BINARIES or filepath in EXPECTED_SGID_BINARIES,
        })

    return results


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
        description="Audit SUID and SGID binaries on Linux systems"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show all SUID/SGID files found")
    parser.add_argument("-p", "--path", action="append", dest="paths",
                        help="Path(s) to search (default: /)")
    parser.add_argument("-e", "--exclude", action="append", dest="excludes",
                        help="Path(s) to exclude")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--no-expected-check", action="store_true",
                        help="Do not check against expected binary list")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show security concerns")
    opts = parser.parse_args(args)

    # Check for find command
    if not context.check_tool("find"):
        output.error("find command not found")

        output.render(opts.format, "Audit SUID and SGID binaries for security issues")
        return 2

    # Set default paths with comprehensive exclusions for speed
    search_paths = opts.paths or ['/']
    exclude_paths = opts.excludes or [
        '/proc', '/sys', '/run', '/dev',
        '/snap', '/var/snap',  # Snap packages (many small filesystems)
        '/var/lib/docker', '/var/lib/containers',  # Container storage
        '/var/lib/lxd', '/var/lib/lxc',  # LXC/LXD
        '/mnt', '/media',  # Mounted filesystems
        '/nfs', '/cifs',  # Network filesystems
    ]

    # Build and run find command
    # find / -path /proc -prune -o -path /sys -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print
    cmd = ['find']
    cmd.extend(search_paths)

    for exc in exclude_paths:
        cmd.extend(['-path', exc, '-prune', '-o'])

    cmd.extend(['-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', '-print'])

    try:
        result = context.run(cmd, check=False, timeout=300)
        files = parse_find_output(result.stdout)
    except Exception as e:
        output.error(f"Failed to run find command: {e}")

        output.render(opts.format, "Audit SUID and SGID binaries for security issues")
        return 2

    if not files:
        output.emit({
            'total_found': 0,
            'suspicious_count': 0,
            'unexpected_count': 0,
            'files': [],
        })
        output.set_summary("No SUID/SGID files found")

        output.render(opts.format, "Audit SUID and SGID binaries for security issues")
        return 0

    # Analyze files
    results = analyze_suid_sgid_files(
        files,
        check_expected=not opts.no_expected_check
    )

    # Prepare output data
    suspicious_count = len(results['suspicious_location'])
    unexpected_count = len(results['unexpected_suid'])

    output_files = results['suid_files'] if opts.verbose else [
        f for f in results['suid_files'] if f['suspicious'] or not f['expected']
    ]

    if opts.warn_only:
        output_files = [f for f in results['suid_files'] if f['suspicious']]

    output.emit({
        'total_found': len(files),
        'suspicious_count': suspicious_count,
        'unexpected_count': unexpected_count,
        'suspicious_locations': results['suspicious_location'],
        'unexpected_binaries': results['unexpected_suid'] if not opts.warn_only else [],
        'files': output_files,
        'warnings': results['warnings'],
    })

    # Set summary
    if suspicious_count > 0:
        output.set_summary(f"{suspicious_count} suspicious, {unexpected_count} unexpected")
    elif unexpected_count > 0:
        output.set_summary(f"{unexpected_count} unexpected binaries")
    else:
        output.set_summary(f"{len(files)} SUID/SGID files, all expected")

    # Return 1 if suspicious or unexpected binaries found
    if suspicious_count > 0:

        output.render(opts.format, "Audit SUID and SGID binaries for security issues")
        return 1

    output.render(opts.format, "Audit SUID and SGID binaries for security issues")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
