#!/usr/bin/env python3
"""
Analyze kernel messages (dmesg) for hardware errors and warnings.

This script parses kernel ring buffer messages to detect hardware issues including:
- Disk I/O errors and timeouts
- Memory/ECC errors
- PCIe errors and link issues
- CPU errors and MCE events
- Network errors
- Filesystem errors
- RAID controller issues

Useful for proactive hardware failure detection before system failures occur.

Exit codes:
    0 - No critical errors or warnings found
    1 - Errors or warnings found in kernel messages
    2 - Usage error or dmesg not available
"""

import argparse
import sys
import subprocess
import re
import json
from collections import defaultdict
from datetime import datetime

# Error patterns organized by category
ERROR_PATTERNS = {
    'disk': [
        (r'(ata\d+\.\d+|sd[a-z]+): (.*(error|failed|timeout).*)', 'CRITICAL'),
        (r'(nvme\d+n\d+): (.*(error|failed|timeout).*)', 'CRITICAL'),
        (r'Buffer I/O error on.*', 'CRITICAL'),
        (r'lost page write due to I/O error.*', 'CRITICAL'),
        (r'(sd[a-z]+|nvme\d+n\d+): rejecting I/O.*', 'WARNING'),
    ],
    'memory': [
        (r'(EDAC|ECC|CE|UE):.*error.*', 'CRITICAL'),
        (r'Hardware Error.*memory.*', 'CRITICAL'),
        (r'memory: page allocation failure.*', 'WARNING'),
        (r'Out of memory.*', 'CRITICAL'),
    ],
    'pcie': [
        (r'PCIe Bus Error.*', 'CRITICAL'),
        (r'AER:.*error.*', 'CRITICAL'),
        (r'pciehp.*failed.*', 'WARNING'),
        (r'PCIe.*link.*down.*', 'WARNING'),
    ],
    'cpu': [
        (r'mce:.*machine check.*', 'CRITICAL'),
        (r'MCE:.*CPU.*error.*', 'CRITICAL'),
        (r'CPU\d+.*microcode.*', 'WARNING'),
        (r'thermal.*critical.*', 'CRITICAL'),
    ],
    'network': [
        (r'(eth\d+|ens\d+|enp\d+s\d+):.*link.*down.*', 'WARNING'),
        (r'(eth\d+|ens\d+|enp\d+s\d+):.*transmit timeout.*', 'WARNING'),
        (r'NETDEV WATCHDOG.*', 'WARNING'),
    ],
    'filesystem': [
        (r'(ext4|xfs|btrfs)-fs.*error.*', 'CRITICAL'),
        (r'(EXT4|XFS|BTRFS)-fs.*warning.*', 'WARNING'),
        (r'journal commit I/O error.*', 'CRITICAL'),
    ],
    'raid': [
        (r'md\d+:.*failed.*', 'CRITICAL'),
        (r'md\d+:.*error.*', 'CRITICAL'),
        (r'md: .*removed from array.*', 'WARNING'),
    ],
    'thermal': [
        (r'temperature above threshold.*', 'CRITICAL'),
        (r'CPU\d+.*thermal.*throttling.*', 'WARNING'),
        (r'coretemp.*critical temperature.*', 'CRITICAL'),
    ],
    'other': [
        (r'Kernel panic.*', 'CRITICAL'),
        (r'BUG:.*', 'CRITICAL'),
        (r'WARNING:.*', 'WARNING'),
        (r'Call Trace:.*', 'WARNING'),
    ],
}


def run_dmesg(since_time=None, follow=False):
    """Execute dmesg command and return output"""
    cmd = ['dmesg', '-T']  # -T for human-readable timestamps

    if since_time:
        cmd.extend(['--since', since_time])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            # Try without -T flag (older dmesg versions)
            cmd = ['dmesg']
            if since_time:
                cmd.extend(['--since', since_time])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

        return result.returncode, result.stdout, result.stderr

    except FileNotFoundError:
        print("Error: 'dmesg' command not found", file=sys.stderr)
        print("Install with: sudo apt-get install util-linux", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print("Error: dmesg command timed out", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error running dmesg: {e}", file=sys.stderr)
        sys.exit(1)


def analyze_dmesg(output, verbose=False):
    """Analyze dmesg output for errors and warnings"""
    findings = defaultdict(list)

    for line in output.split('\n'):
        if not line.strip():
            continue

        # Check each category
        for category, patterns in ERROR_PATTERNS.items():
            for pattern, severity in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    findings[category].append({
                        'severity': severity,
                        'message': line.strip(),
                        'pattern': pattern,
                    })
                    break  # Only match first pattern per line

    return findings


def output_plain(findings, warn_only=False, verbose=False):
    """Output findings in plain text format"""
    if not findings:
        if not warn_only:
            print("No kernel errors or warnings detected")
        return

    # Sort by severity (CRITICAL first)
    categories_sorted = sorted(
        findings.items(),
        key=lambda x: (
            min((f['severity'] for f in x[1]), default='WARNING') != 'CRITICAL',
            x[0]
        )
    )

    for category, issues in categories_sorted:
        if not issues:
            continue

        critical_count = sum(1 for i in issues if i['severity'] == 'CRITICAL')
        warning_count = sum(1 for i in issues if i['severity'] == 'WARNING')

        print(f"\n{category.upper()}: {len(issues)} issue(s) "
              f"({critical_count} critical, {warning_count} warnings)")
        print("-" * 60)

        for issue in issues:
            severity_marker = "!!!" if issue['severity'] == 'CRITICAL' else "  "
            if verbose:
                print(f"{severity_marker} [{issue['severity']}] {issue['message']}")
            else:
                # Truncate long messages
                msg = issue['message']
                if len(msg) > 100:
                    msg = msg[:97] + "..."
                print(f"{severity_marker} {msg}")


def output_json(findings):
    """Output findings in JSON format"""
    output = {
        'summary': {
            'total_categories': len(findings),
            'total_issues': sum(len(issues) for issues in findings.values()),
            'critical_count': sum(
                1 for issues in findings.values()
                for i in issues if i['severity'] == 'CRITICAL'
            ),
            'warning_count': sum(
                1 for issues in findings.values()
                for i in issues if i['severity'] == 'WARNING'
            ),
        },
        'findings': {}
    }

    for category, issues in findings.items():
        output['findings'][category] = [
            {
                'severity': i['severity'],
                'message': i['message'],
            }
            for i in issues
        ]

    print(json.dumps(output, indent=2))


def output_table(findings, warn_only=False, verbose=False):
    """Output findings in table format"""
    if not findings:
        if not warn_only:
            print("No kernel errors or warnings detected")
        return

    # Header
    print(f"{'Category':<12} {'Severity':<10} {'Count':<8} {'Message':<60}")
    print("=" * 90)

    for category, issues in sorted(findings.items()):
        if not issues:
            continue

        # Group by severity
        severity_groups = defaultdict(list)
        for issue in issues:
            severity_groups[issue['severity']].append(issue)

        for severity, severity_issues in sorted(severity_groups.items(), reverse=True):
            msg = severity_issues[0]['message']
            if len(msg) > 60:
                msg = msg[:57] + "..."

            print(f"{category:<12} {severity:<10} {len(severity_issues):<8} {msg:<60}")

            if verbose and len(severity_issues) > 1:
                for issue in severity_issues[1:]:
                    msg = issue['message']
                    if len(msg) > 60:
                        msg = msg[:57] + "..."
                    print(f"{'':<12} {'':<10} {'':<8} {msg:<60}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Analyze kernel messages (dmesg) for hardware errors and warnings',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Analyze all kernel messages
  %(prog)s --since "1 hour ago"     # Only recent messages
  %(prog)s --format json            # JSON output
  %(prog)s --warn-only              # Only show issues
  %(prog)s -v                       # Verbose output with full messages

Categories checked:
  - Disk I/O errors (ATA, SCSI, NVMe)
  - Memory errors (ECC, EDAC)
  - PCIe errors (AER, link issues)
  - CPU errors (MCE, thermal)
  - Network errors (link down, timeouts)
  - Filesystem errors (ext4, xfs, btrfs)
  - RAID errors (md)
  - Thermal warnings
        """
    )

    parser.add_argument(
        '--since',
        help='Only show messages since specified time (e.g., "1 hour ago", "2023-01-01 10:00")'
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
        help='Show full error messages and details'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show issues, suppress "no errors" message'
    )

    args = parser.parse_args()

    # Run dmesg
    returncode, stdout, stderr = run_dmesg(since_time=args.since)

    if returncode != 0 and stderr:
        print(f"Warning: dmesg returned errors: {stderr}", file=sys.stderr)

    # Analyze output
    findings = analyze_dmesg(stdout, verbose=args.verbose)

    # Output results
    if args.format == 'json':
        output_json(findings)
    elif args.format == 'table':
        output_table(findings, warn_only=args.warn_only, verbose=args.verbose)
    else:  # plain
        output_plain(findings, warn_only=args.warn_only, verbose=args.verbose)

    # Exit based on findings
    has_critical = any(
        i['severity'] == 'CRITICAL'
        for issues in findings.values()
        for i in issues
    )
    has_warnings = any(
        i['severity'] == 'WARNING'
        for issues in findings.values()
        for i in issues
    )

    if has_critical or has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
