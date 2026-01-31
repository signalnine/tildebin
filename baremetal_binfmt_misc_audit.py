#!/usr/bin/env python3
"""
Audit binfmt_misc registered binary format handlers for security.

Checks the kernel's binfmt_misc filesystem for registered binary format handlers
that allow executing non-native binaries (e.g., Windows executables via Wine,
QEMU user-mode emulation, Java bytecode). While useful for development and
cross-compilation, these can be security concerns on production servers.

Key checks:
- List all registered binary format handlers
- Identify handlers that could execute unexpected file types
- Detect QEMU user-mode handlers (potential for running untrusted binaries)
- Check for Wine handlers (Windows binary execution)
- Validate handler interpreter paths exist and are secure
- Flag handlers using 'F' (fix-binary) flag that may survive container escapes

Security concerns with binfmt_misc:
- Attackers can exploit registered handlers to execute malicious binaries
- QEMU user-mode allows running foreign architecture binaries
- Wine allows executing Windows malware
- 'F' flag handlers persist interpreter path at registration (not at exec time)
- Misconfigured handlers could allow privilege escalation

Useful for:
- Security auditing of production servers
- Container host security assessment
- Compliance checking (CIS, STIG)
- Identifying unnecessary attack surface
- Fleet-wide security posture assessment

Exit codes:
    0 - No binfmt_misc handlers registered or all handlers are expected
    1 - Unexpected or potentially risky handlers detected
    2 - Usage error or binfmt_misc not available
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


def read_file(path):
    """Read a file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError, PermissionError):
        return None


def check_binfmt_misc_mounted():
    """Check if binfmt_misc filesystem is mounted."""
    binfmt_path = '/proc/sys/fs/binfmt_misc'

    if not os.path.isdir(binfmt_path):
        return False, "binfmt_misc not mounted"

    status = read_file(os.path.join(binfmt_path, 'status'))
    if status is None:
        return False, "Cannot read binfmt_misc status"

    return status == 'enabled', f"binfmt_misc status: {status}"


def parse_binfmt_entry(name, content):
    """Parse a binfmt_misc entry file content.

    Format:
        enabled/disabled
        interpreter /path/to/interpreter
        flags: OCF
        offset N
        magic XXXX
        mask XXXX
    """
    entry = {
        'name': name,
        'enabled': False,
        'interpreter': None,
        'flags': '',
        'offset': 0,
        'magic': None,
        'mask': None,
        'extension': None,
        'type': None,  # 'M' for magic, 'E' for extension
    }

    lines = content.split('\n')

    for line in lines:
        line = line.strip()
        if line == 'enabled':
            entry['enabled'] = True
        elif line == 'disabled':
            entry['enabled'] = False
        elif line.startswith('interpreter '):
            entry['interpreter'] = line.split(' ', 1)[1]
        elif line.startswith('flags: '):
            entry['flags'] = line.split(': ', 1)[1]
        elif line.startswith('offset '):
            try:
                entry['offset'] = int(line.split(' ', 1)[1])
            except ValueError:
                pass
        elif line.startswith('magic '):
            entry['magic'] = line.split(' ', 1)[1]
            entry['type'] = 'M'
        elif line.startswith('mask '):
            entry['mask'] = line.split(' ', 1)[1]
        elif line.startswith('extension '):
            entry['extension'] = line.split(' ', 1)[1]
            entry['type'] = 'E'

    return entry


def get_binfmt_entries():
    """Get all registered binfmt_misc entries."""
    binfmt_path = '/proc/sys/fs/binfmt_misc'
    entries = []

    if not os.path.isdir(binfmt_path):
        return entries

    for name in os.listdir(binfmt_path):
        if name in ('register', 'status'):
            continue

        entry_path = os.path.join(binfmt_path, name)
        if os.path.isfile(entry_path):
            content = read_file(entry_path)
            if content:
                entry = parse_binfmt_entry(name, content)
                entries.append(entry)

    return entries


def check_interpreter_security(interpreter):
    """Check security aspects of an interpreter path."""
    issues = []

    if not interpreter:
        issues.append("No interpreter specified")
        return issues

    # Check if interpreter exists
    if not os.path.isfile(interpreter):
        issues.append(f"Interpreter not found: {interpreter}")
        return issues

    # Check if interpreter is in a suspicious location
    suspicious_paths = ['/tmp', '/var/tmp', '/dev/shm', '/home']
    for path in suspicious_paths:
        if interpreter.startswith(path):
            issues.append(f"Interpreter in suspicious location: {path}")

    # Check interpreter permissions
    try:
        stat = os.stat(interpreter)
        mode = stat.st_mode

        # Check if world-writable
        if mode & 0o002:
            issues.append("Interpreter is world-writable")

        # Check if owned by root
        if stat.st_uid != 0:
            issues.append(f"Interpreter not owned by root (uid={stat.st_uid})")

    except OSError as e:
        issues.append(f"Cannot stat interpreter: {e}")

    return issues


def categorize_handler(entry):
    """Categorize a binfmt handler by its purpose."""
    name = entry['name'].lower()
    interpreter = (entry['interpreter'] or '').lower()

    categories = []

    # QEMU user-mode emulation
    if 'qemu' in name or 'qemu' in interpreter:
        categories.append('qemu')

    # Wine (Windows binary execution)
    if 'wine' in name or 'wine' in interpreter or 'windows' in name:
        categories.append('wine')

    # Java
    if 'java' in name or 'java' in interpreter or entry.get('magic', '').startswith('cafebabe'):
        categories.append('java')

    # Python
    if 'python' in name or 'python' in interpreter:
        categories.append('python')

    # Mono (.NET)
    if 'mono' in name or 'mono' in interpreter or 'cli' in name:
        categories.append('mono')

    # Misc scripts
    if 'script' in name or interpreter.endswith('sh'):
        categories.append('script')

    # Container-related (buildah, podman)
    if 'container' in name or 'buildah' in interpreter or 'podman' in interpreter:
        categories.append('container')

    if not categories:
        categories.append('unknown')

    return categories


def analyze_handler_risk(entry):
    """Analyze security risk of a binfmt handler."""
    risks = []
    categories = categorize_handler(entry)

    # QEMU is high risk on production servers
    if 'qemu' in categories:
        risks.append({
            'severity': 'high',
            'message': 'QEMU user-mode emulation allows running foreign architecture binaries',
        })

    # Wine is high risk
    if 'wine' in categories:
        risks.append({
            'severity': 'high',
            'message': 'Wine allows executing Windows binaries including potential malware',
        })

    # 'F' flag (fix-binary) has security implications
    if 'F' in entry.get('flags', ''):
        risks.append({
            'severity': 'medium',
            'message': "Handler uses 'F' (fix-binary) flag - interpreter path fixed at registration",
        })

    # 'C' flag (credentials) runs with caller's credentials
    if 'C' in entry.get('flags', ''):
        risks.append({
            'severity': 'low',
            'message': "Handler uses 'C' flag - uses caller's credentials",
        })

    # 'O' flag (open-binary) may have security implications
    if 'O' in entry.get('flags', ''):
        risks.append({
            'severity': 'low',
            'message': "Handler uses 'O' flag - passes open file descriptor",
        })

    # Check interpreter security
    interpreter_issues = check_interpreter_security(entry.get('interpreter'))
    for issue in interpreter_issues:
        risks.append({
            'severity': 'medium',
            'message': issue,
        })

    # Unknown handlers should be investigated
    if 'unknown' in categories and entry.get('enabled'):
        risks.append({
            'severity': 'medium',
            'message': 'Unknown handler type - should be investigated',
        })

    return risks


def analyze_all_handlers(entries, allowed_handlers=None):
    """Analyze all binfmt handlers and return findings."""
    if allowed_handlers is None:
        allowed_handlers = set()
    else:
        allowed_handlers = set(allowed_handlers)

    findings = []
    issues = []
    warnings = []
    info_msgs = []

    if not entries:
        info_msgs.append("No binfmt_misc handlers registered")
        return {
            'status': 'healthy',
            'findings': findings,
            'issues': issues,
            'warnings': warnings,
            'info': info_msgs,
        }

    info_msgs.append(f"Found {len(entries)} registered handler(s)")

    enabled_count = sum(1 for e in entries if e.get('enabled'))
    if enabled_count > 0:
        info_msgs.append(f"Enabled handlers: {enabled_count}")

    for entry in entries:
        categories = categorize_handler(entry)
        risks = analyze_handler_risk(entry)

        finding = {
            'name': entry['name'],
            'enabled': entry.get('enabled', False),
            'interpreter': entry.get('interpreter'),
            'flags': entry.get('flags', ''),
            'categories': categories,
            'risks': risks,
            'allowed': entry['name'] in allowed_handlers,
        }
        findings.append(finding)

        # Skip allowed handlers
        if entry['name'] in allowed_handlers:
            continue

        # Only flag enabled handlers
        if not entry.get('enabled'):
            continue

        # Categorize by severity
        for risk in risks:
            msg = f"{entry['name']}: {risk['message']}"
            if risk['severity'] == 'high':
                issues.append(msg)
            elif risk['severity'] == 'medium':
                warnings.append(msg)
            else:
                info_msgs.append(msg)

    # Determine overall status
    if issues:
        status = 'critical'
    elif warnings:
        status = 'warning'
    else:
        status = 'healthy'

    return {
        'status': status,
        'findings': findings,
        'issues': issues,
        'warnings': warnings,
        'info': info_msgs,
    }


def format_plain(entries, analysis, verbose=False):
    """Format output as plain text."""
    lines = []

    lines.append("Binfmt_misc Security Audit")
    lines.append("=" * 40)
    lines.append("")

    # Summary
    enabled = [e for e in entries if e.get('enabled')]
    lines.append(f"Registered handlers: {len(entries)}")
    lines.append(f"Enabled handlers: {len(enabled)}")
    lines.append("")

    # Handler details
    if entries:
        lines.append("Handlers:")
        for entry in entries:
            status = "ENABLED" if entry.get('enabled') else "disabled"
            interp = entry.get('interpreter', 'N/A')
            flags = entry.get('flags', '')
            flag_str = f" [{flags}]" if flags else ""

            lines.append(f"  [{status}] {entry['name']}{flag_str}")
            if verbose:
                lines.append(f"           Interpreter: {interp}")
                cats = categorize_handler(entry)
                lines.append(f"           Categories: {', '.join(cats)}")
        lines.append("")

    # Issues
    if analysis['issues']:
        lines.append("ISSUES (High Risk):")
        for issue in analysis['issues']:
            lines.append(f"  [!] {issue}")
        lines.append("")

    if analysis['warnings']:
        lines.append("WARNINGS (Medium Risk):")
        for warning in analysis['warnings']:
            lines.append(f"  [*] {warning}")
        lines.append("")

    if verbose and analysis['info']:
        lines.append("INFO:")
        for info in analysis['info']:
            lines.append(f"  [i] {info}")
        lines.append("")

    # Summary
    status = analysis['status']
    if status == 'healthy':
        lines.append("[OK] No security concerns detected")
    elif status == 'warning':
        lines.append("[WARNING] Potential security concerns detected")
    else:
        lines.append("[CRITICAL] Security issues detected")

    return "\n".join(lines)


def format_json(entries, analysis, binfmt_status):
    """Format output as JSON."""
    return json.dumps({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'binfmt_misc_enabled': binfmt_status[0],
        'handlers': entries,
        'analysis': {
            'status': analysis['status'],
            'findings': analysis['findings'],
            'issues': analysis['issues'],
            'warnings': analysis['warnings'],
            'info': analysis['info'],
        },
        'summary': {
            'total_handlers': len(entries),
            'enabled_handlers': sum(1 for e in entries if e.get('enabled')),
            'issue_count': len(analysis['issues']),
            'warning_count': len(analysis['warnings']),
        },
        'healthy': analysis['status'] == 'healthy',
    }, indent=2)


def format_table(entries, analysis):
    """Format output as table."""
    lines = []

    lines.append("+" + "-" * 70 + "+")
    lines.append("| Binfmt_misc Security Audit" + " " * 43 + "|")
    lines.append("+" + "-" * 70 + "+")

    lines.append(f"| {'Handler':<20} | {'Status':<8} | {'Flags':<6} | {'Categories':<25} |")
    lines.append("+" + "-" * 70 + "+")

    for entry in entries:
        name = entry['name'][:20]
        status = "ENABLED" if entry.get('enabled') else "off"
        flags = entry.get('flags', '')[:6]
        cats = ', '.join(categorize_handler(entry))[:25]
        lines.append(f"| {name:<20} | {status:<8} | {flags:<6} | {cats:<25} |")

    lines.append("+" + "-" * 70 + "+")

    status_str = analysis['status'].upper()
    issue_count = len(analysis['issues']) + len(analysis['warnings'])
    if issue_count > 0:
        status_line = f"Status: {status_str} ({issue_count} finding(s))"
    else:
        status_line = f"Status: {status_str}"
    lines.append(f"| {status_line:<68} |")
    lines.append("+" + "-" * 70 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Audit binfmt_misc registered binary format handlers for security',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Audit all binfmt handlers
  %(prog)s --format json        # JSON output for monitoring systems
  %(prog)s --verbose            # Show detailed handler information
  %(prog)s --warn-only          # Only show warnings and errors
  %(prog)s --allow qemu-arm     # Allow specific handler names

Common binfmt_misc handlers:
  qemu-*     - QEMU user-mode emulation (cross-architecture execution)
  wine       - Windows binary execution via Wine
  java       - Java bytecode execution
  mono       - .NET/Mono binary execution

Security concerns:
  - QEMU handlers allow running foreign architecture binaries
  - Wine handlers allow executing Windows executables
  - 'F' flag fixes interpreter path at registration (container escape risk)
  - Unexpected handlers may indicate compromise

Exit codes:
  0 - No security concerns (or no handlers registered)
  1 - Security concerns detected (unexpected handlers, risks)
  2 - Usage error or binfmt_misc not available
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if warnings or issues detected'
    )

    parser.add_argument(
        '--allow',
        nargs='+',
        metavar='NAME',
        help='Handler names to allow (skip risk analysis for these)'
    )

    args = parser.parse_args()

    # Check if binfmt_misc is available
    binfmt_status = check_binfmt_misc_mounted()
    if not binfmt_status[0]:
        if args.format == 'json':
            print(json.dumps({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'binfmt_misc_enabled': False,
                'handlers': [],
                'analysis': {
                    'status': 'healthy',
                    'issues': [],
                    'warnings': [],
                    'info': [binfmt_status[1]],
                },
                'healthy': True,
            }, indent=2))
            sys.exit(0)
        else:
            print(f"binfmt_misc: {binfmt_status[1]}")
            print("[OK] No binfmt_misc handlers to audit")
            sys.exit(0)

    # Get all entries
    entries = get_binfmt_entries()

    # Analyze
    analysis = analyze_all_handlers(entries, args.allow)

    # Check if we should output (respecting --warn-only)
    has_findings = analysis['issues'] or analysis['warnings']
    if args.warn_only and not has_findings:
        sys.exit(0)

    # Format and output
    if args.format == 'json':
        output = format_json(entries, analysis, binfmt_status)
    elif args.format == 'table':
        output = format_table(entries, analysis)
    else:
        output = format_plain(entries, analysis, args.verbose)

    print(output)

    # Exit code based on status
    if analysis['status'] == 'critical':
        sys.exit(1)
    elif analysis['status'] == 'warning':
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
