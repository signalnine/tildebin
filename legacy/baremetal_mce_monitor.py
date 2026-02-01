#!/usr/bin/env python3
"""
Monitor Machine Check Exceptions (MCE) for hardware fault detection.

Machine Check Exceptions are hardware-level error reports from the CPU
indicating serious hardware issues such as:
- CPU cache parity/ECC errors
- Memory bus errors
- System bus errors
- Thermal events (CPU overheating)
- Internal CPU errors

This script parses MCE logs from multiple sources:
- /sys/devices/system/machinecheck/ - sysfs MCE data
- mcelog daemon output (if available)
- journalctl/dmesg for MCE-related kernel messages

Critical for detecting failing CPUs, memory controllers, and system buses
before they cause data corruption or system crashes.

Exit codes:
    0 - No MCE errors detected
    1 - MCE errors or warnings detected
    2 - Usage error or missing dependencies
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime


def read_sysfs_file(path):
    """Read a sysfs file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError, PermissionError):
        return None


def check_mce_sysfs_available():
    """Check if MCE sysfs interface is available."""
    return os.path.exists('/sys/devices/system/machinecheck')


def get_cpu_mce_info():
    """
    Get MCE information from sysfs for all CPUs.

    Returns list of dicts with CPU MCE configuration and bank info.
    """
    base_path = '/sys/devices/system/machinecheck'
    if not os.path.exists(base_path):
        return []

    cpu_info = []
    cpu_dirs = glob.glob(f'{base_path}/machinecheck[0-9]*')

    for cpu_dir in sorted(cpu_dirs):
        cpu_name = os.path.basename(cpu_dir)
        cpu_num = cpu_name.replace('machinecheck', '')

        info = {
            'cpu': int(cpu_num),
            'banks': [],
            'trigger': read_sysfs_file(f'{cpu_dir}/trigger'),
            'monarch_timeout': read_sysfs_file(f'{cpu_dir}/monarch_timeout'),
            'tolerant': read_sysfs_file(f'{cpu_dir}/tolerant'),
            'check_interval': read_sysfs_file(f'{cpu_dir}/check_interval'),
        }

        # Get bank information
        bank_files = glob.glob(f'{cpu_dir}/bank[0-9]*')
        for bank_file in sorted(bank_files):
            bank_name = os.path.basename(bank_file)
            bank_num = bank_name.replace('bank', '')
            bank_value = read_sysfs_file(bank_file)

            if bank_value:
                info['banks'].append({
                    'bank': int(bank_num),
                    'control': bank_value
                })

        cpu_info.append(info)

    return cpu_info


def get_ras_pages():
    """
    Get RAS (Reliability, Availability, Serviceability) bad page info.

    Returns list of memory pages that have been retired due to errors.
    """
    ras_path = '/sys/kernel/ras/bad_pages'
    if not os.path.exists(ras_path):
        return []

    content = read_sysfs_file(ras_path)
    if not content:
        return []

    bad_pages = []
    for line in content.split('\n'):
        if line.strip():
            bad_pages.append(line.strip())

    return bad_pages


def run_command(cmd, timeout=10):
    """Execute a command and return output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def check_mcelog_available():
    """Check if mcelog daemon/tool is available."""
    returncode, _, _ = run_command(['which', 'mcelog'])
    return returncode == 0


def get_mcelog_status():
    """
    Get status from mcelog daemon if available.

    Returns dict with mcelog status info or None if not available.
    """
    if not check_mcelog_available():
        return None

    # Try to get mcelog --client status
    returncode, stdout, stderr = run_command(['mcelog', '--client'], timeout=5)

    if returncode != 0:
        # mcelog daemon might not be running
        return {'available': False, 'reason': 'mcelog daemon not running'}

    return {
        'available': True,
        'output': stdout.strip() if stdout else None
    }


def parse_dmesg_mce():
    """
    Parse dmesg for MCE-related messages.

    Returns list of MCE events found in kernel log.
    """
    mce_patterns = [
        (r'\[Hardware Error\].*', 'hardware_error'),
        (r'mce:.*', 'mce'),
        (r'MCE.*error.*', 'mce_error'),
        (r'Machine check events logged', 'mce_logged'),
        (r'CPU.*Machine Check Exception.*', 'cpu_mce'),
        (r'Bank\s+\d+:.*', 'bank_error'),
        (r'CMCI storm.*', 'cmci_storm'),
        (r'Corrected error.*', 'corrected_error'),
        (r'Uncorrected error.*', 'uncorrected_error'),
        (r'Fatal error.*', 'fatal_error'),
    ]

    returncode, stdout, stderr = run_command(['dmesg', '-T'], timeout=10)

    if returncode != 0:
        # Try without -T flag
        returncode, stdout, stderr = run_command(['dmesg'], timeout=10)

    if returncode != 0:
        return []

    mce_events = []
    for line in stdout.split('\n'):
        for pattern, event_type in mce_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                mce_events.append({
                    'type': event_type,
                    'message': line.strip(),
                    'severity': classify_severity(event_type, line)
                })
                break

    return mce_events


def parse_journalctl_mce():
    """
    Parse journalctl for MCE-related messages.

    Returns list of MCE events from systemd journal.
    """
    returncode, stdout, stderr = run_command(
        ['journalctl', '-k', '--no-pager', '-p', 'err', '--since', '24 hours ago'],
        timeout=15
    )

    if returncode != 0:
        return []

    mce_patterns = [
        r'mce:',
        r'Machine check',
        r'\[Hardware Error\]',
        r'CMCI',
        r'Corrected error',
        r'Uncorrected error',
    ]

    mce_events = []
    for line in stdout.split('\n'):
        for pattern in mce_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                mce_events.append({
                    'type': 'journal',
                    'message': line.strip(),
                    'severity': 'WARNING' if 'corrected' in line.lower() else 'CRITICAL'
                })
                break

    return mce_events


def classify_severity(event_type, message):
    """Classify the severity of an MCE event."""
    message_lower = message.lower()

    if any(term in message_lower for term in ['fatal', 'uncorrected', 'panic']):
        return 'CRITICAL'
    elif any(term in message_lower for term in ['corrected', 'cmci']):
        return 'WARNING'
    elif event_type in ['uncorrected_error', 'fatal_error']:
        return 'CRITICAL'
    elif event_type in ['corrected_error', 'cmci_storm']:
        return 'WARNING'
    else:
        return 'INFO'


def get_cpu_microcode_info():
    """
    Get CPU microcode version info.

    Outdated microcode can cause MCE issues on some platforms.
    """
    microcode_info = []

    # Try to read from /proc/cpuinfo
    try:
        with open('/proc/cpuinfo', 'r') as f:
            content = f.read()

        current_cpu = None
        for line in content.split('\n'):
            if line.startswith('processor'):
                match = re.search(r':\s*(\d+)', line)
                if match:
                    current_cpu = int(match.group(1))
            elif line.startswith('microcode') and current_cpu is not None:
                match = re.search(r':\s*(0x[0-9a-fA-F]+|\d+)', line)
                if match:
                    microcode_info.append({
                        'cpu': current_cpu,
                        'microcode': match.group(1)
                    })
    except (IOError, OSError):
        pass

    return microcode_info


def analyze_mce_data(cpu_info, bad_pages, dmesg_events, journal_events, mcelog_status):
    """
    Analyze all MCE data and produce summary.

    Returns dict with analysis results and overall status.
    """
    analysis = {
        'status': 'OK',
        'issues': [],
        'summary': {
            'cpus_monitored': len(cpu_info),
            'bad_pages': len(bad_pages),
            'dmesg_events': len(dmesg_events),
            'journal_events': len(journal_events),
            'mcelog_available': mcelog_status is not None and mcelog_status.get('available', False),
        }
    }

    # Check for bad pages (retired memory)
    if bad_pages:
        analysis['status'] = 'WARNING'
        analysis['issues'].append({
            'type': 'bad_pages',
            'severity': 'WARNING',
            'message': f'{len(bad_pages)} memory page(s) retired due to errors'
        })

    # Check dmesg events
    critical_dmesg = [e for e in dmesg_events if e['severity'] == 'CRITICAL']
    warning_dmesg = [e for e in dmesg_events if e['severity'] == 'WARNING']

    if critical_dmesg:
        analysis['status'] = 'CRITICAL'
        analysis['issues'].append({
            'type': 'dmesg_critical',
            'severity': 'CRITICAL',
            'message': f'{len(critical_dmesg)} critical MCE event(s) in dmesg',
            'events': critical_dmesg[:5]  # First 5 events
        })

    if warning_dmesg:
        if analysis['status'] == 'OK':
            analysis['status'] = 'WARNING'
        analysis['issues'].append({
            'type': 'dmesg_warning',
            'severity': 'WARNING',
            'message': f'{len(warning_dmesg)} warning MCE event(s) in dmesg',
            'events': warning_dmesg[:5]
        })

    # Check journal events
    critical_journal = [e for e in journal_events if e['severity'] == 'CRITICAL']
    if critical_journal:
        analysis['status'] = 'CRITICAL'
        analysis['issues'].append({
            'type': 'journal_critical',
            'severity': 'CRITICAL',
            'message': f'{len(critical_journal)} critical event(s) in journal',
            'events': critical_journal[:5]
        })

    return analysis


def output_plain(analysis, cpu_info, bad_pages, verbose=False, warn_only=False):
    """Output analysis results in plain text format."""
    lines = []

    if not warn_only or analysis['status'] != 'OK':
        lines.append("=== MCE Monitor Summary ===")
        lines.append(f"Status: {analysis['status']}")
        lines.append(f"CPUs Monitored: {analysis['summary']['cpus_monitored']}")
        lines.append(f"Bad Memory Pages: {analysis['summary']['bad_pages']}")
        lines.append(f"MCE Events (dmesg): {analysis['summary']['dmesg_events']}")
        lines.append(f"MCE Events (journal): {analysis['summary']['journal_events']}")
        lines.append(f"mcelog Available: {'Yes' if analysis['summary']['mcelog_available'] else 'No'}")
        lines.append("")

    # Issues
    if analysis['issues']:
        lines.append("=== Issues Detected ===")
        for issue in analysis['issues']:
            severity_marker = "!!!" if issue['severity'] == 'CRITICAL' else " ! "
            lines.append(f"{severity_marker} [{issue['severity']}] {issue['message']}")

            if verbose and 'events' in issue:
                for event in issue['events']:
                    msg = event['message']
                    if len(msg) > 100:
                        msg = msg[:97] + "..."
                    lines.append(f"        {msg}")
        lines.append("")

    # Bad pages details
    if bad_pages and (verbose or not warn_only):
        lines.append("=== Retired Memory Pages ===")
        for page in bad_pages[:10]:  # Limit to first 10
            lines.append(f"  {page}")
        if len(bad_pages) > 10:
            lines.append(f"  ... and {len(bad_pages) - 10} more")
        lines.append("")

    # CPU MCE config (verbose only)
    if verbose and cpu_info:
        lines.append("=== CPU MCE Configuration ===")
        for cpu in cpu_info[:4]:  # Limit to first 4 CPUs
            lines.append(f"CPU {cpu['cpu']}:")
            lines.append(f"  Tolerant Level: {cpu.get('tolerant', 'N/A')}")
            lines.append(f"  Check Interval: {cpu.get('check_interval', 'N/A')} seconds")
            lines.append(f"  MCE Banks: {len(cpu.get('banks', []))}")
        if len(cpu_info) > 4:
            lines.append(f"  ... and {len(cpu_info) - 4} more CPUs")
        lines.append("")

    if not lines:
        if warn_only:
            return "No MCE issues detected."
        else:
            return "MCE monitoring active. No issues detected."

    return '\n'.join(lines)


def output_json(analysis, cpu_info, bad_pages, microcode_info, warn_only=False):
    """Output analysis results in JSON format."""
    result = {
        'summary': analysis['summary'],
        'status': analysis['status'],
        'issues': analysis['issues'],
        'bad_pages': bad_pages,
        'microcode': microcode_info[:8] if microcode_info else [],  # Limit output
    }

    if not warn_only:
        result['cpu_mce_config'] = [
            {
                'cpu': cpu['cpu'],
                'tolerant': cpu.get('tolerant'),
                'check_interval': cpu.get('check_interval'),
                'bank_count': len(cpu.get('banks', []))
            }
            for cpu in cpu_info[:16]  # Limit to first 16 CPUs
        ]

    return json.dumps(result, indent=2)


def output_table(analysis, cpu_info, bad_pages, warn_only=False):
    """Output analysis results in table format."""
    lines = []

    if not warn_only or analysis['status'] != 'OK':
        lines.append("MCE MONITOR STATUS")
        lines.append("-" * 60)
        lines.append(f"{'Metric':<25} {'Value':<20} {'Status':<15}")
        lines.append("-" * 60)
        lines.append(f"{'Overall Status':<25} {analysis['status']:<20} {'':<15}")
        lines.append(f"{'CPUs Monitored':<25} {analysis['summary']['cpus_monitored']:<20} {'OK':<15}")
        lines.append(f"{'Bad Memory Pages':<25} {analysis['summary']['bad_pages']:<20} "
                    f"{'WARNING' if analysis['summary']['bad_pages'] > 0 else 'OK':<15}")
        lines.append(f"{'MCE Events (dmesg)':<25} {analysis['summary']['dmesg_events']:<20} "
                    f"{'WARNING' if analysis['summary']['dmesg_events'] > 0 else 'OK':<15}")
        lines.append(f"{'mcelog Available':<25} "
                    f"{'Yes' if analysis['summary']['mcelog_available'] else 'No':<20} "
                    f"{'OK':<15}")
        lines.append("")

    if analysis['issues']:
        lines.append("ISSUES")
        lines.append("-" * 60)
        lines.append(f"{'Severity':<12} {'Type':<20} {'Details':<28}")
        lines.append("-" * 60)
        for issue in analysis['issues']:
            lines.append(f"{issue['severity']:<12} {issue['type']:<20} {issue['message'][:28]:<28}")

    if not lines:
        return "No MCE issues detected." if warn_only else "MCE monitoring active. No issues detected."

    return '\n'.join(lines)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor Machine Check Exceptions (MCE) for hardware fault detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Check MCE status
  %(prog)s --format json      # JSON output for monitoring
  %(prog)s --warn-only        # Only show issues
  %(prog)s -v                 # Verbose output with CPU config

What MCE monitors:
  - CPU cache parity/ECC errors
  - Memory controller errors
  - System bus errors
  - Internal CPU errors
  - Thermal throttling events

Data sources:
  - /sys/devices/system/machinecheck/ - MCE sysfs interface
  - /sys/kernel/ras/bad_pages - Retired memory pages
  - dmesg - Kernel ring buffer MCE messages
  - journalctl - Systemd journal hardware errors
  - mcelog daemon (optional)

Exit codes:
  0 - No MCE errors detected
  1 - MCE warnings or errors detected
  2 - Usage error or missing dependencies
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
        help='Show detailed MCE configuration and all events'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show issues, suppress OK status messages'
    )

    args = parser.parse_args()

    # Gather MCE data from all sources
    cpu_info = get_cpu_mce_info()
    bad_pages = get_ras_pages()
    dmesg_events = parse_dmesg_mce()
    journal_events = parse_journalctl_mce()
    mcelog_status = get_mcelog_status()
    microcode_info = get_cpu_microcode_info()

    # Analyze collected data
    analysis = analyze_mce_data(
        cpu_info, bad_pages, dmesg_events, journal_events, mcelog_status
    )

    # Output results
    if args.format == 'json':
        output = output_json(analysis, cpu_info, bad_pages, microcode_info, args.warn_only)
    elif args.format == 'table':
        output = output_table(analysis, cpu_info, bad_pages, args.warn_only)
    else:
        output = output_plain(analysis, cpu_info, bad_pages, args.verbose, args.warn_only)

    print(output)

    # Exit based on analysis
    if analysis['status'] == 'CRITICAL':
        sys.exit(1)
    elif analysis['status'] == 'WARNING':
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
