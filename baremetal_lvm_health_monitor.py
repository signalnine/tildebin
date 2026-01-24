#!/usr/bin/env python3
"""
Monitor LVM (Logical Volume Manager) health and configuration.

This script monitors LVM logical volumes, volume groups, and physical volumes
to detect health issues and potential problems. Useful for:

- Detecting thin pool near-exhaustion before writes fail
- Finding aging snapshots consuming space
- Identifying volume groups near capacity
- Monitoring physical volume health and free space
- Detecting LVM configuration issues

The script uses lvs, vgs, and pvs commands to gather LVM status and reports
issues based on configurable thresholds.

Exit codes:
    0 - All LVM components healthy, no issues detected
    1 - Warnings or errors found (near capacity, aging snapshots, etc.)
    2 - Usage error, LVM tools not installed, or no LVM configured
"""

import argparse
import sys
import json
import subprocess
import re
from datetime import datetime


def run_command(cmd):
    """Execute shell command and return result.

    Args:
        cmd: List of command arguments

    Returns:
        tuple: (return_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def check_lvm_available():
    """Check if LVM tools are available.

    Returns:
        bool: True if lvm commands are available
    """
    returncode, _, _ = run_command(['which', 'lvs'])
    return returncode == 0


def get_logical_volumes():
    """Get logical volume information using lvs.

    Returns:
        list: List of LV dictionaries or None on error
    """
    # Get LV info in JSON-like format
    cmd = [
        'lvs', '--noheadings', '--separator', '|',
        '-o', 'lv_name,vg_name,lv_size,data_percent,metadata_percent,'
              'lv_attr,origin,snap_percent,pool_lv,lv_time',
        '--units', 'b'
    ]

    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return None

    lvs = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue

        parts = [p.strip() for p in line.split('|')]
        if len(parts) < 10:
            continue

        lv = {
            'name': parts[0],
            'vg': parts[1],
            'size': parts[2],
            'data_percent': parse_percent(parts[3]),
            'metadata_percent': parse_percent(parts[4]),
            'attr': parts[5],
            'origin': parts[6] if parts[6] else None,
            'snap_percent': parse_percent(parts[7]),
            'pool_lv': parts[8] if parts[8] else None,
            'time': parts[9] if parts[9] else None
        }

        # Parse LV type from attributes
        lv['type'] = parse_lv_type(lv['attr'])

        lvs.append(lv)

    return lvs


def get_volume_groups():
    """Get volume group information using vgs.

    Returns:
        list: List of VG dictionaries or None on error
    """
    cmd = [
        'vgs', '--noheadings', '--separator', '|',
        '-o', 'vg_name,vg_size,vg_free,pv_count,lv_count,vg_attr',
        '--units', 'b'
    ]

    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return None

    vgs = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue

        parts = [p.strip() for p in line.split('|')]
        if len(parts) < 6:
            continue

        size_bytes = parse_size(parts[1])
        free_bytes = parse_size(parts[2])
        used_bytes = size_bytes - free_bytes if size_bytes and free_bytes else 0

        vg = {
            'name': parts[0],
            'size': parts[1],
            'size_bytes': size_bytes,
            'free': parts[2],
            'free_bytes': free_bytes,
            'used_bytes': used_bytes,
            'used_percent': (used_bytes / size_bytes * 100) if size_bytes else 0,
            'pv_count': int(parts[3]) if parts[3].isdigit() else 0,
            'lv_count': int(parts[4]) if parts[4].isdigit() else 0,
            'attr': parts[5]
        }

        vgs.append(vg)

    return vgs


def get_physical_volumes():
    """Get physical volume information using pvs.

    Returns:
        list: List of PV dictionaries or None on error
    """
    cmd = [
        'pvs', '--noheadings', '--separator', '|',
        '-o', 'pv_name,vg_name,pv_size,pv_free,pv_attr',
        '--units', 'b'
    ]

    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return None

    pvs = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue

        parts = [p.strip() for p in line.split('|')]
        if len(parts) < 5:
            continue

        size_bytes = parse_size(parts[2])
        free_bytes = parse_size(parts[3])
        used_bytes = size_bytes - free_bytes if size_bytes and free_bytes else 0

        pv = {
            'name': parts[0],
            'vg': parts[1] if parts[1] else None,
            'size': parts[2],
            'size_bytes': size_bytes,
            'free': parts[3],
            'free_bytes': free_bytes,
            'used_bytes': used_bytes,
            'used_percent': (used_bytes / size_bytes * 100) if size_bytes else 0,
            'attr': parts[4]
        }

        pvs.append(pv)

    return pvs


def parse_percent(value):
    """Parse percentage value from LVM output.

    Args:
        value: String value that may contain a percentage

    Returns:
        float or None: Parsed percentage value
    """
    if not value or value == '':
        return None
    try:
        return float(value)
    except ValueError:
        return None


def parse_size(value):
    """Parse size value from LVM output (in bytes format).

    Args:
        value: String like "100.00B" or "1024B"

    Returns:
        int or None: Size in bytes
    """
    if not value:
        return None
    # Remove 'B' suffix and parse
    value = value.strip()
    if value.endswith('B'):
        value = value[:-1]
    try:
        return int(float(value))
    except ValueError:
        return None


def parse_lv_type(attr):
    """Parse LV type from attribute string.

    Args:
        attr: LV attribute string (e.g., '-wi-a-----')

    Returns:
        str: LV type description
    """
    if not attr or len(attr) < 1:
        return 'unknown'

    type_char = attr[0]
    types = {
        '-': 'standard',
        'C': 'cache',
        'm': 'mirror',
        'M': 'mirror_log',
        'o': 'origin',
        'O': 'origin_merging',
        'r': 'raid',
        'R': 'raid_metadata',
        's': 'snapshot',
        'S': 'snapshot_merging',
        'p': 'pvmove',
        'v': 'virtual',
        'V': 'thin_volume',
        't': 'thin_pool',
        'T': 'thin_pool_data',
        'e': 'raid_metadata',
    }

    return types.get(type_char, 'unknown')


def format_bytes(bytes_val):
    """Format bytes to human readable format.

    Args:
        bytes_val: Size in bytes

    Returns:
        str: Human readable size string
    """
    if bytes_val is None:
        return 'N/A'
    if bytes_val >= 1024 ** 4:
        return f"{bytes_val / (1024 ** 4):.1f} TiB"
    elif bytes_val >= 1024 ** 3:
        return f"{bytes_val / (1024 ** 3):.1f} GiB"
    elif bytes_val >= 1024 ** 2:
        return f"{bytes_val / (1024 ** 2):.1f} MiB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f} KiB"
    else:
        return f"{bytes_val} B"


def analyze_logical_volumes(lvs, thin_warn, thin_crit, snap_age_days):
    """Analyze logical volumes for issues.

    Args:
        lvs: List of LV dictionaries
        thin_warn: Warning threshold for thin pool usage
        thin_crit: Critical threshold for thin pool usage
        snap_age_days: Warning threshold for snapshot age in days

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    for lv in lvs:
        lv_id = f"{lv['vg']}/{lv['name']}"

        # Check thin pool usage
        if lv['type'] == 'thin_pool' and lv['data_percent'] is not None:
            if lv['data_percent'] >= thin_crit:
                issues.append({
                    'severity': 'CRITICAL',
                    'component': 'thin_pool',
                    'name': lv_id,
                    'metric': 'data_percent',
                    'value': lv['data_percent'],
                    'threshold': thin_crit,
                    'message': f"Thin pool {lv_id} critically full: "
                               f"{lv['data_percent']:.1f}% data used"
                })
            elif lv['data_percent'] >= thin_warn:
                issues.append({
                    'severity': 'WARNING',
                    'component': 'thin_pool',
                    'name': lv_id,
                    'metric': 'data_percent',
                    'value': lv['data_percent'],
                    'threshold': thin_warn,
                    'message': f"Thin pool {lv_id} running low: "
                               f"{lv['data_percent']:.1f}% data used"
                })

            # Also check metadata usage
            if lv['metadata_percent'] is not None and lv['metadata_percent'] >= thin_warn:
                severity = 'CRITICAL' if lv['metadata_percent'] >= thin_crit else 'WARNING'
                issues.append({
                    'severity': severity,
                    'component': 'thin_pool',
                    'name': lv_id,
                    'metric': 'metadata_percent',
                    'value': lv['metadata_percent'],
                    'threshold': thin_warn,
                    'message': f"Thin pool {lv_id} metadata usage: "
                               f"{lv['metadata_percent']:.1f}%"
                })

        # Check snapshot usage
        if lv['type'] == 'snapshot' and lv['snap_percent'] is not None:
            if lv['snap_percent'] >= 100:
                issues.append({
                    'severity': 'CRITICAL',
                    'component': 'snapshot',
                    'name': lv_id,
                    'metric': 'snap_percent',
                    'value': lv['snap_percent'],
                    'message': f"Snapshot {lv_id} is FULL (100%) - "
                               f"snapshot is now invalid!"
                })
            elif lv['snap_percent'] >= thin_crit:
                issues.append({
                    'severity': 'CRITICAL',
                    'component': 'snapshot',
                    'name': lv_id,
                    'metric': 'snap_percent',
                    'value': lv['snap_percent'],
                    'threshold': thin_crit,
                    'message': f"Snapshot {lv_id} nearly full: "
                               f"{lv['snap_percent']:.1f}%"
                })
            elif lv['snap_percent'] >= thin_warn:
                issues.append({
                    'severity': 'WARNING',
                    'component': 'snapshot',
                    'name': lv_id,
                    'metric': 'snap_percent',
                    'value': lv['snap_percent'],
                    'threshold': thin_warn,
                    'message': f"Snapshot {lv_id} filling up: "
                               f"{lv['snap_percent']:.1f}%"
                })

        # Check for old snapshots (if we have creation time)
        if lv['type'] == 'snapshot' and lv['time'] and snap_age_days > 0:
            try:
                # Parse LVM timestamp format
                lv_time = datetime.strptime(lv['time'], '%Y-%m-%d %H:%M:%S %z')
                age_days = (datetime.now(lv_time.tzinfo) - lv_time).days
                if age_days >= snap_age_days:
                    issues.append({
                        'severity': 'WARNING',
                        'component': 'snapshot',
                        'name': lv_id,
                        'metric': 'age_days',
                        'value': age_days,
                        'threshold': snap_age_days,
                        'message': f"Snapshot {lv_id} is {age_days} days old "
                                   f"(threshold: {snap_age_days} days)"
                    })
            except (ValueError, TypeError):
                pass  # Skip if timestamp parsing fails

    return issues


def analyze_volume_groups(vgs, vg_warn, vg_crit):
    """Analyze volume groups for capacity issues.

    Args:
        vgs: List of VG dictionaries
        vg_warn: Warning threshold for VG usage percentage
        vg_crit: Critical threshold for VG usage percentage

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    for vg in vgs:
        if vg['used_percent'] >= vg_crit:
            issues.append({
                'severity': 'CRITICAL',
                'component': 'volume_group',
                'name': vg['name'],
                'metric': 'used_percent',
                'value': vg['used_percent'],
                'threshold': vg_crit,
                'message': f"Volume group {vg['name']} critically full: "
                           f"{vg['used_percent']:.1f}% used, "
                           f"{format_bytes(vg['free_bytes'])} free"
            })
        elif vg['used_percent'] >= vg_warn:
            issues.append({
                'severity': 'WARNING',
                'component': 'volume_group',
                'name': vg['name'],
                'metric': 'used_percent',
                'value': vg['used_percent'],
                'threshold': vg_warn,
                'message': f"Volume group {vg['name']} running low: "
                           f"{vg['used_percent']:.1f}% used, "
                           f"{format_bytes(vg['free_bytes'])} free"
            })

        # Check for VG attributes indicating problems
        if vg['attr'] and len(vg['attr']) >= 5:
            # Position 4 is 'c' for clustered, 's' for shared
            # This is informational
            pass

    return issues


def analyze_physical_volumes(pvs):
    """Analyze physical volumes for issues.

    Args:
        pvs: List of PV dictionaries

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    for pv in pvs:
        # Check for orphan PVs (not in any VG)
        if not pv['vg']:
            issues.append({
                'severity': 'INFO',
                'component': 'physical_volume',
                'name': pv['name'],
                'metric': 'orphan',
                'value': True,
                'message': f"Physical volume {pv['name']} is not in any "
                           f"volume group ({format_bytes(pv['size_bytes'])})"
            })

        # Check PV attributes for issues
        if pv['attr'] and len(pv['attr']) >= 3:
            # Position 2 is 'm' for missing
            if pv['attr'][2] == 'm':
                issues.append({
                    'severity': 'CRITICAL',
                    'component': 'physical_volume',
                    'name': pv['name'],
                    'metric': 'missing',
                    'value': True,
                    'message': f"Physical volume {pv['name']} is MISSING!"
                })

    return issues


def output_plain(lvs, vgs, pvs, issues, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only:
        print(f"LVM Health Summary")
        print(f"  Volume Groups: {len(vgs) if vgs else 0}")
        print(f"  Logical Volumes: {len(lvs) if lvs else 0}")
        print(f"  Physical Volumes: {len(pvs) if pvs else 0}")
        print()

        if verbose and vgs:
            print("Volume Groups:")
            for vg in vgs:
                print(f"  {vg['name']}: {format_bytes(vg['used_bytes'])} / "
                      f"{format_bytes(vg['size_bytes'])} "
                      f"({vg['used_percent']:.1f}% used)")
            print()

        if verbose and lvs:
            thin_pools = [lv for lv in lvs if lv['type'] == 'thin_pool']
            snapshots = [lv for lv in lvs if lv['type'] == 'snapshot']

            if thin_pools:
                print("Thin Pools:")
                for lv in thin_pools:
                    print(f"  {lv['vg']}/{lv['name']}: "
                          f"{lv['data_percent']:.1f}% data, "
                          f"{lv['metadata_percent']:.1f}% metadata")
                print()

            if snapshots:
                print("Snapshots:")
                for lv in snapshots:
                    print(f"  {lv['vg']}/{lv['name']}: "
                          f"{lv['snap_percent']:.1f}% used "
                          f"(origin: {lv['origin']})")
                print()

    # Print issues
    if issues:
        for issue in issues:
            severity = issue['severity']

            # Skip INFO messages in warn-only mode
            if warn_only and severity == 'INFO':
                continue

            prefix = {
                'CRITICAL': '[CRITICAL]',
                'WARNING': '[WARNING]',
                'INFO': '[INFO]'
            }.get(severity, '[UNKNOWN]')

            print(f"{prefix} {issue['message']}")
    elif not warn_only:
        print("No issues detected.")


def output_json(lvs, vgs, pvs, issues, verbose):
    """Output results in JSON format."""
    result = {
        'summary': {
            'volume_groups': len(vgs) if vgs else 0,
            'logical_volumes': len(lvs) if lvs else 0,
            'physical_volumes': len(pvs) if pvs else 0
        },
        'issues': issues
    }

    if verbose:
        result['volume_groups'] = vgs if vgs else []
        result['logical_volumes'] = lvs if lvs else []
        result['physical_volumes'] = pvs if pvs else []

    print(json.dumps(result, indent=2, default=str))


def output_table(lvs, vgs, pvs, issues, verbose, warn_only):
    """Output results in table format."""
    if not warn_only:
        print("=" * 70)
        print("LVM HEALTH SUMMARY")
        print("=" * 70)
        print(f"{'Component':<20} {'Count':<15}")
        print("-" * 70)
        print(f"{'Volume Groups':<20} {len(vgs) if vgs else 0:<15}")
        print(f"{'Logical Volumes':<20} {len(lvs) if lvs else 0:<15}")
        print(f"{'Physical Volumes':<20} {len(pvs) if pvs else 0:<15}")
        print("=" * 70)
        print()

        if verbose and vgs:
            print("VOLUME GROUPS")
            print("=" * 70)
            print(f"{'Name':<15} {'Size':<12} {'Used':<12} {'Free':<12} {'Usage':<10}")
            print("-" * 70)
            for vg in vgs:
                print(f"{vg['name']:<15} "
                      f"{format_bytes(vg['size_bytes']):<12} "
                      f"{format_bytes(vg['used_bytes']):<12} "
                      f"{format_bytes(vg['free_bytes']):<12} "
                      f"{vg['used_percent']:.1f}%")
            print("=" * 70)
            print()

        if verbose and lvs:
            thin_pools = [lv for lv in lvs if lv['type'] == 'thin_pool']
            if thin_pools:
                print("THIN POOLS")
                print("=" * 70)
                print(f"{'Name':<25} {'Data %':<12} {'Metadata %':<12}")
                print("-" * 70)
                for lv in thin_pools:
                    name = f"{lv['vg']}/{lv['name']}"
                    data_pct = f"{lv['data_percent']:.1f}%" if lv['data_percent'] else 'N/A'
                    meta_pct = f"{lv['metadata_percent']:.1f}%" if lv['metadata_percent'] else 'N/A'
                    print(f"{name:<25} {data_pct:<12} {meta_pct:<12}")
                print("=" * 70)
                print()

    # Print issues
    if issues:
        print("ISSUES DETECTED")
        print("=" * 70)
        for issue in issues:
            severity = issue['severity']

            # Skip INFO messages in warn-only mode
            if warn_only and severity == 'INFO':
                continue

            print(f"[{severity}] {issue['message']}")
        print()
    elif not warn_only:
        print("No issues detected.")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor LVM logical volumes, volume groups, and physical volumes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check LVM health with default thresholds
  %(prog)s --thin-warn 70 --thin-crit 85  # Custom thin pool thresholds
  %(prog)s --format json            # JSON output for monitoring tools
  %(prog)s --verbose                # Show detailed LVM information
  %(prog)s --warn-only              # Only show warnings/errors

Thresholds:
  --thin-warn: Thin pool usage warning threshold (default: 80%%)
  --thin-crit: Thin pool usage critical threshold (default: 90%%)
  --vg-warn: Volume group usage warning threshold (default: 85%%)
  --vg-crit: Volume group usage critical threshold (default: 95%%)
  --snap-age: Snapshot age warning threshold in days (default: 7)

Exit codes:
  0 - All LVM components healthy
  1 - Warnings or critical issues detected
  2 - Usage error or LVM tools not available
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
        help='Show detailed LVM information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--thin-warn',
        type=float,
        default=80.0,
        metavar='PCT',
        help='Warning threshold for thin pool usage (default: 80%%)'
    )

    parser.add_argument(
        '--thin-crit',
        type=float,
        default=90.0,
        metavar='PCT',
        help='Critical threshold for thin pool usage (default: 90%%)'
    )

    parser.add_argument(
        '--vg-warn',
        type=float,
        default=85.0,
        metavar='PCT',
        help='Warning threshold for volume group usage (default: 85%%)'
    )

    parser.add_argument(
        '--vg-crit',
        type=float,
        default=95.0,
        metavar='PCT',
        help='Critical threshold for volume group usage (default: 95%%)'
    )

    parser.add_argument(
        '--snap-age',
        type=int,
        default=7,
        metavar='DAYS',
        help='Warning threshold for snapshot age in days (default: 7, 0 to disable)'
    )

    args = parser.parse_args()

    # Validate thresholds
    for name, warn, crit in [
        ('thin pool', args.thin_warn, args.thin_crit),
        ('volume group', args.vg_warn, args.vg_crit)
    ]:
        if warn < 0 or warn > 100:
            print(f"Error: {name} warning threshold must be between 0 and 100",
                  file=sys.stderr)
            sys.exit(2)
        if crit < 0 or crit > 100:
            print(f"Error: {name} critical threshold must be between 0 and 100",
                  file=sys.stderr)
            sys.exit(2)
        if warn >= crit:
            print(f"Error: {name} warning threshold must be less than critical",
                  file=sys.stderr)
            sys.exit(2)

    # Check for LVM tools
    if not check_lvm_available():
        print("Error: LVM tools not found (lvs, vgs, pvs)", file=sys.stderr)
        print("Install with: sudo apt-get install lvm2", file=sys.stderr)
        sys.exit(2)

    # Gather LVM information
    lvs = get_logical_volumes()
    vgs = get_volume_groups()
    pvs = get_physical_volumes()

    # Check if any LVM is configured
    if not vgs and not lvs and not pvs:
        if args.format == 'json':
            print(json.dumps({'message': 'No LVM configuration found', 'issues': []}))
        else:
            print("No LVM configuration found on this system.")
        sys.exit(0)

    # Analyze for issues
    issues = []
    if lvs:
        issues.extend(analyze_logical_volumes(
            lvs, args.thin_warn, args.thin_crit, args.snap_age))
    if vgs:
        issues.extend(analyze_volume_groups(vgs, args.vg_warn, args.vg_crit))
    if pvs:
        issues.extend(analyze_physical_volumes(pvs))

    # Output results
    if args.format == 'json':
        output_json(lvs, vgs, pvs, issues, args.verbose)
    elif args.format == 'table':
        output_table(lvs, vgs, pvs, issues, args.verbose, args.warn_only)
    else:  # plain
        output_plain(lvs, vgs, pvs, issues, args.verbose, args.warn_only)

    # Determine exit code based on issues
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
