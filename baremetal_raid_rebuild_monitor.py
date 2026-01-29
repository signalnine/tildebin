#!/usr/bin/env python3
"""
Monitor RAID array rebuild/resync progress with time estimation.

This script tracks the progress of RAID rebuild operations (resync, recovery,
reshape, check) and provides estimated time to completion. It's designed for
situations where you need to monitor long-running RAID operations and plan
maintenance windows accordingly.

Supports:
- Linux software RAID (mdadm) via /proc/mdstat
- Provides current progress, speed, and ETA
- Can monitor specific arrays or all arrays

Exit codes:
    0 - Success (no rebuilds in progress, or rebuild completed)
    1 - Rebuild in progress (use for alerting)
    2 - Usage error or missing dependency
"""

import argparse
import os
import re
import sys
import json
import time
from datetime import datetime, timedelta


def read_file(path):
    """Read file contents, return None on error"""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (IOError, OSError, PermissionError):
        return None


def parse_mdstat():
    """Parse /proc/mdstat for array status and rebuild progress"""
    content = read_file('/proc/mdstat')
    if content is None:
        return None

    arrays = []
    lines = content.split('\n')
    i = 0

    while i < len(lines):
        line = lines[i]

        # Match array line: "md0 : active raid1 sda1[0] sdb1[1]"
        array_match = re.match(r'^(md\d+)\s*:\s*(\w+)\s+(\w+)\s+(.+)$', line)
        if array_match:
            array_name = array_match.group(1)
            state = array_match.group(2)
            raid_level = array_match.group(3)
            devices_str = array_match.group(4)

            array_info = {
                'name': array_name,
                'device': f'/dev/{array_name}',
                'state': state,
                'level': raid_level,
                'devices': devices_str.strip(),
                'rebuild_in_progress': False,
                'operation': None,
                'progress_percent': None,
                'speed': None,
                'eta_minutes': None,
                'finish_time': None,
            }

            # Check following lines for status info
            j = i + 1
            while j < len(lines) and not re.match(r'^md\d+\s*:', lines[j]) and lines[j].strip():
                status_line = lines[j]

                # Match size line: "12345678 blocks super 1.2 [2/2] [UU]"
                # or degraded: "12345678 blocks super 1.2 [2/1] [U_]"
                size_match = re.search(r'(\d+)\s+blocks', status_line)
                if size_match:
                    array_info['size_blocks'] = int(size_match.group(1))

                # Match disk status: [UU] or [U_] or [_U]
                disk_status_match = re.search(r'\[([U_]+)\]', status_line)
                if disk_status_match:
                    disk_status = disk_status_match.group(1)
                    array_info['disk_status'] = disk_status
                    array_info['disks_active'] = disk_status.count('U')
                    array_info['disks_total'] = len(disk_status)
                    array_info['degraded'] = '_' in disk_status

                # Match rebuild progress line:
                # "[==>..................]  recovery = 12.5% (123456/987654) finish=45.6min speed=12345K/sec"
                # or check/resync:
                # "[==>..................]  check = 12.5% (123456/987654) finish=45.6min speed=12345K/sec"
                progress_match = re.search(
                    r'\[([=>.]+)\]\s+(\w+)\s*=\s*([\d.]+)%\s*'
                    r'\((\d+)/(\d+)\)\s*'
                    r'finish=([\d.]+)(min|sec|hour)?\s*'
                    r'speed=(\d+)([KMG]?)/sec',
                    status_line
                )
                if progress_match:
                    array_info['rebuild_in_progress'] = True
                    array_info['operation'] = progress_match.group(2)
                    array_info['progress_percent'] = float(progress_match.group(3))
                    array_info['blocks_done'] = int(progress_match.group(4))
                    array_info['blocks_total'] = int(progress_match.group(5))

                    # Parse finish time
                    finish_val = float(progress_match.group(6))
                    finish_unit = progress_match.group(7) or 'min'
                    if finish_unit == 'sec':
                        array_info['eta_minutes'] = finish_val / 60.0
                    elif finish_unit == 'hour':
                        array_info['eta_minutes'] = finish_val * 60.0
                    else:
                        array_info['eta_minutes'] = finish_val

                    # Calculate estimated finish time
                    finish_time = datetime.now() + timedelta(minutes=array_info['eta_minutes'])
                    array_info['finish_time'] = finish_time.strftime('%Y-%m-%d %H:%M:%S')

                    # Parse speed
                    speed_val = int(progress_match.group(8))
                    speed_unit = progress_match.group(9)
                    if speed_unit == 'M':
                        speed_val *= 1024
                    elif speed_unit == 'G':
                        speed_val *= 1024 * 1024
                    array_info['speed'] = speed_val  # KB/sec
                    array_info['speed_human'] = format_speed(speed_val)

                j += 1

            arrays.append(array_info)

        i += 1

    return arrays


def format_speed(kb_per_sec):
    """Format speed in human-readable form"""
    if kb_per_sec >= 1024 * 1024:
        return f"{kb_per_sec / (1024 * 1024):.1f} GB/s"
    elif kb_per_sec >= 1024:
        return f"{kb_per_sec / 1024:.1f} MB/s"
    else:
        return f"{kb_per_sec} KB/s"


def format_time(minutes):
    """Format minutes in human-readable form"""
    if minutes is None:
        return "unknown"
    if minutes < 1:
        return f"{int(minutes * 60)} seconds"
    elif minutes < 60:
        return f"{int(minutes)} minutes"
    elif minutes < 1440:  # Less than 24 hours
        hours = int(minutes / 60)
        mins = int(minutes % 60)
        return f"{hours}h {mins}m"
    else:
        days = int(minutes / 1440)
        hours = int((minutes % 1440) / 60)
        return f"{days}d {hours}h"


def output_plain(arrays, verbose=False, rebuilding_only=False):
    """Output in plain text format"""
    if rebuilding_only:
        arrays = [a for a in arrays if a['rebuild_in_progress']]

    if not arrays:
        print("No RAID arrays found" if not rebuilding_only else "No rebuilds in progress")
        return

    print("RAID Rebuild Status")
    print("=" * 70)
    print()

    for array in arrays:
        if array['rebuild_in_progress']:
            print(f"[*] {array['name']} ({array['level']}) - {array['operation'].upper()} IN PROGRESS")
            print(f"    Progress: {array['progress_percent']:.1f}%")
            print(f"    Speed:    {array.get('speed_human', 'unknown')}")
            print(f"    ETA:      {format_time(array['eta_minutes'])}")
            print(f"    Finish:   {array.get('finish_time', 'unknown')}")
            if verbose:
                print(f"    Blocks:   {array.get('blocks_done', 0):,} / {array.get('blocks_total', 0):,}")
                print(f"    Devices:  {array['devices']}")
        else:
            status = "DEGRADED" if array.get('degraded') else "OK"
            symbol = "[!]" if array.get('degraded') else "[+]"
            print(f"{symbol} {array['name']} ({array['level']}) - {status}")
            if verbose:
                print(f"    State:    {array['state']}")
                print(f"    Disks:    {array.get('disks_active', '?')}/{array.get('disks_total', '?')} active")
                print(f"    Devices:  {array['devices']}")
        print()


def output_json(arrays, rebuilding_only=False):
    """Output in JSON format"""
    if rebuilding_only:
        arrays = [a for a in arrays if a['rebuild_in_progress']]

    output = {
        'timestamp': datetime.now().isoformat(),
        'arrays': arrays,
        'summary': {
            'total_arrays': len(arrays),
            'rebuilding': sum(1 for a in arrays if a['rebuild_in_progress']),
            'degraded': sum(1 for a in arrays if a.get('degraded')),
        }
    }
    print(json.dumps(output, indent=2, default=str))


def output_table(arrays, rebuilding_only=False):
    """Output in table format"""
    if rebuilding_only:
        arrays = [a for a in arrays if a['rebuild_in_progress']]

    if not arrays:
        print("No arrays to display")
        return

    # Header
    print(f"{'Array':<8} {'Level':<8} {'Status':<12} {'Progress':<10} {'Speed':<12} {'ETA':<15}")
    print("-" * 70)

    for array in arrays:
        name = array['name']
        level = array['level']

        if array['rebuild_in_progress']:
            status = array['operation']
            progress = f"{array['progress_percent']:.1f}%"
            speed = array.get('speed_human', '-')
            eta = format_time(array['eta_minutes'])
        else:
            status = "DEGRADED" if array.get('degraded') else "OK"
            progress = "-"
            speed = "-"
            eta = "-"

        print(f"{name:<8} {level:<8} {status:<12} {progress:<10} {speed:<12} {eta:<15}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor RAID array rebuild/resync progress with time estimation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    Show status of all RAID arrays
  %(prog)s --rebuilding-only  Only show arrays being rebuilt
  %(prog)s --format json      Output in JSON format for automation
  %(prog)s -v                 Show verbose information
  %(prog)s --array md0        Monitor specific array

Exit codes:
  0 - No rebuilds in progress (or all healthy)
  1 - Rebuild in progress or array degraded
  2 - Error (no mdstat, usage error)
"""
    )

    parser.add_argument(
        '-a', '--array',
        help="Monitor specific array (e.g., md0)"
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Show detailed information"
    )

    parser.add_argument(
        '--rebuilding-only',
        action='store_true',
        help="Only show arrays with active rebuild/resync operations"
    )

    args = parser.parse_args()

    # Check for /proc/mdstat
    if not os.path.exists('/proc/mdstat'):
        print("Error: /proc/mdstat not found", file=sys.stderr)
        print("This system may not have software RAID configured", file=sys.stderr)
        sys.exit(2)

    # Parse mdstat
    arrays = parse_mdstat()
    if arrays is None:
        print("Error: Unable to read /proc/mdstat", file=sys.stderr)
        sys.exit(2)

    # Filter by array name if specified
    if args.array:
        array_name = args.array
        if not array_name.startswith('md'):
            array_name = f"md{array_name}"
        arrays = [a for a in arrays if a['name'] == array_name]
        if not arrays:
            print(f"Error: Array {args.array} not found", file=sys.stderr)
            sys.exit(2)

    # Output
    if args.format == 'json':
        output_json(arrays, args.rebuilding_only)
    elif args.format == 'table':
        output_table(arrays, args.rebuilding_only)
    else:
        output_plain(arrays, args.verbose, args.rebuilding_only)

    # Exit code: 1 if any rebuilds in progress or degraded
    has_rebuilds = any(a['rebuild_in_progress'] for a in arrays)
    has_degraded = any(a.get('degraded') for a in arrays)

    if has_rebuilds or has_degraded:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
