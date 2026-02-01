#!/usr/bin/env python3
"""
Pre-maintenance validation checker for baremetal systems.

This script performs a comprehensive pre-flight check before planned maintenance
operations (reboots, upgrades, hardware changes). It validates that:

- No critical processes are in unusual states (D-state, zombie)
- Filesystem integrity is OK (no read-only mounts, pending syncs)
- Memory pressure is acceptable (no imminent OOM risk)
- Disk health is acceptable (no failing drives)
- No pending critical system updates that should be applied first
- System services are stable (no restart loops)
- Network connectivity is healthy
- No hung NFS/iSCSI mounts that could cause boot issues

This script is designed to be run before scheduled maintenance windows to
catch issues that could cause problems during or after the maintenance.

Exit codes:
    0 - All checks passed, safe to proceed with maintenance
    1 - Warnings or errors found, review before proceeding
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
import subprocess
import time


def check_proc_available():
    """Verify /proc filesystem is available."""
    if not os.path.exists('/proc'):
        print("Error: /proc filesystem not available (non-Linux system?)", file=sys.stderr)
        sys.exit(2)


def check_dstate_processes():
    """Check for processes in uninterruptible sleep (D-state).

    D-state processes are often stuck on I/O and can indicate storage issues
    that could cause problems during reboot.

    Returns:
        dict: Check result with status and details
    """
    dstate_procs = []

    try:
        for pid_dir in os.listdir('/proc'):
            if not pid_dir.isdigit():
                continue

            pid = int(pid_dir)
            stat_path = f'/proc/{pid}/stat'

            try:
                with open(stat_path, 'r') as f:
                    stat_line = f.read()

                # Parse stat line - format: pid (comm) state ...
                # Find the closing paren to handle commands with parens
                close_paren = stat_line.rfind(')')
                if close_paren < 0:
                    continue

                state = stat_line[close_paren + 2]

                if state == 'D':
                    # Get process name
                    comm_start = stat_line.find('(') + 1
                    comm = stat_line[comm_start:close_paren]

                    # Read cmdline for more context
                    try:
                        with open(f'/proc/{pid}/cmdline', 'r') as f:
                            cmdline = f.read().replace('\x00', ' ').strip()[:100]
                    except Exception:
                        cmdline = comm

                    dstate_procs.append({
                        'pid': pid,
                        'name': comm,
                        'cmdline': cmdline
                    })
            except (FileNotFoundError, PermissionError):
                continue
    except Exception as e:
        return {
            'name': 'D-State Processes',
            'status': 'ERROR',
            'message': f'Could not check D-state processes: {e}',
            'details': []
        }

    if dstate_procs:
        return {
            'name': 'D-State Processes',
            'status': 'WARNING',
            'message': f'{len(dstate_procs)} process(es) in uninterruptible sleep (may indicate I/O hang)',
            'details': dstate_procs
        }

    return {
        'name': 'D-State Processes',
        'status': 'OK',
        'message': 'No processes stuck in D-state',
        'details': []
    }


def check_zombie_processes():
    """Check for zombie processes.

    Too many zombies can indicate parent process issues.

    Returns:
        dict: Check result with status and details
    """
    zombies = []

    try:
        for pid_dir in os.listdir('/proc'):
            if not pid_dir.isdigit():
                continue

            pid = int(pid_dir)
            stat_path = f'/proc/{pid}/stat'

            try:
                with open(stat_path, 'r') as f:
                    stat_line = f.read()

                close_paren = stat_line.rfind(')')
                if close_paren < 0:
                    continue

                state = stat_line[close_paren + 2]

                if state == 'Z':
                    comm_start = stat_line.find('(') + 1
                    comm = stat_line[comm_start:close_paren]

                    zombies.append({
                        'pid': pid,
                        'name': comm
                    })
            except (FileNotFoundError, PermissionError):
                continue
    except Exception as e:
        return {
            'name': 'Zombie Processes',
            'status': 'ERROR',
            'message': f'Could not check zombie processes: {e}',
            'details': []
        }

    if len(zombies) > 10:
        return {
            'name': 'Zombie Processes',
            'status': 'WARNING',
            'message': f'{len(zombies)} zombie processes detected',
            'details': zombies[:10]  # Limit detail output
        }

    return {
        'name': 'Zombie Processes',
        'status': 'OK',
        'message': f'{len(zombies)} zombie process(es) (acceptable)',
        'details': []
    }


def check_readonly_mounts():
    """Check for unexpectedly read-only mounted filesystems.

    Read-only mounts can indicate disk errors or filesystem corruption.

    Returns:
        dict: Check result with status and details
    """
    readonly_mounts = []
    expected_ro = {'squashfs', 'iso9660', 'udf', 'cramfs'}  # Normally read-only

    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue

                device, mountpoint, fstype, options = parts[:4]

                # Skip pseudo-filesystems and expected read-only types
                if fstype in expected_ro or fstype.startswith(('proc', 'sys', 'dev', 'cgroup')):
                    continue

                # Check if mounted read-only
                if 'ro' in options.split(',') and ',ro,' in f',{options},' or options.startswith('ro,') or options.endswith(',ro') or options == 'ro':
                    # More precise check for 'ro' option
                    opt_list = options.split(',')
                    if 'ro' in opt_list:
                        readonly_mounts.append({
                            'device': device,
                            'mountpoint': mountpoint,
                            'fstype': fstype
                        })
    except Exception as e:
        return {
            'name': 'Read-Only Mounts',
            'status': 'ERROR',
            'message': f'Could not check mounts: {e}',
            'details': []
        }

    if readonly_mounts:
        return {
            'name': 'Read-Only Mounts',
            'status': 'CRITICAL',
            'message': f'{len(readonly_mounts)} filesystem(s) unexpectedly mounted read-only',
            'details': readonly_mounts
        }

    return {
        'name': 'Read-Only Mounts',
        'status': 'OK',
        'message': 'No unexpected read-only mounts',
        'details': []
    }


def check_memory_pressure():
    """Check for memory pressure that could complicate maintenance.

    Returns:
        dict: Check result with status and details
    """
    try:
        with open('/proc/meminfo', 'r') as f:
            meminfo = {}
            for line in f:
                if ':' in line:
                    key, value = line.split(':', 1)
                    meminfo[key.strip()] = int(value.strip().split()[0])

        mem_total = meminfo.get('MemTotal', 0)
        mem_available = meminfo.get('MemAvailable', 0)
        swap_total = meminfo.get('SwapTotal', 0)
        swap_free = meminfo.get('SwapFree', 0)

        if mem_total == 0:
            return {
                'name': 'Memory Pressure',
                'status': 'ERROR',
                'message': 'Could not determine memory status',
                'details': {}
            }

        mem_available_pct = (mem_available / mem_total) * 100
        swap_used_pct = ((swap_total - swap_free) / swap_total * 100) if swap_total > 0 else 0

        details = {
            'mem_available_pct': round(mem_available_pct, 1),
            'swap_used_pct': round(swap_used_pct, 1),
            'mem_available_mb': mem_available // 1024,
            'mem_total_mb': mem_total // 1024
        }

        if mem_available_pct < 5:
            return {
                'name': 'Memory Pressure',
                'status': 'CRITICAL',
                'message': f'Critical memory pressure: only {mem_available_pct:.1f}% available',
                'details': details
            }
        elif mem_available_pct < 10 or swap_used_pct > 75:
            return {
                'name': 'Memory Pressure',
                'status': 'WARNING',
                'message': f'Elevated memory pressure: {mem_available_pct:.1f}% available, {swap_used_pct:.1f}% swap used',
                'details': details
            }

        return {
            'name': 'Memory Pressure',
            'status': 'OK',
            'message': f'{mem_available_pct:.1f}% memory available',
            'details': details
        }
    except Exception as e:
        return {
            'name': 'Memory Pressure',
            'status': 'ERROR',
            'message': f'Could not check memory: {e}',
            'details': {}
        }


def check_disk_space():
    """Check for critically low disk space.

    Returns:
        dict: Check result with status and details
    """
    low_space_mounts = []

    try:
        # Get mount points
        mounts = []
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    device, mountpoint = parts[:2]
                    # Skip pseudo-filesystems
                    if device.startswith('/dev/') or device.startswith('/dev/mapper/'):
                        mounts.append(mountpoint)

        for mountpoint in mounts:
            try:
                stat = os.statvfs(mountpoint)
                total = stat.f_blocks * stat.f_frsize
                free = stat.f_bfree * stat.f_frsize

                if total == 0:
                    continue

                free_pct = (free / total) * 100

                if free_pct < 5:
                    low_space_mounts.append({
                        'mountpoint': mountpoint,
                        'free_pct': round(free_pct, 1),
                        'free_gb': round(free / (1024**3), 1)
                    })
            except (OSError, PermissionError):
                continue

        if low_space_mounts:
            critical = [m for m in low_space_mounts if m['free_pct'] < 2]
            if critical:
                return {
                    'name': 'Disk Space',
                    'status': 'CRITICAL',
                    'message': f'{len(critical)} filesystem(s) critically low on space (<2%)',
                    'details': low_space_mounts
                }
            return {
                'name': 'Disk Space',
                'status': 'WARNING',
                'message': f'{len(low_space_mounts)} filesystem(s) low on space (<5%)',
                'details': low_space_mounts
            }

        return {
            'name': 'Disk Space',
            'status': 'OK',
            'message': 'All filesystems have adequate free space',
            'details': []
        }
    except Exception as e:
        return {
            'name': 'Disk Space',
            'status': 'ERROR',
            'message': f'Could not check disk space: {e}',
            'details': []
        }


def check_pending_syncs():
    """Check for pending disk writes (dirty pages).

    High dirty pages could indicate storage performance issues.

    Returns:
        dict: Check result with status and details
    """
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('Dirty:'):
                    dirty_kb = int(line.split()[1])
                    dirty_mb = dirty_kb / 1024

                    if dirty_mb > 1000:  # More than 1GB pending
                        return {
                            'name': 'Pending Disk Writes',
                            'status': 'WARNING',
                            'message': f'{dirty_mb:.0f} MB of dirty pages pending write',
                            'details': {'dirty_mb': round(dirty_mb, 1)}
                        }

                    return {
                        'name': 'Pending Disk Writes',
                        'status': 'OK',
                        'message': f'{dirty_mb:.1f} MB dirty pages (acceptable)',
                        'details': {'dirty_mb': round(dirty_mb, 1)}
                    }

        return {
            'name': 'Pending Disk Writes',
            'status': 'OK',
            'message': 'Dirty pages check passed',
            'details': {}
        }
    except Exception as e:
        return {
            'name': 'Pending Disk Writes',
            'status': 'ERROR',
            'message': f'Could not check dirty pages: {e}',
            'details': {}
        }


def check_load_average():
    """Check if system load is unusually high.

    Returns:
        dict: Check result with status and details
    """
    try:
        with open('/proc/loadavg', 'r') as f:
            parts = f.read().split()
            load1 = float(parts[0])
            load5 = float(parts[1])
            load15 = float(parts[2])

        # Get CPU count for context
        cpu_count = os.cpu_count() or 1

        # Load per CPU
        load_per_cpu = load1 / cpu_count

        details = {
            'load_1min': load1,
            'load_5min': load5,
            'load_15min': load15,
            'cpu_count': cpu_count,
            'load_per_cpu': round(load_per_cpu, 2)
        }

        if load_per_cpu > 5:
            return {
                'name': 'System Load',
                'status': 'CRITICAL',
                'message': f'Extremely high load: {load1:.1f} ({load_per_cpu:.1f} per CPU)',
                'details': details
            }
        elif load_per_cpu > 2:
            return {
                'name': 'System Load',
                'status': 'WARNING',
                'message': f'Elevated system load: {load1:.1f} ({load_per_cpu:.1f} per CPU)',
                'details': details
            }

        return {
            'name': 'System Load',
            'status': 'OK',
            'message': f'Load average: {load1:.2f} ({load_per_cpu:.2f} per CPU)',
            'details': details
        }
    except Exception as e:
        return {
            'name': 'System Load',
            'status': 'ERROR',
            'message': f'Could not check load average: {e}',
            'details': {}
        }


def check_network_connectivity():
    """Basic network connectivity check.

    Returns:
        dict: Check result with status and details
    """
    # Check if network interfaces are up
    up_interfaces = []
    down_interfaces = []

    try:
        net_dir = '/sys/class/net'
        if os.path.exists(net_dir):
            for iface in os.listdir(net_dir):
                if iface == 'lo':
                    continue

                try:
                    with open(f'{net_dir}/{iface}/operstate', 'r') as f:
                        state = f.read().strip()

                    if state == 'up':
                        up_interfaces.append(iface)
                    elif state == 'down':
                        # Check if it's a physical interface (has a device link)
                        if os.path.exists(f'{net_dir}/{iface}/device'):
                            down_interfaces.append(iface)
                except Exception:
                    continue

        details = {
            'up_interfaces': up_interfaces,
            'down_interfaces': down_interfaces
        }

        if not up_interfaces:
            return {
                'name': 'Network Connectivity',
                'status': 'CRITICAL',
                'message': 'No network interfaces are up',
                'details': details
            }

        if down_interfaces:
            return {
                'name': 'Network Connectivity',
                'status': 'WARNING',
                'message': f'{len(down_interfaces)} physical interface(s) down: {", ".join(down_interfaces)}',
                'details': details
            }

        return {
            'name': 'Network Connectivity',
            'status': 'OK',
            'message': f'{len(up_interfaces)} network interface(s) up',
            'details': details
        }
    except Exception as e:
        return {
            'name': 'Network Connectivity',
            'status': 'ERROR',
            'message': f'Could not check network: {e}',
            'details': {}
        }


def check_systemd_failed_units():
    """Check for failed systemd units.

    Returns:
        dict: Check result with status and details
    """
    try:
        result = subprocess.run(
            ['systemctl', 'list-units', '--state=failed', '--no-legend', '--plain'],
            capture_output=True,
            text=True,
            timeout=10
        )

        failed_units = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                unit = line.split()[0] if line.split() else ''
                if unit:
                    failed_units.append(unit)

        if failed_units:
            return {
                'name': 'Systemd Units',
                'status': 'WARNING',
                'message': f'{len(failed_units)} failed systemd unit(s)',
                'details': failed_units[:10]  # Limit output
            }

        return {
            'name': 'Systemd Units',
            'status': 'OK',
            'message': 'No failed systemd units',
            'details': []
        }
    except FileNotFoundError:
        return {
            'name': 'Systemd Units',
            'status': 'SKIPPED',
            'message': 'systemctl not available',
            'details': []
        }
    except subprocess.TimeoutExpired:
        return {
            'name': 'Systemd Units',
            'status': 'WARNING',
            'message': 'systemctl timed out (system may be under heavy load)',
            'details': []
        }
    except Exception as e:
        return {
            'name': 'Systemd Units',
            'status': 'ERROR',
            'message': f'Could not check systemd: {e}',
            'details': []
        }


def check_recent_oom_kills():
    """Check for recent OOM kills in kernel log.

    Returns:
        dict: Check result with status and details
    """
    oom_events = []

    try:
        result = subprocess.run(
            ['dmesg', '-T'],
            capture_output=True,
            text=True,
            timeout=10
        )

        for line in result.stdout.split('\n'):
            if 'Out of memory' in line or 'oom-kill' in line.lower() or 'Killed process' in line:
                oom_events.append(line.strip()[:150])

        if oom_events:
            return {
                'name': 'Recent OOM Kills',
                'status': 'WARNING',
                'message': f'{len(oom_events)} OOM events found in kernel log',
                'details': oom_events[-5:]  # Last 5 events
            }

        return {
            'name': 'Recent OOM Kills',
            'status': 'OK',
            'message': 'No OOM kills in kernel log',
            'details': []
        }
    except subprocess.TimeoutExpired:
        return {
            'name': 'Recent OOM Kills',
            'status': 'SKIPPED',
            'message': 'dmesg timed out',
            'details': []
        }
    except Exception as e:
        return {
            'name': 'Recent OOM Kills',
            'status': 'SKIPPED',
            'message': f'Could not check dmesg: {e}',
            'details': []
        }


def check_nfs_mounts():
    """Check for potentially hung NFS mounts.

    Returns:
        dict: Check result with status and details
    """
    nfs_mounts = []
    hung_mounts = []

    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    device, mountpoint, fstype = parts[:3]
                    if fstype in ('nfs', 'nfs4', 'nfsd'):
                        nfs_mounts.append(mountpoint)

                        # Try a quick stat to see if it's responsive
                        try:
                            start = time.time()
                            os.stat(mountpoint)
                            elapsed = time.time() - start
                            if elapsed > 1.0:  # More than 1 second is suspicious
                                hung_mounts.append({
                                    'mountpoint': mountpoint,
                                    'response_time_s': round(elapsed, 2)
                                })
                        except Exception:
                            hung_mounts.append({
                                'mountpoint': mountpoint,
                                'response_time_s': -1,
                                'error': 'stat failed'
                            })

        if hung_mounts:
            return {
                'name': 'NFS Mounts',
                'status': 'CRITICAL',
                'message': f'{len(hung_mounts)} NFS mount(s) unresponsive',
                'details': hung_mounts
            }

        if nfs_mounts:
            return {
                'name': 'NFS Mounts',
                'status': 'OK',
                'message': f'{len(nfs_mounts)} NFS mount(s) healthy',
                'details': nfs_mounts
            }

        return {
            'name': 'NFS Mounts',
            'status': 'OK',
            'message': 'No NFS mounts configured',
            'details': []
        }
    except Exception as e:
        return {
            'name': 'NFS Mounts',
            'status': 'ERROR',
            'message': f'Could not check NFS mounts: {e}',
            'details': []
        }


def check_kernel_taint():
    """Check for kernel taint flags.

    Returns:
        dict: Check result with status and details
    """
    taint_flags = {
        0: 'Proprietary module loaded',
        1: 'Module forced load',
        2: 'Kernel running on out-of-spec system',
        3: 'Module forced unload',
        4: 'Processor reported MCE',
        5: 'Bad page found',
        6: 'User requested taint',
        7: 'Kernel died recently (OOPS or BUG)',
        8: 'ACPI table overridden',
        9: 'Kernel issued warning',
        10: 'Staging driver loaded',
        11: 'Workaround for platform firmware bug applied',
        12: 'Externally-built module loaded',
        13: 'Unsigned module loaded',
        14: 'Soft lockup occurred',
        15: 'Live patch applied',
        16: 'Auxiliary taint, for distro use',
        17: 'Kernel was built with struct randomization'
    }

    try:
        with open('/proc/sys/kernel/tainted', 'r') as f:
            taint = int(f.read().strip())

        if taint == 0:
            return {
                'name': 'Kernel Taint',
                'status': 'OK',
                'message': 'Kernel is not tainted',
                'details': {}
            }

        # Decode taint flags
        active_taints = []
        concerning_taints = []
        for bit, desc in taint_flags.items():
            if taint & (1 << bit):
                active_taints.append(desc)
                # These indicate potential instability
                if bit in (4, 5, 7, 14):  # MCE, bad page, OOPS, soft lockup
                    concerning_taints.append(desc)

        details = {
            'taint_value': taint,
            'active_flags': active_taints
        }

        if concerning_taints:
            return {
                'name': 'Kernel Taint',
                'status': 'CRITICAL',
                'message': f'Kernel has concerning taint flags: {", ".join(concerning_taints)}',
                'details': details
            }

        return {
            'name': 'Kernel Taint',
            'status': 'WARNING',
            'message': f'Kernel is tainted: {", ".join(active_taints[:3])}',
            'details': details
        }
    except Exception as e:
        return {
            'name': 'Kernel Taint',
            'status': 'ERROR',
            'message': f'Could not check kernel taint: {e}',
            'details': {}
        }


def format_status(status):
    """Format status with color codes if terminal supports it."""
    colors = {
        'OK': '\033[32m',       # Green
        'WARNING': '\033[33m',  # Yellow
        'CRITICAL': '\033[31m', # Red
        'ERROR': '\033[31m',    # Red
        'SKIPPED': '\033[36m',  # Cyan
    }
    reset = '\033[0m'

    if sys.stdout.isatty():
        return f"{colors.get(status, '')}{status}{reset}"
    return status


def output_plain(results, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only:
        print("=" * 60)
        print("PRE-MAINTENANCE SYSTEM CHECK")
        print("=" * 60)
        print()

    for result in results:
        status = result['status']

        # In warn-only mode, skip OK and SKIPPED
        if warn_only and status in ('OK', 'SKIPPED'):
            continue

        status_str = format_status(status)
        print(f"[{status_str:^8}] {result['name']}: {result['message']}")

        if verbose and result.get('details'):
            details = result['details']
            if isinstance(details, list):
                for item in details[:5]:
                    if isinstance(item, dict):
                        print(f"           - {item}")
                    else:
                        print(f"           - {item}")
            elif isinstance(details, dict):
                for key, value in list(details.items())[:5]:
                    print(f"           {key}: {value}")

    if not warn_only:
        print()


def output_json(results):
    """Output results in JSON format."""
    critical_count = sum(1 for r in results if r['status'] == 'CRITICAL')
    warning_count = sum(1 for r in results if r['status'] == 'WARNING')
    ok_count = sum(1 for r in results if r['status'] == 'OK')

    output = {
        'summary': {
            'safe_to_proceed': critical_count == 0 and warning_count == 0,
            'critical': critical_count,
            'warnings': warning_count,
            'ok': ok_count
        },
        'checks': results
    }
    print(json.dumps(output, indent=2))


def output_table(results, verbose, warn_only):
    """Output results in table format."""
    if not warn_only:
        print("=" * 80)
        print(f"{'PRE-MAINTENANCE SYSTEM CHECK':^80}")
        print("=" * 80)
        print(f"{'Check':<30} {'Status':<12} {'Message':<36}")
        print("-" * 80)

    for result in results:
        status = result['status']

        if warn_only and status in ('OK', 'SKIPPED'):
            continue

        name = result['name'][:30]
        message = result['message'][:36]

        print(f"{name:<30} {format_status(status):<12} {message:<36}")

    if not warn_only:
        print("=" * 80)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Pre-maintenance validation checker for baremetal systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Run all pre-maintenance checks
  %(prog)s --format json        # JSON output for automation
  %(prog)s --warn-only          # Only show warnings/errors
  %(prog)s --verbose            # Show detailed information

Use Cases:
  Run before scheduled reboots to ensure system is healthy
  Run before applying kernel updates or major patches
  Run before hardware maintenance windows
  Include in maintenance runbooks and automation

Exit codes:
  0 - All checks passed, safe to proceed
  1 - Warnings or critical issues found
  2 - Usage error
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
        help='Show detailed check information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors'
    )

    parser.add_argument(
        '--quick',
        action='store_true',
        help='Skip slower checks (NFS responsiveness, dmesg parsing)'
    )

    args = parser.parse_args()

    # Verify we're on Linux
    check_proc_available()

    # Run all checks
    results = []

    # Fast checks (always run)
    results.append(check_dstate_processes())
    results.append(check_zombie_processes())
    results.append(check_readonly_mounts())
    results.append(check_memory_pressure())
    results.append(check_disk_space())
    results.append(check_pending_syncs())
    results.append(check_load_average())
    results.append(check_network_connectivity())
    results.append(check_systemd_failed_units())
    results.append(check_kernel_taint())

    # Slower checks (skip if --quick)
    if not args.quick:
        results.append(check_nfs_mounts())
        results.append(check_recent_oom_kills())

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.verbose, args.warn_only)
    else:
        output_plain(results, args.verbose, args.warn_only)

    # Determine exit code
    critical_count = sum(1 for r in results if r['status'] == 'CRITICAL')
    warning_count = sum(1 for r in results if r['status'] == 'WARNING')

    if not args.warn_only and args.format == 'plain':
        if critical_count == 0 and warning_count == 0:
            print("✓ All pre-maintenance checks passed. Safe to proceed.")
        else:
            print(f"⚠ Found {critical_count} critical, {warning_count} warning issue(s). Review before proceeding.")

    if critical_count > 0 or warning_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
