#!/usr/bin/env python3
"""
Audit CPU isolation configuration on baremetal systems.

Examines kernel CPU isolation settings for latency-sensitive workloads:
- isolcpus: CPUs excluded from general scheduler
- nohz_full: CPUs with reduced timer interrupts (tickless)
- rcu_nocbs: CPUs with RCU callbacks offloaded to other CPUs
- CPU affinity of critical processes

Critical for:
- DPDK and network packet processing applications
- Real-time and low-latency workloads
- KVM/QEMU CPU pinning for VMs
- High-frequency trading systems
- Telecommunications infrastructure
- Any workload requiring predictable CPU scheduling

This script verifies:
1. Isolation parameters are consistent (isolcpus + nohz_full + rcu_nocbs)
2. Isolated CPUs aren't running unexpected processes
3. IRQ affinity respects CPU isolation
4. Kernel threads are properly excluded from isolated CPUs

Exit codes:
    0 - CPU isolation configured correctly
    1 - Warnings or misconfiguration detected
    2 - Usage error or required info unavailable
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone


def read_file(path):
    """Read a file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError, PermissionError):
        return None


def parse_cpu_list(cpu_str):
    """
    Parse CPU list string (e.g., '0-3,8-11') into set of CPU numbers.

    Handles formats:
    - Single CPU: '0'
    - Range: '0-3'
    - List: '0,2,4'
    - Combined: '0-3,8,12-15'
    """
    if not cpu_str or cpu_str.strip() == '':
        return set()

    cpus = set()
    for part in cpu_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                cpus.update(range(int(start), int(end) + 1))
            except ValueError:
                pass
        else:
            try:
                cpus.add(int(part))
            except ValueError:
                pass
    return cpus


def get_cmdline_param(param_name):
    """Extract a kernel command line parameter value."""
    cmdline = read_file('/proc/cmdline')
    if not cmdline:
        return None

    # Match param=value or just param
    pattern = rf'\b{param_name}=([^\s]+)'
    match = re.search(pattern, cmdline)
    if match:
        return match.group(1)

    # Check for bare parameter (no value)
    if re.search(rf'\b{param_name}\b', cmdline):
        return ''

    return None


def get_online_cpus():
    """Get set of online CPU numbers."""
    online = read_file('/sys/devices/system/cpu/online')
    if online:
        return parse_cpu_list(online)

    # Fallback: count from /sys/devices/system/cpu/cpu*
    cpus = set()
    try:
        for entry in os.listdir('/sys/devices/system/cpu'):
            if entry.startswith('cpu') and entry[3:].isdigit():
                cpus.add(int(entry[3:]))
    except OSError:
        pass
    return cpus


def get_isolated_cpus():
    """Get CPUs isolated via kernel parameters."""
    result = {
        'isolcpus': set(),
        'nohz_full': set(),
        'rcu_nocbs': set(),
        'cmdline_raw': {},
    }

    # Parse isolcpus
    isolcpus = get_cmdline_param('isolcpus')
    if isolcpus is not None:
        result['cmdline_raw']['isolcpus'] = isolcpus
        # isolcpus can have flags like 'domain,managed_irq,1-3'
        # Extract just the CPU list (last comma-separated part that looks like CPUs)
        parts = isolcpus.split(',')
        cpu_parts = []
        for part in parts:
            if re.match(r'^[\d\-]+$', part.strip()):
                cpu_parts.append(part)
        if cpu_parts:
            result['isolcpus'] = parse_cpu_list(','.join(cpu_parts))

    # Parse nohz_full
    nohz_full = get_cmdline_param('nohz_full')
    if nohz_full is not None:
        result['cmdline_raw']['nohz_full'] = nohz_full
        result['nohz_full'] = parse_cpu_list(nohz_full)

    # Parse rcu_nocbs
    rcu_nocbs = get_cmdline_param('rcu_nocbs')
    if rcu_nocbs is not None:
        result['cmdline_raw']['rcu_nocbs'] = rcu_nocbs
        result['rcu_nocbs'] = parse_cpu_list(rcu_nocbs)

    return result


def get_process_cpu_affinity():
    """
    Get CPU affinity for running processes.

    Returns dict: {pid: {'name': str, 'cpus': set, 'cmdline': str}}
    """
    processes = {}

    try:
        for pid_str in os.listdir('/proc'):
            if not pid_str.isdigit():
                continue

            pid = int(pid_str)
            proc_path = f'/proc/{pid}'

            # Get process name
            comm = read_file(f'{proc_path}/comm')
            if not comm:
                continue

            # Get CPU affinity from status
            status = read_file(f'{proc_path}/status')
            cpus_allowed = set()
            if status:
                for line in status.split('\n'):
                    if line.startswith('Cpus_allowed_list:'):
                        cpu_list = line.split(':', 1)[1].strip()
                        cpus_allowed = parse_cpu_list(cpu_list)
                        break

            # Get cmdline for context
            cmdline = read_file(f'{proc_path}/cmdline')
            if cmdline:
                cmdline = cmdline.replace('\x00', ' ').strip()[:100]
            else:
                cmdline = ''

            processes[pid] = {
                'name': comm,
                'cpus': cpus_allowed,
                'cmdline': cmdline,
            }

    except OSError:
        pass

    return processes


def get_irq_affinity():
    """
    Get IRQ CPU affinity settings.

    Returns dict: {irq_num: {'name': str, 'cpus': set}}
    """
    irqs = {}

    try:
        # Parse /proc/interrupts for IRQ names
        interrupts = read_file('/proc/interrupts')
        irq_names = {}
        if interrupts:
            for line in interrupts.split('\n')[1:]:  # Skip header
                parts = line.split()
                if parts:
                    irq_id = parts[0].rstrip(':')
                    if irq_id.isdigit():
                        # Last part is usually the device name
                        name = parts[-1] if len(parts) > 1 else 'unknown'
                        irq_names[irq_id] = name

        # Get affinity from /proc/irq/*/smp_affinity_list
        irq_path = '/proc/irq'
        for irq_num in os.listdir(irq_path):
            if not irq_num.isdigit():
                continue

            affinity_file = f'{irq_path}/{irq_num}/smp_affinity_list'
            affinity = read_file(affinity_file)

            if affinity:
                irqs[int(irq_num)] = {
                    'name': irq_names.get(irq_num, 'unknown'),
                    'cpus': parse_cpu_list(affinity),
                }

    except OSError:
        pass

    return irqs


def check_kernel_threads_on_isolated(isolated_cpus, processes):
    """
    Check for kernel threads running on isolated CPUs.

    Returns list of (pid, name, cpus) tuples for kernel threads on isolated CPUs.
    """
    violations = []

    # Kernel threads typically have names in brackets like [kworker/0:1]
    # or no cmdline at all
    for pid, info in processes.items():
        name = info['name']
        cpus = info['cpus']

        # Check if this is a kernel thread
        is_kernel_thread = (
            name.startswith('[') or
            name.startswith('kworker') or
            name.startswith('ksoftirqd') or
            name.startswith('migration') or
            name.startswith('rcu') or
            (info['cmdline'] == '' and pid > 1)
        )

        if not is_kernel_thread:
            continue

        # Check if affinity includes isolated CPUs
        overlap = cpus & isolated_cpus
        if overlap and cpus != isolated_cpus:
            # Thread can run on isolated CPUs but isn't fully confined to them
            # (if it's fully confined, it might be intentional)
            violations.append({
                'pid': pid,
                'name': name,
                'cpus': sorted(overlap),
                'all_cpus': sorted(cpus),
            })

    return violations


def check_irqs_on_isolated(isolated_cpus, irqs):
    """
    Check for IRQs that can fire on isolated CPUs.

    Returns list of IRQs with affinity including isolated CPUs.
    """
    violations = []

    for irq_num, info in irqs.items():
        cpus = info['cpus']
        overlap = cpus & isolated_cpus

        if overlap:
            violations.append({
                'irq': irq_num,
                'name': info['name'],
                'cpus': sorted(overlap),
                'all_cpus': sorted(cpus),
            })

    return violations


def check_user_processes_on_isolated(isolated_cpus, processes):
    """
    Check for regular user processes allowed on isolated CPUs.

    Returns processes that might unexpectedly run on isolated CPUs.
    """
    findings = []

    # System processes that are typically fine on isolated CPUs
    system_procs = {
        'systemd', 'init', 'kthreadd', 'rcu_sched', 'migration',
        'watchdog', 'cpuhp', 'idle_inject', 'writeback', 'kcompactd',
        'ksmd', 'khugepaged', 'crypto', 'kintegrityd', 'kblockd',
        'blkcg_punt_bio', 'ata_sff', 'md', 'edac-poller', 'devfreq_wq',
        'watchdogd', 'pm_wq', 'tpm', 'netns', 'inet_frag_wq',
    }

    for pid, info in processes.items():
        name = info['name']
        cpus = info['cpus']

        # Skip if no overlap with isolated CPUs
        if not (cpus & isolated_cpus):
            continue

        # Skip kernel threads (handled separately)
        if name.startswith('[') or info['cmdline'] == '':
            continue

        # Skip known system processes
        base_name = name.split('/')[0].split(':')[0]
        if base_name in system_procs:
            continue

        # This is a user process that can run on isolated CPUs
        findings.append({
            'pid': pid,
            'name': name,
            'cpus': sorted(cpus & isolated_cpus),
            'cmdline': info['cmdline'][:60],
        })

    return findings


def analyze_isolation(online_cpus, isolation_config, processes, irqs):
    """
    Analyze CPU isolation configuration and return findings.

    Returns dict with 'status', 'issues', 'warnings', 'info'.
    """
    issues = []
    warnings = []
    info_msgs = []

    isolcpus = isolation_config['isolcpus']
    nohz_full = isolation_config['nohz_full']
    rcu_nocbs = isolation_config['rcu_nocbs']

    # Check if any isolation is configured
    all_isolated = isolcpus | nohz_full | rcu_nocbs

    if not all_isolated:
        info_msgs.append("No CPU isolation configured")
        return {
            'status': 'none',
            'issues': issues,
            'warnings': warnings,
            'info': info_msgs,
        }

    info_msgs.append(f"Isolated CPUs configured: {sorted(all_isolated)}")

    # Check consistency between isolation parameters
    if isolcpus and nohz_full and isolcpus != nohz_full:
        if not nohz_full.issubset(isolcpus):
            warnings.append(
                f"nohz_full CPUs {sorted(nohz_full - isolcpus)} "
                "are not in isolcpus - timer ticks may still occur"
            )

    if isolcpus and rcu_nocbs and not rcu_nocbs.issuperset(isolcpus):
        missing = isolcpus - rcu_nocbs
        warnings.append(
            f"isolcpus {sorted(missing)} missing from rcu_nocbs - "
            "RCU callbacks will still run on these CPUs"
        )

    # Best practice: all three should match for full isolation
    if isolcpus and nohz_full and rcu_nocbs:
        if isolcpus == nohz_full == rcu_nocbs:
            info_msgs.append(
                "Full isolation: isolcpus, nohz_full, and rcu_nocbs are consistent"
            )
        else:
            warnings.append(
                "Isolation parameters are inconsistent - "
                "consider aligning isolcpus, nohz_full, and rcu_nocbs"
            )

    # Check for isolated CPUs not in online set
    offline_isolated = all_isolated - online_cpus
    if offline_isolated:
        warnings.append(
            f"Isolated CPUs {sorted(offline_isolated)} are not online"
        )

    # Check kernel threads on isolated CPUs
    kernel_violations = check_kernel_threads_on_isolated(isolcpus, processes)
    if kernel_violations:
        for v in kernel_violations[:5]:  # Limit to 5
            warnings.append(
                f"Kernel thread '{v['name']}' (pid {v['pid']}) "
                f"can run on isolated CPUs {v['cpus']}"
            )
        if len(kernel_violations) > 5:
            warnings.append(
                f"... and {len(kernel_violations) - 5} more kernel threads"
            )

    # Check IRQs on isolated CPUs
    irq_violations = check_irqs_on_isolated(isolcpus, irqs)
    if irq_violations:
        for v in irq_violations[:5]:
            issues.append(
                f"IRQ {v['irq']} ({v['name']}) can fire on "
                f"isolated CPUs {v['cpus']}"
            )
        if len(irq_violations) > 5:
            issues.append(f"... and {len(irq_violations) - 5} more IRQs")

    # Check user processes on isolated CPUs
    user_violations = check_user_processes_on_isolated(isolcpus, processes)
    if user_violations:
        for v in user_violations[:3]:
            info_msgs.append(
                f"Process '{v['name']}' (pid {v['pid']}) "
                f"allowed on isolated CPUs {v['cpus']}"
            )
        if len(user_violations) > 3:
            info_msgs.append(
                f"... and {len(user_violations) - 3} more processes"
            )

    # Check if CPU 0 is isolated (usually a bad idea)
    if 0 in isolcpus:
        warnings.append(
            "CPU 0 is isolated - some kernel tasks require CPU 0; "
            "this may cause issues"
        )

    # Determine status
    if issues:
        status = 'error'
    elif warnings:
        status = 'warning'
    else:
        status = 'ok'

    return {
        'status': status,
        'issues': issues,
        'warnings': warnings,
        'info': info_msgs,
    }


def format_plain(online_cpus, isolation_config, analysis, verbose=False):
    """Format output as plain text."""
    lines = []

    lines.append("CPU Isolation Auditor")
    lines.append("=" * 50)
    lines.append("")

    # Overview
    lines.append(f"Online CPUs: {len(online_cpus)} ({min(online_cpus)}-{max(online_cpus)})")

    isolcpus = isolation_config['isolcpus']
    nohz_full = isolation_config['nohz_full']
    rcu_nocbs = isolation_config['rcu_nocbs']

    if isolcpus:
        lines.append(f"isolcpus: {sorted(isolcpus)}")
    if nohz_full:
        lines.append(f"nohz_full: {sorted(nohz_full)}")
    if rcu_nocbs:
        lines.append(f"rcu_nocbs: {sorted(rcu_nocbs)}")

    if not (isolcpus or nohz_full or rcu_nocbs):
        lines.append("No CPU isolation configured")

    lines.append("")

    # Raw cmdline params if verbose
    if verbose and isolation_config.get('cmdline_raw'):
        lines.append("Kernel cmdline parameters:")
        for param, value in isolation_config['cmdline_raw'].items():
            lines.append(f"  {param}={value}")
        lines.append("")

    # Issues
    if analysis['issues']:
        lines.append("ISSUES:")
        for issue in analysis['issues']:
            lines.append(f"  [!] {issue}")
        lines.append("")

    # Warnings
    if analysis['warnings']:
        lines.append("WARNINGS:")
        for warning in analysis['warnings']:
            lines.append(f"  [*] {warning}")
        lines.append("")

    # Info (verbose only)
    if verbose and analysis['info']:
        lines.append("INFO:")
        for info in analysis['info']:
            lines.append(f"  [i] {info}")
        lines.append("")

    # Summary
    status = analysis['status']
    if status == 'none':
        lines.append("[INFO] No CPU isolation configured on this system")
    elif status == 'ok':
        lines.append("[OK] CPU isolation is properly configured")
    elif status == 'warning':
        lines.append(f"[WARN] CPU isolation has {len(analysis['warnings'])} warning(s)")
    else:
        lines.append(f"[ERROR] CPU isolation has {len(analysis['issues'])} issue(s)")

    return "\n".join(lines)


def format_json(online_cpus, isolation_config, analysis):
    """Format output as JSON."""
    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'online_cpus': sorted(online_cpus),
        'cpu_count': len(online_cpus),
        'isolation': {
            'isolcpus': sorted(isolation_config['isolcpus']),
            'nohz_full': sorted(isolation_config['nohz_full']),
            'rcu_nocbs': sorted(isolation_config['rcu_nocbs']),
            'cmdline_raw': isolation_config.get('cmdline_raw', {}),
        },
        'status': analysis['status'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'info': analysis['info'],
        'healthy': analysis['status'] in ('ok', 'none'),
    }

    return json.dumps(output, indent=2)


def format_table(online_cpus, isolation_config, analysis):
    """Format output as table."""
    lines = []

    lines.append("+" + "-" * 60 + "+")
    lines.append("| CPU Isolation Auditor" + " " * 38 + "|")
    lines.append("+" + "-" * 60 + "+")

    # Summary row
    isolcpus = isolation_config['isolcpus']
    nohz_full = isolation_config['nohz_full']
    rcu_nocbs = isolation_config['rcu_nocbs']

    lines.append(f"| {'Parameter':<15} | {'CPUs':<40} |")
    lines.append("+" + "-" * 60 + "+")

    lines.append(f"| {'Online':<15} | {str(len(online_cpus)) + ' CPUs':<40} |")

    if isolcpus:
        cpu_str = ','.join(map(str, sorted(isolcpus)))[:38]
        lines.append(f"| {'isolcpus':<15} | {cpu_str:<40} |")
    else:
        lines.append(f"| {'isolcpus':<15} | {'(none)':<40} |")

    if nohz_full:
        cpu_str = ','.join(map(str, sorted(nohz_full)))[:38]
        lines.append(f"| {'nohz_full':<15} | {cpu_str:<40} |")
    else:
        lines.append(f"| {'nohz_full':<15} | {'(none)':<40} |")

    if rcu_nocbs:
        cpu_str = ','.join(map(str, sorted(rcu_nocbs)))[:38]
        lines.append(f"| {'rcu_nocbs':<15} | {cpu_str:<40} |")
    else:
        lines.append(f"| {'rcu_nocbs':<15} | {'(none)':<40} |")

    lines.append("+" + "-" * 60 + "+")

    # Status
    status = analysis['status'].upper()
    issue_count = len(analysis['issues'])
    warn_count = len(analysis['warnings'])
    status_str = f"Status: {status} ({issue_count} issues, {warn_count} warnings)"
    lines.append(f"| {status_str:<58} |")
    lines.append("+" + "-" * 60 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Audit CPU isolation configuration for latency-sensitive workloads',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Basic isolation check
  %(prog)s --format json        # JSON output for monitoring
  %(prog)s --verbose            # Show detailed process/IRQ info
  %(prog)s --warn-only          # Only show if issues exist

CPU Isolation Parameters:
  isolcpus    - Exclude CPUs from general scheduler (most important)
  nohz_full   - Disable timer ticks on CPUs when idle/single task
  rcu_nocbs   - Offload RCU callbacks to other CPUs

Why This Matters:
  - Latency spikes from scheduler interruptions
  - Timer tick jitter (1-10ms) on isolated workloads
  - RCU callbacks causing unpredictable delays
  - IRQ processing stealing CPU cycles

Recommended Configuration:
  For best isolation, use all three parameters with the same CPU set:
  isolcpus=2-7 nohz_full=2-7 rcu_nocbs=2-7

Exit codes:
  0 - CPU isolation properly configured (or none configured)
  1 - Warnings or issues detected
  2 - Usage error or required info unavailable
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
        help='Show detailed information including processes and IRQs'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if warnings or issues detected'
    )

    args = parser.parse_args()

    # Get online CPUs
    online_cpus = get_online_cpus()
    if not online_cpus:
        print("Error: Cannot determine online CPUs", file=sys.stderr)
        sys.exit(2)

    # Get isolation configuration
    isolation_config = get_isolated_cpus()

    # Only scan processes and IRQs if isolation is configured
    # (scanning can be slow on systems with many processes)
    all_isolated = (
        isolation_config['isolcpus'] |
        isolation_config['nohz_full'] |
        isolation_config['rcu_nocbs']
    )

    if all_isolated:
        # Get process and IRQ info for detailed analysis
        processes = get_process_cpu_affinity()
        irqs = get_irq_affinity()
    else:
        # No isolation configured - skip expensive scans
        processes = {}
        irqs = {}

    # Analyze
    analysis = analyze_isolation(online_cpus, isolation_config, processes, irqs)

    # Check if we should output (respecting --warn-only)
    has_findings = analysis['issues'] or analysis['warnings']
    if args.warn_only and not has_findings:
        sys.exit(0)

    # Format and output
    if args.format == 'json':
        output = format_json(online_cpus, isolation_config, analysis)
    elif args.format == 'table':
        output = format_table(online_cpus, isolation_config, analysis)
    else:
        output = format_plain(online_cpus, isolation_config, analysis, args.verbose)

    print(output)

    # Exit code based on findings
    if analysis['issues']:
        sys.exit(1)
    elif analysis['warnings']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
