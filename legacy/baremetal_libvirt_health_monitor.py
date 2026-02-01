#!/usr/bin/env python3
"""
Monitor libvirt/KVM hypervisor and virtual machine health.

This script checks the health of libvirt-managed virtual machines and the
hypervisor itself. Useful for baremetal environments running KVM virtualization.

Key metrics monitored:
- Libvirt daemon connectivity and version
- VM states (running, paused, shutoff, crashed)
- VM resource usage (vCPUs, memory)
- VM autostart configuration
- Storage pool health
- Network health

Exit codes:
    0 - All VMs and hypervisor healthy
    1 - Warnings or errors detected (crashed VMs, issues found)
    2 - Missing dependencies or usage error
"""

import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET


def run_command(cmd):
    """Execute a command and return output."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "Command not found"
    except Exception as e:
        return -1, "", str(e)


def check_virsh_available():
    """Check if virsh is installed."""
    returncode, stdout, _ = run_command(['which', 'virsh'])
    return returncode == 0


def check_libvirt_running():
    """Check if libvirtd is running and accessible."""
    returncode, stdout, stderr = run_command(['virsh', 'version'])
    if returncode == 0:
        return True, stdout
    return False, stderr


def get_hypervisor_info():
    """Get hypervisor information."""
    info = {
        'connected': False,
        'hypervisor': None,
        'api_version': None,
        'host_cpu': None,
        'host_memory_mb': None,
    }

    # Get version info
    returncode, stdout, _ = run_command(['virsh', 'version'])
    if returncode == 0:
        info['connected'] = True
        for line in stdout.split('\n'):
            if 'hypervisor:' in line.lower():
                info['hypervisor'] = line.split(':', 1)[1].strip() if ':' in line else None
            elif 'API:' in line:
                info['api_version'] = line.split(':', 1)[1].strip() if ':' in line else None

    # Get node info
    returncode, stdout, _ = run_command(['virsh', 'nodeinfo'])
    if returncode == 0:
        for line in stdout.split('\n'):
            if line.startswith('CPU model:'):
                info['host_cpu'] = line.split(':', 1)[1].strip()
            elif line.startswith('Memory size:'):
                mem_str = line.split(':', 1)[1].strip()
                # Convert KiB to MB
                try:
                    mem_kib = int(mem_str.split()[0])
                    info['host_memory_mb'] = mem_kib // 1024
                except (ValueError, IndexError):
                    pass

    return info


def get_vm_list():
    """Get list of all VMs (running and stopped)."""
    returncode, stdout, _ = run_command(['virsh', 'list', '--all'])
    if returncode != 0:
        return []

    vms = []
    lines = stdout.strip().split('\n')
    # Skip header lines
    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 2:
            # Format: ID Name State (ID is - for stopped VMs)
            vm_id = parts[0] if parts[0] != '-' else None
            vm_name = parts[1]
            vm_state = ' '.join(parts[2:]) if len(parts) > 2 else 'unknown'
            vms.append({
                'id': vm_id,
                'name': vm_name,
                'state': vm_state,
            })

    return vms


def get_vm_details(vm_name):
    """Get detailed information about a VM."""
    details = {
        'name': vm_name,
        'vcpus': None,
        'memory_mb': None,
        'autostart': None,
        'persistent': None,
    }

    # Get dominfo
    returncode, stdout, _ = run_command(['virsh', 'dominfo', vm_name])
    if returncode == 0:
        for line in stdout.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()

                if key == 'cpu(s)':
                    try:
                        details['vcpus'] = int(value)
                    except ValueError:
                        pass
                elif key == 'max memory':
                    try:
                        mem_kib = int(value.split()[0])
                        details['memory_mb'] = mem_kib // 1024
                    except (ValueError, IndexError):
                        pass
                elif key == 'autostart':
                    details['autostart'] = value.lower() == 'enable'
                elif key == 'persistent':
                    details['persistent'] = value.lower() == 'yes'

    return details


def get_storage_pools():
    """Get storage pool status."""
    returncode, stdout, _ = run_command(['virsh', 'pool-list', '--all'])
    if returncode != 0:
        return []

    pools = []
    lines = stdout.strip().split('\n')
    # Skip header lines
    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 2:
            pool_name = parts[0]
            pool_state = parts[1] if len(parts) > 1 else 'unknown'
            pool_autostart = parts[2] if len(parts) > 2 else 'unknown'
            pools.append({
                'name': pool_name,
                'state': pool_state,
                'autostart': pool_autostart,
            })

    return pools


def get_networks():
    """Get virtual network status."""
    returncode, stdout, _ = run_command(['virsh', 'net-list', '--all'])
    if returncode != 0:
        return []

    networks = []
    lines = stdout.strip().split('\n')
    # Skip header lines
    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 2:
            net_name = parts[0]
            net_state = parts[1] if len(parts) > 1 else 'unknown'
            net_autostart = parts[2] if len(parts) > 2 else 'unknown'
            net_persistent = parts[3] if len(parts) > 3 else 'unknown'
            networks.append({
                'name': net_name,
                'state': net_state,
                'autostart': net_autostart,
                'persistent': net_persistent,
            })

    return networks


def analyze_health(hypervisor_info, vms, pools, networks, check_autostart):
    """Analyze overall health and generate warnings."""
    warnings = []
    status = 'healthy'

    # Check hypervisor
    if not hypervisor_info['connected']:
        status = 'critical'
        warnings.append('Cannot connect to libvirt daemon')
        return status, warnings

    # Check VMs
    for vm in vms:
        vm_state = vm['state'].lower()

        if 'crash' in vm_state:
            status = 'critical'
            warnings.append('VM {} is crashed'.format(vm['name']))
        elif 'paused' in vm_state:
            if status != 'critical':
                status = 'warning'
            warnings.append('VM {} is paused'.format(vm['name']))

        # Check autostart for running VMs
        if check_autostart and 'running' in vm_state:
            details = get_vm_details(vm['name'])
            if details['autostart'] is False:
                if status != 'critical':
                    status = 'warning'
                warnings.append('VM {} is running but autostart is disabled'.format(vm['name']))

    # Check storage pools
    for pool in pools:
        if pool['state'].lower() != 'active':
            if status != 'critical':
                status = 'warning'
            warnings.append('Storage pool {} is not active ({})'.format(
                pool['name'], pool['state']))

    # Check networks
    for net in networks:
        if net['state'].lower() != 'active' and net['autostart'].lower() == 'yes':
            if status != 'critical':
                status = 'warning'
            warnings.append('Network {} is not active but has autostart enabled'.format(
                net['name']))

    return status, warnings


def main():
    parser = argparse.ArgumentParser(
        description='Monitor libvirt/KVM hypervisor and VM health',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Check all VMs and hypervisor
  %(prog)s --vm myvm           # Check specific VM
  %(prog)s --format json       # JSON output for monitoring systems
  %(prog)s --check-autostart   # Warn if running VMs lack autostart

Exit codes:
  0 - All healthy
  1 - Warnings or errors detected
  2 - Missing dependencies or usage error
"""
    )
    parser.add_argument(
        '--vm',
        metavar='NAME',
        help='Check specific VM only'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed VM information'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show VMs with warnings or issues'
    )
    parser.add_argument(
        '--check-autostart',
        action='store_true',
        help='Warn if running VMs do not have autostart enabled'
    )
    parser.add_argument(
        '--skip-pools',
        action='store_true',
        help='Skip storage pool checks'
    )
    parser.add_argument(
        '--skip-networks',
        action='store_true',
        help='Skip network checks'
    )

    args = parser.parse_args()

    # Check if virsh is available
    if not check_virsh_available():
        print("Error: virsh is not installed. Please install libvirt-clients.",
              file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt-get install libvirt-clients",
              file=sys.stderr)
        print("  RHEL/CentOS: sudo yum install libvirt-client", file=sys.stderr)
        sys.exit(2)

    # Check if libvirt is running
    running, version_info = check_libvirt_running()
    if not running:
        print("Error: Cannot connect to libvirt daemon.", file=sys.stderr)
        print("  Ensure libvirtd is running: sudo systemctl start libvirtd",
              file=sys.stderr)
        print("  Check your permissions: groups $(whoami)", file=sys.stderr)
        sys.exit(2)

    # Gather information
    hypervisor_info = get_hypervisor_info()
    vms = get_vm_list()

    # Filter to specific VM if requested
    if args.vm:
        vms = [vm for vm in vms if vm['name'] == args.vm]
        if not vms:
            print("Error: VM '{}' not found".format(args.vm), file=sys.stderr)
            sys.exit(2)

    pools = [] if args.skip_pools else get_storage_pools()
    networks = [] if args.skip_networks else get_networks()

    # Analyze health
    status, warnings = analyze_health(
        hypervisor_info, vms, pools, networks, args.check_autostart
    )

    # Get detailed VM info if needed
    vm_details = []
    for vm in vms:
        details = get_vm_details(vm['name'])
        details['state'] = vm['state']
        details['id'] = vm['id']

        # Determine VM status
        vm_state = vm['state'].lower()
        if 'crash' in vm_state:
            details['status'] = 'critical'
        elif 'paused' in vm_state:
            details['status'] = 'warning'
        elif 'running' in vm_state:
            details['status'] = 'running'
        elif 'shut' in vm_state:
            details['status'] = 'stopped'
        else:
            details['status'] = 'unknown'

        if not args.warn_only or details['status'] in ['critical', 'warning']:
            vm_details.append(details)

    # Output results
    if args.format == 'json':
        output = {
            'hypervisor': hypervisor_info,
            'vms': vm_details,
            'storage_pools': pools,
            'networks': networks,
            'summary': {
                'status': status,
                'warnings': warnings,
                'total_vms': len(vms),
                'running_vms': sum(1 for vm in vms if 'running' in vm['state'].lower()),
                'stopped_vms': sum(1 for vm in vms if 'shut' in vm['state'].lower()),
            }
        }
        print(json.dumps(output, indent=2))

    elif args.format == 'table':
        # Hypervisor info
        print("Hypervisor: {}".format(hypervisor_info.get('hypervisor', 'N/A')))
        print()

        # VM table
        print("{:<20} {:<6} {:<12} {:<6} {:<10} {:<10}".format(
            'NAME', 'ID', 'STATE', 'VCPUS', 'MEM (MB)', 'AUTOSTART'
        ))
        print("-" * 70)

        for vm in vm_details:
            vm_id = vm['id'] if vm['id'] else '-'
            autostart = 'yes' if vm['autostart'] else 'no' if vm['autostart'] is not None else '?'
            print("{:<20} {:<6} {:<12} {:<6} {:<10} {:<10}".format(
                vm['name'][:20],
                vm_id,
                vm['state'][:12],
                vm['vcpus'] or '-',
                vm['memory_mb'] or '-',
                autostart
            ))

        # Storage pools
        if pools:
            print()
            print("Storage Pools:")
            for pool in pools:
                print("  {} - {}".format(pool['name'], pool['state']))

        # Networks
        if networks:
            print()
            print("Networks:")
            for net in networks:
                print("  {} - {}".format(net['name'], net['state']))

    else:  # plain
        # Status symbol for overall health
        if status == 'healthy':
            overall_symbol = '[OK]'
        elif status == 'warning':
            overall_symbol = '[WARN]'
        else:
            overall_symbol = '[CRIT]'

        print("{} Hypervisor: {} ({})".format(
            overall_symbol,
            hypervisor_info.get('hypervisor', 'Unknown'),
            hypervisor_info.get('api_version', 'N/A')
        ))

        if args.verbose:
            print("  Host CPU: {}".format(hypervisor_info.get('host_cpu', 'N/A')))
            print("  Host Memory: {} MB".format(hypervisor_info.get('host_memory_mb', 'N/A')))

        # Print warnings
        for warning in warnings:
            print("  ! {}".format(warning))

        print()

        # VM status
        if vm_details:
            print("Virtual Machines:")
            for vm in vm_details:
                if vm['status'] == 'critical':
                    symbol = '[CRIT]'
                elif vm['status'] == 'warning':
                    symbol = '[WARN]'
                elif vm['status'] == 'running':
                    symbol = '[RUN]'
                elif vm['status'] == 'stopped':
                    symbol = '[STOP]'
                else:
                    symbol = '[????]'

                print("  {} {} - {}".format(symbol, vm['name'], vm['state']))

                if args.verbose:
                    print("      vCPUs: {}, Memory: {} MB, Autostart: {}".format(
                        vm['vcpus'] or 'N/A',
                        vm['memory_mb'] or 'N/A',
                        'yes' if vm['autostart'] else 'no'
                    ))
        else:
            print("No VMs found")

        # Storage pools (verbose only)
        if args.verbose and pools:
            print()
            print("Storage Pools:")
            for pool in pools:
                state_symbol = '[OK]' if pool['state'].lower() == 'active' else '[--]'
                print("  {} {} - {}".format(state_symbol, pool['name'], pool['state']))

        # Networks (verbose only)
        if args.verbose and networks:
            print()
            print("Networks:")
            for net in networks:
                state_symbol = '[OK]' if net['state'].lower() == 'active' else '[--]'
                print("  {} {} - {}".format(state_symbol, net['name'], net['state']))

    # Summary
    if args.format == 'plain' and not args.warn_only:
        running = sum(1 for vm in vms if 'running' in vm['state'].lower())
        stopped = sum(1 for vm in vms if 'shut' in vm['state'].lower())
        print()
        print("Summary: {} running, {} stopped".format(running, stopped))

    # Exit code
    if status == 'critical':
        sys.exit(1)
    elif status == 'warning':
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
