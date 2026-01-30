tildebin
========

small utilities for your ~/bin/

## Testing

Run all tests:
```bash
make test
```

See [tests/README.md](tests/README.md) for detailed testing documentation.

## Scripts

### AWS EC2 Management
- `listec2hosts.py`: List EC2 instances with options for region, output format, and instance state filtering
- `ec2_tag_summary.py`: Summarize EC2 instances by tags across regions
- `ec2_manage.py`: Manage EC2 instances (start, stop, restart)
- `terminate_instance.py`: Terminate an EC2 instance with user confirmation
- `stop_all_instances.py`: Stop all running EC2 instances in a region with user confirmation
- `emptysgs.py`: Find unused AWS EC2 Security Groups
- `listvolumes.py`: List EC2 EBS volumes with filtering and formatting options
- `grephosts.sh`: Filter EC2 host output based on a search query

### SSH Operations
- `acrosshosts.sh`: Execute a command on multiple hosts via SSH
- `useradd.sh`: Create a user account with SSH access on multiple hosts

### Baremetal System Monitoring
- `baremetal_dmesg_analyzer.py`: Analyze kernel messages (dmesg) for hardware errors and warnings across all subsystems (disk, memory, PCIe, CPU, network, filesystem, RAID, thermal)
- `baremetal_efi_boot_audit.py`: Audit EFI/UEFI boot configuration including boot entries, boot order, Secure Boot status, and detect stale or duplicate entries for consistent boot configuration across server fleets
- `baremetal_firmware_security_audit.py`: Audit firmware security settings including Secure Boot status, TPM presence and version, UEFI vs Legacy BIOS mode, IOMMU/VT-d/AMD-Vi status, Intel TXT, AMD SEV, and kernel lockdown mode for security compliance across server fleets
- `baremetal_grub_config_audit.py`: Audit GRUB bootloader configuration for security and consistency, checking password protection, kernel command line parameters (IOMMU, KASLR, mitigations), file permissions, timeout settings, and installed kernels for fleet-wide boot configuration compliance
- `baremetal_kernel_hardening_audit.py`: Audit kernel security hardening settings including ASLR/KASLR, NX/DEP, SMEP/SMAP, PTI/KPTI, Spectre/Meltdown mitigations, stack protector, kernel pointer hiding, dmesg restrictions, unprivileged BPF/userfaultfd, Yama ptrace scope, and module signing for security compliance across server fleets
- `baremetal_tpm_health_monitor.py`: Monitor TPM (Trusted Platform Module) health and status including TPM presence and version (1.2/2.0), firmware info, self-test validation, lockout counter, and PCR bank configuration for disk encryption (LUKS), attestation workflows, and security compliance
- `baremetal_failed_login_monitor.py`: Monitor failed SSH and login attempts from auth logs to detect brute-force attacks, track offending IPs, and identify targeted user accounts for security monitoring
- `baremetal_sshd_health_monitor.py`: Monitor SSH daemon health, configuration, and connection limits including service status, MaxSessions/MaxStartups thresholds, authentication settings, active sessions by user, and connection attempt statistics from auth logs for bastion hosts and jump servers
- `baremetal_authorized_keys_audit.py`: Audit SSH authorized_keys files for security issues including weak key algorithms (DSA, short RSA), unrestricted access (no from= restriction), dangerous options, duplicate keys across users, and insecure file permissions
- `baremetal_active_sessions_monitor.py`: Monitor active login sessions to detect unauthorized users, idle sessions exceeding thresholds, root logins, and sessions from unusual source IPs for security auditing
- `baremetal_selinux_apparmor_monitor.py`: Monitor SELinux and AppArmor mandatory access control (MAC) status including enforcement mode (enforcing/permissive/disabled), policy violations from audit logs, profile statistics, and security-relevant boolean settings - essential for security-hardened environments (NIST 800-53, PCI-DSS, CIS benchmarks)
- `baremetal_suid_sgid_audit.py`: Audit SUID and SGID binaries on Linux systems to detect potential privilege escalation vectors, unexpected privileged binaries, and files in suspicious locations (/tmp, /home) - essential for security compliance and detecting unauthorized privilege escalation
- `baremetal_fd_limit_monitor.py`: Monitor file descriptor usage across system and per-process to prevent resource exhaustion and identify processes approaching their limits
- `baremetal_open_file_monitor.py`: Monitor open file handles across the system to identify processes with high FD counts, detect potential FD leaks, and find processes holding deleted files open (common disk space leak after log rotation)
- `baremetal_process_fd_monitor.py`: Monitor per-process file descriptor usage to identify processes approaching their RLIMIT_NOFILE limits, show top fd consumers, and detect processes with dangerously low limits - essential for preventing service failures in database servers, web proxies, and high-connection services
- `baremetal_process_memory_growth.py`: Monitor processes for memory growth over time to detect potential memory leaks by sampling RSS at intervals, calculating growth rates, and identifying top memory growers - critical for detecting memory leaks in long-running services before they exhaust system resources
- `baremetal_process_io_monitor.py`: Monitor per-process I/O usage by reading /proc/[pid]/io to identify which processes are causing disk I/O bottlenecks - critical for troubleshooting database servers with unexpected I/O patterns, runaway backup jobs, log writers consuming bandwidth, and memory-mapped file thrashing
- `baremetal_process_accounting_monitor.py`: Monitor process resource accounting from /proc to identify resource hogs by analyzing per-process I/O statistics, CPU time, and memory usage - useful for capacity planning, detecting runaway processes, and auditing resource consumption with configurable thresholds and filters by user/command
- `baremetal_interrupt_balance_monitor.py`: Monitor hardware interrupt (IRQ) distribution across CPU cores to detect performance issues from poor interrupt balancing
- `baremetal_kernel_version_audit.py`: Audit kernel version and configuration to detect version drift across server fleets, identify outdated kernels, and verify kernel command-line parameters are consistent
- `baremetal_kernel_cmdline_audit.py`: Audit kernel boot parameters from /proc/cmdline for security hardening (IOMMU, KPTI, KASLR, mitigations), debug options that should be disabled in production, and performance tuning. Supports baseline comparison for fleet consistency.
- `baremetal_kernel_module_audit.py`: Audit loaded kernel modules for security and compliance, identifying unsigned modules, out-of-tree modules, proprietary drivers, and kernel taint sources
- `baremetal_kernel_taint_monitor.py`: Monitor kernel taint status for fleet consistency, compliance auditing, and operations alerting, detecting proprietary modules, crashes, MCEs, unsigned modules, and other kernel-tainting conditions
- `baremetal_kernel_config_audit.py`: Audit kernel runtime configuration (sysctl) against security and performance baselines with built-in profiles for security hardening, performance tuning, and balanced configurations
- `baremetal_livepatch_monitor.py`: Monitor kernel live patching status (kpatch, livepatch, ksplice) for security compliance, detecting active patches, disabled patches, and systems missing security patches that can be applied without reboots
- `baremetal_reboot_required_monitor.py`: Monitor system reboot requirements for fleet-wide maintenance planning - detects kernel version mismatches, Debian/Ubuntu reboot-required flags, RHEL needs-restarting status, and processes using deleted libraries
- `baremetal_initramfs_health_monitor.py`: Monitor initramfs/initrd health for all installed kernels - detects missing, corrupted, or orphaned initramfs images, validates compression and permissions, and checks for regeneration tools availability - critical for preventing unbootable systems after kernel updates
- `baremetal_kernel_log_rate_monitor.py`: Monitor kernel log message rates to detect anomalies that may indicate hardware problems, driver issues, or system instability with configurable thresholds and burst detection
- `disk_health_check.py`: Monitor disk health using SMART attributes
- `baremetal_disk_life_predictor.py`: Predict disk failure risk using SMART attribute trend analysis with weighted risk scoring for both SATA/SAS and NVMe drives
- `baremetal_trim_status_monitor.py`: Monitor TRIM/discard status for SSDs and NVMe drives to identify misconfigured devices where TRIM is not enabled, causing performance degradation over time
- `baremetal_partition_alignment_checker.py`: Check disk partition alignment for optimal I/O performance - misaligned partitions cause read-modify-write cycles that significantly degrade SSD and Advanced Format HDD performance
- `baremetal_disk_space_forecaster.py`: Forecast disk space exhaustion by sampling filesystem usage and predicting days until full based on growth rate estimation
- `nvme_health_monitor.py`: Monitor NVMe SSD health metrics including wear level, power cycles, unsafe shutdowns, media errors, and thermal throttling
- `baremetal_ssd_wear_monitor.py`: Monitor SSD wear levels and endurance metrics for both NVMe and SATA SSDs, tracking percentage used, available spare capacity, total data written, and media errors with configurable warning thresholds
- `disk_io_monitor.py`: Monitor disk I/O performance and identify bottlenecks
- `baremetal_block_error_monitor.py`: Monitor block device error statistics from /sys/block/*/stat to detect I/O errors, high queue times, and early signs of disk problems
- `baremetal_scsi_error_monitor.py`: Monitor SCSI/SAS device error counters (ioerr_cnt, iotmo_cnt) from sysfs to detect failing disks, SAS cable issues, or HBA problems before complete failure
- `iosched_audit.py`: Audit I/O scheduler configuration across block devices and detect misconfigurations (NVMe using complex schedulers, HDDs using 'none', etc.)
- `check_raid.py`: Check status of hardware and software RAID arrays
- `baremetal_raid_rebuild_monitor.py`: Monitor RAID array rebuild/resync progress with ETA estimation - tracks recovery, resync, reshape, and check operations on mdadm arrays, providing progress percentage, speed, and estimated completion time for maintenance window planning
- `baremetal_lvm_health_monitor.py`: Monitor LVM logical volumes, volume groups, and physical volumes for health issues including thin pool exhaustion, snapshot aging, and VG capacity warnings
- `baremetal_zfs_pool_health.py`: Monitor ZFS pool health including pool state (online/degraded/faulted), capacity, fragmentation, scrub age, device errors, and data integrity - essential for ZFS-based storage infrastructure
- `baremetal_mce_monitor.py`: Monitor Machine Check Exceptions (MCE) for hardware fault detection including CPU cache errors, memory bus errors, system bus errors, and thermal events - critical for detecting failing hardware before data corruption
- `baremetal_multipath_health_monitor.py`: Monitor dm-multipath device health, detecting failed or degraded paths, path flapping, and configuration issues for SAN/NAS storage
- `baremetal_drbd_health_monitor.py`: Monitor DRBD (Distributed Replicated Block Device) replication health including synchronization state, split-brain detection, connection status, and resync progress for high-availability storage clusters
- `baremetal_iscsi_health.py`: Monitor iSCSI session health including target connectivity, session state, error counts, and multipath status for SAN storage environments
- `baremetal_nfs_mount_monitor.py`: Monitor NFS mount health including stale mount detection, server connectivity, mount latency, and configuration validation for large-scale environments with shared storage
- `baremetal_mount_health_monitor.py`: Monitor all mounted filesystems for hung mounts (NFS/CIFS/FUSE that stop responding), stale NFS handles, read-only remounts, bind mount consistency, and mount option issues - critical for detecting storage problems before they cascade into system-wide failures
- `cpu_frequency_monitor.py`: Monitor CPU frequency scaling and governor settings
- `baremetal_cpu_time_analyzer.py`: Analyze CPU time distribution (user, system, iowait, steal, softirq) for performance diagnosis
- `baremetal_cpu_steal_monitor.py`: Monitor CPU steal time for virtualized environments to detect hypervisor resource contention, noisy neighbors on shared hosts, and VM CPU starvation before application performance is impacted
- `baremetal_context_switch_monitor.py`: Monitor context switch rates to detect CPU contention, scheduling overhead, and run queue depth issues
- `firmware_version_audit.py`: Audit firmware versions for BIOS, BMC/IPMI, network interfaces, and RAID controllers to detect version drift across server fleets
- `load_average_monitor.py`: Monitor system load averages and process queue depth to identify overloaded systems
- `hardware_temperature_monitor.py`: Monitor hardware temperature sensors and fan speeds
- `baremetal_thermal_throttle_monitor.py`: Monitor CPU thermal throttling events by reading kernel throttle counters to detect performance degradation from overheating
- `gpu_health_monitor.py`: Monitor NVIDIA GPU health, temperature, memory, ECC errors, and power consumption
- `ipmi_sel_monitor.py`: Monitor IPMI System Event Log (SEL) for hardware errors and critical events
- `baremetal_psu_monitor.py`: Monitor Power Supply Unit (PSU) health via IPMI including power supply status, redundancy, voltage sensors, and FRU information for proactive failure detection
- `baremetal_ups_monitor.py`: Monitor UPS (Uninterruptible Power Supply) status via NUT or apcaccess including battery charge, runtime remaining, load percentage, and power status for datacenter power monitoring
- `memory_health_monitor.py`: Monitor memory health, ECC errors, and memory pressure
- `baremetal_tmpfs_monitor.py`: Monitor tmpfs filesystem usage including /dev/shm, /run, and /tmp to detect high usage that could lead to silent OOM conditions, with configurable warning/critical thresholds
- `network_interface_health.py`: Monitor network interface health and error statistics
- `baremetal_nic_firmware_audit.py`: Audit NIC driver and firmware versions across physical interfaces to detect version inconsistencies that cause subtle packet loss, latency issues, or performance degradation in large-scale baremetal environments
- `baremetal_nic_link_speed_audit.py`: Audit NIC link speeds to detect interfaces negotiating at suboptimal speeds due to cable issues, switch misconfigurations, or auto-negotiation failures
- `baremetal_ethtool_audit.py`: Audit network interface driver settings, offloads (TSO, GSO, GRO, checksums), and ring buffer configurations using ethtool to detect performance issues from disabled offloads, suboptimal ring buffer sizes, driver version inconsistencies, and MTU mismatches in bonded interfaces
- `baremetal_vlan_config_audit.py`: Audit VLAN configuration and health to detect orphaned VLANs, MTU mismatches, parent interface issues, and VLAN ID conflicts in datacenter environments
- `network_bond_status.sh`: Check status of network bonded interfaces
- `baremetal_bond_health_monitor.py`: Monitor network bond health with detailed diagnostics including slave status, failover readiness, link failures, and speed/duplex mismatch detection
- `baremetal_boot_performance_monitor.py`: Monitor system boot performance and systemd initialization times to identify slow-booting systems and problematic services that delay startup
- `baremetal_boot_issues_analyzer.py`: Analyze boot issues from journald logs across recent system boots including kernel panics, OOM kills, emergency mode entries, failed units, and hardware errors - useful for identifying machines with problematic boots in large fleets
- `baremetal_uptime_monitor.py`: Monitor system uptime and reboot history to detect flapping servers with frequent reboots, analyze reboot patterns, and identify unstable systems in large baremetal environments
- `baremetal_load_average_monitor.py`: Monitor system load averages relative to CPU count, providing normalized load per CPU metrics, trend analysis (increasing/decreasing/stable), and configurable thresholds for capacity planning and overload detection
- `baremetal_network_config_audit.py`: Audit network interface configuration for common misconfigurations (MTU mismatches, bonding inconsistencies, IPv6 configuration drift)
- `baremetal_netns_health_monitor.py`: Monitor network namespace health on container hosts, detecting orphaned namespaces, dangling veth pairs, and namespace interface issues
- `baremetal_bandwidth_monitor.py`: Monitor network interface bandwidth utilization and throughput by sampling /proc/net/dev, calculating bytes/packets per second, utilization percentage, and detecting saturation with configurable thresholds
- `baremetal_tcp_retransmission_monitor.py`: Monitor TCP retransmission rates to detect packet loss, network congestion, and connectivity issues by sampling /proc/net/snmp statistics with configurable warning thresholds
- `baremetal_softnet_backlog_monitor.py`: Monitor Linux softnet backlog statistics for packet processing issues including queue overflows, time squeeze events, and CPU imbalance in packet processing to detect when network packet rates exceed CPU capacity
- `baremetal_softirq_monitor.py`: Monitor software interrupt (softirq) activity to detect CPU imbalance and overload including NET_RX/NET_TX network bottlenecks, BLOCK I/O completion delays, timer jitter, RCU callback storms, and RSS/RPS configuration issues
- `baremetal_napi_health_monitor.py`: Monitor Linux NAPI (New API) polling health for network performance including netdev_budget, dev_weight, GRO batch settings, per-interface NAPI configuration, and NET_RX/NET_TX softirq distribution across CPUs
- `baremetal_infiniband_health_monitor.py`: Monitor InfiniBand and RDMA health for HPC environments including port states, error counters (symbol errors, link recoveries, CRC errors), performance counters, subnet manager connectivity, and RDMA device availability
- `baremetal_packet_drop_analyzer.py`: Analyze per-interface packet drops with detailed breakdown by cause (rx_dropped, rx_errors, rx_missed, rx_fifo, tx_dropped, tx_carrier, etc.) to help distinguish between driver bugs, misconfigurations, buffer exhaustion, and potential attacks
- `baremetal_link_flap_detector.py`: Detect network interface link flapping by monitoring carrier state transitions over time to identify unstable cables, failing transceivers, bad switch ports, or auto-negotiation issues causing intermittent connectivity
- `baremetal_route_health_monitor.py`: Monitor network routing health including default gateway reachability, routing table consistency, and interface status to detect routing issues causing connectivity problems
- `baremetal_arp_table_monitor.py`: Monitor ARP table health to detect stale entries, duplicate MACs (potential IP conflicts or spoofing), table exhaustion, and gateway reachability issues for network troubleshooting
- `baremetal_dns_resolver_monitor.py`: Monitor DNS resolver configuration and health including /etc/resolv.conf validation, nameserver reachability testing, DNS resolution verification, and systemd-resolved status for large-scale baremetal environments
- `baremetal_service_port_monitor.py`: Monitor service port availability and responsiveness with support for common service presets (redis, mysql, postgres, http, https, ssh, etc.) and custom port definitions, useful for verifying critical services are listening and responding without requiring service-specific clients
- `ntp_drift_monitor.py`: Monitor NTP/Chrony time synchronization and detect clock drift
- `baremetal_hwclock_drift_monitor.py`: Monitor hardware clock (RTC) drift against system time to detect failing CMOS batteries, clock crystal issues, or RTC misconfiguration that causes time jumps on reboot
- `baremetal_clocksource_monitor.py`: Monitor kernel clock source configuration and stability (TSC, HPET, ACPI_PM) to ensure optimal timekeeping for high-frequency trading, distributed systems, and virtualization workloads - checks TSC stability flags (constant_tsc, nonstop_tsc) and detects suboptimal clock source configurations
- `pcie_health_monitor.py`: Monitor PCIe device health, link status, and error counters
- `baremetal_pcie_topology_analyzer.py`: Analyze PCIe topology including IOMMU groups, device-to-NUMA node mapping, PCIe link speed/width validation, and identification of suboptimal device placement for GPU clusters and high-performance workloads
- `power_consumption_monitor.py`: Monitor server power consumption using IPMI, turbostat, and RAPL sensors
- `system_inventory.py`: Generate hardware inventory for baremetal systems
- `systemd_service_monitor.py`: Monitor systemd service health and identify failed or degraded units
- `filesystem_usage_tracker.py`: Track filesystem usage and identify large directories
- `baremetal_filesystem_readonly_monitor.py`: Monitor filesystems for read-only status and detect storage issues that cause filesystems to remount readonly
- `baremetal_ext4_journal_health.py`: Monitor ext4 filesystem journal health including journal size, error counts, filesystem state, and recent recovery events to detect potential data corruption issues before they become catastrophic
- `sysctl_audit.py`: Audit kernel parameters (sysctl) against a baseline configuration
- `baremetal_sysctl_security_audit.py`: Audit kernel sysctl parameters against built-in security best practices (CIS benchmarks, STIG guidelines) covering network security, kernel memory protections, filesystem security, and user namespace controls without requiring a baseline file
- `process_resource_monitor.py`: Monitor process resource consumption and detect zombie/resource-hungry processes
- `baremetal_socket_state_monitor.py`: Monitor TCP/UDP socket state distribution to detect connection anomalies like excessive TIME_WAIT sockets (port exhaustion), CLOSE_WAIT accumulation (file descriptor leaks), and SYN flood attacks
- `baremetal_socket_buffer_monitor.py`: Monitor socket buffer memory usage and pressure to detect network bottlenecks from undersized or exhausted buffers (tcp_mem, udp_mem, rmem/wmem) that cause packet drops and connection throttling
- `baremetal_socket_queue_monitor.py`: Monitor socket receive and send queue depths to identify slow consumers, network congestion, and listen backlog issues by analyzing per-socket buffer usage via ss and /proc/net with configurable thresholds
- `baremetal_listening_port_monitor.py`: Monitor listening ports and detect unexpected services by analyzing /proc/net files to identify all listening TCP/UDP ports with their associated processes, supporting expected/unexpected port validation and security auditing
- `baremetal_process_connection_audit.py`: Audit active network connections per process by analyzing non-LISTEN TCP sockets to identify which processes have established connections, detect excessive connection counts, find unexpected outbound connections for security auditing, and troubleshoot connectivity issues
- `baremetal_process_capabilities_auditor.py`: Audit Linux process capabilities for security monitoring, identifying non-root processes with elevated capabilities (CAP_SYS_ADMIN, CAP_NET_RAW, CAP_DAC_OVERRIDE, etc.) that may indicate privilege escalation risks or misconfigured services
- `baremetal_ephemeral_port_monitor.py`: Monitor ephemeral (dynamic) port usage against the kernel-configured range to detect exhaustion risk before services fail with "Cannot assign requested address" errors, tracking TIME_WAIT accumulation and per-destination port consumption
- `baremetal_swap_monitor.py`: Monitor swap usage and memory pressure indicators to detect insufficient RAM, excessive swap activity, and systems at risk of OOM killer activation
- `baremetal_memory_reclaim_monitor.py`: Monitor kernel memory reclamation activity (kswapd, direct reclaim, compaction) to detect memory pressure before it impacts application performance or triggers OOM kills - tracks page scan rates, reclaim efficiency, and allocation stalls
- `baremetal_sysv_ipc_monitor.py`: Monitor System V IPC resource usage (semaphores, shared memory, message queues) to detect exhaustion before "No space left on device" errors impact databases (PostgreSQL, Oracle, SAP), middleware, and HPC applications
- `baremetal_etcd_health_monitor.py`: Monitor standalone etcd cluster health including member connectivity, leader election, database size, latency, and alarm conditions - essential for distributed systems using etcd for coordination
- `baremetal_entropy_monitor.py`: Monitor system entropy pool levels for cryptographic operations, detecting low entropy that causes /dev/random blocking, TLS handshake delays, and key generation issues on high-traffic servers or VMs
- `baremetal_hugepage_monitor.py`: Monitor hugepage allocation and usage including static hugepages, THP status, per-NUMA distribution, and fragmentation issues for database and VM workloads
- `baremetal_oom_risk_analyzer.py`: Analyze processes at risk of being killed by the Linux OOM killer by examining OOM scores and memory usage to identify candidates for termination before a memory crisis
- `baremetal_oom_kill_history.py`: Analyze OOM kill history from kernel logs (dmesg/journalctl) to identify patterns including frequently killed processes, time distribution of kills, memory state at kill time, and cgroup/container context for post-incident analysis
- `baremetal_package_security_audit.py`: Audit system packages for pending security updates on apt/dnf/yum-based systems, categorizing by severity (critical/important/moderate/low) for compliance and vulnerability management
- `baremetal_security_policy_monitor.py`: Monitor Linux Security Module (LSM) status including SELinux and AppArmor, detecting disabled/permissive modes, policy violations, recent denials, and configuration drift for enterprise security compliance
- `baremetal_auditd_health_monitor.py`: Monitor Linux audit daemon (auditd) health and configuration including service status, audit rule verification, log file status, lost event detection, and backlog monitoring for security compliance in enterprise baremetal environments
- `baremetal_usb_device_monitor.py`: Monitor USB devices connected to servers for security compliance, detecting mass storage devices (potential data exfiltration) and checking against device whitelists for data center security auditing
- `baremetal_numa_balance_monitor.py`: Monitor NUMA topology and memory balance on multi-socket systems to detect cross-node memory imbalances, high NUMA miss ratios, and per-node memory pressure
- `baremetal_numa_latency_monitor.py`: Analyze NUMA distance matrix and memory access latency on multi-socket systems to identify high-latency inter-node paths, asymmetric topologies, and page migration issues that impact performance of memory-intensive workloads
- `baremetal_memory_fragmentation_analyzer.py`: Analyze memory fragmentation using buddy allocator statistics to detect external fragmentation causing allocation failures despite available free memory, monitor hugepage availability, and identify need for memory compaction
- `baremetal_cgroup_pressure_monitor.py`: Monitor cgroup v2 PSI (Pressure Stall Information) to detect CPU, memory, and I/O contention on container hosts before performance degradation or OOM kills occur
- `baremetal_cgroup_memory_limits_monitor.py`: Monitor container/cgroup memory usage against configured limits (memory.max) to identify containers at risk of OOM kills, track memory-hungry workloads, and provide early warning before memory exhaustion on Docker/containerd/Kubernetes nodes
- `baremetal_conntrack_monitor.py`: Monitor Linux connection tracking (conntrack) table saturation to detect DDoS attacks, traffic spikes, or misconfigured applications causing table exhaustion and dropped connections
- `baremetal_coredump_monitor.py`: Monitor coredump configuration and storage to ensure crash dumps are properly captured for debugging, including core pattern, ulimit settings, systemd-coredump config, and storage space
- `baremetal_cpu_vulnerability_scanner.py`: Scan CPU hardware vulnerabilities (Spectre, Meltdown, MDS, etc.) and verify kernel mitigations are enabled for security compliance across server fleets
- `baremetal_smt_status_monitor.py`: Monitor SMT (Simultaneous Multithreading/Hyperthreading) status and security implications including CPU topology, thread siblings, and vulnerabilities that can be mitigated by disabling SMT (L1TF, MDS, TAA) - essential for security-sensitive environments
- `baremetal_cpu_microcode_monitor.py`: Monitor CPU microcode versions across sockets and cores to detect outdated or inconsistent microcode, verify security patches are applied, and support fleet-wide compliance checking with minimum version enforcement
- `baremetal_cstate_residency_monitor.py`: Monitor CPU C-state (idle state) residency to analyze power management effectiveness, detect CPUs stuck in shallow sleep states, identify workloads preventing deep sleep, and validate datacenter power configurations
- `baremetal_fd_exhaustion_monitor.py`: Monitor system-wide and per-process file descriptor usage to detect fd exhaustion before "too many open files" errors cause service failures, connection drops, and application crashes
- `baremetal_fd_leak_detector.py`: Detect file descriptor leaks in long-running processes by tracking FD counts over time, identifying processes with unusually high FD counts, and monitoring FD growth rates to catch leaks before exhaustion
- `baremetal_inotify_exhaustion_monitor.py`: Monitor inotify watch usage to detect exhaustion risk before "No space left on device" errors impact kubelet, IDEs, file sync tools, and build systems that rely on filesystem event monitoring
- `baremetal_inode_exhaustion_monitor.py`: Monitor filesystem inode usage to detect exhaustion before cryptic "no space left on device" errors occur even when disk space is available - critical for systems with millions of small files
- `baremetal_kdump_config_audit.py`: Audit kdump (kernel crash dump) configuration for disaster recovery readiness, checking crashkernel reservation, service status, dump target configuration, and available storage for crash analysis
- `baremetal_io_latency_analyzer.py`: Analyze I/O latency patterns by sampling /proc/diskstats to identify slow storage operations, high latency devices, and I/O bottlenecks with configurable thresholds
- `baremetal_systemd_journal_analyzer.py`: Analyze systemd journal for service failures, restart loops, OOM kills, segfaults, authentication failures, and error patterns to detect application-level issues before they cascade
- `baremetal_journal_disk_usage.py`: Monitor systemd journal disk usage and health including total disk consumption, journal integrity verification, top log-producing services, and journal configuration validation with configurable percentage and absolute size thresholds
- `baremetal_syslog_rate_monitor.py`: Monitor syslog/journald message rates to detect log storms, excessive logging from specific services, and unusual message patterns that may indicate runaway services, security events, or application failures
- `baremetal_logrotate_status_monitor.py`: Monitor logrotate status and log file health including large unrotated logs, stale rotation state, logrotate configuration errors, and log directory sizes to detect failed log rotation before disk exhaustion
- `baremetal_slab_monitor.py`: Monitor kernel slab allocator health to detect memory fragmentation, kernel memory leaks, and runaway caches (dentry storms, inode leaks) before they cause system instability
- `baremetal_zombie_process_monitor.py`: Detect and report zombie (defunct) processes, identify parent processes not properly reaping children, and track zombie age to prevent PID exhaustion
- `baremetal_signal_disposition_monitor.py`: Monitor process signal dispositions to detect processes ignoring SIGTERM (won't gracefully shut down), blocking critical signals, or having unusual signal masks - useful for pre-deployment checks and identifying misbehaving applications
- `baremetal_defunct_parent_analyzer.py`: Analyze processes orphaned (reparented to init/PID 1) which may indicate crashed parent processes, detecting service crashes that left child workers running, resource leaks from unsupervised processes, and application instability patterns
- `baremetal_uninterruptible_process_monitor.py`: Detect processes stuck in uninterruptible sleep (D-state), identify wait channels (NFS hangs, disk I/O, kernel locks), and categorize blocking causes to diagnose storage, network, or driver issues before cascading failures
- `baremetal_container_runtime_health.py`: Monitor container runtime health (Docker, containerd, podman) including service status, storage usage, container states, and image management
- `baremetal_libvirt_health_monitor.py`: Monitor libvirt/KVM hypervisor and virtual machine health including VM states, autostart configuration, storage pools, and virtual networks
- `baremetal_kernel_lockup_detector.py`: Detect kernel lockups, RCU stalls, hung tasks, and other indicators of system instability from dmesg/journalctl to identify hardware problems or driver bugs
- `baremetal_systemd_timer_monitor.py`: Monitor systemd timer health including failed timers, missed executions, and associated service failures to ensure scheduled tasks run reliably
- `baremetal_cron_job_monitor.py`: Monitor cron job health including syntax errors, invalid commands, orphaned user crontabs, and permission issues across system crontabs and user crontabs
- `baremetal_systemd_restart_loop_detector.py`: Detect systemd services stuck in restart loops by monitoring restart counts within configurable time windows, identifying services that are repeatedly crashing and restarting
- `baremetal_systemd_unit_drift_detector.py`: Detect systemd unit files with local overrides, drop-in configurations, or masked states that differ from package defaults - useful for security auditing, configuration management, and fleet consistency
- `baremetal_systemd_dependency_analyzer.py`: Analyze systemd unit dependencies to detect broken or problematic configurations including failed dependencies, masked dependencies, missing units, circular dependency risks, and deep dependency chains that slow boot times
- `baremetal_systemd_slice_monitor.py`: Monitor systemd slice resource usage (CPU, memory, I/O) using cgroup v2 statistics for capacity planning and troubleshooting on container hosts and multi-tenant systems, tracking resource consumption per slice with PSI (Pressure Stall Information) support
- `baremetal_systemd_security_scanner.py`: Scan systemd service units for security configuration issues using `systemd-analyze security`, identifying services lacking sandboxing (PrivateTmp, ProtectSystem, etc.) and prioritizing hardening improvements by exposure score
- `baremetal_watchdog_monitor.py`: Monitor hardware and software watchdog timer status to ensure automatic system recovery from hangs, checking watchdog device availability, daemon status, timeout settings, and systemd watchdog configuration
- `baremetal_ssl_cert_scanner.py`: Scan filesystem for SSL/TLS certificates and check expiration status to prevent outages from expired certificates in web servers, databases, and other services
- `baremetal_disk_queue_monitor.py`: Monitor disk I/O queue depths to detect storage bottlenecks and saturation before they cause latency spikes, with configurable thresholds and IOPS tracking
- `baremetal_iptables_audit.py`: Audit iptables firewall rules for security and performance issues including rule count analysis, empty chains, unused rules, overly permissive/restrictive rules, and default policy review
- `baremetal_process_limits_monitor.py`: Monitor per-process resource limits (ulimits) to detect processes approaching their configured limits before hitting "too many open files" or other resource exhaustion errors
- `baremetal_vmalloc_monitor.py`: Monitor kernel vmalloc memory usage to detect exhaustion before cryptic allocation failures, tracking total usage, fragmentation, and top consumers
- `baremetal_writeback_monitor.py`: Monitor kernel writeback cache behavior and dirty page pressure to detect I/O bottlenecks, track dirty page ratios vs thresholds, and identify when processes are at risk of being throttled due to excessive buffered writes
- `baremetal_scheduler_affinity_auditor.py`: Audit CPU affinity masks and scheduler policies (SCHED_FIFO, SCHED_RR, SCHED_OTHER) to detect misconfigurations causing latency spikes, RT process starvation risks, and CPU isolation violations
- `baremetal_firmware_inventory.py`: Collect firmware version inventory including BIOS/UEFI, BMC/IPMI, CPU microcode, storage controller, network adapter, and GPU firmware for fleet-wide tracking, security assessments, and compliance reporting

### Kubernetes Management
- `kubernetes_node_health.py`: Check Kubernetes node health and resource availability
- `k8s_kubelet_health_monitor.py`: Monitor kubelet health on Kubernetes nodes including node conditions, heartbeat staleness, restart frequency, and version consistency across the cluster
- `k8s_pod_resource_audit.py`: Audit pod resource usage and identify resource issues
- `k8s_extended_resources_audit.py`: Audit extended resources (GPUs, FPGAs, custom device plugins) allocation and utilization across heterogeneous baremetal clusters
- `k8s_pv_health_check.py`: Check persistent volume health and storage status
- `k8s_pvc_stuck_detector.py`: Detect PersistentVolumeClaims stuck in Pending state with diagnostic information about provisioning issues
- `k8s_backup_health_monitor.py`: Monitor backup health including Velero backups, VolumeSnapshots, and backup CronJobs for disaster recovery compliance
- `k8s_deployment_status.py`: Monitor Deployment and StatefulSet rollout status and replica availability
- `k8s_helm_release_monitor.py`: Monitor Helm release health and deployment status including release state, chart versions, and detection of failed or stalled releases
- `k8s_statefulset_health.py`: Monitor StatefulSet health with detailed pod and PVC status checking
- `k8s_job_monitor.py`: Monitor Kubernetes Jobs and CronJobs health, detecting failed jobs, stuck jobs, and CronJob scheduling issues
- `k8s_daemonset_health_monitor.py`: Monitor DaemonSet health with node coverage verification, pod status on each node, and detection of scheduling issues
- `k8s_cni_health_monitor.py`: Monitor CNI (Container Network Interface) health including plugin detection, DaemonSet status, node network conditions, and IPAM status
- `k8s_dns_health_monitor.py`: Monitor DNS health including CoreDNS/kube-dns pod status and resolution testing
- `k8s_metrics_server_health_monitor.py`: Monitor Metrics Server health critical for HPA/VPA functionality, including deployment status, API availability, and metrics freshness
- `k8s_event_monitor.py`: Monitor Kubernetes events to track cluster issues and anomalies
- `k8s_node_capacity_planner.py`: Analyze cluster capacity and forecast resource allocation
- `k8s_node_resource_fragmentation_analyzer.py`: Analyze resource fragmentation across nodes, detect phantom capacity where free resources can't schedule pods, identify limiting factors
- `k8s_crd_health_analyzer.py`: Analyze Custom Resource Definition (CRD) health including establishment status, version compatibility, conversion webhooks, and unused CRD detection for operators like Prometheus, Cert-Manager, etc.
- `k8s_cpu_throttling_detector.py`: Detect pods experiencing or at risk of CPU throttling
- `k8s_ingress_cert_checker.py`: Check Ingress certificates for expiration and health status
- `k8s_node_drain_readiness.py`: Analyze node drainability and orchestrate graceful node maintenance
- `k8s_memory_pressure_analyzer.py`: Detect memory pressure on nodes and analyze pod memory usage patterns
- `k8s_node_pressure_monitor.py`: Monitor all node pressure conditions (MemoryPressure, DiskPressure, PIDPressure, NetworkUnavailable) for proactive capacity management
- `k8s_pdb_health_monitor.py`: Monitor PodDisruptionBudget health to detect PDBs blocking maintenance or protecting unhealthy workloads
- `k8s_pdb_coverage_analyzer.py`: Analyze PDB coverage across Deployments, StatefulSets, and ReplicaSets to identify workloads vulnerable to unexpected disruptions
- `k8s_pod_eviction_risk_analyzer.py`: Identify pods at risk of eviction due to resource pressure or QoS class
- `k8s_qos_class_auditor.py`: Audit pod QoS classes (Guaranteed/Burstable/BestEffort) to identify eviction risks and critical workloads without proper QoS configuration
- `k8s_pending_pod_analyzer.py`: Analyze pods stuck in Pending state and diagnose scheduling failures (resources, taints, affinity, PVC issues)
- `k8s_pod_topology_analyzer.py`: Analyze pod topology spread constraints and affinity rules to ensure high availability
- `k8s_node_restart_monitor.py`: Monitor node restart activity and detect nodes with excessive restarts
- `k8s_pod_count_analyzer.py`: Audit pod counts, scaling configuration, and resource quota usage
- `k8s_orphaned_resources_finder.py`: Find orphaned and unused resources (ConfigMaps, Secrets, PVCs, Services, ServiceAccounts)
- `k8s_configmap_secret_size_analyzer.py`: Analyze ConfigMap and Secret sizes to find oversized objects that stress etcd and degrade cluster performance
- `k8s_finalizer_analyzer.py`: Find resources stuck in Terminating state due to finalizers blocking deletion
- `k8s_gitops_sync_monitor.py`: Monitor GitOps controller sync status for Flux CD (Kustomizations, HelmReleases, GitRepositories) and ArgoCD (Applications, ApplicationSets), detecting failed reconciliations, stalled syncs, and suspended resources
- `k8s_container_restart_analyzer.py`: Analyze container restart patterns and identify root causes with remediation suggestions
- `k8s_job_failure_analyzer.py`: Analyze Kubernetes Job and CronJob failures to identify patterns, root causes, and provide remediation suggestions for batch workloads
- `k8s_init_container_analyzer.py`: Analyze init container failures and startup issues including image pull errors, crash loops, config errors, slow/stuck init containers, and OOMKills with remediation suggestions
- `k8s_workload_restart_age_analyzer.py`: Analyze workload age and restart patterns to detect stale deployments and track deployment freshness
- `k8s_workload_generation_analyzer.py`: Analyze Kubernetes workload ownership chains to trace pod origins through controllers, operators, and Helm/ArgoCD deployments for compliance auditing and troubleshooting
- `k8s_pod_startup_latency_analyzer.py`: Analyze pod startup latency to identify slow-starting pods, breaking down scheduling, init container, and container startup phases
- `k8s_configmap_audit.py`: Audit ConfigMaps for size limits, unused ConfigMaps, missing keys referenced by pods, and configuration best practices
- `k8s_network_policy_audit.py`: Audit network policies and identify security gaps, unprotected pods, and configuration issues
- `k8s_node_taint_analyzer.py`: Analyze node taints and their impact on pod scheduling, identifying blocking taints, orphaned taints, and workload distribution
- `k8s_node_label_auditor.py`: Audit node labels and annotations for consistency, compliance with naming conventions, missing topology/role labels, and deprecated labels
- `k8s_node_kernel_config_audit.py`: Audit sysctl kernel parameters across Kubernetes nodes to detect inconsistencies and non-compliant configurations critical for baremetal clusters
- `k8s_resource_quota_auditor.py`: Audit ResourceQuota and LimitRange policies across namespaces to ensure proper resource governance
- `k8s_namespace_resource_analyzer.py`: Analyze namespace resource utilization for capacity planning, chargeback, and multi-tenant governance
- `k8s_resource_right_sizer.py`: Analyze resource requests/limits against actual usage to identify over-provisioned and under-provisioned workloads for cost optimization
- `k8s_image_pull_analyzer.py`: Analyze image pull issues including ImagePullBackOff errors, slow pulls, registry connectivity, and authentication failures
- `k8s_image_policy_auditor.py`: Audit container images for security best practices including digest pinning, mutable tags (latest/dev), and untrusted registries for supply chain security
- `k8s_pod_image_registry_audit.py`: Audit running pod container image registries for compliance, detecting unapproved registries, public Docker Hub usage in production, and implicit docker.io references
- `k8s_job_health_monitor.py`: Monitor Job and CronJob health including completion status, scheduling patterns, stuck jobs, and resource consumption
- `k8s_webhook_health_monitor.py`: Monitor admission webhook health including certificate expiration, endpoint availability, failure policies, and recent webhook rejections
- `k8s_storageclass_health_monitor.py`: Monitor StorageClass provisioners and CSI driver health including provisioner status, PVC failures, and stuck volume attachments
- `k8s_volume_snapshot_monitor.py`: Monitor VolumeSnapshot health and backup operations including failed or stuck snapshots, old snapshots exceeding retention, orphaned VolumeSnapshotContent, and missing VolumeSnapshotClass configuration
- `k8s_volume_attachment_analyzer.py`: Analyze VolumeAttachment resources for health issues including stale attachments, orphaned node references, multi-attach violations on RWO volumes, and stuck terminating attachments that can cause pod scheduling failures
- `k8s_hpa_health_monitor.py`: Monitor HorizontalPodAutoscaler health and effectiveness including metrics server availability, scaling issues, and HPA misconfigurations
- `k8s_hpa_thrashing_detector.py`: Detect HPA thrashing (rapid scale-up/scale-down cycles) by analyzing scaling events, identifying HPAs stuck at min/max replicas, and detecting metrics availability issues
- `k8s_service_endpoint_monitor.py`: Monitor Service endpoint health to detect services without healthy endpoints, selector mismatches, LoadBalancer IP issues, and endpoint readiness problems
- `k8s_endpointslice_health_monitor.py`: Monitor EndpointSlice health for service discovery issues including no-ready endpoints, high not-ready ratios, missing EndpointSlices, and slice fragmentation
- `k8s_service_health_monitor.py`: Monitor Kubernetes Service health by checking endpoint availability, identifying services with zero endpoints or partially ready endpoints, and correlating service configuration with endpoint status
- `k8s_rbac_auditor.py`: Audit Kubernetes RBAC roles and bindings for security issues including cluster-admin access, wildcard permissions, dangerous verbs, anonymous user access, and overly permissive service account bindings
- `k8s_serviceaccount_auditor.py`: Audit Kubernetes ServiceAccounts for security issues including automountServiceAccountToken settings, default ServiceAccount usage, unused accounts, and high-privilege role bindings
- `k8s_pod_security_audit.py`: Audit pod security contexts and Linux capabilities for security risks including privileged containers, root user execution, dangerous capabilities, host namespace sharing, and missing security profiles
- `k8s_probe_config_audit.py`: Audit Kubernetes pod health probe configurations to identify reliability issues including missing liveness/readiness/startup probes, misconfigured timeouts and thresholds, and probe anti-patterns that can lead to service outages
- `k8s_pod_lifecycle_hook_analyzer.py`: Analyze pod lifecycle hook configurations (preStop/postStart) to identify issues affecting graceful shutdown during node drains and rolling updates, including missing preStop hooks on stateful workloads, timeout mismatches with terminationGracePeriodSeconds, and hook failures from events
- `k8s_control_plane_health.py`: Monitor Kubernetes control plane health including API server availability and latency, etcd cluster status, controller-manager and scheduler leader election, and control plane pod health
- `k8s_kubeconfig_health_check.py`: Validate kubeconfig files and cluster connectivity including certificate expiration, API server reachability, authentication validation, and multi-kubeconfig support for CI/CD and multi-cluster environments
- `k8s_api_latency_analyzer.py`: Analyze Kubernetes API server response times to detect performance degradation, measure latencies for various API operations (LIST, GET), and identify slow operations before they cause cluster issues
- `k8s_secret_expiry_monitor.py`: Monitor Kubernetes Secret age and TLS certificate expiration to detect expired certificates, approaching expirations, and stale secrets
- `k8s_csr_health_monitor.py`: Monitor Kubernetes CertificateSigningRequest (CSR) health and approval status including pending requests, denied/failed CSRs, approval latency tracking, and certificate rotation health for kubelet bootstrap and cert-manager workflows
- `k8s_lease_monitor.py`: Monitor Kubernetes Lease objects for leader election health, detecting stale leases, orphaned holders, leadership instability, and missed renewals
- `k8s_priority_class_analyzer.py`: Analyze PriorityClass configuration and usage including pod scheduling priorities, preemption policies, global defaults, and identify pods without explicit priority assignment
- `k8s_operator_health_monitor.py`: Monitor Kubernetes operator health (Prometheus, Cert-Manager, ArgoCD, Flux, Istio, etc.) including controller pod status, CRD availability, and deployment readiness
- `k8s_api_deprecation_checker.py`: Check for deprecated Kubernetes API versions in cluster resources to prepare for upgrades, identifying resources using removed or deprecated APIs with replacement suggestions and removal version information
- `k8s_runtimeclass_analyzer.py`: Analyze Kubernetes RuntimeClass usage across workloads to understand runtime distribution (runc, kata, gVisor), identify pods running with default runtime, detect references to non-existent RuntimeClasses, and provide isolation level summaries for security audits and compliance reporting

### System Utilities
- `generate_fstab.sh`: Generate an /etc/fstab file from current mounts using UUIDs

## Usage

### listec2hosts.py
```
python listec2hosts.py [-a] [-r region] [--format format] [--boto3]
  -a, --all: Include all instances, not just running instances
  -r, --region: Specify the AWS region (default: us-west-2)
  --format: Output format, either 'plain' or 'table' (default: plain)
  --boto3: Use the newer boto3 library instead of boto (deprecated)
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region
  - `EC2_URL`: Override the default EC2 URL

### ec2_manage.py
```
python ec2_manage.py [action] [instance_id] [-r region] [--boto3]
  action: Action to perform - 'start', 'stop', or 'restart'
  instance_id: ID of the EC2 instance to manage
  -r, --region: Specify the AWS region (default: us-west-2)
  --boto3: Use the newer boto3 library instead of boto (deprecated)
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region
  - `EC2_URL`: Override the default EC2 URL

### acrosshosts.sh
```
acrosshosts.sh [OPTIONS] <hostlist> <command>
  <hostlist>    File containing list of hosts (one per line)
  <command>     Command to execute on each host

Options:
  -j, --jobs N          Run N jobs in parallel (default: 1)
  -t, --timeout N       SSH connection timeout in seconds (default: 30)
  -u, --user USER       SSH username (default: current user)
  -s, --strict          Enable strict host key checking (default: disabled)
  -o, --ssh-opts OPTS   Additional SSH options (quoted string)
  -T, --teleport        Use Teleport (tsh ssh) instead of regular SSH
  -v, --verbose         Verbose output (show SSH commands)
  -q, --quiet           Quiet mode (only show errors)
  -n, --dry-run         Show what would be executed without running
  -h, --help            Display help message
```

Features:
  - Parallel execution with configurable job count
  - Support for both standard SSH and Teleport (tsh ssh)
  - Configurable SSH timeout (prevents hanging on unreachable hosts)
  - Comprehensive error handling and reporting
  - Dry-run mode for safety before destructive operations
  - Support for comments and empty lines in hostlist
  - Color-coded output (success/failure indicators)
  - Summary report showing succeeded and failed hosts

Exit codes:
  - 0: All hosts succeeded
  - 1: One or more hosts failed
  - 2: Usage error or invalid arguments

Examples:
```bash
# Run uptime on all hosts
acrosshosts.sh hosts.txt "uptime"

# Run with 5 parallel connections
acrosshosts.sh -j 5 hosts.txt "df -h"

# Use specific user with verbose output
acrosshosts.sh -u admin -v hosts.txt "systemctl status nginx"

# Dry run to see what would execute
acrosshosts.sh -n hosts.txt "rm -rf /tmp/old_files"

# Custom timeout and SSH options
acrosshosts.sh -t 10 -o "-p 2222" hosts.txt "hostname"

# Use Teleport for secure access
acrosshosts.sh -T hosts.txt "uptime"

# Use Teleport with parallel execution and specific user
acrosshosts.sh -T -j 5 -u admin hosts.txt "systemctl status app"
```

### useradd.sh
```
useradd.sh [hostlist.txt] [username] [sshpubkey]
```

### grephosts.sh
```
grephosts.sh [search query]
```

### generate_fstab.sh
```
generate_fstab.sh
```

### emptysgs.py
```
python emptysgs.py [-r region]
  -r, --region: Specify the AWS region (default: us-east-1)
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region

### ec2_tag_summary.py
```
python ec2_tag_summary.py --tag-key TAG_KEY [--tag-value TAG_VALUE] [--regions REGION1 REGION2 ...] [--format FORMAT]
  --tag-key: The tag key to group instances by (required)
  --tag-value: Optional tag value to filter by
  --regions: AWS regions to scan (default: us-west-2 us-east-1)
  --format: Output format, either 'plain' or 'json' (default: plain)
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region

### terminate_instance.py
```
python terminate_instance.py [instance_id] [-r region]
  instance_id: ID of the EC2 instance to terminate
  -r, --region: Specify the AWS region (default: us-west-2)
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region
  - `EC2_URL`: Override the default EC2 URL

### stop_all_instances.py
```
python stop_all_instances.py [-r region] [--force] [--dry-run]
  -r, --region: Specify the AWS region (default: us-west-2)
  --force: Force stop without confirmation prompt
  --dry-run: Show instances that would be stopped without actually stopping them
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region

### listvolumes.py
```
python listvolumes.py [-f filters] [-r region] [--format format] [--boto3]
  -f, --filters: Filters to apply (e.g., 'status=available', 'attachment.status=attached')
  -r, --region: Specify the AWS region (default: us-west-2)
  --format: Output format, either 'plain', 'table', or 'json' (default: plain)
  --boto3: Use the newer boto3 library instead of boto (deprecated)
```

Supported environment variables:
  - `AWS_ACCESS_KEY_ID` or `AWS_ACCESS_KEY`: AWS access key
  - `AWS_SECRET_ACCESS_KEY` or `AWS_SECRET_KEY`: AWS secret key
  - `EC2_REGION`: Override the default region

### baremetal_dmesg_analyzer.py
```
python baremetal_dmesg_analyzer.py [--since SINCE] [--format FORMAT] [-v] [-w]
  --since: Only show messages since specified time (e.g., "1 hour ago", "2023-01-01 10:00")
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show full error messages and details
  -w, --warn-only: Only show issues, suppress "no errors" message
```

Categories checked:
  - Disk I/O errors (ATA, SCSI, NVMe)
  - Memory errors (ECC, EDAC)
  - PCIe errors (AER, link issues)
  - CPU errors (MCE, thermal)
  - Network errors (link down, timeouts)
  - Filesystem errors (ext4, xfs, btrfs)
  - RAID errors (md)
  - Thermal warnings

Exit codes:
  - 0: No critical errors or warnings found
  - 1: Errors or warnings found in kernel messages
  - 2: Usage error or dmesg not available

Examples:
```bash
# Analyze all kernel messages
baremetal_dmesg_analyzer.py

# Only recent messages
baremetal_dmesg_analyzer.py --since "1 hour ago"

# JSON output
baremetal_dmesg_analyzer.py --format json

# Only show issues with full details
baremetal_dmesg_analyzer.py --warn-only -v

# Table format for recent critical issues
baremetal_dmesg_analyzer.py --since "24 hours ago" --format table
```

### baremetal_kernel_log_rate_monitor.py
```
python baremetal_kernel_log_rate_monitor.py [--warn-rate RATE] [--crit-rate RATE] [--burst-threshold N] [--format FORMAT] [-v] [-w]
  --warn-rate: Warning threshold in messages/minute (default: 50)
  --crit-rate: Critical threshold in messages/minute (default: 200)
  --burst-threshold: Burst detection threshold - messages in 5 seconds (default: 20)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information including priority breakdown
  -w, --warn-only: Only show output if issues are detected
```

Monitors kernel log message rates to detect anomalies:
  - Calculates overall message rate from kernel ring buffer
  - Detects rate anomalies using configurable thresholds
  - Identifies burst patterns (many messages in short time)
  - Tracks high-priority messages (emerg, alert, crit, err)
  - Early warning for hardware problems or driver issues

Exit codes:
  - 0: Normal message rate, no anomalies
  - 1: Elevated rate or anomalies detected
  - 2: Usage error or dmesg not available

Examples:
```bash
# Check current message rates
baremetal_kernel_log_rate_monitor.py

# JSON output for monitoring integration
baremetal_kernel_log_rate_monitor.py --format json

# Custom warning threshold
baremetal_kernel_log_rate_monitor.py --warn-rate 100 --crit-rate 500

# Verbose output with priority breakdown
baremetal_kernel_log_rate_monitor.py -v

# Only alert on issues (for monitoring scripts)
baremetal_kernel_log_rate_monitor.py --warn-only
```

### baremetal_efi_boot_audit.py
```
python baremetal_efi_boot_audit.py [--format FORMAT] [-v] [-w]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed boot entry information and device paths
  -w, --warn-only: Only show warnings and issues
```

Audits UEFI/EFI boot configuration:
  - Boot entry inventory and status
  - Boot order validation
  - Secure Boot status and Setup Mode detection
  - Duplicate or stale entry detection
  - Orphaned entries not in boot order
  - Boot timeout configuration

Exit codes:
  - 0: No issues detected
  - 1: Warnings detected (misconfiguration, duplicate entries, etc.)
  - 2: Usage error or not an EFI system (efibootmgr not available)

Examples:
```bash
# Basic EFI boot audit
baremetal_efi_boot_audit.py

# Show detailed boot entries and device paths
baremetal_efi_boot_audit.py --verbose

# Table format with full details
baremetal_efi_boot_audit.py --format table -v

# JSON output for automation
baremetal_efi_boot_audit.py --format json

# Only show issues (for monitoring)
baremetal_efi_boot_audit.py --warn-only
```

### baremetal_fd_limit_monitor.py
```
python baremetal_fd_limit_monitor.py [--format FORMAT] [-a] [-t THRESHOLD] [-n NAME] [-u USER] [-v] [--warn-only]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -a, --all: Show all processes, not just those above threshold
  -t, --threshold: Warning threshold percentage (default: 80.0)
  -n, --name: Filter by process name (case-insensitive substring match)
  -u, --user: Filter by process owner username
  -v, --verbose: Show detailed information
  --warn-only: Only show processes above threshold (default behavior)
```

Monitors file descriptor usage to prevent "too many open files" errors:
  - System-wide FD usage vs. limits
  - Per-process FD consumption
  - Detection of processes approaching ulimits (>80% usage)
  - Top FD consumers identification
  - Helps identify FD leaks in long-running services

Exit codes:
  - 0: No issues (all processes below threshold)
  - 1: Warnings (processes above threshold)
  - 2: Usage error or missing dependencies

Examples:
```bash
# Show all processes using >80% of FD limit
baremetal_fd_limit_monitor.py

# Show all processes with their FD usage
baremetal_fd_limit_monitor.py --all

# Filter by process name
baremetal_fd_limit_monitor.py --name nginx

# Filter by user
baremetal_fd_limit_monitor.py --user www-data

# Set custom threshold (70%)
baremetal_fd_limit_monitor.py --threshold 70

# JSON output for monitoring systems
baremetal_fd_limit_monitor.py --format json

# Table format with verbose output
baremetal_fd_limit_monitor.py --format table --verbose
```

### baremetal_open_file_monitor.py
```
python baremetal_open_file_monitor.py [--format FORMAT] [-v] [--min-fds N] [--warn-percent PCT] [--top N] [--name PATTERN] [--user USER] [--deleted-only] [-w]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information including file type breakdown
  --min-fds N: Minimum open FD count to report (default: 10)
  --warn-percent PCT: Warn when FD usage exceeds this percentage (default: 80)
  --top N: Show only top N processes by FD count (default: 20, 0=all)
  --name PATTERN: Filter by process name (case-insensitive substring match)
  --user USER: Filter by username
  --deleted-only: Only show processes holding deleted files open
  -w, --warn-only: Only show processes with warnings
```

Monitors open file handles to detect resource leaks and disk space issues:
  - Lists processes with highest open file descriptor counts
  - Detects processes holding deleted files open (disk space leaks after log rotation)
  - Identifies file types (regular files, sockets, pipes, devices)
  - Shows per-process FD usage vs limits
  - Supports filtering by process name, user, or minimum FD count

Exit codes:
  - 0: No issues detected (all processes within thresholds)
  - 1: Warnings detected (high FD usage or deleted files held open)
  - 2: Usage error or missing dependency

Examples:
```bash
# Show top processes by open FD count
baremetal_open_file_monitor.py

# Only show processes with 100+ open FDs
baremetal_open_file_monitor.py --min-fds 100

# Find processes holding deleted files (disk space leak)
baremetal_open_file_monitor.py --deleted-only

# Filter by process name
baremetal_open_file_monitor.py --name nginx

# Filter by user
baremetal_open_file_monitor.py --user www-data

# Top 10 in table format
baremetal_open_file_monitor.py --top 10 --format table

# JSON output for monitoring systems
baremetal_open_file_monitor.py --format json

# Verbose with type breakdown
baremetal_open_file_monitor.py -v --min-fds 50

# Custom warning threshold (50%)
baremetal_open_file_monitor.py --warn-percent 50
```

### disk_health_check.py
```
python disk_health_check.py [-d disk] [-v] [--format format] [--warn-only]
  -d, --disk: Specific disk to check (e.g., /dev/sda)
  -v, --verbose: Show detailed SMART attributes
  --format: Output format, either 'plain' or 'json' (default: plain)
  --warn-only: Only show disks with warnings or failures
```

Requirements:
  - smartmontools package (smartctl command)
  - Ubuntu/Debian: `sudo apt-get install smartmontools`
  - RHEL/CentOS: `sudo yum install smartmontools`

### baremetal_ssd_wear_monitor.py
```
python baremetal_ssd_wear_monitor.py [-d disk] [-v] [--format format] [--warn-only] [--warn N] [--critical N]
  -d, --disk: Specific disk to check (e.g., /dev/nvme0n1, /dev/sda)
  -v, --verbose: Show detailed wear metrics (data written, power on hours)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only: Only show SSDs with warnings or critical status
  --warn N: Warning threshold for remaining life percentage (default: 20)
  --critical N: Critical threshold for remaining life percentage (default: 10)
```

Metrics monitored:
  - Wear level / percentage used (life remaining)
  - Available spare capacity
  - Total data written (TB)
  - Media/data integrity errors
  - Power on hours

Example output:
```
[OK] /dev/nvme0n1 (500G Samsung SSD 980 PRO) - 95% life remaining
[WARN] /dev/sda (256G INTEL SSDSC2KB256G8) - 15% life remaining
  ! Wear level low: 15% remaining
```

Requirements:
  - smartmontools package (smartctl command)
  - Ubuntu/Debian: `sudo apt-get install smartmontools`
  - RHEL/CentOS: `sudo yum install smartmontools`

### baremetal_disk_life_predictor.py
```
python baremetal_disk_life_predictor.py [-d disk] [-v] [-w] [--format format]
  -d, --disk: Specific disk to check (e.g., /dev/sda)
  -v, --verbose: Show detailed information for all disks
  -w, --warn-only: Only show disks with elevated risk (LOW or higher)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
```

Risk levels:
  - MINIMAL: No concerning indicators (score < 10)
  - LOW: Minor indicators, monitor closely (score 10-29)
  - MEDIUM: Elevated risk, plan replacement (score 30-59)
  - HIGH: Imminent failure likely, replace ASAP (score >= 60)

Critical SMART attributes analyzed:
  - Reallocated sectors (ID 5) - bad sectors remapped to spare area
  - Pending sectors (ID 197) - sectors waiting to be remapped
  - Offline uncorrectable (ID 198) - sectors that couldn't be recovered
  - Reported uncorrect (ID 187) - uncorrectable errors reported
  - Command timeout (ID 188) - drive command timeouts
  - UDMA CRC errors (ID 199) - cable/connection issues

NVMe-specific metrics:
  - Percentage used (wear level)
  - Media errors
  - Available spare capacity

Requirements:
  - smartmontools package (smartctl command)
  - nvme-cli package for NVMe devices (optional)
  - Ubuntu/Debian: `sudo apt-get install smartmontools nvme-cli`
  - RHEL/CentOS: `sudo yum install smartmontools nvme-cli`

Exit codes:
  - 0: All disks healthy (minimal risk)
  - 1: Warnings detected (medium/high risk disks found)
  - 2: Missing dependency or no disks found

### baremetal_trim_status_monitor.py
```
python baremetal_trim_status_monitor.py [-d device] [-v] [-w] [--format format]
  -d, --device: Specific device to check (e.g., nvme0n1, sda)
  -v, --verbose: Show detailed information including partition mount status
  -w, --warn-only: Only show devices with TRIM issues
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
```

TRIM/discard commands allow SSDs to maintain performance by informing the drive which blocks are no longer in use. Without TRIM, SSD performance degrades over time.

Checks performed:
  - Whether SSDs support discard operations (via sysfs)
  - Filesystem mount options (discard mount option)
  - fstrim.timer systemd service status (preferred method)
  - Discard granularity and maximum bytes

Best practices:
  - Use fstrim.timer (recommended) - weekly batch TRIM operations
  - Or use 'discard' mount option - continuous TRIM (higher overhead)
  - fstrim.timer is preferred as it batches operations and reduces overhead

Exit codes:
  - 0: All SSDs have proper TRIM configuration
  - 1: SSDs found with TRIM misconfiguration
  - 2: Usage error

Examples:
```bash
# Check all SSDs for TRIM configuration
baremetal_trim_status_monitor.py

# Check specific device
baremetal_trim_status_monitor.py -d nvme0n1

# Show only devices with issues
baremetal_trim_status_monitor.py --warn-only

# JSON output for automation
baremetal_trim_status_monitor.py --format json
```

### baremetal_partition_alignment_checker.py
```
python baremetal_partition_alignment_checker.py [-d device] [-v] [-w] [--format format]
  -d, --device: Specific device to check (e.g., sda, nvme0n1)
  -v, --verbose: Show detailed information including sector sizes
  -w, --warn-only: Only show misaligned partitions
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
```

Partition alignment is critical for optimal I/O performance. Misaligned partitions cause read-modify-write cycles that significantly degrade performance on:
  - SSDs (especially with 4K or larger physical sectors)
  - Advanced Format HDDs (4K sector size)
  - RAID arrays with specific stripe sizes
  - NVMe drives with various LBA formats

Checks performed:
  - Partition start offset alignment to physical sector size
  - Optimal alignment for modern configurations (1MiB boundary)
  - Detection of legacy MBR-style misalignment (sector 63)
  - Optimal I/O size alignment when applicable

Alignment guidelines:
  - Modern drives should have partitions aligned to 1MiB (2048 sectors)
  - At minimum, partitions should be aligned to 4K (8 sectors for 512B logical)
  - SSDs and Advanced Format HDDs are especially sensitive to misalignment

Exit codes:
  - 0: All partitions properly aligned
  - 1: Misaligned partitions found
  - 2: Usage error or missing tools

Examples:
```bash
# Check all disk devices for partition alignment
baremetal_partition_alignment_checker.py

# Check specific device
baremetal_partition_alignment_checker.py -d sda

# Show only misaligned partitions
baremetal_partition_alignment_checker.py --warn-only

# Verbose output with sector size details
baremetal_partition_alignment_checker.py -v

# JSON output for automation
baremetal_partition_alignment_checker.py --format json
```

### nvme_health_monitor.py
```
python nvme_health_monitor.py [--format format] [-w] [-v] [--warn-wear N] [--critical-wear N] [--warn-temp N] [--critical-temp N]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show devices with warnings or issues
  -v, --verbose: Show detailed information
  --warn-wear: Wear level warning threshold percentage (default: 80)
  --critical-wear: Wear level critical threshold percentage (default: 90)
  --warn-temp: Temperature warning threshold in Celsius (default: 70)
  --critical-temp: Temperature critical threshold in Celsius (default: 80)
  --max-unsafe-shutdowns: Maximum unsafe shutdowns before warning (default: 10)
```

Requirements:
  - nvme-cli package (nvme command)
  - Ubuntu/Debian: `sudo apt-get install nvme-cli`
  - RHEL/CentOS: `sudo yum install nvme-cli`

Exit codes:
  - 0: All NVMe devices healthy
  - 1: Warnings or errors detected (high wear, media errors, thermal throttling)
  - 2: Missing dependency (nvme-cli not installed)

### disk_io_monitor.py
```
python disk_io_monitor.py [-f format] [-w] [-v]
  -f, --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show devices with warnings or issues
  -v, --verbose: Show detailed information and all issues
```

Requirements:
  - sysstat package (iostat command)
  - Ubuntu/Debian: `sudo apt-get install sysstat`
  - RHEL/CentOS: `sudo yum install sysstat`

Exit codes:
  - 0: All disks performing normally
  - 1: Performance warnings or issues detected
  - 2: Usage error or missing dependencies

Features:
  - Monitor disk I/O utilization and detect saturated devices
  - Track I/O latency (await time) and identify slow devices
  - Detect high I/O queue lengths indicating backlog
  - Analyze read vs write performance imbalance
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode to focus on problem devices
  - JSON output for monitoring system integration

Examples:
```bash
# Check all disk I/O performance
disk_io_monitor.py

# Show only devices with issues
disk_io_monitor.py --warn-only

# Detailed output with all issues
disk_io_monitor.py --verbose

# JSON output for monitoring integration
disk_io_monitor.py --format json

# Table format for easy reading
disk_io_monitor.py --format table

# Combine options: table format with warnings only
disk_io_monitor.py --format table --warn-only
```

Use Case: In large-scale baremetal environments, disk I/O bottlenecks can severely impact application performance. This script monitors I/O utilization, latency, and queue depth to identify slow or saturated disks before they cause application slowdowns. Critical for database servers, storage nodes, and high-throughput workloads where I/O performance directly impacts service quality. Use in monitoring pipelines to detect degrading disks, saturated RAID controllers, or misconfigured I/O schedulers.

### iosched_audit.py
```
python iosched_audit.py [--format format] [-w] [-v] [--include-virtual]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show devices with suboptimal scheduler settings
  -v, --verbose: Show detailed device information (model, queue depth, available schedulers)
  --include-virtual: Include virtual devices (loop, dm, md, ram)
```

Requirements:
  - sysfs filesystem mounted at /sys
  - Read access to /sys/block/* (no special privileges required)

Exit codes:
  - 0: All devices have optimal scheduler configuration
  - 1: Suboptimal or inconsistent scheduler configurations detected
  - 2: Usage error or /sys/block not accessible

Features:
  - Audit I/O scheduler settings across all block devices
  - Detect NVMe devices using complex schedulers (performance degradation)
  - Detect rotational disks using 'none' scheduler (potential performance issues)
  - Display device type (NVMe, SSD, HDD) and provide recommendations
  - Show queue depth and available schedulers
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode to focus on misconfigured devices
  - JSON output for automated auditing

Scheduler Recommendations:
  - **NVMe devices**: 'none' (bypass scheduler overhead for maximum IOPS)
  - **SSD devices**: 'none' or 'mq-deadline' (minimal overhead)
  - **Rotational (HDD)**: 'mq-deadline' or 'bfq' (optimize seek patterns)

Examples:
```bash
# Check all block devices
iosched_audit.py

# Show only misconfigurations
iosched_audit.py --warn-only

# Detailed output with queue information
iosched_audit.py --verbose

# JSON output for automation
iosched_audit.py --format json

# Table format for easy reading
iosched_audit.py --format table

# Combine: show only warnings in table format
iosched_audit.py --format table --warn-only
```

Use Case: In large-scale baremetal environments, incorrect I/O scheduler configuration is a common performance issue that often goes undetected. NVMe drives with complex schedulers (mq-deadline, bfq) suffer unnecessary overhead and reduced IOPS, while traditional spinning disks with 'none' scheduler experience poor performance due to unoptimized seeks. This script audits scheduler settings across your entire fleet to identify misconfigurations before they impact production workloads. Essential for database servers, storage nodes, and any high-performance I/O workload. Use in provisioning pipelines to verify correct configuration or in monitoring systems to detect configuration drift.

### check_raid.py
```
python check_raid.py [-t type] [-v] [--format format] [--warn-only]
  -t, --type: Type of RAID to check - 'all', 'software', or 'hardware' (default: all)
  -v, --verbose: Show detailed information
  --format: Output format, either 'plain' or 'json' (default: plain)
  --warn-only: Only show arrays with warnings or failures
```

Requirements:
  - Software RAID: /proc/mdstat (built-in on Linux)
  - LSI/Broadcom hardware RAID: MegaCli
  - HP hardware RAID: hpacucli/ssacli
  - Requires root privileges for hardware RAID detection

### baremetal_raid_rebuild_monitor.py
```
python baremetal_raid_rebuild_monitor.py [-a array] [--format format] [-v] [--rebuilding-only]
  -a, --array: Monitor specific array (e.g., md0)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information including block counts and device list
  --rebuilding-only: Only show arrays with active rebuild/resync operations
```

Requirements:
  - Linux software RAID with /proc/mdstat

Example output during rebuild:
```
RAID Rebuild Status
======================================================================

[*] md0 (raid1) - RECOVERY IN PROGRESS
    Progress: 45.2%
    Speed:    125.3 MB/s
    ETA:      2h 15m
    Finish:   2025-01-29 18:30:00
```

Use Case: During hardware failures and maintenance windows, knowing the estimated completion time of RAID rebuilds is critical for planning. This script provides real-time progress tracking with ETA for mdadm software RAID operations (recovery, resync, reshape, check). Use it to monitor rebuilds after disk replacement, estimate maintenance window duration, or integrate with alerting systems to track long-running operations. Exit code 1 indicates rebuild in progress, useful for scripting.

### baremetal_lvm_health_monitor.py
```
python baremetal_lvm_health_monitor.py [--format format] [-v] [-w] [--thin-warn PCT] [--thin-crit PCT] [--vg-warn PCT] [--vg-crit PCT] [--snap-age DAYS]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed LVM information
  -w, --warn-only: Only show warnings and errors
  --thin-warn: Warning threshold for thin pool usage (default: 80%)
  --thin-crit: Critical threshold for thin pool usage (default: 90%)
  --vg-warn: Warning threshold for volume group usage (default: 85%)
  --vg-crit: Critical threshold for volume group usage (default: 95%)
  --snap-age: Warning threshold for snapshot age in days (default: 7, 0 to disable)
```

Requirements:
  - LVM2 tools (lvs, vgs, pvs commands)
  - Ubuntu/Debian: `sudo apt-get install lvm2`
  - RHEL/CentOS: `sudo yum install lvm2`

Exit codes:
  - 0: All LVM components healthy
  - 1: Warnings or critical issues detected
  - 2: Usage error or LVM tools not available

Features:
  - Monitor thin pool data and metadata usage
  - Detect snapshot space exhaustion before failure
  - Track aging snapshots consuming space
  - Monitor volume group capacity
  - Detect missing or orphaned physical volumes
  - Multiple output formats (plain, JSON, table)

Examples:
```bash
# Check all LVM components with default thresholds
baremetal_lvm_health_monitor.py

# Custom thin pool thresholds
baremetal_lvm_health_monitor.py --thin-warn 70 --thin-crit 85

# Show detailed LVM information
baremetal_lvm_health_monitor.py --verbose

# JSON output for monitoring integration
baremetal_lvm_health_monitor.py --format json

# Only show warnings and errors
baremetal_lvm_health_monitor.py --warn-only

# Warn about snapshots older than 14 days
baremetal_lvm_health_monitor.py --snap-age 14
```

### baremetal_zfs_pool_health.py
```
python baremetal_zfs_pool_health.py [--format format] [-v] [-w] [--capacity-warn PCT] [--capacity-crit PCT] [--frag-warn PCT] [--scrub-warn DAYS] [--error-threshold COUNT]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed pool and device information
  -w, --warn-only: Only show warnings and errors
  --capacity-warn: Warning threshold for pool capacity (default: 80%)
  --capacity-crit: Critical threshold for pool capacity (default: 90%)
  --frag-warn: Warning threshold for fragmentation (default: 50%)
  --scrub-warn: Days since last scrub warning threshold (default: 14)
  --error-threshold: Device error count threshold (default: 1)
```

Requirements:
  - ZFS utilities (zpool, zfs commands)
  - Install with: `sudo apt-get install zfsutils-linux`

Exit codes:
  - 0: All ZFS pools healthy
  - 1: Warnings or critical issues detected
  - 2: Usage error or ZFS tools not available

Features:
  - Monitor pool health state (ONLINE, DEGRADED, FAULTED, OFFLINE)
  - Track pool capacity with configurable thresholds
  - Monitor fragmentation levels (important for ZFS performance)
  - Check scrub age and warn when pools haven't been scrubbed recently
  - Detect device errors (read, write, checksum) before data loss
  - Identify degraded or faulted devices in mirror/raidz vdevs
  - Report data integrity errors

Examples:
```bash
# Check all ZFS pools with default thresholds
baremetal_zfs_pool_health.py

# Custom capacity thresholds for high-utilization pools
baremetal_zfs_pool_health.py --capacity-warn 70 --capacity-crit 85

# Show detailed pool and device information
baremetal_zfs_pool_health.py --verbose

# JSON output for monitoring integration
baremetal_zfs_pool_health.py --format json

# Only show warnings and errors
baremetal_zfs_pool_health.py --warn-only

# Strict scrub requirement (warn after 7 days)
baremetal_zfs_pool_health.py --scrub-warn 7

# Strict error checking (warn on any errors)
baremetal_zfs_pool_health.py --error-threshold 1
```

### baremetal_mce_monitor.py
```
python baremetal_mce_monitor.py [--format format] [-v] [-w]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed MCE configuration and all events
  -w, --warn-only: Only show issues, suppress OK status messages
```

Requirements:
  - Linux kernel with MCE support (x86/x86_64 architecture)
  - Access to /sys/devices/system/machinecheck/ (requires root for some info)
  - Optional: mcelog daemon for enhanced diagnostics

Exit codes:
  - 0: No MCE errors detected
  - 1: MCE warnings or errors detected (hardware fault found)
  - 2: Usage error or missing dependencies

Features:
  - Monitor Machine Check Exceptions from multiple data sources
  - Parse MCE sysfs interface for CPU/memory controller errors
  - Detect retired memory pages from RAS (Reliability, Availability, Serviceability)
  - Analyze dmesg and journalctl for MCE-related kernel messages
  - Report CPU microcode versions (outdated microcode can cause MCEs)
  - Multiple output formats for monitoring integration

What MCE detects:
  - CPU cache parity/ECC errors
  - Memory controller errors (internal and bus)
  - System bus errors
  - Thermal throttling events
  - Internal CPU errors

Examples:
```bash
# Check MCE status with default output
baremetal_mce_monitor.py

# JSON output for monitoring systems (Prometheus, Nagios, etc.)
baremetal_mce_monitor.py --format json

# Only show issues, suppress "OK" messages
baremetal_mce_monitor.py --warn-only

# Verbose output with CPU MCE configuration
baremetal_mce_monitor.py --verbose

# Table format for quick review
baremetal_mce_monitor.py --format table
```

### baremetal_multipath_health_monitor.py
```
python baremetal_multipath_health_monitor.py [--format format] [-v] [-w] [--min-paths-warn N] [--min-paths-crit N]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed path information
  -w, --warn-only: Only show warnings and errors
  --min-paths-warn: Warn if active paths <= N (default: 1)
  --min-paths-crit: Critical if active paths <= N (default: 0)
```

Requirements:
  - multipath-tools package (multipath, multipathd commands)
  - Ubuntu/Debian: `sudo apt-get install multipath-tools`
  - RHEL/CentOS: `sudo yum install device-mapper-multipath`
  - multipathd service must be running

Exit codes:
  - 0: All multipath devices healthy
  - 1: Warnings or critical issues detected (failed paths, degraded devices)
  - 2: Usage error, multipath tools not available, or multipathd not running

Features:
  - Monitor multipath device health and path status
  - Detect failed or degraded paths to SAN/NAS storage
  - Track path priority and load balancing health
  - Identify devices with reduced redundancy
  - Detect path checker failures and abnormal states
  - Multiple output formats (plain, JSON, table)

Examples:
```bash
# Check all multipath devices
baremetal_multipath_health_monitor.py

# Warn if fewer than 2 active paths per device
baremetal_multipath_health_monitor.py --min-paths-warn 2

# Show detailed path information
baremetal_multipath_health_monitor.py --verbose

# JSON output for monitoring integration
baremetal_multipath_health_monitor.py --format json

# Only show warnings and errors
baremetal_multipath_health_monitor.py --warn-only

# Table format with path details
baremetal_multipath_health_monitor.py --format table --verbose
```

### baremetal_drbd_health_monitor.py
```
python baremetal_drbd_health_monitor.py [--format format] [-v] [-w] [--sync-warn PERCENT] [--sync-crit PERCENT]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed resource information
  -w, --warn-only: Only show warnings and errors
  --sync-warn: Warn if sync percent < PERCENT (default: 90)
  --sync-crit: Critical if sync percent < PERCENT (default: 50)
```

Requirements:
  - drbd-utils package (drbdadm command)
  - Ubuntu/Debian: `sudo apt-get install drbd-utils`
  - RHEL/CentOS: `sudo yum install drbd-utils` or `drbd90-utils`
  - DRBD kernel module must be loaded

Exit codes:
  - 0: All DRBD resources healthy and synchronized
  - 1: Issues found (out-of-sync, degraded, split-brain, etc.)
  - 2: Usage error, DRBD not installed, or module not loaded

Features:
  - Monitor DRBD resource synchronization state
  - Detect split-brain conditions (both nodes Primary)
  - Track connection state (Connected, StandAlone, WFConnection, etc.)
  - Monitor disk states (UpToDate, Inconsistent, Outdated, Failed)
  - Track resync progress with configurable thresholds
  - Report out-of-sync data amounts
  - Support for DRBD 8.x (/proc/drbd) and DRBD 9+ (JSON API)
  - Multiple output formats (plain, JSON, table)

Examples:
```bash
# Check all DRBD resources
baremetal_drbd_health_monitor.py

# Show detailed resource information
baremetal_drbd_health_monitor.py --verbose

# JSON output for monitoring integration
baremetal_drbd_health_monitor.py --format json

# Only show warnings and errors
baremetal_drbd_health_monitor.py --warn-only

# Custom sync thresholds (warn if <80%, critical if <30%)
baremetal_drbd_health_monitor.py --sync-warn 80 --sync-crit 30

# Table format with details
baremetal_drbd_health_monitor.py --format table --verbose
```

### baremetal_iscsi_health.py
```
python baremetal_iscsi_health.py [--format format] [-v] [-w] [--skip-multipath]
  --format, -f: Output format - 'plain' or 'json' (default: plain)
  -v, --verbose: Show detailed session information including devices and I/O stats
  -w, --warn-only: Only show sessions with warnings or errors
  --skip-multipath: Skip multipath status check
```

Requirements:
  - open-iscsi package (iscsiadm command)
  - Ubuntu/Debian: `sudo apt-get install open-iscsi`
  - RHEL/CentOS: `sudo yum install iscsi-initiator-utils`
  - Optional: multipath-tools for multipath status

Exit codes:
  - 0: All iSCSI sessions healthy
  - 1: Issues found (degraded sessions, errors, connectivity problems)
  - 2: Usage error or iscsiadm not available

Features:
  - Monitor active iSCSI sessions and their state
  - Check target connectivity and portal availability
  - Track session error counts (timeout, digest errors)
  - Analyze attached SCSI devices and their state
  - Check multipath status for iSCSI devices
  - Detect degraded or failed connections
  - Multiple output formats (plain, JSON)

Examples:
```bash
# Check all iSCSI sessions
baremetal_iscsi_health.py

# Verbose output with device details
baremetal_iscsi_health.py --verbose

# JSON output for monitoring integration
baremetal_iscsi_health.py --format json

# Only show sessions with issues
baremetal_iscsi_health.py --warn-only

# Skip multipath check (faster, if not using multipath)
baremetal_iscsi_health.py --skip-multipath

# Combine options for targeted monitoring
baremetal_iscsi_health.py -v -w -f json
```

### hardware_temperature_monitor.py
```
python hardware_temperature_monitor.py [-f format] [-w] [-v]
  -f, --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show sensors with warnings or critical status
  -v, --verbose: Show detailed threshold information
```

Requirements:
  - lm-sensors package (sensors command)
  - Ubuntu/Debian: `sudo apt-get install lm-sensors`
  - RHEL/CentOS: `sudo yum install lm_sensors`
  - Run `sensors-detect` after installation to configure sensors

Exit codes:
  - 0: All temperatures normal
  - 1: Warning or critical temperatures detected
  - 2: Usage error or missing dependencies

Features:
  - Monitor CPU, GPU, and motherboard temperatures
  - Track fan speeds and detect fan failures
  - Compare readings against hardware thresholds
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode to focus on thermal issues
  - JSON output for monitoring system integration

Examples:
```bash
# Check all temperature sensors
hardware_temperature_monitor.py

# Show only warnings and critical temperatures
hardware_temperature_monitor.py --warn-only

# Detailed output with all thresholds
hardware_temperature_monitor.py --verbose

# JSON output for monitoring integration
hardware_temperature_monitor.py --format json

# Table format with warnings only
hardware_temperature_monitor.py --format table --warn-only
```

Use Case: In large-scale baremetal datacenters, thermal issues can lead to hardware throttling, system instability, or permanent damage. This script provides visibility into temperature sensors and fan speeds across servers, making it ideal for proactive thermal monitoring and capacity planning. Critical for high-density deployments where cooling is a concern.

### baremetal_thermal_throttle_monitor.py
```
python baremetal_thermal_throttle_monitor.py [-f format] [-w] [-v] [--threshold N]
  -f, --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show CPUs with throttle events
  -v, --verbose: Show detailed per-CPU information
  --threshold N: Minimum throttle count to report as issue (default: 0)
```

Requirements:
  - Linux kernel with thermal throttle interface
  - Access to /sys/devices/system/cpu/cpu*/thermal_throttle/

Features:
  - Core-level throttle event counting
  - Package-level throttle event counting
  - Throttle time duration tracking (when available)
  - Per-CPU breakdown of throttling events
  - Threshold-based alerting
  - JSON output for monitoring system integration

Examples:
```bash
# Check for thermal throttling
baremetal_thermal_throttle_monitor.py

# Show only CPUs that have experienced throttling
baremetal_thermal_throttle_monitor.py --warn-only

# Verbose output with per-CPU details
baremetal_thermal_throttle_monitor.py --verbose

# JSON output for monitoring integration
baremetal_thermal_throttle_monitor.py --format json

# Table format for easy reading
baremetal_thermal_throttle_monitor.py --format table

# Only alert if more than 10 throttle events
baremetal_thermal_throttle_monitor.py --threshold 10
```

Use Case: While temperature monitoring shows current thermal state, this script detects actual throttling events that indicate performance degradation has occurred. Essential for identifying servers with cooling problems that are silently underperforming. Throttle counters persist across time, making this useful for post-incident analysis and fleet-wide auditing.

### gpu_health_monitor.py
```
python gpu_health_monitor.py [-f format] [-w] [-v]
  -f, --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show GPUs with warnings or critical status
  -v, --verbose: Show detailed information (power, clocks, ECC errors)
```

Requirements:
  - NVIDIA GPU with drivers installed
  - nvidia-smi command available in PATH

Features:
  - Temperature monitoring (GPU and memory)
  - Memory usage and utilization tracking
  - ECC error detection (corrected and uncorrected)
  - Power consumption monitoring
  - Clock speed and throttling detection
  - Performance state (P-state) reporting
  - Fan speed monitoring
  - JSON output for monitoring system integration

Examples:
```bash
# Check all GPU health metrics
gpu_health_monitor.py

# Show only warnings and critical issues
gpu_health_monitor.py --warn-only

# Detailed output with power, clocks, and ECC details
gpu_health_monitor.py --verbose

# JSON output for monitoring integration
gpu_health_monitor.py --format json

# Table format for quick overview
gpu_health_monitor.py --format table
```

Use Case: GPU clusters for ML/AI workloads require proactive health monitoring to prevent silent data corruption from ECC errors, detect thermal throttling that degrades performance, and identify failing hardware before total failure. This script provides comprehensive NVIDIA GPU health metrics including temperature, memory, power consumption, and ECC error tracking. Essential for datacenter GPU deployments where reliability and performance are critical.

### ipmi_sel_monitor.py
```
python ipmi_sel_monitor.py [-f format] [-w] [-v] [--hours N] [--clear]
  -f, --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show warning and critical events
  -v, --verbose: Show detailed SEL information
  --hours: Only show events from the last N hours
  --clear: Clear SEL after displaying (requires root privileges)
```

Requirements:
  - ipmitool package
  - Ubuntu/Debian: `sudo apt-get install ipmitool`
  - RHEL/CentOS: `sudo yum install ipmitool`
  - Requires root privileges or proper IPMI user permissions

Exit codes:
  - 0: No critical events or only informational events
  - 1: Warning or critical events detected
  - 2: Usage error or missing dependencies

Features:
  - Monitor IPMI System Event Log (SEL) for hardware failures
  - Detect power supply failures, memory ECC errors, fan failures
  - Track temperature threshold violations and voltage anomalies
  - Categorize events by severity (CRITICAL, WARNING, INFO)
  - Filter events by time range (e.g., last 24 hours)
  - Multiple output formats (plain, JSON, table)
  - SEL clearing capability for maintenance
  - JSON output for monitoring system integration

Examples:
```bash
# Check all SEL entries
ipmi_sel_monitor.py

# Show only warnings and critical events
ipmi_sel_monitor.py --warn-only

# Show events from last 24 hours
ipmi_sel_monitor.py --hours 24

# JSON output for monitoring integration
ipmi_sel_monitor.py --format json

# Table format with recent warnings
ipmi_sel_monitor.py --format table --warn-only --hours 48

# Clear SEL after viewing (requires root)
sudo ipmi_sel_monitor.py --clear
```

Use Case: The IPMI System Event Log is a critical component of hardware monitoring in baremetal datacenters. It captures hardware-level events that may not be visible to the operating system, including power supply failures, memory errors, thermal events, and fan failures. This script provides proactive detection of hardware issues before they cause system downtime, making it essential for large-scale baremetal fleet management. The SEL often contains early warning signs of impending hardware failures, allowing for preventive maintenance.

### memory_health_monitor.py
```
python memory_health_monitor.py [--format format] [--warn-only] [--verbose]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only: Only show memory issues (warnings/critical)
  --verbose: Show detailed DIMM information
```

Requirements:
  - Linux kernel with EDAC support for ECC error monitoring (/sys/devices/system/edac/mc)
  - /proc/meminfo for memory usage statistics (available on all Linux systems)
  - ECC-capable hardware and enabled EDAC kernel modules for full functionality

Exit codes:
  - 0: No memory errors detected
  - 1: Memory warnings or errors detected
  - 2: Usage error or missing dependencies

Features:
  - Monitor ECC (Error-Correcting Code) memory errors
  - Detect correctable (CE) and uncorrectable (UE) memory errors
  - Per-DIMM error tracking with location information
  - Memory pressure analysis (RAM and swap usage)
  - Multiple memory controller support
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode to focus on failing DIMMs
  - JSON output for monitoring system integration

Examples:
```bash
# Check memory health and ECC errors
memory_health_monitor.py

# Show only issues (warnings/critical)
memory_health_monitor.py --warn-only

# Detailed DIMM information
memory_health_monitor.py --verbose

# JSON output for monitoring integration
memory_health_monitor.py --format json

# Table format with warnings only
memory_health_monitor.py --format table --warn-only
```

Use Case: In large-scale baremetal environments, memory failures are a leading cause of system crashes and data corruption. ECC memory can detect and correct single-bit errors, but tracking these errors is critical for predictive maintenance. This script monitors ECC error counts at both the memory controller and individual DIMM level, enabling proactive replacement of failing DIMMs before uncorrectable errors occur. It also monitors memory pressure to detect capacity issues. Essential for maintaining reliability in production baremetal infrastructure.

### baremetal_tmpfs_monitor.py
```
python baremetal_tmpfs_monitor.py [--format format] [--warn-only] [--verbose] [--warn PCT] [--critical PCT] [--mountpoint PATH]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show tmpfs with warnings or critical status
  --verbose, -v: Show detailed information including inodes and options
  --warn: Warning threshold percentage (default: 80)
  --critical: Critical threshold percentage (default: 90)
  --mountpoint, -m: Monitor only this specific tmpfs mountpoint
```

Requirements:
  - Linux system with /proc/mounts (all Linux systems)
  - No special permissions required for reading tmpfs stats

Exit codes:
  - 0: All tmpfs filesystems healthy (usage below thresholds)
  - 1: Warning or critical usage detected on one or more tmpfs
  - 2: Usage error or invalid arguments

Features:
  - Monitor all tmpfs mounts including /dev/shm, /run, /tmp
  - Track both space and inode usage
  - Configurable warning and critical thresholds
  - Filter to specific mountpoints
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode to focus on issues

Examples:
```bash
# Check all tmpfs filesystems
baremetal_tmpfs_monitor.py

# Show only warnings and critical issues
baremetal_tmpfs_monitor.py --warn-only

# Output in JSON format for monitoring systems
baremetal_tmpfs_monitor.py --format json

# Custom thresholds (warn at 70%, critical at 85%)
baremetal_tmpfs_monitor.py --warn 70 --critical 85

# Monitor specific mountpoint
baremetal_tmpfs_monitor.py --mountpoint /dev/shm

# Verbose output with inode details
baremetal_tmpfs_monitor.py --verbose
```

Use Case: tmpfs filesystems are RAM-backed and commonly used for /dev/shm (shared memory), /run (runtime data), and /tmp (temporary files). Unlike regular disk filesystems, tmpfs exhaustion doesn't trigger standard disk space alerts and can cause silent OOM conditions or application failures. This is particularly critical for systems running databases (which use shared memory heavily), containerized workloads, or applications that rely on fast temporary storage. Monitoring tmpfs usage proactively prevents these hard-to-diagnose failures.

### firmware_version_audit.py
```
python firmware_version_audit.py [--format format] [-v]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information
```

Requirements:
  - dmidecode (for BIOS and system information)
  - ethtool (for network interface firmware)
  - ipmitool (optional, for BMC firmware)
  - Root privileges (sudo) for full functionality

Exit codes:
  - 0: Success (all firmware info collected)
  - 1: Partial failure (some tools missing or checks failed)
  - 2: Usage error or critical dependency missing

Features:
  - BIOS/UEFI version and release date detection
  - BMC/IPMI firmware version checking
  - Network interface firmware version reporting
  - System manufacturer and product information
  - Multiple output formats (plain, JSON, table)
  - Graceful handling of missing tools or privileges

Use case:
  - Identify firmware version drift across server fleets
  - Detect outdated firmware requiring security patches
  - Audit firmware consistency in datacenters
  - Prevent mysterious issues caused by firmware variations

Examples:
```bash
# Basic audit (requires sudo for complete results)
sudo python firmware_version_audit.py

# JSON output for automation
sudo python firmware_version_audit.py --format json

# Table format for quick overview
sudo python firmware_version_audit.py --format table
```

### cpu_frequency_monitor.py
```
python cpu_frequency_monitor.py [--format format] [--expected-governor governor] [--warn-only] [--verbose] [--no-throttle-check]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --expected-governor: Expected governor (e.g., performance, powersave)
  --warn-only: Only show CPUs with warnings or issues
  --verbose: Show detailed information for all CPUs
  --no-throttle-check: Disable throttling detection
```

Requirements:
  - Linux kernel with cpufreq support (sysfs interface at /sys/devices/system/cpu)
  - Most modern Linux systems have this enabled by default

Exit codes:
  - 0: All CPUs configured correctly
  - 1: Issues detected (wrong governor, throttling, scaling limits)
  - 2: Usage error or missing cpufreq interface

Features:
  - Monitor current CPU frequencies across all cores
  - Verify CPU governor settings (performance, powersave, ondemand, etc.)
  - Detect CPU throttling or frequency capping
  - Identify scaling limit constraints
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode to focus on problem CPUs
  - JSON output for monitoring system integration

Examples:
```bash
# Check CPU frequency status
cpu_frequency_monitor.py

# Verify all CPUs are using 'performance' governor
cpu_frequency_monitor.py --expected-governor performance

# Show only CPUs with issues
cpu_frequency_monitor.py --warn-only

# Detailed output for all CPUs
cpu_frequency_monitor.py --verbose

# JSON output for monitoring integration
cpu_frequency_monitor.py --format json

# Table format showing all CPUs
cpu_frequency_monitor.py --format table

# Check without false positives from normal frequency scaling
cpu_frequency_monitor.py --no-throttle-check
```

Use Case: In large-scale baremetal environments, incorrect CPU governor settings or unexpected frequency throttling can severely impact workload performance. This script helps identify nodes running at reduced clock speeds due to thermal throttling, power management misconfiguration, or BIOS settings. Essential for Kubernetes worker nodes and compute-intensive workloads where consistent CPU performance is critical. Use in your monitoring stack to detect performance degradation before it impacts production services.

### baremetal_cpu_time_analyzer.py
```
python baremetal_cpu_time_analyzer.py [--format format] [--warn-only] [--verbose] [threshold options]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only: Only show issues, suppress normal output
  --verbose: Show per-CPU breakdown
  --steal-warn PCT: Steal time warning threshold (default: 5%)
  --steal-crit PCT: Steal time critical threshold (default: 15%)
  --iowait-warn PCT: I/O wait warning threshold (default: 10%)
  --iowait-crit PCT: I/O wait critical threshold (default: 25%)
  --interrupt-warn PCT: Interrupt time warning threshold (default: 10%)
  --interrupt-crit PCT: Interrupt time critical threshold (default: 25%)
  --system-warn PCT: System time warning threshold (default: 30%)
  --system-crit PCT: System time critical threshold (default: 50%)
  --imbalance-warn PCT: CPU imbalance warning threshold (default: 40%)
  --imbalance-crit PCT: CPU imbalance critical threshold (default: 60%)
```

Requirements:
  - Linux /proc/stat (available on all Linux systems)

Exit codes:
  - 0: No issues detected (all metrics within thresholds)
  - 1: Warnings or issues detected (high steal, iowait, etc.)
  - 2: Usage error or required files not available

Features:
  - Analyze CPU time distribution across all CPUs
  - Monitor steal time for virtualization overhead detection
  - Track I/O wait for storage bottleneck identification
  - Measure IRQ/softIRQ time for interrupt storm detection
  - Calculate system time for syscall overhead analysis
  - Detect per-CPU load imbalance
  - Configurable thresholds for all metrics
  - Multiple output formats (plain, JSON, table)

Examples:
```bash
# Basic CPU time analysis
baremetal_cpu_time_analyzer.py

# Show per-CPU breakdown
baremetal_cpu_time_analyzer.py -v

# JSON output for monitoring integration
baremetal_cpu_time_analyzer.py --format json

# Lower steal time threshold for sensitive workloads
baremetal_cpu_time_analyzer.py --steal-warn 3 --steal-crit 10

# Only show problems
baremetal_cpu_time_analyzer.py --warn-only

# Table format for quick overview
baremetal_cpu_time_analyzer.py --format table
```

Use Case: Critical for diagnosing performance issues in large-scale environments. High steal time indicates hypervisor contention on VMs, high iowait suggests storage bottlenecks, elevated softirq time may indicate network interrupt storms, and CPU imbalance reveals workload distribution problems. Essential for troubleshooting "noisy neighbor" problems in virtualized environments and identifying misconfigured interrupt affinity in baremetal systems. Integrate into monitoring pipelines to catch performance degradation early.

### baremetal_context_switch_monitor.py
```
python baremetal_context_switch_monitor.py [--format format] [--warn-only] [--verbose] [--interval SECONDS] [threshold options]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only: Only show issues, suppress normal output
  --verbose: Show additional metrics (page faults)
  --interval: Sampling interval in seconds (default: 1.0)
  --ctxt-warn N: Context switches/sec per CPU warning threshold (default: 20000)
  --ctxt-crit N: Context switches/sec per CPU critical threshold (default: 50000)
  --intr-warn N: Interrupts/sec per CPU warning threshold (default: 50000)
  --intr-crit N: Interrupts/sec per CPU critical threshold (default: 100000)
  --run-queue-warn N: Run queue depth per CPU warning threshold (default: 2.0)
  --run-queue-crit N: Run queue depth per CPU critical threshold (default: 5.0)
  --blocked-warn N: Blocked process count warning threshold (default: 5)
  --blocked-crit N: Blocked process count critical threshold (default: 20)
  --fork-warn N: Process creation rate/sec warning threshold (default: 500)
  --fork-crit N: Process creation rate/sec critical threshold (default: 2000)
```

Requirements:
  - Linux /proc/stat and optionally /proc/vmstat
  - Available on all modern Linux systems

Exit codes:
  - 0: Context switch rates and process metrics are within thresholds
  - 1: Elevated context switches, run queue depth, or other issues detected
  - 2: Usage error or /proc/stat not available

Features:
  - Monitor system-wide context switches per second
  - Track per-CPU context switch rates to identify contention
  - Measure interrupt rates that drive context switches
  - Monitor run queue depth (runnable processes) for CPU saturation
  - Track blocked processes waiting on I/O
  - Detect fork storms (excessive process creation)
  - Configurable sampling interval for different use cases
  - Multiple output formats (plain, JSON, table)

Examples:
```bash
# Basic context switch monitoring (1 second sample)
baremetal_context_switch_monitor.py

# Quick check with 100ms sample
baremetal_context_switch_monitor.py --interval 0.1

# JSON output for monitoring integration
baremetal_context_switch_monitor.py --format json

# Lower thresholds for latency-sensitive workloads
baremetal_context_switch_monitor.py --ctxt-warn 10000 --run-queue-warn 1

# Only show problems
baremetal_context_switch_monitor.py --warn-only

# Verbose output with page fault metrics
baremetal_context_switch_monitor.py -v
```

Use Case: Essential for diagnosing CPU contention and scheduling overhead in busy systems. High context switch rates indicate too many threads competing for CPU time, lock contention, or inefficient application design. Elevated run queue depth reveals CPU saturation before it impacts response times. Monitor blocked processes to correlate with I/O bottlenecks. Detect fork storms from misbehaving applications or runaway scripts. Useful baseline: typical idle systems see 1,000-5,000 context switches/sec per CPU; busy but healthy systems see 5,000-20,000; rates above 50,000 usually indicate problems.

### load_average_monitor.py
```
python load_average_monitor.py [--format format] [--warn-only] [--warn-multiplier N] [--crit-multiplier N] [--verbose]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only: Only show output if there are warnings or issues
  --warn-multiplier: Warning threshold as multiple of CPU count (default: 1.0)
  --crit-multiplier: Critical threshold as multiple of CPU count (default: 2.0)
  --verbose: Show detailed information including per-core load
```

Requirements:
  - Linux /proc/loadavg and /proc/cpuinfo
  - Available on all modern Linux systems

Exit codes:
  - 0: Load averages are within acceptable range
  - 1: Load average exceeds thresholds
  - 2: Usage error or invalid thresholds

Features:
  - Monitor 1, 5, and 15-minute load averages
  - Compare load against CPU core count
  - Track running and total process counts
  - Customizable warning and critical thresholds
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode to suppress output when healthy
  - Calculate load per CPU core

Examples:
```bash
# Check current load status
load_average_monitor.py

# Show only if there are issues
load_average_monitor.py --warn-only

# JSON output for monitoring integration
load_average_monitor.py --format json

# Table format with detailed view
load_average_monitor.py --format table --verbose

# Custom thresholds (warn at 150%, critical at 250% of CPU count)
load_average_monitor.py --warn-multiplier 1.5 --crit-multiplier 2.5

# Use in cron for alerts (only outputs if issues found)
load_average_monitor.py --warn-only --format plain
```

Use Case: Load average is a fundamental metric for understanding system health in baremetal datacenters. A load average consistently higher than the CPU core count indicates the system is oversubscribed and processes are waiting for CPU time. This script helps identify overloaded servers before they impact application performance. Essential for capacity planning, detecting resource exhaustion, and early warning of system degradation. Unlike CPU usage percentage, load average shows queuing depth, making it better for detecting saturation. Use in monitoring dashboards to track fleet-wide load patterns and identify servers needing intervention.

### network_interface_health.py
```
python network_interface_health.py [-i interface] [-v] [--format format] [--warn-only]
  -i, --interface: Specific interface to check (e.g., eth0)
  -v, --verbose: Show detailed error statistics
  --format: Output format, either 'plain' or 'json' (default: plain)
  --warn-only: Only show interfaces with warnings or errors
```

Requirements:
  - ip command-line tool (iproute2 package, usually pre-installed)
  - ethtool command-line tool (optional, for speed/duplex info)

Exit codes:
  - 0: All interfaces healthy
  - 1: One or more interfaces degraded or down
  - 2: Usage error or missing dependencies

Features:
  - Monitor RX/TX packet errors, drops, and overruns
  - Detect interface link state (UP/DOWN)
  - Display speed and duplex mode (with ethtool)
  - Show interface IP addresses and MTU
  - JSON output for monitoring integration
  - Warn-only mode to focus on problem interfaces

Examples:
```bash
# Check all network interfaces
network_interface_health.py

# Check specific interface with detailed stats
network_interface_health.py -i eth0 -v

# Show only interfaces with errors
network_interface_health.py --warn-only

# Output as JSON for monitoring
network_interface_health.py --format json
```

### baremetal_nic_link_speed_audit.py
```
python baremetal_nic_link_speed_audit.py [-i interface] [--min-speed MBPS] [--format format] [-v] [-w]
  -i, --interface: Specific interface to check (default: all physical NICs)
  --min-speed: Minimum expected speed in Mbps (e.g., 10000 for 10Gb/s)
  --format: Output format - 'plain' or 'json' (default: plain)
  -v, --verbose: Show detailed interface information
  -w, --warn-only: Only show interfaces with issues
```

Requirements:
  - ethtool package
  - Ubuntu/Debian: `sudo apt-get install ethtool`
  - RHEL/CentOS: `sudo yum install ethtool`

Exit codes:
  - 0: All interfaces at expected speeds
  - 1: One or more interfaces at suboptimal speeds
  - 2: Usage error or missing dependency

Features:
  - Detects NICs negotiating at suboptimal speeds
  - Compares actual speed vs maximum supported speed
  - Identifies half-duplex negotiation issues
  - Filters physical interfaces only (excludes bridges, bonds, vlans)
  - Reports driver and auto-negotiation status
  - JSON output for monitoring integration

Examples:
```bash
# Check all physical NICs
baremetal_nic_link_speed_audit.py

# Check specific interface with details
baremetal_nic_link_speed_audit.py -i eth0 -v

# Flag any NIC below 10Gb/s
baremetal_nic_link_speed_audit.py --min-speed 10000

# Only show interfaces with issues
baremetal_nic_link_speed_audit.py --warn-only

# Output as JSON for monitoring
baremetal_nic_link_speed_audit.py --format json
```

Use Case: In large baremetal environments, NICs often silently negotiate to lower speeds due to cable problems (damaged, wrong category, too long), switch port misconfigurations, or auto-negotiation failures. A 10Gb NIC running at 1Gb or 100Mb causes significant but non-obvious performance degradation. This script audits all physical NICs to detect these issues before they impact production workloads.

### baremetal_vlan_config_audit.py
```
python baremetal_vlan_config_audit.py [--format format] [-v] [-w]
  --format: Output format - 'plain' or 'json' (default: plain)
  -v, --verbose: Show detailed VLAN information
  -w, --warn-only: Only show VLANs with issues
```

Exit codes:
  - 0: All VLANs healthy (or no VLANs configured)
  - 1: One or more VLANs have configuration issues
  - 2: Usage error or missing dependency

Features:
  - Detect orphaned VLANs (parent interface no longer exists)
  - Check MTU mismatches between VLAN and parent interface
  - Verify parent interface is up and has carrier
  - Detect VLAN ID conflicts on the same parent
  - Identify VLANs without IP addresses configured
  - Works with 802.1Q VLANs via /proc/net/vlan/config and sysfs

Examples:
```bash
# Audit all VLAN interfaces
baremetal_vlan_config_audit.py

# Show detailed VLAN information
baremetal_vlan_config_audit.py -v

# Only show VLANs with issues
baremetal_vlan_config_audit.py --warn-only

# Output as JSON for monitoring
baremetal_vlan_config_audit.py --format json
```

Use Case: In datacenter environments, VLANs are commonly used for network segmentation but misconfigurations often go unnoticed until they cause connectivity issues. Common problems include VLANs whose parent interface was removed during network reconfiguration, MTU mismatches causing fragmentation, and parent interfaces going down without proper alerting. This script audits VLAN configuration to catch these issues proactively.

### ntp_drift_monitor.py
```
python ntp_drift_monitor.py [-f format] [-v] [-w threshold] [-c threshold]
  -f, --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed synchronization information
  -w, --warn-threshold: Warning threshold for time offset in seconds (default: 0.100)
  -c, --crit-threshold: Critical threshold for time offset in seconds (default: 1.000)
```

Requirements:
  - chrony (recommended) or ntp daemon
  - Ubuntu/Debian: `sudo apt-get install chrony`
  - RHEL/CentOS: `sudo yum install chrony`

Exit codes:
  - 0: Time synchronized within acceptable limits
  - 1: Warning or critical drift detected
  - 2: Usage error or missing dependencies

Features:
  - Monitor NTP/Chrony time synchronization status
  - Detect clock drift and offset from reference time
  - Check stratum level and reference source
  - Track RMS offset and frequency drift (chrony)
  - Multiple output formats (plain, JSON, table)
  - Configurable warning and critical thresholds
  - Critical for distributed systems, databases, and K8s clusters

Examples:
```bash
# Check time synchronization status
ntp_drift_monitor.py

# Show detailed sync information
ntp_drift_monitor.py --verbose

# Output as JSON for monitoring systems
ntp_drift_monitor.py --format json

# Custom thresholds (warn at 50ms, critical at 500ms)
ntp_drift_monitor.py --warn-threshold 0.050 --crit-threshold 0.500

# Table format for overview
ntp_drift_monitor.py --format table
```

Use Case: Time synchronization is critical for distributed systems, Kubernetes clusters, databases (especially distributed ones), and certificate validation. Clock drift can cause authentication failures, data inconsistencies, and cluster coordination issues. This script monitors NTP/Chrony status to detect and alert on time synchronization problems before they impact services.

### baremetal_hwclock_drift_monitor.py
```
sudo baremetal_hwclock_drift_monitor.py [-f format] [-v] [-w threshold] [-c threshold]
  -f, --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed RTC information
  -w, --warn-threshold: Warning threshold for drift in seconds (default: 5.0)
  -c, --crit-threshold: Critical threshold for drift in seconds (default: 60.0)
```

Requirements:
  - hwclock command (part of util-linux, available on all Linux systems)
  - Root/sudo access required to read the hardware clock

Exit codes:
  - 0: Hardware clock within acceptable drift
  - 1: Warning or critical drift detected
  - 2: Missing dependencies or permission denied

Features:
  - Monitors hardware clock (RTC) drift against system time
  - Detects failing CMOS batteries causing RTC drift
  - Identifies clock crystal degradation or RTC misconfiguration
  - Complements ntp_drift_monitor.py by checking the local RTC
  - Reports RTC device, time mode (UTC/local), and drift magnitude

Examples:
```bash
# Check hardware clock drift (requires root)
sudo baremetal_hwclock_drift_monitor.py

# Show detailed RTC information
sudo baremetal_hwclock_drift_monitor.py --verbose

# Output as JSON for monitoring systems
sudo baremetal_hwclock_drift_monitor.py --format json

# Custom thresholds (warn at 1s, critical at 60s)
sudo baremetal_hwclock_drift_monitor.py --warn-threshold 1.0 --crit-threshold 60.0

# Table format for overview
sudo baremetal_hwclock_drift_monitor.py --format table
```

Use Case: While NTP keeps system time synchronized during runtime, the hardware clock (RTC) determines initial time on boot. A drifting RTC from a failing CMOS battery or degraded clock crystal causes time jumps on reboot, breaking TLS certificate validation, distributed system coordination, and log timestamp accuracy. This script monitors RTC accuracy to detect hardware clock issues before they cause problems after the next reboot.

Use Case: In large baremetal environments, network interface errors can indicate hardware problems, driver issues, or network congestion. This script provides quick visibility into interface health across all network adapters, making it ideal for periodic health checks or monitoring integration.

### baremetal_network_config_audit.py
```
python baremetal_network_config_audit.py [--format format] [-v] [-w]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information
  -w, --warn-only: Only show warnings and errors
```

Requirements:
  - Access to /sys/class/net filesystem (available on all Linux systems)
  - No special privileges required for basic checks

Exit codes:
  - 0: No configuration issues detected
  - 1: Configuration issues or warnings found
  - 2: Usage error or /sys/class/net not accessible

Features:
  - Detect MTU mismatches across active interfaces
  - Verify bond slave MTU consistency
  - Identify inconsistent bonding modes across bond interfaces
  - Check IPv6 enabled/disabled inconsistencies
  - Detect promiscuous mode on production interfaces
  - Identify down bond slaves
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode for monitoring integration

Examples:
```bash
# Audit network configuration
baremetal_network_config_audit.py

# Show only issues
baremetal_network_config_audit.py --warn-only

# Detailed output with all interface info
baremetal_network_config_audit.py --verbose

# JSON output for monitoring systems
baremetal_network_config_audit.py --format json

# Table format for easy reading
baremetal_network_config_audit.py --format table

# Combine options: table format with warnings only
baremetal_network_config_audit.py --format table --warn-only
```

Use Case: In large-scale baremetal deployments, network configuration mismatches are a leading cause of intermittent connectivity issues. Different MTU settings cause packet fragmentation, bonding mode inconsistencies reduce performance, and IPv6 configuration drift creates routing problems. This script audits network interface configuration for common misconfigurations that may not be immediately obvious but can cause significant issues in production. Complement network_interface_health.py by focusing on configuration correctness rather than operational health. Essential for ensuring consistent network configuration across baremetal fleets where manual configuration can lead to drift.

### baremetal_bandwidth_monitor.py
```
python baremetal_bandwidth_monitor.py [-i SECONDS] [--interface IFACE] [--format format] [-v] [-w] [--warn PCT] [--crit PCT]
  -i, --interval: Sampling interval in seconds (default: 1.0)
  --interface: Monitor specific interface only
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information
  -w, --warn-only: Only output if issues are detected
  --warn: Warning threshold percentage (default: 80)
  --crit: Critical threshold percentage (default: 95)
  --exclude-down: Exclude interfaces that are not up
```

Features:
- Samples /proc/net/dev to calculate real-time bandwidth
- RX/TX bytes and packets per second
- Bandwidth utilization percentage (when link speed is known)
- Configurable warning and critical thresholds
- Interface filtering and state filtering

Exit codes:
- 0: No issues (utilization within thresholds)
- 1: Bandwidth utilization exceeds warning/critical threshold
- 2: Missing /proc/net/dev or usage error

Examples:
```bash
# Monitor all interfaces for 1 second
baremetal_bandwidth_monitor.py

# Longer sample for more accurate measurements
baremetal_bandwidth_monitor.py -i 5

# Monitor specific interface
baremetal_bandwidth_monitor.py --interface eth0

# JSON output for monitoring integration
baremetal_bandwidth_monitor.py --format json

# Custom thresholds (warn at 70%, critical at 90%)
baremetal_bandwidth_monitor.py --warn 70 --crit 90

# Only show if saturation detected
baremetal_bandwidth_monitor.py --warn-only

# Table format with only up interfaces
baremetal_bandwidth_monitor.py --format table --exclude-down
```

Use Case: In large-scale baremetal environments, network bandwidth saturation causes latency spikes, packet loss, and application timeouts. This script provides real-time visibility into interface throughput and utilization, enabling capacity planning, bottleneck detection, and traffic pattern analysis. Essential for identifying overloaded network links before they impact production workloads, especially useful for high-bandwidth applications like storage replication, database sync, or media streaming.

### baremetal_link_flap_detector.py
```
python baremetal_link_flap_detector.py [-d SECONDS] [-p SECONDS] [-I IFACE] [-t COUNT] [--format format] [-v] [-w]
  -d, --duration: Monitoring duration in seconds (default: 10)
  -p, --poll-interval: Polling interval for carrier state (default: 0.1)
  -I, --interface: Specific interface to check (default: all)
  -t, --threshold: Carrier changes threshold for flapping alert (default: 2)
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed transition information
  -w, --warn-only: Only output if flapping is detected
```

Features:
  - Uses kernel carrier_changes counter when available (Linux 3.18+) for accuracy
  - Falls back to carrier state polling on older kernels
  - Tracks carrier up/down counts (Linux 5.0+)
  - Detects intermittent connectivity issues from failing hardware
  - Records individual state transitions with timestamps
  - Configurable monitoring duration and flapping threshold
  - Multiple output formats for monitoring integration

Requirements:
  - Linux /sys/class/net filesystem
  - Read access to interface sysfs files

Exit codes:
  - 0: No link flapping detected
  - 1: Link flapping detected on one or more interfaces
  - 2: Missing /sys filesystem or usage error

Examples:
```bash
# Monitor all interfaces for 10 seconds (default)
baremetal_link_flap_detector.py

# Monitor for 60 seconds with verbose output
baremetal_link_flap_detector.py -d 60 -v

# Check specific interface
baremetal_link_flap_detector.py -I eth0 -d 30

# Alert on 4+ carrier changes in 30 seconds
baremetal_link_flap_detector.py -d 30 -t 4

# JSON output for monitoring integration
baremetal_link_flap_detector.py --format json -d 60

# Only alert if flapping detected
baremetal_link_flap_detector.py --warn-only -d 60
```

Use Case: In large-scale baremetal datacenters, link flapping is a common symptom of failing network hardware. A bad cable, dying SFP transceiver, or faulty switch port can cause intermittent connectivity that's difficult to diagnose. This script monitors carrier state transitions over time to detect unstable links before they cause service disruptions. Essential for proactive hardware maintenance and troubleshooting hard-to-reproduce network issues.

### baremetal_route_health_monitor.py
```
python baremetal_route_health_monitor.py [-v] [--format format] [--no-ping] [--warn-only] [--ping-count N] [--ping-timeout N]
  -v, --verbose: Show detailed route and gateway information
  --format: Output format, either 'plain' or 'json' (default: plain)
  --no-ping: Skip gateway reachability checks (no ICMP ping)
  --warn-only: Only show routes or gateways with issues
  --ping-count: Number of ping packets to send (default: 3)
  --ping-timeout: Ping timeout in seconds (default: 2)
```

Features:
  - Monitors default gateway reachability via ICMP ping
  - Tracks IPv4 and IPv6 default routes
  - Detects unreachable gateways before they cause outages
  - Measures gateway latency and packet loss
  - Validates interface status for route interfaces
  - Detects multiple default routes with same metric (potential issues)
  - JSON output for monitoring integration

Requirements:
  - iproute2 (ip command)
  - ping/ping6 for gateway reachability checks

Exit codes:
  - 0: All routes healthy, gateways reachable
  - 1: Routing issues detected (unreachable gateway, interface down)
  - 2: Missing dependencies or usage error

Examples:
```bash
# Check all default routes and ping gateways
baremetal_route_health_monitor.py

# Skip ping checks (faster, useful in high-security environments)
baremetal_route_health_monitor.py --no-ping

# JSON output for monitoring integration
baremetal_route_health_monitor.py --format json

# Verbose output showing all routes
baremetal_route_health_monitor.py -v

# Only alert if issues detected
baremetal_route_health_monitor.py --warn-only

# Longer ping test with more packets
baremetal_route_health_monitor.py --ping-count 10 --ping-timeout 5
```

Use Case: In large-scale baremetal environments, silent routing failures can cause cascading connectivity issues. A failed default gateway, missing route, or downed interface can isolate servers from the network without obvious symptoms. This script proactively monitors routing health by checking gateway reachability and interface status, detecting issues before they cause service disruptions. Essential for environments with redundant gateways, policy-based routing, or complex network topologies.

### network_bond_status.sh
```
network_bond_status.sh [-b bond] [-v] [-j]
  -b, --bond: Check specific bond interface
  -v, --verbose: Show detailed information
  -j, --json: Output in JSON format
```

Requirements:
  - Linux bonding module loaded
  - /proc/net/bonding directory

### baremetal_bond_health_monitor.py
```
python baremetal_bond_health_monitor.py [-b bond] [-v] [--format format] [--warn-only]
  -b, --bond: Specific bond interface to check (e.g., bond0)
  -v, --verbose: Show detailed slave information
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show bonds with warnings or errors
```

Features:
  - Comprehensive bond health analysis with slave status tracking
  - Link failure count monitoring per slave interface
  - Speed and duplex mismatch detection across slaves
  - Mode-specific validation (active-backup, LACP/802.3ad)
  - MII polling interval verification
  - Detailed error and warning categorization
  - Multiple output formats for integration with monitoring systems

Requirements:
  - Linux bonding module loaded
  - /proc/net/bonding directory

Exit codes:
  - 0: All bonds healthy
  - 1: Bond degradation or errors detected
  - 2: Missing dependencies or usage error

Examples:
```bash
# Check all bonds
baremetal_bond_health_monitor.py

# Check specific bond with verbose output
baremetal_bond_health_monitor.py -b bond0 -v

# Only show problematic bonds in JSON format
baremetal_bond_health_monitor.py --warn-only --format json

# Table format for quick overview
baremetal_bond_health_monitor.py --format table
```

### baremetal_boot_performance_monitor.py
```
python baremetal_boot_performance_monitor.py [--format format] [-v] [-w] [--boot-threshold N] [--userspace-threshold N] [--service-threshold N]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information including top slow services
  -w, --warn-only: Only show warnings and issues
  --boot-threshold N: Warning threshold for total boot time in seconds (default: 120)
  --userspace-threshold N: Warning threshold for userspace init time in seconds (default: 60)
  --service-threshold N: Warning threshold for individual service start time in seconds (default: 10)
```

Features:
  - Monitor total system boot time (firmware, bootloader, kernel, userspace)
  - Identify slow-starting systemd services impacting boot time
  - Track kernel vs. userspace initialization performance
  - Configurable thresholds for boot time warnings
  - Useful for identifying systems with degraded boot performance in large fleets
  - Multiple output formats for integration with monitoring systems

Requirements:
  - systemd-based Linux system
  - systemd-analyze command available

Exit codes:
  - 0: Boot performance is normal
  - 1: Boot time exceeds warning thresholds
  - 2: systemd-analyze not available or usage error

Examples:
```bash
# Check boot performance with default thresholds
baremetal_boot_performance_monitor.py

# Show detailed information including slow services
baremetal_boot_performance_monitor.py -v

# Custom thresholds (60s boot, 30s userspace, 5s per service)
baremetal_boot_performance_monitor.py --boot-threshold 60 --userspace-threshold 30 --service-threshold 5

# Only show issues in JSON format
baremetal_boot_performance_monitor.py --warn-only --format json

# Table format for quick overview
baremetal_boot_performance_monitor.py --format table -v
```

### baremetal_boot_issues_analyzer.py
```
python baremetal_boot_issues_analyzer.py [--format format] [-v] [--warn-only] [--boots N] [--current-only] [--checks CHECKS]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed issue messages
  --warn-only: Only show boots with issues
  --boots N: Number of recent boots to analyze (default: 5)
  --current-only: Only analyze current boot
  --checks CHECKS: Comma-separated list of checks to run (default: kernel,oom,emergency,units,hardware,filesystem)
```

Available checks:
  - `kernel`: Kernel panics, oopses, BUGs, general protection faults
  - `oom`: Out of memory kills during boot
  - `emergency`: Emergency/rescue mode entries
  - `units`: Failed systemd units during boot
  - `hardware`: Hardware errors (MCE, ACPI, PCIe AER, ECC, I/O errors)
  - `critical`: Critical/alert/emergency level log messages
  - `filesystem`: Filesystem errors (EXT4, XFS, journal recovery)

Features:
  - Analyze multiple recent boots for recurring issues
  - Identify machines that experienced problematic boots
  - Detect kernel panics, OOM kills, and emergency mode entries
  - Find hardware errors detected during boot
  - Track failed systemd units during boot sequence
  - Useful for fleet-wide boot health monitoring
  - Multiple output formats for integration with monitoring systems

Requirements:
  - systemd-based Linux system
  - journalctl command available with persistent journal

Exit codes:
  - 0: No boot issues detected
  - 1: Boot issues found
  - 2: journalctl not available or usage error

Examples:
```bash
# Analyze last 5 boots with default checks
baremetal_boot_issues_analyzer.py

# Analyze last 10 boots
baremetal_boot_issues_analyzer.py --boots 10

# Only analyze current boot with verbose output
baremetal_boot_issues_analyzer.py --current-only -v

# Only check for kernel issues and OOM kills
baremetal_boot_issues_analyzer.py --checks kernel,oom

# JSON output for monitoring systems, only show boots with issues
baremetal_boot_issues_analyzer.py --format json --warn-only

# Table format for quick overview
baremetal_boot_issues_analyzer.py --format table
```

### baremetal_uptime_monitor.py
```
python baremetal_uptime_monitor.py [--format format] [-v] [-w] [--min-uptime HOURS] [--max-reboots-24h N] [--max-reboots-7d N]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed reboot history
  -w, --warn-only: Only output if issues are detected
  --min-uptime HOURS: Minimum acceptable uptime in hours (default: 1)
  --max-reboots-24h N: Maximum acceptable reboots in 24 hours (default: 2)
  --max-reboots-7d N: Maximum acceptable reboots in 7 days (default: 5)
```

Features:
  - Monitor current system uptime from /proc/uptime
  - Track reboot history using the `last` command
  - Detect flapping servers with frequent reboots
  - Configurable thresholds for uptime and reboot frequency
  - Identify unstable systems in large baremetal environments
  - Multiple output formats for integration with monitoring systems

Requirements:
  - Linux system with /proc/uptime
  - `last` command for reboot history (optional, degrades gracefully)

Exit codes:
  - 0: System is stable (uptime meets threshold, no excessive reboots)
  - 1: Issues detected (low uptime or frequent reboots)
  - 2: Usage error or required files not available

Examples:
```bash
# Check uptime with default thresholds
baremetal_uptime_monitor.py

# Show detailed reboot history
baremetal_uptime_monitor.py -v

# Custom thresholds (2 hour minimum uptime, max 1 reboot in 24h)
baremetal_uptime_monitor.py --min-uptime 2 --max-reboots-24h 1

# Only alert on issues in JSON format (good for monitoring)
baremetal_uptime_monitor.py --warn-only --format json

# Table format for quick overview
baremetal_uptime_monitor.py --format table -v
```

### baremetal_load_average_monitor.py
```
python baremetal_load_average_monitor.py [--format format] [-v] [-w] [--warning THRESHOLD] [--critical THRESHOLD]
  --format, -f: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information including process counts
  -w, --warn-only: Only show output if issues or warnings detected
  --warning, -W THRESHOLD: Warning threshold for normalized load per CPU (default: 0.7)
  --critical, -C THRESHOLD: Critical threshold for normalized load per CPU (default: 1.0)
```

Requirements:
  - Linux system with /proc/loadavg (standard on all Linux systems)
  - Python 3.6+

Exit codes:
  - 0: Load averages within acceptable thresholds
  - 1: Load issues detected (overload or warnings)
  - 2: Usage error or unable to read system metrics

Features:
  - Monitor 1, 5, and 15-minute load averages
  - Calculate normalized load per CPU for meaningful cross-system comparison
  - Trend analysis (increasing, decreasing, stable)
  - Track online vs configured CPUs (detect offline CPUs)
  - Configurable warning/critical thresholds
  - Multiple output formats (plain, JSON, table)
  - Process count information in verbose mode

Examples:
```bash
# Basic load check
baremetal_load_average_monitor.py

# JSON output for monitoring integration
baremetal_load_average_monitor.py --format json

# Custom thresholds (warn at 80% CPU utilization, critical at 150%)
baremetal_load_average_monitor.py --warning 0.8 --critical 1.5

# Only show output when load is concerning
baremetal_load_average_monitor.py --warn-only

# Table format for quick overview
baremetal_load_average_monitor.py --format table

# Verbose output with process counts
baremetal_load_average_monitor.py -v
```

Use Case: In large-scale baremetal environments, raw load averages can be misleading - a load of 10 is healthy on a 256-core system but critical on a 4-core system. This script normalizes load by CPU count, making it easy to compare system health across heterogeneous hardware. The trend analysis helps identify runaway processes or gradually increasing load before it becomes critical. Essential for capacity planning and workload balancing in datacenter environments.

### baremetal_conntrack_monitor.py
```
python baremetal_conntrack_monitor.py [--format format] [-v] [-w] [--warn PERCENT] [--crit PERCENT]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information including timeout settings
  -w, --warn-only: Only show warnings and errors
  --warn PERCENT: Warning threshold for usage percentage (default: 75)
  --crit PERCENT: Critical threshold for usage percentage (default: 90)
```

Features:
  - Monitor connection tracking table usage (current vs maximum entries)
  - Detect table saturation that causes dropped connections
  - Identify DDoS attacks or traffic spikes before they impact service
  - Track hash bucket configuration for tuning recommendations
  - Show timeout settings affecting connection lifecycle
  - Multiple output formats for integration with monitoring systems

Requirements:
  - Linux system with netfilter/iptables (nf_conntrack module loaded)
  - Read access to /proc/sys/net/netfilter/

Exit codes:
  - 0: Connection tracking usage is healthy
  - 1: High usage detected (warning or critical threshold exceeded)
  - 2: Connection tracking not available (module not loaded) or usage error

Remediation:
  - Increase max connections: sysctl -w net.netfilter.nf_conntrack_max=262144
  - Reduce TCP established timeout: sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=3600
  - Investigate applications creating excessive connections

Examples:
```bash
# Check conntrack usage with default thresholds (75%/90%)
baremetal_conntrack_monitor.py

# Custom thresholds for high-traffic systems
baremetal_conntrack_monitor.py --warn 80 --crit 95

# Show timeout settings and hash bucket info
baremetal_conntrack_monitor.py --verbose

# JSON output for monitoring integration
baremetal_conntrack_monitor.py --format json

# Table format for human-readable output
baremetal_conntrack_monitor.py --format table

# Only alert when thresholds exceeded
baremetal_conntrack_monitor.py --warn-only
```

### baremetal_coredump_monitor.py
```
python baremetal_coredump_monitor.py [--format format] [-v] [-w] [--storage-warn PERCENT] [--storage-crit PERCENT]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show additional details
  -w, --warn-only: Only show warnings and issues (suppress normal output)
  --storage-warn: Storage warning threshold percentage (default: 75)
  --storage-crit: Storage critical threshold percentage (default: 90)
```

Features:
  - Monitor kernel core_pattern configuration
  - Check core file size ulimit settings
  - Detect systemd-coredump configuration (storage mode, compression)
  - Monitor coredump storage space usage
  - Find and report recent coredump files
  - Check for ABRT (Automatic Bug Reporting Tool)
  - Verify pipe handler limits for piped patterns

Exit codes:
  - 0: Coredump configuration is healthy
  - 1: Issues detected (misconfiguration or storage concerns)
  - 2: Usage error or system files not accessible

Examples:
```bash
# Check coredump configuration
baremetal_coredump_monitor.py

# JSON output for monitoring integration
baremetal_coredump_monitor.py --format json

# Custom storage thresholds
baremetal_coredump_monitor.py --storage-warn 70 --storage-crit 85

# Only show problems
baremetal_coredump_monitor.py --warn-only

# Table format with all details
baremetal_coredump_monitor.py --format table -v
```

### baremetal_cpu_vulnerability_scanner.py
```
python baremetal_cpu_vulnerability_scanner.py [--format format] [-v] [-w]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed CPU information (family, model, stepping)
  -w, --warn-only: Only show warnings and issues (suppress normal output)
```

Features:
  - Scan all known CPU vulnerabilities (Spectre v1/v2, Meltdown, MDS, L1TF, etc.)
  - Verify kernel mitigations are active via /sys/devices/system/cpu/vulnerabilities/
  - Detect disabled mitigations in kernel command line (mitigations=off, nopti, etc.)
  - Report CPU model, vendor, and microcode version for fleet tracking
  - Identify systems needing microcode updates or kernel patches
  - Multiple output formats for security compliance dashboards

Requirements:
  - Linux kernel 4.14+ with vulnerability reporting support
  - Read access to /sys/devices/system/cpu/vulnerabilities/
  - Read access to /proc/cpuinfo and /proc/cmdline

Exit codes:
  - 0: All mitigations active, no vulnerabilities exposed
  - 1: Vulnerabilities detected or mitigations not fully enabled
  - 2: Vulnerability information not available or usage error

Remediation:
  - Enable mitigations: Remove 'mitigations=off' from kernel cmdline
  - Update microcode: Install intel-microcode or amd-microcode packages
  - Update kernel: Newer kernels include improved mitigations
  - For performance-critical systems: Evaluate which mitigations can be disabled safely

Examples:
```bash
# Scan CPU vulnerabilities with default output
baremetal_cpu_vulnerability_scanner.py

# Show detailed CPU information
baremetal_cpu_vulnerability_scanner.py --verbose

# JSON output for security compliance systems
baremetal_cpu_vulnerability_scanner.py --format json

# Table format for human-readable reports
baremetal_cpu_vulnerability_scanner.py --format table

# Only show issues (for alerting)
baremetal_cpu_vulnerability_scanner.py --warn-only

# Combine with fleet management for scanning all hosts
for host in $(cat hosts.txt); do
  ssh $host baremetal_cpu_vulnerability_scanner.py --format json
done | jq -s '.'
```

### baremetal_smt_status_monitor.py
```
python baremetal_smt_status_monitor.py [--format format] [-v] [-w] [--require-disabled]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed core mapping and vulnerability status
  -w, --warn-only: Only show warnings and issues (suppress normal output)
  --require-disabled: Warn if SMT is enabled (for security-sensitive environments)
```

Features:
  - Monitor SMT (Intel Hyper-Threading/AMD SMT) status system-wide
  - Report CPU topology including packages, physical cores, logical CPUs, threads per core
  - Show per-core thread sibling mapping in verbose mode
  - Check CPU vulnerability status for SMT-related issues (L1TF, MDS, TAA, etc.)
  - Identify inconsistent SMT configuration
  - Support security compliance checking with --require-disabled flag

Requirements:
  - Linux kernel with sysfs CPU topology support
  - Read access to /sys/devices/system/cpu/

Exit codes:
  - 0: No SMT-related warnings detected
  - 1: SMT-related security warnings or inconsistencies
  - 2: Usage error or missing dependencies

Security considerations:
  SMT allows multiple threads to share CPU resources, which can leak information
  through side-channel attacks. High-security environments may need to disable SMT:
  - Temporarily: echo off > /sys/devices/system/cpu/smt/control
  - Permanently: Add nosmt to kernel command line

Examples:
```bash
# Check SMT status with default output
baremetal_smt_status_monitor.py

# Verbose output with core mapping and vulnerabilities
baremetal_smt_status_monitor.py --verbose

# JSON output for automation
baremetal_smt_status_monitor.py --format json

# Table format for quick overview
baremetal_smt_status_monitor.py --format table

# Alert if SMT is enabled (for security-sensitive systems)
baremetal_smt_status_monitor.py --require-disabled

# Fleet-wide SMT compliance check
for host in $(cat hosts.txt); do
  echo "=== $host ==="
  ssh $host baremetal_smt_status_monitor.py --require-disabled --warn-only
done
```

### baremetal_cpu_microcode_monitor.py
```
python baremetal_cpu_microcode_monitor.py [--format format] [-v] [-w] [--min-version VERSION]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed per-socket information
  -w, --warn-only: Only show warnings and issues (suppress normal output)
  --min-version VERSION: Minimum acceptable microcode version (hex, e.g., 0x20)
```

Features:
  - Monitor CPU microcode versions from /proc/cpuinfo
  - Detect inconsistent microcode versions across sockets or cores
  - Verify microcode updates are applied after security patches
  - Support minimum version checking for fleet compliance
  - Track microcode by physical socket for multi-socket systems
  - Identify systems with missing or unknown microcode information

Requirements:
  - Linux system with /proc/cpuinfo
  - Microcode information available in /proc/cpuinfo (most modern CPUs)

Exit codes:
  - 0: Consistent microcode versions, no issues detected
  - 1: Microcode issues detected (inconsistent, outdated, or missing)
  - 2: /proc/cpuinfo not available or usage error

Examples:
```bash
# Check microcode status with default output
baremetal_cpu_microcode_monitor.py

# Show detailed per-socket information
baremetal_cpu_microcode_monitor.py --verbose

# JSON output for monitoring systems
baremetal_cpu_microcode_monitor.py --format json

# Table format for human-readable reports
baremetal_cpu_microcode_monitor.py --format table

# Only show issues (for alerting)
baremetal_cpu_microcode_monitor.py --warn-only

# Check against minimum version for compliance
baremetal_cpu_microcode_monitor.py --min-version 0x830107d

# Fleet-wide microcode inventory
for host in $(cat hosts.txt); do
  echo "=== $host ===" && ssh $host baremetal_cpu_microcode_monitor.py --format json
done | jq -s '.'
```

### baremetal_cstate_residency_monitor.py
```
python baremetal_cstate_residency_monitor.py [--format format] [-v] [-w] [--min-deep-residency PCT]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed per-CPU C-state information
  -w, --warn-only: Only show warnings and issues
  --min-deep-residency PCT: Minimum deep C-state residency percentage before warning (default: 10)
```

Features:
  - Monitor CPU idle state (C-state) residency across all CPUs
  - Analyze power management effectiveness by tracking time in each C-state
  - Detect CPUs stuck in shallow sleep states (wasting power)
  - Identify workloads preventing deep C-states (C3, C6, etc.)
  - Show cpuidle driver and governor configuration
  - Track disabled C-states that may impact power efficiency
  - Aggregate and per-CPU residency analysis

Requirements:
  - Linux cpuidle sysfs interface (/sys/devices/system/cpu/cpuN/cpuidle)
  - Kernel with CONFIG_CPU_IDLE enabled
  - cpuidle driver loaded (intel_idle, acpi_idle, etc.)

Exit codes:
  - 0: C-state data retrieved successfully
  - 1: Issues detected (low deep sleep residency, disabled states)
  - 2: Usage error or no cpuidle support

Examples:
```bash
# Check C-state residency summary
baremetal_cstate_residency_monitor.py

# Show detailed per-CPU information
baremetal_cstate_residency_monitor.py --verbose

# Only show CPUs with potential issues
baremetal_cstate_residency_monitor.py --warn-only

# Output in JSON format for automation
baremetal_cstate_residency_monitor.py --format json

# Table format for quick overview
baremetal_cstate_residency_monitor.py --format table

# Custom threshold for deep sleep warning (default 10%)
baremetal_cstate_residency_monitor.py --min-deep-residency 5

# Fleet-wide power management audit
for host in $(cat hosts.txt); do
  echo "=== $host ===" && ssh $host baremetal_cstate_residency_monitor.py --format json
done | jq -s '.'

# Check for power management issues across datacenter
baremetal_cstate_residency_monitor.py --warn-only --format table
```

### baremetal_fd_exhaustion_monitor.py
```
python baremetal_fd_exhaustion_monitor.py [--format format] [-v] [-w] [--warn PERCENT] [--crit PERCENT] [--process-warn PERCENT] [--top N]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show top file descriptor consumers
  -w, --warn-only: Only show warnings and errors
  --warn PERCENT: System warning threshold for usage percentage (default: 75)
  --crit PERCENT: System critical threshold for usage percentage (default: 90)
  --process-warn PERCENT: Per-process warning threshold (default: 80)
  --top N: Number of top fd consumers to show (default: 10)
```

Features:
  - Monitor system-wide file descriptor allocation vs kernel limit (file-max)
  - Track per-process fd usage vs ulimit to detect approaching limits
  - Identify top fd consuming processes (useful for finding leaks)
  - Detect processes approaching their ulimit before failures occur
  - Multiple output formats for monitoring system integration
  - Customizable thresholds for different workloads

Requirements:
  - Linux /proc/sys/fs/file-nr, /proc/[pid]/fd, /proc/[pid]/limits
  - No external dependencies required

Exit codes:
  - 0: File descriptor usage is healthy
  - 1: High usage detected (system or process level)
  - 2: Cannot read fd information or usage error

Examples:
```bash
# Check fd usage with default thresholds (75%/90%)
baremetal_fd_exhaustion_monitor.py

# Show top fd consumers
baremetal_fd_exhaustion_monitor.py --verbose

# Show top 20 fd consumers
baremetal_fd_exhaustion_monitor.py --verbose --top 20

# Custom thresholds for high-load systems
baremetal_fd_exhaustion_monitor.py --warn 80 --crit 95

# Alert on processes using more than 50% of their limit
baremetal_fd_exhaustion_monitor.py --process-warn 50

# JSON output for monitoring integration
baremetal_fd_exhaustion_monitor.py --format json --verbose

# Table format for human-readable output
baremetal_fd_exhaustion_monitor.py --format table

# Only alert when thresholds exceeded
baremetal_fd_exhaustion_monitor.py --warn-only
```

### baremetal_inode_exhaustion_monitor.py
```
python baremetal_inode_exhaustion_monitor.py [--format format] [-v] [-w] [--warn PERCENT] [--crit PERCENT] [--mountpoint PATH]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed filesystem information
  -w, --warn-only: Only show warnings and errors, suppress normal output
  --warn PERCENT: Warning threshold for inode usage (default: 80%)
  --crit PERCENT: Critical threshold for inode usage (default: 90%)
  --mountpoint PATH: Only check specific mountpoint
```

Features:
  - Monitor inode usage across all mounted filesystems
  - Detect filesystems approaching inode exhaustion
  - Filter to specific mountpoints for targeted monitoring
  - Multiple output formats for integration with monitoring systems
  - Remediation guidance in help text

Requirements:
  - Linux with standard df command
  - No special permissions needed for basic monitoring

Exit codes:
  - 0: Inode usage healthy across all filesystems
  - 1: High inode usage detected (warning or critical)
  - 2: Usage error or cannot read filesystem information

Examples:
```bash
# Check inode usage with default thresholds (80%/90%)
baremetal_inode_exhaustion_monitor.py

# Show detailed filesystem information
baremetal_inode_exhaustion_monitor.py --verbose

# Custom thresholds for strict monitoring
baremetal_inode_exhaustion_monitor.py --warn 70 --crit 85

# Check only root filesystem
baremetal_inode_exhaustion_monitor.py --mountpoint /

# JSON output for monitoring integration
baremetal_inode_exhaustion_monitor.py --format json

# Table format for human-readable output
baremetal_inode_exhaustion_monitor.py --format table

# Only alert when thresholds exceeded
baremetal_inode_exhaustion_monitor.py --warn-only

# Find directories with most inodes on a filesystem
find /path -xdev -printf '%h\n' | sort | uniq -c | sort -rn | head -20
```

### baremetal_iptables_audit.py
```
python baremetal_iptables_audit.py [--format format] [-v] [-w] [-t table] [--max-rules N] [--unused-threshold N]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed chain information
  -w, --warn-only: Only show warnings and errors, suppress info messages
  -t, --table: iptables table to audit: filter, nat, mangle, raw (default: filter)
  --max-rules N: Warn if a chain has more than N rules (default: 50)
  --unused-threshold N: Packet count threshold for "unused" detection (default: 0)
```

Features:
  - Analyze total rule count and warn on high counts (performance impact)
  - Detect empty chains that can be cleaned up
  - Identify chains with excessive rules (suggests consolidation needed)
  - Find rules with zero packet/byte counters (potentially unused)
  - Detect overly permissive rules (ACCEPT all from anywhere)
  - Detect overly restrictive rules (DROP all not at end of chain)
  - Review default chain policies for security

Requirements:
  - Linux with iptables installed
  - Root/sudo access to read iptables rules

Exit codes:
  - 0: No issues detected
  - 1: Warnings or issues found
  - 2: Usage error or iptables not available

Examples:
```bash
# Basic audit with default thresholds
baremetal_iptables_audit.py

# Include detailed chain information
baremetal_iptables_audit.py --verbose

# JSON output for monitoring integration
baremetal_iptables_audit.py --format json

# Audit NAT table instead of filter
baremetal_iptables_audit.py --table nat

# Warn if any chain has more than 100 rules
baremetal_iptables_audit.py --max-rules 100

# Only show warnings and errors
baremetal_iptables_audit.py --warn-only

# Table format for human-readable output
baremetal_iptables_audit.py --format table --verbose
```

### baremetal_package_security_audit.py
```
python baremetal_package_security_audit.py [--format format] [-v] [-w] [--critical-only] [--package-manager TYPE]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed package information
  -w, --warn-only: Only show output if updates are pending
  --critical-only: Only return exit code 1 for critical/important updates
  --package-manager: Force specific package manager (apt, dnf, yum, auto)
```

Features:
  - Auto-detect package manager (apt, dnf, yum)
  - Identify security updates by severity (critical, important, moderate, low)
  - Support for Debian/Ubuntu (apt), RHEL/CentOS (yum), Fedora (dnf)
  - JSON output for integration with monitoring and compliance systems
  - Critical-only mode for alerting on high-priority patches

Requirements:
  - Linux with apt, dnf, or yum package manager
  - Package list access (may need root for apt-get update)

Exit codes:
  - 0: No security updates pending (or only non-critical with --critical-only)
  - 1: Security updates available or errors encountered
  - 2: Usage error or unsupported package manager

Examples:
```bash
# Check for security updates
baremetal_package_security_audit.py

# Verbose output showing all packages
baremetal_package_security_audit.py --verbose

# JSON output for monitoring integration
baremetal_package_security_audit.py --format json

# Table format for review
baremetal_package_security_audit.py --format table

# Only alert on critical/important updates
baremetal_package_security_audit.py --critical-only

# Force specific package manager
baremetal_package_security_audit.py --package-manager apt
```

Use Cases:
  - Security compliance: Track pending security patches across fleets
  - Vulnerability management: Identify critical patches needing immediate attention
  - Patch scheduling: Prioritize updates based on severity
  - Audit reporting: Generate JSON reports for compliance systems

### baremetal_security_policy_monitor.py
```
python baremetal_security_policy_monitor.py [--format format] [-v] [-w] [--expected MODE] [--require-lsm]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information
  -w, --warn-only: Only show output if issues are found
  --expected MODE: Expected security mode (enforcing, permissive, complain, disabled)
  --require-lsm: Exit with error if no LSM is active
```

Features:
  - Detect active Linux Security Module (SELinux or AppArmor)
  - Report enforcement mode (enforcing, permissive, complain, disabled)
  - Parse recent security denials from audit logs and journal
  - Support for both SELinux (RHEL/CentOS/Fedora) and AppArmor (Ubuntu/Debian/SUSE)
  - Check for configuration drift from expected state
  - Count AppArmor profiles in enforce vs complain mode

Requirements:
  - Linux kernel with LSM support
  - Optional: getenforce, sestatus, ausearch (SELinux)
  - Optional: aa-status (AppArmor)
  - Optional: journalctl for denial log analysis

Exit codes:
  - 0: Security policy is healthy and enforcing
  - 1: Security issues detected (disabled, permissive, denials)
  - 2: Error determining LSM status

Examples:
```bash
# Check security policy status
baremetal_security_policy_monitor.py

# JSON output for monitoring integration
baremetal_security_policy_monitor.py --format json

# Table format for review
baremetal_security_policy_monitor.py --format table

# Alert if not in enforcing mode
baremetal_security_policy_monitor.py --expected enforcing

# Only output if issues found (for alerting)
baremetal_security_policy_monitor.py --warn-only

# Require MAC to be active
baremetal_security_policy_monitor.py --require-lsm
```

Use Cases:
  - Security compliance: Verify mandatory access control is active and enforcing
  - Fleet auditing: Detect systems with SELinux/AppArmor disabled
  - Incident response: Find recent security policy denials
  - Configuration drift: Alert when security mode changes unexpectedly
  - Enterprise standards: Enforce consistent security policy across servers

### baremetal_usb_device_monitor.py
```
python baremetal_usb_device_monitor.py [--format format] [-v] [-w] [--whitelist FILE] [--no-flag-storage]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed device information including interfaces
  -w, --warn-only: Only show output if flagged devices are detected
  --whitelist FILE: Path to device whitelist file (vendor_id:product_id per line)
  --no-flag-storage: Do not flag mass storage devices as issues
```

Features:
  - Enumerate all connected USB devices from /sys/bus/usb/devices
  - Classify devices by USB class (storage, HID, hub, network, etc.)
  - Detect mass storage devices (potential data exfiltration risk)
  - Support device whitelists for authorized devices
  - Report device manufacturer, product, serial number, and speed

Requirements:
  - Linux /sys/bus/usb filesystem
  - Read access to sysfs (no root required)

Exit codes:
  - 0: No flagged devices detected (or no storage devices if default check)
  - 1: Unauthorized or flagged devices detected
  - 2: Usage error or /sys/bus/usb not available

Whitelist file format:
```
# Device whitelist - one per line
# Format: vendor_id:product_id  # optional comment
046d:c52b  # Logitech Unifying Receiver
8087:0024  # Intel USB Hub
0424:2514  # Standard Hub
```

Examples:
```bash
# List all USB devices
baremetal_usb_device_monitor.py

# Show detailed device information
baremetal_usb_device_monitor.py --verbose

# JSON output for monitoring integration
baremetal_usb_device_monitor.py --format json

# Only alert if unauthorized devices found
baremetal_usb_device_monitor.py --warn-only

# Check against whitelist (flag anything not listed)
baremetal_usb_device_monitor.py --whitelist /etc/usb-allowed-devices.txt

# Don't flag storage devices (for workstations)
baremetal_usb_device_monitor.py --no-flag-storage

# Table format for review
baremetal_usb_device_monitor.py --format table
```

Use Cases:
  - Data center security: Detect unauthorized USB storage devices
  - Compliance auditing: Verify only approved USB devices are connected
  - Change detection: Monitor for newly connected devices
  - Inventory management: List all USB peripherals across server fleet
  - Incident response: Identify potential data exfiltration devices

### baremetal_process_memory_growth.py
```
python baremetal_process_memory_growth.py [--format format] [-v] [-w] [-s N] [-i SEC] [--min-growth KB] [--min-pct PCT] [--top N] [--user USERNAME] [--cmd PATTERN]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information including top growers
  -w, --warn-only: Only show processes with warnings or critical growth
  -s, --samples N: Number of samples to take (default: 3, min: 2)
  -i, --interval SEC: Interval between samples in seconds (default: 5.0)
  --min-growth KB: Minimum growth in KB to report (default: 512)
  --min-pct PCT: Minimum growth percentage for warning (default: 10.0)
  --top N: Show top N growers (default: 10 with --verbose)
  --user USERNAME: Only monitor processes owned by this user
  --cmd PATTERN: Only monitor processes matching command pattern (regex)
```

Features:
  - Sample process RSS memory at configurable intervals
  - Calculate growth rate per sample period (KB/min)
  - Identify top memory growers by absolute and percentage growth
  - Filter by minimum growth threshold to reduce noise
  - Filter by user or command pattern for targeted monitoring
  - Detect processes with >50% memory growth as critical
  - Support multiple output formats for monitoring integration

Requirements:
  - Linux /proc filesystem
  - Read access to /proc/[pid]/status directories

Exit codes:
  - 0: No significant memory growth detected
  - 1: One or more processes showing concerning growth
  - 2: Usage error or /proc filesystem not available

Examples:
```bash
# Basic check with default 3 samples, 5 seconds apart
baremetal_process_memory_growth.py

# Extended monitoring: 5 samples, 5 seconds apart (25 sec total)
baremetal_process_memory_growth.py -s 5 -i 5

# Monitor only www-data user processes
baremetal_process_memory_growth.py --user www-data

# Monitor processes matching 'nginx' pattern
baremetal_process_memory_growth.py --cmd nginx

# Only report growth > 1MB
baremetal_process_memory_growth.py --min-growth 1024

# JSON output for monitoring systems
baremetal_process_memory_growth.py --format json

# Show top 10 memory growers with verbose output
baremetal_process_memory_growth.py -v --top 10

# Quick check with short intervals for testing
baremetal_process_memory_growth.py -s 2 -i 1 --min-growth 256
```

### baremetal_process_limits_monitor.py
```
python baremetal_process_limits_monitor.py [--format format] [-v] [-w] [--warn PCT] [--crit PCT] [--name PATTERN] [--top N]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed metrics for all processes
  -w, --warn-only: Only show processes with warnings or critical issues
  --warn PCT: Warning threshold percentage (default: 80)
  --crit PCT: Critical threshold percentage (default: 95)
  --name PATTERN: Filter processes by name (case-insensitive partial match)
  --top N: Show only top N processes by file descriptor usage
```

Features:
  - Monitor per-process open file descriptor usage vs RLIMIT_NOFILE
  - Check virtual memory (address space) vs RLIMIT_AS limit
  - Check stack size vs RLIMIT_STACK limit
  - Track thread count per process
  - Filter by process name pattern or user
  - Sort by resource usage to find highest consumers
  - Configurable warning/critical thresholds

Requirements:
  - Linux /proc filesystem
  - Read access to /proc/[pid]/ directories (root for all processes)

Exit codes:
  - 0: All processes within safe limits
  - 1: Processes found at risk (above warning threshold)
  - 2: Usage error or /proc filesystem not available

Examples:
```bash
# Check all accessible processes with default thresholds
baremetal_process_limits_monitor.py

# Show only processes with issues
baremetal_process_limits_monitor.py --warn-only

# Custom thresholds for high-load servers
baremetal_process_limits_monitor.py --warn 70 --crit 90

# Filter to check only nginx processes
baremetal_process_limits_monitor.py --name nginx

# Show top 10 file descriptor consumers
baremetal_process_limits_monitor.py --top 10

# JSON output for monitoring integration
baremetal_process_limits_monitor.py --format json

# Table format with verbose metrics
baremetal_process_limits_monitor.py --format table --verbose

# Combined: check nginx processes, alert at 60%
baremetal_process_limits_monitor.py --name nginx --warn 60 --crit 85 --format json
```

### baremetal_socket_state_monitor.py
```
python baremetal_socket_state_monitor.py [--format format] [-v] [-w] [--time-wait N] [--close-wait N] [--syn-recv N] [--established N]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information including thresholds
  -w, --warn-only: Only output if issues are detected
  --time-wait N: TIME_WAIT threshold (default: 1000)
  --close-wait N: CLOSE_WAIT threshold (default: 100)
  --syn-recv N: SYN_RECV threshold (default: 100)
  --established N: ESTABLISHED threshold (default: 5000)
```

Features:
  - Monitor TCP/UDP socket state distribution across the system
  - Detect excessive TIME_WAIT sockets indicating port exhaustion risk
  - Identify CLOSE_WAIT accumulation indicating file descriptor leaks
  - Detect SYN_RECV buildup indicating potential SYN flood attacks
  - Track established connection patterns for capacity planning
  - Customizable thresholds for different environments
  - Multiple output formats for monitoring system integration

Requirements:
  - Linux /proc/net/tcp, /proc/net/tcp6 files
  - No external dependencies required

Exit codes:
  - 0: No anomalies detected (healthy state)
  - 1: Socket state anomalies or warnings detected
  - 2: Missing /proc files or usage error

Examples:
```bash
# Check socket states with default thresholds
baremetal_socket_state_monitor.py

# Output in JSON format for monitoring integration
baremetal_socket_state_monitor.py --format json

# Custom thresholds for high-traffic servers
baremetal_socket_state_monitor.py --time-wait 2000 --established 10000

# Only alert if issues detected (monitoring mode)
baremetal_socket_state_monitor.py --warn-only --format json

# Verbose output showing thresholds
baremetal_socket_state_monitor.py -v

# Table format for quick overview
baremetal_socket_state_monitor.py --format table
```

### baremetal_socket_buffer_monitor.py
```
python baremetal_socket_buffer_monitor.py [--format format] [-v] [-w] [--warn PCT] [--crit PCT]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed buffer configuration and statistics
  -w, --warn-only: Only output if issues or warnings detected
  --warn PCT: Warning threshold percentage (default: 70)
  --crit PCT: Critical threshold percentage (default: 85)
```

Features:
  - Monitor socket buffer memory usage (tcp_mem, udp_mem) vs configured limits
  - Detect when socket memory is near kernel pressure thresholds
  - Identify protocols with high buffer utilization
  - Show per-protocol socket counts and memory usage
  - Report high orphan socket counts (connection leaks)
  - Report high TIME_WAIT counts (port exhaustion risk)
  - Configurable warning and critical thresholds
  - Useful for tuning tcp_rmem/tcp_wmem/tcp_mem sysctl settings

Requirements:
  - Linux /proc/net/sockstat, /proc/sys/net/* files
  - No external dependencies required

Exit codes:
  - 0: No socket buffer pressure detected
  - 1: Socket buffer pressure or warnings detected
  - 2: Missing /proc files or usage error

Examples:
```bash
# Check socket buffer status
baremetal_socket_buffer_monitor.py

# Output in JSON format for monitoring integration
baremetal_socket_buffer_monitor.py --format json

# Custom thresholds for high-traffic servers
baremetal_socket_buffer_monitor.py --warn 60 --crit 80

# Only alert if issues detected (monitoring mode)
baremetal_socket_buffer_monitor.py --warn-only --format json

# Verbose output with buffer configuration details
baremetal_socket_buffer_monitor.py -v

# Table format for quick protocol overview
baremetal_socket_buffer_monitor.py --format table
```

### baremetal_socket_queue_monitor.py
```
python baremetal_socket_queue_monitor.py [--format format] [-v] [-w] [--protocol PROTO] [--recv-warn N] [--recv-crit N] [--send-warn N] [--send-crit N] [--listen-warn N] [--listen-crit N] [--min-queue N]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information including per-process statistics
  -w, --warn-only: Only output if queue issues detected
  --protocol: Protocol to monitor - tcp, udp, or all (default: tcp)
  --recv-warn N: Receive queue warning threshold in bytes (default: 1MB)
  --recv-crit N: Receive queue critical threshold in bytes (default: 10MB)
  --send-warn N: Send queue warning threshold in bytes (default: 1MB)
  --send-crit N: Send queue critical threshold in bytes (default: 10MB)
  --listen-warn N: Listen backlog warning threshold (default: 128 connections)
  --listen-crit N: Listen backlog critical threshold (default: 1024 connections)
  --min-queue N: Minimum queue depth to analyze (default: 1KB)
```

Features:
  - Monitor per-socket receive and send queue depths
  - Detect slow consumers with large receive queue backlogs
  - Identify network congestion via send queue accumulation
  - Monitor listen socket accept queue backlog
  - Per-process socket queue statistics aggregation
  - Process identification via ss command or /proc lookup
  - Configurable thresholds for different workload types

Requirements:
  - Linux ss command (iproute2 package) or /proc/net access
  - No external dependencies required

Exit codes:
  - 0: All socket queues within thresholds
  - 1: Warning or critical queue depths detected
  - 2: Missing data sources or usage error

Examples:
```bash
# Check TCP socket queues with defaults
baremetal_socket_queue_monitor.py

# Output in JSON format for monitoring integration
baremetal_socket_queue_monitor.py --format json

# Monitor both TCP and UDP
baremetal_socket_queue_monitor.py --protocol all

# Custom thresholds for high-throughput servers
baremetal_socket_queue_monitor.py --recv-warn 5242880 --recv-crit 52428800

# Alert on listen backlog issues (accept queue full)
baremetal_socket_queue_monitor.py --listen-warn 64 --listen-crit 256

# Only show sockets with issues (monitoring mode)
baremetal_socket_queue_monitor.py --warn-only --format json

# Verbose output with per-process stats
baremetal_socket_queue_monitor.py -v
```

### baremetal_listening_port_monitor.py
```
python baremetal_listening_port_monitor.py [--format format] [-v] [-w] [--expected PORTS] [--unexpected PORTS] [--tcp-only] [--udp-only] [--port PORT] [--show-all-interfaces]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information
  -w, --warn-only: Only output if issues are detected
  --expected PORTS: Comma-separated list of expected ports (e.g., 22,80,443 or 8000-8010)
  --unexpected PORTS: Comma-separated list of unexpected ports to alert on
  --tcp-only: Only show TCP listening ports
  --udp-only: Only show UDP listening ports
  --port PORT: Filter to specific port number
  --show-all-interfaces: Only show ports bound to all interfaces (0.0.0.0 or ::)
```

Features:
  - List all listening TCP and UDP ports with process information
  - Detect unexpected services binding to ports (security auditing)
  - Verify expected services are running and listening
  - Distinguish between ports bound to all interfaces vs localhost only
  - Filter by protocol (TCP/UDP) or specific port numbers
  - Process name and PID identification via /proc filesystem
  - Multiple output formats for monitoring system integration

Requirements:
  - Linux /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6 files
  - Read access to /proc/[pid]/fd for process identification (optional)
  - No external dependencies required

Exit codes:
  - 0: No issues detected (all expected ports found, no unexpected ports)
  - 1: Unexpected ports found or expected ports missing
  - 2: Missing /proc files or usage error

Examples:
```bash
# List all listening ports with process info
baremetal_listening_port_monitor.py

# Output in JSON format for monitoring integration
baremetal_listening_port_monitor.py --format json

# Verify expected services are listening
baremetal_listening_port_monitor.py --expected 22,80,443

# Alert if unexpected ports are found (security audit)
baremetal_listening_port_monitor.py --unexpected 23,3389,5900

# Only show TCP ports bound to all interfaces
baremetal_listening_port_monitor.py --tcp-only --show-all-interfaces

# Check specific port
baremetal_listening_port_monitor.py --port 8080

# Monitoring mode: only output on issues
baremetal_listening_port_monitor.py --expected 22,80 --unexpected 23 --warn-only --format json

# Table format for quick overview
baremetal_listening_port_monitor.py --format table
```

### baremetal_process_connection_audit.py
```
python baremetal_process_connection_audit.py [--format format] [-v] [-w] [--max-per-process N] [--max-to-single-host N] [--process NAME] [--pid PID] [--remote-port PORT] [--remote-ip IP] [--state STATE] [--exclude-loopback]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show individual connections instead of summary
  -w, --warn-only: Only output if issues are detected
  --max-per-process N: Alert if a process has more than N connections (default: 1000)
  --max-to-single-host N: Alert if process has >N connections to single host (default: 100)
  --process NAME: Filter to connections owned by specific process name
  --pid PID: Filter to connections owned by specific PID
  --remote-port PORT: Filter to connections to specific remote port
  --remote-ip IP: Filter to connections to specific remote IP
  --state STATE: Filter to specific TCP state (ESTABLISHED, TIME_WAIT, etc.)
  --exclude-loopback: Exclude connections to localhost/127.0.0.1/::1
```

Audits active (non-LISTEN) network connections with per-process mapping. Unlike listening port monitors that show inbound services, this script shows what your processes are actively communicating with.

**Use cases:**
- Security auditing: Identify unexpected outbound connections
- Troubleshooting: Map connections to owning processes
- Capacity planning: Understand connection patterns
- Leak detection: Find processes with excessive connections

**Metrics tracked:**
- Per-process connection counts
- Unique remote hosts per process
- TCP state breakdown (ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.)
- Top remote destinations by connection count

Exit codes: 0=healthy, 1=processes exceed thresholds, 2=missing /proc files or usage error

Examples:
```bash
# Show process connection summary
baremetal_process_connection_audit.py

# Output in JSON format for monitoring integration
baremetal_process_connection_audit.py --format json

# Show individual connections (verbose mode)
baremetal_process_connection_audit.py -v

# Alert if any process has >500 connections
baremetal_process_connection_audit.py --max-per-process 500

# Filter to specific process (e.g., nginx)
baremetal_process_connection_audit.py --process nginx

# Find all connections to port 443 (HTTPS)
baremetal_process_connection_audit.py --remote-port 443

# Show only ESTABLISHED connections
baremetal_process_connection_audit.py --state ESTABLISHED

# Exclude local connections
baremetal_process_connection_audit.py --exclude-loopback

# Monitoring mode: alert only when thresholds exceeded
baremetal_process_connection_audit.py --max-per-process 1000 --warn-only --format json
```

### baremetal_ephemeral_port_monitor.py
```
python baremetal_ephemeral_port_monitor.py [--format format] [-v] [-w] [--warning PERCENT] [--critical PERCENT] [--time-wait-percent PERCENT]
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information including top destinations
  -w, --warn-only: Only output if issues are detected
  --warning: Warning threshold percentage (default: 70)
  --critical: Critical threshold percentage (default: 85)
  --time-wait-percent: TIME_WAIT accumulation warning threshold (default: 30)
```

Monitors ephemeral port usage against the kernel's configured range (`/proc/sys/net/ipv4/ip_local_port_range`) to detect exhaustion before "Cannot assign requested address" errors occur.

**Metrics tracked:**
- Ephemeral port range and availability
- Current usage percentage
- Connection state distribution (ESTABLISHED, TIME_WAIT, etc.)
- Top remote destinations consuming ports

**Common causes of exhaustion:**
- Load balancers with many backend connections
- High-throughput web servers or proxies
- Connection leaks in applications
- TIME_WAIT accumulation from short-lived connections

Exit codes: 0=healthy, 1=high usage or issues detected, 2=missing /proc files or usage error

Examples:
```bash
# Check ephemeral port usage
baremetal_ephemeral_port_monitor.py

# Output in JSON format for monitoring integration
baremetal_ephemeral_port_monitor.py --format json

# Custom thresholds for high-traffic servers
baremetal_ephemeral_port_monitor.py --warning 60 --critical 80

# Verbose output showing top destinations
baremetal_ephemeral_port_monitor.py -v

# Monitoring mode: only output on issues
baremetal_ephemeral_port_monitor.py --warn-only --format json

# Table format for quick overview
baremetal_ephemeral_port_monitor.py --format table
```

### baremetal_etcd_health_monitor.py
```
python baremetal_etcd_health_monitor.py [--endpoints ENDPOINTS] [--cacert PATH] [--cert PATH] [--key PATH] [--format format] [-v] [-w] [--db-warn-mb MB] [--db-crit-mb MB]
  -e, --endpoints: Comma-separated etcd endpoints (default: http://127.0.0.1:2379)
  --cacert: Path to CA certificate for TLS
  --cert: Path to client certificate for TLS
  --key: Path to client key for TLS
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information including member list and endpoint health
  -w, --warn-only: Only output if issues are detected
  --db-warn-mb: Database size warning threshold in MB (default: 2048)
  --db-crit-mb: Database size critical threshold in MB (default: 6144)
  --latency-warn-ms: Latency warning threshold in ms (default: 100)
  --latency-crit-ms: Latency critical threshold in ms (default: 500)
```

Requirements:
  - etcdctl (etcd package: https://etcd.io/docs/latest/install/)

Monitors standalone etcd cluster health for distributed systems using etcd for coordination (outside of Kubernetes). Essential for pre-Kubernetes infrastructure, Consul, CoreDNS, or custom applications.

**Checks performed:**
- Cluster health and member connectivity
- Leader election status
- Database size and fragmentation risk
- Active alarms (NOSPACE, CORRUPT, etc.)
- Quorum availability
- Latency measurements

**Environment variables supported:**
- `ETCDCTL_ENDPOINTS`: Default endpoints
- `ETCDCTL_CACERT`: Default CA certificate path
- `ETCDCTL_CERT`: Default client certificate path
- `ETCDCTL_KEY`: Default client key path

Exit codes: 0=cluster healthy, 1=issues detected (degraded, alarms, high latency), 2=etcdctl not found or connection failed

Examples:
```bash
# Check local etcd instance
baremetal_etcd_health_monitor.py

# Check remote cluster with multiple endpoints
baremetal_etcd_health_monitor.py --endpoints https://etcd1:2379,https://etcd2:2379,https://etcd3:2379

# With TLS certificates
baremetal_etcd_health_monitor.py --cacert /etc/etcd/ca.crt --cert /etc/etcd/client.crt --key /etc/etcd/client.key

# JSON output for monitoring systems
baremetal_etcd_health_monitor.py --format json

# Only alert on problems
baremetal_etcd_health_monitor.py --warn-only

# Verbose output showing all members
baremetal_etcd_health_monitor.py -v

# Custom database size thresholds
baremetal_etcd_health_monitor.py --db-warn-mb 1024 --db-crit-mb 4096

# Table format for quick overview
baremetal_etcd_health_monitor.py --format table
```

Use Case: etcd is the backbone of many distributed systems including Kubernetes. For standalone etcd clusters used in pre-Kubernetes infrastructure, service discovery, or configuration management, monitoring cluster health is critical. This script detects leader election issues, quorum loss, database size problems (which can cause write failures), and active alarms before they cause outages. Integrates with monitoring systems via JSON output.

### baremetal_libvirt_health_monitor.py
```
python baremetal_libvirt_health_monitor.py [--vm NAME] [-v] [--format format] [-w] [--check-autostart] [--skip-pools] [--skip-networks]
  --vm: Check specific VM only
  -v, --verbose: Show detailed VM information
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show VMs with warnings or issues
  --check-autostart: Warn if running VMs do not have autostart enabled
  --skip-pools: Skip storage pool checks
  --skip-networks: Skip network checks
```

Requirements:
  - virsh (libvirt-clients)
  - Ubuntu/Debian: `sudo apt-get install libvirt-clients`
  - RHEL/CentOS: `sudo yum install libvirt-client`

Examples:
```bash
# Check all VMs and hypervisor status
baremetal_libvirt_health_monitor.py

# Check specific VM
baremetal_libvirt_health_monitor.py --vm webserver01

# JSON output for monitoring systems
baremetal_libvirt_health_monitor.py --format json

# Warn if running VMs lack autostart
baremetal_libvirt_health_monitor.py --check-autostart

# Verbose output with storage pools and networks
baremetal_libvirt_health_monitor.py -v

# Only show problematic VMs
baremetal_libvirt_health_monitor.py --warn-only

# Table format for quick overview
baremetal_libvirt_health_monitor.py --format table
```

Use Case: KVM/libvirt is commonly used for virtualization on baremetal servers. This script monitors hypervisor connectivity, VM states (detecting crashed or paused VMs), autostart configuration (ensuring VMs restart after host reboot), storage pool availability, and virtual network status. Integrates with monitoring systems via JSON output. Essential for environments running mixed workloads on baremetal with some VMs for legacy applications or testing.

### system_inventory.py
```
python system_inventory.py [--format format] [-o output] [--include-pci]
  --format: Output format, either 'plain' or 'json' (default: plain)
  -o, --output: Output file (default: stdout)
  --include-pci: Include PCI device listing
```

Note: Run as root for additional hardware details from dmidecode

### systemd_service_monitor.py
```
python systemd_service_monitor.py [--format format] [--warn-only] [--verbose] [--type type] [--filter pattern]
  -f, --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show problematic units
  -v, --verbose: Show detailed information about problematic units
  -t, --type: Filter by unit type (service, timer, socket, etc.)
  --filter: Filter units by pattern (e.g., "nginx*")
```

Requirements:
  - systemd/systemctl (standard on systemd-based Linux distributions)

Exit codes:
  - 0: All services healthy
  - 1: One or more services have issues
  - 2: systemctl not available or usage error

Features:
  - Monitor all systemd units (services, timers, sockets, etc.)
  - Identify failed, degraded, or problematic units
  - Multiple output formats (plain, JSON, table)
  - Filter by unit type or pattern
  - Warn-only mode for monitoring integration
  - Detailed verbose output with error messages
  - Detect load errors and masked units

Examples:
```bash
# Check all systemd units
systemd_service_monitor.py

# Show only problematic units
systemd_service_monitor.py --warn-only

# Check only services (not timers, sockets, etc.)
systemd_service_monitor.py --type service

# Get JSON output for monitoring systems
systemd_service_monitor.py --format json

# Verbose output with error details
systemd_service_monitor.py --verbose --warn-only

# Check specific units matching a pattern
systemd_service_monitor.py --filter "nginx*"

# Table format overview
systemd_service_monitor.py --format table --warn-only
```

Use Case: In large baremetal fleets, tracking systemd service health across all hosts is essential for identifying failed services, degraded states, or configuration errors. This script provides a quick overview of all systemd units, making it ideal for automated health checks, pre-deployment validation, or troubleshooting. Integration with monitoring systems (via JSON output) enables alerting on service failures.

### baremetal_systemd_unit_drift_detector.py
```
python baremetal_systemd_unit_drift_detector.py [--format format] [--warn-only] [--verbose] [--type type] [--unit unit]
  -f, --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show units with drift
  -v, --verbose: Show detailed information including file paths and drop-ins
  -t, --type: Filter by unit type (service, timer, socket, etc.)
  -u, --unit: Check a specific unit
```

Requirements:
  - systemctl (systemd package, standard on modern Linux systems)

Exit codes:
  - 0: No configuration drift detected (all units match package defaults)
  - 1: Drift detected (local overrides, drop-ins, or masked units found)
  - 2: systemctl not available or usage error

Features:
  - Detects local admin overrides in /etc/systemd/system
  - Finds drop-in configuration files (.d/*.conf overrides)
  - Identifies masked units (symlinked to /dev/null)
  - Multiple output formats for automation and human readability
  - Filter by unit type or check specific units

Drift types detected:
  - `local_override`: Unit file exists in /etc/systemd/system overriding package version
  - `has_drop_ins`: Unit has drop-in configuration files modifying behavior
  - `masked`: Unit is masked (disabled by linking to /dev/null)

Examples:
```bash
# Check all units for configuration drift
baremetal_systemd_unit_drift_detector.py

# Show only units with drift
baremetal_systemd_unit_drift_detector.py --warn-only

# Check only services
baremetal_systemd_unit_drift_detector.py --type service --warn-only

# Verbose output showing file paths
baremetal_systemd_unit_drift_detector.py --verbose --warn-only

# JSON output for automation
baremetal_systemd_unit_drift_detector.py --format json

# Check a specific unit
baremetal_systemd_unit_drift_detector.py --unit sshd.service --verbose

# Table format for overview
baremetal_systemd_unit_drift_detector.py --format table --type service
```

Use Case: In large baremetal fleets, configuration drift is a significant source of inconsistency and security risk. This script detects when systemd units have been locally modified, overridden with drop-in files, or masked. Useful for security auditing (detecting tampering), configuration management (tracking customizations), troubleshooting (finding non-standard configurations), and ensuring fleet consistency. Integrates with monitoring systems via JSON output.

### baremetal_systemd_dependency_analyzer.py
```
python baremetal_systemd_dependency_analyzer.py [--format format] [--warn-only] [--verbose] [--unit unit] [--type type] [--all] [--check-depth] [--max-depth-warn N]
  -f, --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  -w, --warn-only: Only show units with dependency issues
  -v, --verbose: Show detailed dependency information
  -u, --unit: Analyze a specific unit
  -t, --type: Analyze units of specific type (service, timer, socket, etc.)
  -a, --all: Analyze all loaded units (can be slow)
  --check-depth: Include dependency chain depth analysis
  --max-depth-warn N: Warn if dependency depth exceeds N (default: 8)
```

Requirements:
  - systemctl (systemd package, standard on modern Linux systems)

Exit codes:
  - 0: No dependency issues detected
  - 1: Dependency issues found (failed, masked, or missing dependencies)
  - 2: systemctl not available or usage error

Features:
  - Detects failed dependencies (Requires/BindsTo/Requisite targets in failed state)
  - Identifies masked dependencies (dependencies linked to /dev/null)
  - Finds missing dependencies (units that don't exist)
  - Detects inactive strong dependencies while unit is active
  - Flags conflicting units that are both running
  - Analyzes dependency chain depth (optional)
  - Detects potential circular dependencies

Issue types detected:
  - `failed_dependency`: Strong dependency (Requires/BindsTo/Requisite) is in failed state
  - `masked_dependency`: Strong dependency is masked
  - `missing_dependency`: Dependency unit not found
  - `inactive_dependency`: Strong dependency inactive while unit is active
  - `missing_wants`: Soft dependency (Wants) not found
  - `conflict_running`: Unit and its declared conflict are both active
  - `deep_dependency_chain`: Dependency chain exceeds threshold (with --check-depth)

Examples:
```bash
# Analyze failed units and common services
baremetal_systemd_dependency_analyzer.py

# Analyze a specific unit
baremetal_systemd_dependency_analyzer.py --unit docker.service --verbose

# Analyze all services with dependency depth checking
baremetal_systemd_dependency_analyzer.py --type service --check-depth

# Show only units with issues
baremetal_systemd_dependency_analyzer.py --warn-only

# JSON output for automation
baremetal_systemd_dependency_analyzer.py --format json

# Full analysis of all units (slow but thorough)
baremetal_systemd_dependency_analyzer.py --all --check-depth --warn-only
```

Use Case: Service startup failures in large baremetal environments often stem from broken dependencies. This script helps diagnose why services fail to start by examining the dependency graph for issues like failed dependencies, masked units, missing units, and circular or overly deep dependency chains that slow boot times. Essential for troubleshooting systemd startup problems and optimizing boot performance.

### filesystem_usage_tracker.py
```
python filesystem_usage_tracker.py <path> [-d depth] [-n top] [--format format] [-q]
  path: Root filesystem path to scan (required)
  -d, --depth: Maximum directory depth to traverse (default: 3)
  -n, --top: Number of top entries to display (default: 10)
  --format: Output format, either 'plain', 'table', or 'json' (default: table)
  -q, --quiet: Suppress progress messages
```

Requirements:
  - du command-line tool (coreutils package, usually pre-installed)

Exit codes:
  - 0: Successful scan
  - 1: Error during scanning (permission denied, path not found, etc.)
  - 2: Usage error (invalid arguments)

Features:
  - Identifies large directories consuming the most disk space
  - Multiple output formats for scripting and human readability
  - Configurable depth and result count
  - Parallel processing with du for performance
  - Graceful error handling with helpful messages

Examples:
```bash
# Scan /var for large directories (default: depth 3, show top 10)
filesystem_usage_tracker.py /var

# Show top 20 directories in /home with detailed tree (depth 5)
filesystem_usage_tracker.py /home -d 5 -n 20

# Get JSON output for monitoring or scripting
filesystem_usage_tracker.py /opt --format json

# Quiet mode - suppress progress messages
filesystem_usage_tracker.py /var -q

# Scan with plain format (space-separated values)
filesystem_usage_tracker.py /usr --format plain
```

### sysctl_audit.py
```
python sysctl_audit.py [-b baseline] [--save file] [-p parameter] [-v] [--warn-only] [--format format]
  -b, --baseline: Baseline configuration file to compare against
  --save: Save current sysctl values as a baseline file
  -p, --parameter: Check a specific parameter value
  -v, --verbose: Show all parameters including matches
  --warn-only, -w: Only show parameters with warnings or mismatches
  --format: Output format, either 'plain' or 'json' (default: plain)
```

Requirements:
  - sysctl command-line tool (procps-ng package on Linux)
  - Read access to /proc/sys or appropriate permissions for sysctl

Exit codes:
  - 0: All parameters match baseline (or parameter found)
  - 1: One or more parameters differ from baseline
  - 2: Usage error, missing dependencies, or file not found

Features:
  - Create baseline snapshots of current kernel parameters
  - Compare system settings against baseline configuration
  - JSON output for integration with monitoring systems
  - Verbose mode to verify all settings match baseline
  - Warn-only mode to see only deviations

Examples:
```bash
# Create a baseline of current kernel settings
sysctl_audit.py --save baseline.conf

# Check if system matches baseline
sysctl_audit.py -b baseline.conf

# Show only mismatched parameters
sysctl_audit.py -b baseline.conf --warn-only

# Check a specific parameter
sysctl_audit.py -p net.ipv4.ip_forward

# Get JSON output for monitoring integration
sysctl_audit.py -b baseline.conf --format json

# Show all parameters with their match status
sysctl_audit.py -b baseline.conf --verbose
```

Use Case: In large baremetal deployments, ensuring consistent kernel settings across all hosts is critical. Create a baseline on a reference system, then use this script in your provisioning or monitoring pipeline to verify all nodes have the correct sysctl configuration.

### baremetal_sysctl_security_audit.py
```
python baremetal_sysctl_security_audit.py [-c category] [-s severity] [--format format] [-v] [-w] [-l]
  -c, --category: Category to audit - 'network', 'kernel', 'filesystem', or 'all' (default: all)
  -s, --severity: Minimum severity to check - 'critical', 'high', 'medium', 'low', or 'all' (default: all)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show all checks including passed ones
  -w, --warn-only: Only show failed checks
  -l, --list-checks: List all checks without running them
```

Requirements:
  - sysctl command-line tool (procps-ng package on Linux)
  - Read access to /proc/sys or appropriate permissions for sysctl

Exit codes:
  - 0: All security checks pass
  - 1: One or more security checks failed
  - 2: Usage error or sysctl command not found

Categories checked:
  - network_ipv4: IPv4 network security (forwarding, ICMP, spoofing protection)
  - network_ipv6: IPv6 network security
  - kernel_memory: ASLR, ptrace restrictions, kernel pointer exposure
  - kernel_modules: Module loading and kexec controls
  - filesystem: Symlink/hardlink protections, core dump settings
  - user_namespaces: Unprivileged namespace and BPF restrictions

Examples:
```bash
# Run all security checks
baremetal_sysctl_security_audit.py

# Check only network settings
baremetal_sysctl_security_audit.py --category network

# Only check high/critical severity issues
baremetal_sysctl_security_audit.py --severity high

# JSON output for automation
baremetal_sysctl_security_audit.py --format json

# Only show failures
baremetal_sysctl_security_audit.py --warn-only

# List all checks without running them
baremetal_sysctl_security_audit.py --list-checks
```

Use Case: Unlike sysctl_audit.py which compares against a user-provided baseline, this script has built-in security recommendations based on CIS benchmarks and STIG guidelines. Use it for quick security assessments on new systems, compliance audits, or as part of security hardening workflows without needing to maintain baseline files.

### process_resource_monitor.py
```
python process_resource_monitor.py [--format format] [--top-n N] [--mem-threshold PCT] [--by-user] [--warn-only] [--verbose]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --top-n: Number of top processes to show (default: 10)
  --mem-threshold: Alert on processes exceeding this memory percentage
  --by-user: Show process count by user
  --warn-only: Only show warnings and issues (zombies, threshold violations)
  --verbose: Show detailed information
```

Requirements:
  - Linux /proc filesystem (standard on all Linux systems)
  - No external dependencies required

Exit codes:
  - 0: No issues detected
  - 1: Zombies found or thresholds exceeded
  - 2: Usage error

Features:
  - Monitor top CPU/memory consuming processes
  - Detect zombie processes (state Z)
  - Track process counts per user
  - Set memory usage thresholds for alerts
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode for monitoring integration
  - Parse /proc filesystem directly (no external tools required)

Examples:
```bash
# Show top 10 CPU and memory consumers
process_resource_monitor.py

# Show top 20 consumers with detailed info
process_resource_monitor.py --top-n 20 --verbose

# Alert on processes using more than 10% memory
process_resource_monitor.py --mem-threshold 10

# Show process counts by user
process_resource_monitor.py --by-user

# Only show warnings (zombies, threshold violations)
process_resource_monitor.py --warn-only

# JSON output for monitoring systems
process_resource_monitor.py --format json

# Table format with memory threshold
process_resource_monitor.py --format table --mem-threshold 5

# Combine options: top 15, memory alert, show by user
process_resource_monitor.py --top-n 15 --mem-threshold 8 --by-user
```

Use Case: In large-scale baremetal environments, identifying resource-hungry processes and zombie processes is critical for troubleshooting performance issues. This script provides quick visibility into process-level resource consumption across servers, making it ideal for debugging CPU or memory bottlenecks. Zombie processes indicate parent process issues that need investigation. The memory threshold feature enables proactive alerting on processes consuming excessive RAM, preventing OOM conditions. Essential for baremetal servers running diverse workloads where process monitoring complements system-level metrics.

### pcie_health_monitor.py
```
python pcie_health_monitor.py [--format format] [--warn-only] [--verbose]
  --format, -f: Output format, either 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show devices with warnings or critical status
  --verbose, -v: Show detailed device information including N/A devices
```

Requirements:
  - lspci command-line tool (pciutils package on Linux)
  - Read access to PCIe configuration space

Exit codes:
  - 0: All PCIe devices healthy
  - 1: Warning or critical conditions detected
  - 2: Usage error or missing dependencies

Features:
  - Monitor PCIe link speed and width (detect degradation)
  - Check for PCIe errors (correctable, uncorrectable, fatal)
  - Compare current link status vs. device capabilities
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode for monitoring integration
  - Detect devices running below capability (x16 at x8, Gen3 at Gen2)

Examples:
```bash
# Check all PCIe devices
pcie_health_monitor.py

# Show only devices with issues
pcie_health_monitor.py --warn-only

# Output as JSON for monitoring systems
pcie_health_monitor.py --format json

# Show table format with all details
pcie_health_monitor.py --format table --verbose
```

Use Case: In baremetal environments with GPUs, NVMe storage, or high-speed networking, PCIe link degradation can cause significant performance issues that are difficult to diagnose. This script detects PCIe devices running below their capabilities (such as a GPU running at x8 instead of x16, or a Gen3 device downgraded to Gen2), as well as devices with error counters indicating hardware problems. Regular monitoring can catch failing risers, thermal issues, or marginal PCIe slots before they cause complete failures.

### power_consumption_monitor.py
```
python power_consumption_monitor.py [--format format] [--warn-only] [--verbose] [--skip-ipmi] [--skip-turbostat] [--skip-rapl]
  --format, -f: Output format, either 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show warnings or critical power readings
  --verbose, -v: Show detailed information including sensor source
  --skip-ipmi: Skip IPMI sensor checks
  --skip-turbostat: Skip turbostat checks (requires root)
  --skip-rapl: Skip RAPL/sysfs checks
```

Requirements:
  - At least one of: ipmitool, turbostat, or RAPL sysfs support
  - ipmitool: Install with `apt-get install ipmitool`
  - turbostat: Part of linux-tools package (requires root access)
  - RAPL: Available on Intel CPUs via /sys/class/powercap/intel-rapl

Exit codes:
  - 0: Success (all power metrics retrieved)
  - 1: Warning/Critical power levels detected
  - 2: Usage error or missing dependencies

Features:
  - Monitor power consumption via IPMI BMC sensors
  - CPU package power via turbostat (Intel CPUs)
  - RAPL energy counters via sysfs (/sys/class/powercap)
  - Multiple output formats (plain, JSON, table)
  - Warn-only mode for monitoring integration
  - Detect power sensors exceeding thresholds
  - Support for skipping specific sensor sources

Examples:
```bash
# Check all available power sensors
power_consumption_monitor.py

# Show only warnings/critical readings
power_consumption_monitor.py --warn-only

# Output as JSON for monitoring systems
power_consumption_monitor.py --format json

# Show table format with sensor sources
power_consumption_monitor.py --format table --verbose

# Skip IPMI, only use RAPL
power_consumption_monitor.py --skip-ipmi --skip-turbostat
```

Use Case: In large-scale datacenter environments, power consumption monitoring is critical for capacity planning, cost optimization, and detecting hardware anomalies. This script aggregates power metrics from multiple sources (IPMI BMC sensors, Intel RAPL counters, and turbostat) to provide comprehensive visibility into server power usage. It can detect servers drawing unusually high power (potential hardware issues or runaway processes), servers with failing power supplies, or identify opportunities for power optimization. Regular monitoring helps with datacenter power budgeting and can alert on power supply failures before they cause outages.

### kubernetes_node_health.py
```
python kubernetes_node_health.py [--format format] [--warn-only]
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show nodes with warnings or issues
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - Optional: metrics-server for resource usage metrics

Exit codes:
  - 0: All nodes healthy
  - 1: One or more nodes unhealthy or warnings detected
  - 2: Usage error or kubectl not available

Examples:
```bash
# Check all nodes with plain output
kubernetes_node_health.py

# Show only problematic nodes
kubernetes_node_health.py --warn-only

# Get JSON output for monitoring integration
kubernetes_node_health.py --format json

# Combine options
kubernetes_node_health.py -f json -w
```

### k8s_pod_resource_audit.py
```
python k8s_pod_resource_audit.py [--namespace NAMESPACE] [--format format] [--warn-only] [--show-quotas]
  --namespace, -n: Namespace to audit (default: all namespaces)
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show pods with warnings or issues
  --show-quotas, -q: Show resource quota information
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - Optional: metrics-server for current resource usage metrics

Exit codes:
  - 0: No resource issues detected
  - 1: Resource issues found (warnings)
  - 2: Usage error or kubectl not available

Features:
  - Detects pods with no resource requests/limits set
  - Identifies OOMKilled pods and excessive restarts
  - Shows pods in CrashLoopBackOff or other error states
  - Reports evicted pods
  - Displays current resource usage (when metrics-server available)
  - Shows namespace resource quota utilization

Examples:
```bash
# Audit all pods across all namespaces
k8s_pod_resource_audit.py

# Audit pods in production namespace only
k8s_pod_resource_audit.py -n production

# Show only pods with issues
k8s_pod_resource_audit.py --warn-only

# Get JSON output for monitoring integration
k8s_pod_resource_audit.py --format json

# Show resource quotas along with pod status
k8s_pod_resource_audit.py --show-quotas

# Combine options: only problematic pods in JSON format
k8s_pod_resource_audit.py -w -f json -n kube-system
```

### k8s_extended_resources_audit.py
```
python k8s_extended_resources_audit.py [--namespace NAMESPACE] [--format format] [--warn-only] [--verbose]
  --namespace, -n: Namespace to audit (default: all namespaces)
  --format, -f: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show warnings (hide INFO level issues)
  --verbose, -v: Show detailed per-node and per-pod information
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No issues detected
  - 1: Issues found (underutilization, pending pods, misconfigurations)
  - 2: Usage error or kubectl not available

Features:
  - Audits extended resources: NVIDIA GPUs, AMD GPUs, Intel devices, FPGAs, SR-IOV NICs, hugepages, custom device plugins
  - Shows cluster-wide resource utilization for all extended resources
  - Identifies pending pods waiting for unavailable hardware
  - Detects underutilized extended resources (capacity waste)
  - Warns about pods requesting hardware without proper node affinity
  - Per-node breakdown showing which pods consume each resource

Examples:
```bash
# Audit all extended resources cluster-wide
k8s_extended_resources_audit.py

# Audit extended resources in GPU workloads namespace
k8s_extended_resources_audit.py -n gpu-workloads

# Get JSON output for monitoring integration
k8s_extended_resources_audit.py --format json

# Tabular output for reporting
k8s_extended_resources_audit.py --format table

# Show only warnings (hide INFO)
k8s_extended_resources_audit.py -w

# Verbose output with per-pod details
k8s_extended_resources_audit.py -v

# Combine options: verbose JSON in specific namespace
k8s_extended_resources_audit.py -n ml-training -f json -v
```

Use Cases:
  - **GPU Cluster Management**: Track NVIDIA/AMD GPU allocation and utilization across ML training nodes
  - **Heterogeneous Hardware**: Audit clusters with mixed hardware (GPUs, FPGAs, NVMe, SR-IOV)
  - **Capacity Planning**: Identify underutilized extended resources for better scheduling
  - **Scheduling Diagnostics**: Find pending pods blocked on unavailable hardware
  - **Cost Optimization**: Detect expensive hardware sitting idle in baremetal clusters
  - **Compliance Auditing**: Ensure workloads have proper placement constraints for specialized hardware

### k8s_pv_health_check.py
```
python k8s_pv_health_check.py [--format format] [--warn-only]
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show PVs with warnings or issues
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All persistent volumes healthy
  - 1: One or more PVs unhealthy or warnings detected
  - 2: Usage error or kubectl not available

Features:
  - Detects persistent volumes in unhealthy states
  - Verifies PVCs are bound to existing volumes
  - Identifies released volumes with Retain policy
  - Warns about unusually small storage capacity
  - Cross-references PVs and PVCs for consistency
  - Supports plain text and JSON output formats

Examples:
```bash
# Check all persistent volumes with plain output
k8s_pv_health_check.py

# Show only volumes with issues
k8s_pv_health_check.py --warn-only

# Get JSON output for monitoring integration
k8s_pv_health_check.py --format json

# Combine options: only problematic volumes in JSON format
k8s_pv_health_check.py -w -f json
```

### k8s_pvc_stuck_detector.py
```
python k8s_pvc_stuck_detector.py [--threshold MINUTES] [--namespace NAMESPACE] [--format format] [--verbose]
  --threshold, -t: Minimum age in minutes to consider PVC stuck (default: 5)
  --namespace, -n: Namespace to check (default: all namespaces)
  --format, -f: Output format: 'plain', 'json', or 'table' (default: plain)
  --verbose, -v: Show additional diagnostic details
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No stuck PVCs found
  - 1: One or more PVCs stuck in Pending state
  - 2: Usage error or kubectl unavailable

Features:
  - Identifies PVCs stuck in Pending state beyond a configurable threshold
  - Provides diagnostic information about why PVCs may be stuck:
    - Missing or misconfigured StorageClass
    - No matching PersistentVolume available
    - Provisioner using no-provisioner (requires manual binding)
    - Selector constraints that can't be satisfied
    - Recent provisioning failure events
    - RWX access mode requiring shared storage support
  - Supports multiple output formats (plain, JSON, table)
  - Useful for monitoring storage provisioning health in baremetal clusters

Examples:
```bash
# Find PVCs pending longer than 5 minutes (default threshold)
k8s_pvc_stuck_detector.py

# Find PVCs pending longer than 1 hour
k8s_pvc_stuck_detector.py -t 60

# Check only a specific namespace
k8s_pvc_stuck_detector.py -n production

# Get JSON output for scripting/monitoring
k8s_pvc_stuck_detector.py --format json

# Table format for quick overview
k8s_pvc_stuck_detector.py --format table

# Verbose output with all diagnostic details
k8s_pvc_stuck_detector.py -v

# Combine: JSON output for PVCs stuck over 2 hours in monitoring namespace
k8s_pvc_stuck_detector.py -t 120 -n monitoring -f json
```

### k8s_backup_health_monitor.py
```
python k8s_backup_health_monitor.py [--namespace NAMESPACE] [--max-age HOURS] [--format format] [--warn-only] [--verbose]
  --namespace, -n: Namespace to check (default: all namespaces)
  --max-age, -a: Maximum age in hours for backups before warning (default: 24)
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show items with warnings or issues
  --verbose, -v: Show detailed information
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - Optional: Velero installed for Velero backup monitoring
  - Optional: VolumeSnapshot CRDs for snapshot monitoring

Exit codes:
  - 0: All backups healthy (recent successful backups exist)
  - 1: Backup issues detected (stale, failed, or missing backups)
  - 2: Usage error or kubectl not available

Features:
  - Monitors Velero backup schedules and recent backup completion status
  - Checks VolumeSnapshot health and readiness
  - Monitors backup-related CronJobs (etcd backups, database dumps, etc.)
  - Detects stale backups exceeding configurable age threshold
  - Identifies failed or partially failed backups
  - Essential for disaster recovery compliance tracking
  - Supports plain text and JSON output formats

Use cases:
  - **DR Compliance**: Verify backups exist and are recent for compliance requirements
  - **Backup Monitoring**: Detect failed backups before they become critical
  - **Snapshot Health**: Track VolumeSnapshot readiness and errors
  - **CronJob Auditing**: Ensure backup CronJobs are executing successfully
  - **Multi-System Coverage**: Single tool monitors Velero, VolumeSnapshots, and CronJobs

Examples:
```bash
# Check all backup systems with plain output
k8s_backup_health_monitor.py

# Show only items with issues
k8s_backup_health_monitor.py --warn-only

# Alert if backups older than 48 hours
k8s_backup_health_monitor.py --max-age 48

# Check backups in velero namespace
k8s_backup_health_monitor.py -n velero

# Get JSON output for monitoring integration
k8s_backup_health_monitor.py --format json

# Verbose output with all backup details
k8s_backup_health_monitor.py -v

# Combine options: issues only, JSON format, 48h threshold
k8s_backup_health_monitor.py -w -f json -a 48
```

### k8s_deployment_status.py
```
python k8s_deployment_status.py [--namespace NAMESPACE] [--format format] [--warn-only]
  --namespace, -n: Namespace to check (default: all namespaces)
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show deployments/statefulsets with issues
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All deployments/statefulsets healthy and fully rolled out
  - 1: One or more deployments/statefulsets not ready or unhealthy
  - 2: Usage error or kubectl not available

Features:
  - Monitors Deployment and StatefulSet rollout status
  - Tracks replica availability (desired, ready, updated, available)
  - Detects stalled rollouts and pending replicas
  - Shows currently deployed image versions
  - Checks Progressing and Available conditions
  - Supports plain text and JSON output formats

Examples:
```bash
# Check all deployments and statefulsets with plain output
k8s_deployment_status.py

# Show only deployments with issues
k8s_deployment_status.py --warn-only

# Check specific namespace
k8s_deployment_status.py -n production

# Get JSON output for monitoring integration
k8s_deployment_status.py --format json

# Combine options: production namespace, only problematic, JSON format
k8s_deployment_status.py -n production -w -f json
```

### k8s_statefulset_health.py
```
python k8s_statefulset_health.py [--namespace NAMESPACE] [--format format] [--warn-only]
  --namespace, -n: Namespace to check (default: all namespaces)
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show StatefulSets with issues or warnings
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All StatefulSets healthy with all pods ready
  - 1: One or more StatefulSets unhealthy or have warnings
  - 2: Usage error or kubectl not available

Features:
  - StatefulSet-specific health monitoring beyond basic replica counts
  - Checks pod readiness and ordering (StatefulSets maintain stable pod identities)
  - Validates PersistentVolumeClaim binding status for each pod
  - Detects partition rollout status (for staged rollouts)
  - Monitors pod restart counts and container readiness
  - Identifies volume attachment issues
  - Validates StatefulSet update strategy configuration
  - Per-pod issue reporting for granular troubleshooting
  - Supports plain text and JSON output formats

Examples:
```bash
# Check all StatefulSets with plain output
k8s_statefulset_health.py

# Show only StatefulSets with issues
k8s_statefulset_health.py --warn-only

# Check specific namespace
k8s_statefulset_health.py -n production

# Get JSON output for monitoring integration
k8s_statefulset_health.py --format json

# Combine options: production namespace, only problematic, JSON format
k8s_statefulset_health.py -n production -w -f json
```

### k8s_job_monitor.py
```
python k8s_job_monitor.py [--namespace NAMESPACE] [--format format] [--warn-only] [--failed-only] [--max-duration HOURS]
  --namespace, -n: Namespace to check (default: all namespaces)
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show jobs with issues
  --failed-only: Only show failed jobs
  --max-duration: Maximum job duration in hours before flagging as stuck (default: 24)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All jobs healthy (no failed jobs, no stuck jobs)
  - 1: One or more jobs failed or stuck
  - 2: Usage error or kubectl not available

Features:
  - Monitor Job completion status (succeeded, failed, active)
  - Track job duration and timing
  - Monitor CronJob schedule and last run status
  - Detect failed jobs with reason analysis
  - Identify stuck or long-running jobs
  - Check backoff limit reached status
  - Detect CronJobs with concurrent job issues
  - Alert on CronJobs without recent successful runs
  - Supports plain text and JSON output formats

Examples:
```bash
# Check all jobs and cronjobs with plain output
k8s_job_monitor.py

# Show only jobs with issues
k8s_job_monitor.py --warn-only

# Show only failed jobs
k8s_job_monitor.py --failed-only

# Check specific namespace
k8s_job_monitor.py -n production

# Get JSON output for monitoring integration
k8s_job_monitor.py --format json

# Flag jobs running longer than 12 hours as stuck
k8s_job_monitor.py --max-duration 12

# Combine options: production namespace, only problematic, JSON format
k8s_job_monitor.py -n production -w -f json
```

### k8s_daemonset_health_monitor.py
```
python k8s_daemonset_health_monitor.py [--namespace NAMESPACE] [--format format] [--warn-only]
  --namespace, -n: Namespace to check (default: all namespaces)
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show DaemonSets with issues or warnings
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All DaemonSets healthy with pods on all expected nodes
  - 1: One or more DaemonSets unhealthy or have warnings
  - 2: Usage error or kubectl not available

Features:
  - Verifies pods are running on all expected nodes (node coverage check)
  - Detects missing pods on schedulable nodes
  - Identifies ImagePullBackOff and CrashLoopBackOff issues
  - Tracks pod restart counts and readiness
  - Detects node selector and toleration issues preventing scheduling
  - Monitors update strategy status and rollout progress
  - Identifies misscheduled pods (running on wrong nodes)
  - Reports resource constraints blocking pod placement
  - Supports filtering by namespace
  - Provides plain text and JSON output formats
  - Essential for monitoring critical infrastructure DaemonSets (CNI, CSI, kube-proxy)

Examples:
```bash
# Check all DaemonSets cluster-wide
k8s_daemonset_health_monitor.py

# Check DaemonSets in kube-system namespace (common for infrastructure)
k8s_daemonset_health_monitor.py -n kube-system

# Only show DaemonSets with issues
k8s_daemonset_health_monitor.py --warn-only

# JSON output for monitoring integration
k8s_daemonset_health_monitor.py --format json

# Combine options: kube-system namespace, only problematic, JSON format
k8s_daemonset_health_monitor.py -n kube-system -w -f json
```

### k8s_cni_health_monitor.py
```
python k8s_cni_health_monitor.py [--format format] [--warn-only] [--verbose]
  --format, -f: Output format, either 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show output if issues or warnings are detected
  --verbose, -v: Show detailed information including per-node status
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All CNI components healthy
  - 1: CNI issues detected
  - 2: Usage error or kubectl not available

Supported CNI plugins:
  - Calico
  - Cilium
  - Flannel
  - Weave
  - AWS VPC CNI
  - Azure CNI

Features:
  - Auto-detects installed CNI plugin
  - Monitors CNI DaemonSet health (desired vs ready pods)
  - Checks node NetworkUnavailable condition
  - Verifies pod CIDR allocation on nodes
  - Detects pods with network-related failures
  - Checks CNI-specific IPAM status (Calico IPPool, Cilium)
  - Identifies high-restart CNI pods indicating instability

Examples:
```bash
# Check CNI health with plain output
k8s_cni_health_monitor.py

# JSON output for monitoring systems
k8s_cni_health_monitor.py --format json

# Only show problems
k8s_cni_health_monitor.py --warn-only

# Verbose output with per-node network status
k8s_cni_health_monitor.py --verbose

# Table format for easy reading
k8s_cni_health_monitor.py --format table
```

### k8s_dns_health_monitor.py
```
python k8s_dns_health_monitor.py [--namespace NAMESPACE] [--format format] [--warn-only] [--no-dns-test] [--test-domain DOMAIN]
  --namespace, -n: Namespace where DNS pods are running (default: kube-system)
  --format, -f: Output format, either 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show output if issues or warnings are detected
  --no-dns-test: Skip DNS resolution test (faster but less thorough)
  --test-domain: Domain to test DNS resolution (default: kubernetes.default.svc.cluster.local)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All DNS components healthy
  - 1: DNS issues detected
  - 2: Usage error or kubectl not available

Features:
  - Monitors CoreDNS/kube-dns pod health and readiness
  - Tests actual DNS resolution from within the cluster
  - Checks DNS service ClusterIP and endpoint availability
  - Tracks pod restart counts that may indicate instability
  - Validates DNS ConfigMap presence
  - Detects common DNS failure modes (no ready endpoints, service misconfiguration)
  - Supports plain text, JSON, and table output formats

Examples:
```bash
# Check DNS health with plain output
k8s_dns_health_monitor.py

# JSON output for monitoring systems
k8s_dns_health_monitor.py --format json

# Check DNS in a specific namespace
k8s_dns_health_monitor.py --namespace custom-dns

# Only show problems
k8s_dns_health_monitor.py --warn-only

# Skip DNS resolution test (faster)
k8s_dns_health_monitor.py --no-dns-test

# Test resolution of a custom domain
k8s_dns_health_monitor.py --test-domain my-service.production.svc.cluster.local

# Table format for easy reading
k8s_dns_health_monitor.py --format table
```

### k8s_metrics_server_health_monitor.py
```
python k8s_metrics_server_health_monitor.py [--namespace NAMESPACE] [--format format] [--verbose] [--warn-only]
  --namespace, -n: Namespace where metrics-server is deployed (default: kube-system)
  --format: Output format, either 'plain', 'json', or 'table' (default: plain)
  --verbose, -v: Show detailed information including node metrics breakdown
  --warn-only: Only show output if issues or warnings are detected
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - Metrics Server deployed in the cluster

Exit codes:
  - 0: Metrics server healthy and operational
  - 1: Issues detected (warnings or errors)
  - 2: Usage error or kubectl not available

Features:
  - Monitors Metrics Server deployment health and readiness
  - Checks API service (v1beta1.metrics.k8s.io) availability
  - Verifies node and pod metrics are being collected
  - Detects silently failing metrics server (breaks HPA/VPA)
  - Tracks pod restarts that may indicate instability
  - Warns on single-replica deployments (no HA)
  - Supports plain text, JSON, and table output formats

Examples:
```bash
# Basic health check
k8s_metrics_server_health_monitor.py

# JSON output for monitoring systems
k8s_metrics_server_health_monitor.py --format json

# Verbose output with node details
k8s_metrics_server_health_monitor.py --verbose

# Only show if there are problems
k8s_metrics_server_health_monitor.py --warn-only

# Check metrics server in custom namespace
k8s_metrics_server_health_monitor.py --namespace monitoring

# Table format for easy reading
k8s_metrics_server_health_monitor.py --format table
```

### k8s_event_monitor.py
```
python k8s_event_monitor.py [--namespace NAMESPACE] [--minutes MINUTES] [--format format] [--warn-only] [--categories]
  --namespace, -n: Namespace to monitor (default: all namespaces)
  --minutes, -m: Show events from last N minutes (default: all events)
  --format, -f: Output format, either 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show warnings and errors
  --categories, -c: Show event category summary
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No critical events found
  - 1: Warning or error events detected
  - 2: Usage error or kubectl not available

Features:
  - Aggregates all events from a Kubernetes cluster
  - Filters events by namespace and time window
  - Categorizes events by type and reason
  - Tracks repeated events with count
  - Separates errors from warnings for quick identification
  - Supports multiple output formats (plain text and JSON)

Examples:
```bash
# Show all events across all namespaces
k8s_event_monitor.py

# Monitor only production namespace
k8s_event_monitor.py -n production

# Show events from the last 30 minutes
k8s_event_monitor.py --minutes 30

# Only show warnings and errors
k8s_event_monitor.py --warn-only

# Get JSON output for monitoring integration
k8s_event_monitor.py --format json

# Combine options: recent errors/warnings in JSON format
k8s_event_monitor.py -w -f json -m 60

# Show event category summary
k8s_event_monitor.py --categories
```

### k8s_node_capacity_planner.py
```
python k8s_node_capacity_planner.py [--format format] [--warn-only]
  --format, -f: Output format, either 'table', 'plain', 'json', or 'summary' (default: table)
  --warn-only, -w: Only show nodes with WARNING or CRITICAL capacity status
```

Requirements:
  - Python kubernetes library: `pip install kubernetes`
  - kubectl configured to access the Kubernetes cluster
  - Access to a Kubernetes cluster

Exit codes:
  - 0: Successfully analyzed cluster capacity
  - 1: Error accessing cluster or missing dependencies
  - 2: Usage error (invalid arguments)

Features:
  - Analyzes node allocatable resources (CPU, memory, pod count)
  - Calculates current pod requests and utilization percentages
  - Identifies nodes approaching capacity thresholds
  - Automatic capacity status determination (OK, MODERATE, WARNING, CRITICAL)
  - Multiple output formats for different use cases
  - Cluster-wide capacity summary and forecasting
  - Graceful handling of nodes with missing resource information

Output Formats:
  - **table**: Human-readable columnar format showing all nodes (default)
  - **plain**: Space-separated values for easy scripting
  - **json**: Machine-parseable JSON format with detailed metrics
  - **summary**: High-level cluster capacity overview with recommendations

Capacity Status Thresholds:
  - **OK**: < 50% utilization (lowest of CPU, memory, or pod count)
  - **MODERATE**: 50-75% utilization
  - **WARNING**: 75-90% utilization
  - **CRITICAL**: > 90% utilization

Examples:
```bash
# View all nodes with current capacity (default table format)
k8s_node_capacity_planner.py

# Show only nodes approaching capacity limits
k8s_node_capacity_planner.py --warn-only

# Get cluster-wide capacity summary
k8s_node_capacity_planner.py --format summary

# JSON output for monitoring integration
k8s_node_capacity_planner.py --format json

# Plain format for scripting/shell tools
k8s_node_capacity_planner.py --format plain

# Combine options: only critical nodes in JSON format
k8s_node_capacity_planner.py -w -f json
```

Use Cases:
  - **Capacity Planning**: Identify when cluster needs additional nodes
  - **Resource Management**: Detect underutilized or overprovisioned nodes
  - **Admission Control**: Understand which node can safely accept new workloads
  - **Cost Optimization**: Identify opportunities to consolidate workloads
  - **Monitoring Integration**: Export metrics via JSON for dashboards and alerting
  - **Baremetal Deployments**: Critical for on-premises K8s where adding hardware is expensive

### k8s_node_resource_fragmentation_analyzer.py
```
python k8s_node_resource_fragmentation_analyzer.py [--namespace NAMESPACE] [--format format] [--warn-only] [--verbose] [--cpu CPU] [--memory MEMORY]
  --namespace, -n: Namespace to analyze (default: all namespaces)
  --format, -f: Output format: 'plain', 'table', or 'json' (default: table)
  --warn-only, -w: Only show nodes with fragmentation issues
  --verbose, -v: Show cluster summary and additional details
  --cpu: Reference pod CPU request (default: 500m)
  --memory: Reference pod memory request (default: 512Mi)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No significant fragmentation detected
  - 1: Fragmentation issues found (phantom capacity or high fragmentation)
  - 2: Usage error or kubectl not available

Features:
  - **Fragmentation Detection**: Identifies nodes where free resources can't fit typical pods
  - **Phantom Capacity**: Detects "phantom capacity" where aggregate free resources exist but can't schedule pods
  - **Limiting Factor Analysis**: Shows whether CPU, memory, or pod count limits schedulability
  - **Reference Pod Sizing**: Customizable reference pod size for realistic capacity estimates
  - **Cluster Summary**: Compares actual schedulable capacity vs theoretical capacity
  - **Unschedulable Node Marking**: Identifies cordoned or tainted nodes

Status Values:
  - **OK**: Node can schedule reference pods with available resources
  - **PHANTOM_CAPACITY**: Free resources exist but can't fit even one reference pod
  - **MODERATE_FRAGMENTATION**: 25-50% of free resources unusable for reference pods
  - **HIGH_FRAGMENTATION**: >50% of free resources unusable for reference pods

Examples:
```bash
# Analyze with default reference pod (500m CPU, 512Mi memory)
k8s_node_resource_fragmentation_analyzer.py

# Analyze with custom reference pod size (for larger workloads)
k8s_node_resource_fragmentation_analyzer.py --cpu 1000m --memory 1Gi

# Show only problematic nodes
k8s_node_resource_fragmentation_analyzer.py --warn-only

# Include cluster-wide summary
k8s_node_resource_fragmentation_analyzer.py -v

# JSON output for monitoring integration
k8s_node_resource_fragmentation_analyzer.py --format json

# Combine options: problematic nodes with cluster summary
k8s_node_resource_fragmentation_analyzer.py -w -v
```

Use Cases:
  - **Scheduling Troubleshooting**: Answer "Why can't my pod schedule when cluster shows free capacity?"
  - **Capacity Planning**: Understand real vs theoretical capacity for workload planning
  - **Right-sizing**: Determine optimal pod sizes for cluster efficiency
  - **Defragmentation Planning**: Identify candidates for pod rescheduling
  - **Cost Optimization**: Find wasted capacity due to fragmentation

### k8s_cpu_throttling_detector.py
```
python k8s_cpu_throttling_detector.py [--namespace NAMESPACE] [--format format] [--warn-only]
  --namespace, -n: Namespace to check (default: all namespaces)
  --format, -f: Output format, either 'plain', 'table', or 'json' (default: table)
  --warn-only, -w: Only show pods at risk of throttling
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - Optional: metrics-server for current CPU usage metrics

Exit codes:
  - 0: No throttled pods detected
  - 1: One or more pods experiencing throttling or at risk
  - 2: Usage error or kubectl not available

Features:
  - Detects pods with very low CPU limits that may cause throttling
  - Identifies pods with no CPU requests/limits set (at risk)
  - Tracks pods currently using >75% of their CPU limit (when metrics available)
  - Flags pods using >90% of limit as HIGH priority
  - Multiple output formats for integration with monitoring systems

Examples:
```bash
# Check all pods with table output
k8s_cpu_throttling_detector.py

# Show only at-risk pods
k8s_cpu_throttling_detector.py --warn-only

# Check specific namespace
k8s_cpu_throttling_detector.py -n production

# Get JSON output for monitoring integration
k8s_cpu_throttling_detector.py --format json

# Combine options: production namespace, only problematic, JSON format
k8s_cpu_throttling_detector.py -n production -w -f json
```

Use Cases:
  - **Performance Troubleshooting**: Identify workloads being throttled due to CPU limits
  - **Resource Optimization**: Find pods with insufficient CPU allocation
  - **Capacity Planning**: Detect applications needing more CPU resources
  - **Monitoring Integration**: Export throttling risks via JSON for dashboards
  - **Multi-tenant Environments**: Identify noisy neighbors affecting other pods

### k8s_ingress_cert_checker.py
```
python k8s_ingress_cert_checker.py [--namespace NAMESPACE] [--format FORMAT] [--warn-only]
  --namespace, -n: Kubernetes namespace to check (default: all namespaces)
  --format, -f: Output format - 'plain' or 'json' (default: plain)
  --warn-only, -w: Show only ingresses with warnings or issues
  --help, -h: Show this help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - Optional: openssl for certificate parsing

Exit codes:
  - 0: All ingresses healthy, certificates valid
  - 1: Certificate warnings/expiration or ingress issues detected
  - 2: Usage error or kubectl not available

Features:
  - Checks TLS certificate expiration dates and warnings
  - Monitors ingress backend service status and health
  - Verifies load balancer IP/hostname assignment
  - Detects missing or invalid TLS secrets
  - Identifies service endpoints for backend availability
  - Supports per-namespace or cluster-wide checking

Examples:
```bash
# Check all ingresses across cluster
k8s_ingress_cert_checker.py

# Check ingresses in production namespace
k8s_ingress_cert_checker.py -n production

# Show only ingresses with issues
k8s_ingress_cert_checker.py --warn-only

# Get JSON output for monitoring systems
k8s_ingress_cert_checker.py --format json

# Check production namespace, only problematic, JSON format
k8s_ingress_cert_checker.py -n production -w -f json
```

Use Cases:
  - **Certificate Expiration Prevention**: Proactive monitoring to prevent certificate-based outages
  - **Ingress Health Monitoring**: Verify load balancer assignment and backend connectivity
  - **TLS Configuration Auditing**: Detect missing or misconfigured TLS secrets
  - **Operational Dashboards**: Export ingress status via JSON for monitoring integration
  - **Multi-namespace Environments**: Monitor ingress health across multiple namespaces
  - **Incident Prevention**: Catch certificate expiration before impacting services

### k8s_node_drain_readiness.py
```
python k8s_node_drain_readiness.py [node] [--action ACTION] [--format FORMAT] [--warn-only] [--dry-run] [--force] [--grace-period SECONDS]
  node: Node name to check/drain (not required for --action check-all)
  --action: Action to perform - 'check', 'drain', 'uncordon', or 'check-all' (default: check)
  --format, -f: Output format - 'plain', 'table', or 'json' (default: table)
  --warn-only, -w: Only show pods with eviction issues
  --dry-run: Simulate action without making changes
  --force: Force drain including pods with emptyDir data (for drain action)
  --grace-period: Grace period for pod termination in seconds (default: 30)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - Sufficient permissions to cordon/drain nodes

Exit codes:
  - 0: Node is safe to drain / action succeeded
  - 1: Node has issues preventing safe drain / action failed
  - 2: Usage error or kubectl not available

Features:
  - Analyzes pod constraints (local storage, critical annotations, PDB conflicts)
  - Identifies stateful workloads requiring manual intervention
  - Respects PodDisruptionBudgets for high-availability applications
  - Gracefully cordons nodes to prevent new pod scheduling
  - Drains pods with configurable grace period
  - Uncordons nodes after maintenance is complete
  - Supports cluster-wide readiness assessment
  - Dry-run mode for validation before actual operations

Examples:
```bash
# Check if a node is safe to drain
k8s_node_drain_readiness.py node-1

# Show only problematic pods
k8s_node_drain_readiness.py node-1 --warn-only

# Simulate drain without making changes
k8s_node_drain_readiness.py node-1 --action drain --dry-run

# Actually drain a node with 60 second grace period
k8s_node_drain_readiness.py node-1 --action drain --grace-period 60

# Drain with force flag for stateful workloads
k8s_node_drain_readiness.py node-1 --action drain --force

# Uncordon a node after maintenance
k8s_node_drain_readiness.py node-1 --action uncordon

# Check all nodes for drainability
k8s_node_drain_readiness.py --action check-all

# Get JSON output for automation
k8s_node_drain_readiness.py node-1 --format json
```

Use Cases:
  - **Node Maintenance**: Safely prepare nodes for patching, reboots, or hardware maintenance
  - **Rolling Upgrades**: Orchestrate graceful node decommissioning during cluster upgrades
  - **Resource Optimization**: Identify pods preventing node consolidation or scale-down
  - **Capacity Planning**: Detect workloads with constraints (local storage, affinity) affecting scheduling
  - **Automation Integration**: Export drain readiness via JSON for orchestration scripts
  - **Incident Response**: Quickly isolate problematic nodes while ensuring pod availability
  - **Baremetal Operations**: Critical for on-premises clusters where downtime is expensive

### k8s_memory_pressure_analyzer.py
```
python3 k8s_memory_pressure_analyzer.py [options]
  -n, --namespace: Analyze specific namespace (default: all namespaces)
  --nodes-only: Only show node memory pressure information
  --pods-only: Only show pod memory usage information
  -h, --help: Show help message
```

Examples:
```bash
# Check memory pressure in all namespaces
python3 k8s_memory_pressure_analyzer.py

# Check memory pressure in production namespace
python3 k8s_memory_pressure_analyzer.py -n production

# Show only node memory status
python3 k8s_memory_pressure_analyzer.py --nodes-only

# Show only pod memory usage
python3 k8s_memory_pressure_analyzer.py --pods-only

# Check specific namespace pod memory
python3 k8s_memory_pressure_analyzer.py -n kube-system --pods-only
```

Use Cases:
  - **Memory Pressure Detection**: Identify nodes experiencing memory pressure before OOMKill events
  - **Pod Memory Audit**: Find pods without memory limits that could destabilize the cluster
  - **Capacity Planning**: Analyze memory allocation across namespaces for resource forecasting
  - **Performance Troubleshooting**: Detect memory contention causing pod evictions
  - **Baremetal Optimization**: Critical for on-premises clusters where memory is limited and evictions are expensive
  - **Proactive Scaling**: Identify when clusters need memory upgrades or node additions
  - **Compliance**: Ensure all pods have proper memory limits for SLA adherence

### k8s_node_pressure_monitor.py
```
python3 k8s_node_pressure_monitor.py [options]
  --format, -f: Output format - 'plain' or 'json' (default: plain)
  --warn-only, -w: Only show nodes with pressure conditions or warnings
  --reserved-warn PCT: Warn if system-reserved resources exceed PCT% (default: 30)
  -h, --help: Show help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No pressure conditions detected
  - 1: Pressure conditions or warnings found
  - 2: Usage error or kubectl not available

Features:
  - Monitors all node pressure conditions (MemoryPressure, DiskPressure, PIDPressure)
  - Detects NetworkUnavailable status
  - Analyzes allocatable vs capacity for memory, CPU, storage, pods, PIDs
  - Warns when system-reserved resources are unusually high
  - Reports Ready/NotReady status

Pressure Conditions Monitored:
  - **MemoryPressure**: Node is running low on memory, may trigger pod evictions
  - **DiskPressure**: Node is running low on disk space, may trigger evictions
  - **PIDPressure**: Node is running low on process IDs
  - **NetworkUnavailable**: Node network is not properly configured

Examples:
```bash
# Check all nodes for pressure conditions
k8s_node_pressure_monitor.py

# Show only nodes with issues or warnings
k8s_node_pressure_monitor.py --warn-only

# JSON output for monitoring integration
k8s_node_pressure_monitor.py --format json

# Warn if system reserves more than 40% of resources
k8s_node_pressure_monitor.py --reserved-warn 40

# Combine options for automation
k8s_node_pressure_monitor.py -w -f json
```

Use Cases:
  - **Proactive Capacity Management**: Detect pressure conditions before pod evictions occur
  - **Baremetal Monitoring**: Critical for on-premises clusters where node resources are fixed
  - **Alerting Integration**: JSON output enables integration with Prometheus/Alertmanager
  - **Maintenance Planning**: Identify nodes under pressure before scheduling maintenance
  - **Resource Forecasting**: Track allocatable vs capacity trends across nodes
  - **Incident Response**: Quickly identify which nodes are experiencing resource exhaustion

### k8s_pdb_health_monitor.py
```
python3 k8s_pdb_health_monitor.py [options]
  -n, --namespace: Check specific namespace (default: all namespaces)
  --format: Output format - 'plain', 'table', or 'json' (default: plain)
  -w, --warn-only: Only show PDBs with issues
  -v, --verbose: Show detailed PDB information including selectors and workloads
  -h, --help: Show help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All PDBs healthy
  - 1: PDB issues detected
  - 2: Usage error or kubectl not available

Features:
  - Detects PDBs blocking disruptions (disruptionsAllowed=0)
  - Identifies PDBs with no matching pods
  - Finds misconfigured PDBs (minAvailable > expected pods)
  - Detects unhealthy pods protected by PDBs
  - Cross-references PDBs with Deployments and StatefulSets
  - Categorizes issues by severity (critical/warning)

Issue Detection:
  - **Critical**: PDB blocking disruptions - will prevent node drains
  - **Critical**: minAvailable exceeds expected pod count
  - **Warning**: No pods match PDB selector
  - **Warning**: Unhealthy pods protected by PDB
  - **Warning**: Matching workloads have unready replicas

Examples:
```bash
# Check all PDBs across all namespaces
k8s_pdb_health_monitor.py

# Check PDBs in production namespace
k8s_pdb_health_monitor.py -n production

# Show only PDBs with issues
k8s_pdb_health_monitor.py --warn-only

# Verbose output with workload details
k8s_pdb_health_monitor.py -v

# Get JSON output for monitoring integration
k8s_pdb_health_monitor.py --format json

# Table format for quick overview
k8s_pdb_health_monitor.py --format table
```

Use Cases:
  - **Maintenance Planning**: Identify PDBs that will block node drains before starting maintenance
  - **Cluster Health**: Detect PDBs protecting unhealthy workloads that need attention
  - **Configuration Audit**: Find misconfigured PDBs that don't match any pods
  - **Upgrade Readiness**: Verify PDBs allow sufficient disruptions for rolling upgrades
  - **Baremetal Clusters**: Critical for on-premises environments where maintenance windows are planned
  - **SLA Compliance**: Ensure PDBs are configured correctly to maintain availability guarantees

### k8s_pdb_coverage_analyzer.py
```
python3 k8s_pdb_coverage_analyzer.py [options]
  -n, --namespace: Check specific namespace (default: all namespaces)
  -f, --format: Output format - 'plain', 'table', or 'json' (default: table)
  -w, --warn-only: Only show workloads with issues (exclude OK severity)
  -v, --verbose: Show detailed information including suggestions
  --suggest: Include PDB configuration suggestions
  --kind: Workload kind to analyze - 'all', 'deployment', 'statefulset', 'replicaset' (default: all)
  -h, --help: Show help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Severity Levels:
  - **CRITICAL**: Critical namespace workload without PDB (kube-system, monitoring, etc.)
  - **HIGH**: Multi-replica workload without PDB coverage
  - **WARNING**: Has PDB but policy may be too restrictive
  - **LOW**: Single replica workload (PDB would not help)
  - **OK**: Adequate PDB coverage

Examples:
```bash
# Check all workloads for PDB coverage
k8s_pdb_coverage_analyzer.py

# Check only production namespace
k8s_pdb_coverage_analyzer.py -n production

# Show only workloads missing PDB coverage
k8s_pdb_coverage_analyzer.py --warn-only

# Get suggestions for PDB configurations
k8s_pdb_coverage_analyzer.py --suggest

# Analyze only Deployments
k8s_pdb_coverage_analyzer.py --kind deployment

# Get JSON output for CI/CD integration
k8s_pdb_coverage_analyzer.py --format json
```

Use Cases:
  - **Pre-Maintenance Validation**: Ensure all critical workloads have PDB protection before node drains
  - **Cluster Hardening**: Identify workloads vulnerable to unexpected disruptions during upgrades
  - **SLA Compliance**: Verify production workloads meet availability requirements with proper PDBs
  - **Security Auditing**: Find critical system components (kube-system) lacking disruption protection
  - **Onboarding Review**: Audit new deployments for PDB coverage before production rollout

### k8s_pod_eviction_risk_analyzer.py
```
python3 k8s_pod_eviction_risk_analyzer.py [options]
  -n, --namespace: Analyze specific namespace (default: all namespaces)
  -f, --format: Output format - 'plain', 'table', or 'json' (default: table)
  -w, --warn-only: Only show pods at medium/high/critical risk
  -h, --help: Show help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No pods at risk of eviction
  - 1: One or more pods at risk of eviction detected
  - 2: Usage error or kubectl not available

Features:
  - Detects pods on nodes with memory/disk/PID pressure
  - Analyzes QoS class (BestEffort evicted first, then Burstable, then Guaranteed)
  - Identifies pods without memory limits on pressure nodes
  - Tracks pod restart counts and OOMKill history
  - Flags containers without resource requests or limits
  - Monitors node condition changes that trigger eviction
  - Categorizes risk levels: NONE, LOW, MEDIUM, HIGH, CRITICAL

Risk Assessment Criteria:
  - **CRITICAL**: Pod on node with MemoryPressure, or container was OOMKilled
  - **HIGH**: BestEffort QoS pod, or Burstable pod without memory limits
  - **MEDIUM**: Pod on pressure node, or containers without memory limits
  - **LOW**: Stable pod with resource constraints in place
  - **NONE**: Healthy pod with no risk factors

Examples:
```bash
# Check all pods for eviction risk
k8s_pod_eviction_risk_analyzer.py

# Check pods in production namespace only
k8s_pod_eviction_risk_analyzer.py -n production

# Show only high-risk pods (MEDIUM, HIGH, CRITICAL)
k8s_pod_eviction_risk_analyzer.py --warn-only

# Get table output for human review
k8s_pod_eviction_risk_analyzer.py --format table

# Get JSON output for monitoring integration
k8s_pod_eviction_risk_analyzer.py --format json

# Combine options: production namespace, warn-only, JSON format
k8s_pod_eviction_risk_analyzer.py -n production -w -f json
```

Use Cases:
  - **Proactive Eviction Prevention**: Identify pods likely to be evicted before disruptions occur
  - **QoS Optimization**: Audit pod QoS classes and find BestEffort workloads in production
  - **Resource Planning**: Understand which pods are vulnerable to resource pressure
  - **Cluster Health**: Monitor pod stability during high-load periods
  - **Baremetal Deployments**: Critical for on-premises clusters where evictions cause expensive downtime
  - **SLA Compliance**: Ensure production workloads have Guaranteed QoS and proper resource limits
  - **Capacity Planning**: Identify when nodes are approaching resource exhaustion
  - **Monitoring Integration**: Export eviction risk via JSON for alerting systems

### k8s_qos_class_auditor.py
```
python3 k8s_qos_class_auditor.py [options]
  -n, --namespace: Analyze specific namespace (default: all namespaces)
  -f, --format: Output format - 'plain', 'table', or 'json' (default: plain)
  -w, --warn-only: Only show pods with QoS issues
  -v, --verbose: Show detailed recommendations and upgradeable pods
  --critical-only: Only analyze pods marked as critical
  --exclude-namespace: Exclude specific namespace (can repeat)
  -h, --help: Show help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No QoS issues detected
  - 1: Issues found (BestEffort pods or critical workloads without Guaranteed QoS)
  - 2: Usage error or kubectl not available

QoS Classes Explained:
  - **Guaranteed**: All containers have CPU/memory requests equal to limits - protected from eviction
  - **Burstable**: At least one container has CPU or memory request - may be evicted under pressure
  - **BestEffort**: No resource requests or limits set - first to be evicted

Output includes:
  - Pod QoS class distribution summary
  - Critical pods without Guaranteed QoS (high risk)
  - BestEffort pods with high eviction risk
  - Namespace-level QoS distribution statistics
  - Upgrade recommendations for Burstable pods

Examples:
```bash
# Audit all pods in the cluster
k8s_qos_class_auditor.py

# Audit specific namespace
k8s_qos_class_auditor.py -n production

# Only show pods with QoS issues
k8s_qos_class_auditor.py --warn-only

# Focus on critical workloads only
k8s_qos_class_auditor.py --critical-only

# Show upgrade recommendations
k8s_qos_class_auditor.py --verbose

# JSON output for automation
k8s_qos_class_auditor.py --format json

# Table output for human review
k8s_qos_class_auditor.py --format table

# Exclude system namespaces
k8s_qos_class_auditor.py --exclude-namespace kube-system --exclude-namespace kube-public
```

Use Cases:
  - **Eviction Prevention**: Identify BestEffort pods that will be evicted first under memory pressure
  - **Critical Workload Protection**: Ensure system-critical pods have Guaranteed QoS
  - **Capacity Planning**: Understand QoS distribution for cluster capacity decisions
  - **Resource Governance**: Audit namespace compliance with QoS policies
  - **Cluster Stability**: Find pods vulnerable to eviction during high-load periods
  - **Baremetal Clusters**: Essential for on-premises deployments where evictions are costly

### k8s_pending_pod_analyzer.py
```
python3 k8s_pending_pod_analyzer.py [options]
  -n, --namespace: Analyze specific namespace (default: all namespaces)
  -f, --format: Output format - 'plain', 'table', or 'json' (default: plain)
  -v, --verbose: Show detailed failure reasons from events
  -h, --help: Show help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No pending pods found
  - 1: Pending pods found (with analysis)
  - 2: Usage error or kubectl not available

Output includes:
  - Pending pod namespace and name
  - Duration pod has been pending
  - Resource requests (CPU/memory)
  - Categorized failure reason
  - Summary by failure type

Failure types detected:
  - **resources**: Insufficient CPU or memory on nodes
  - **storage**: PVC binding or provisioning issues
  - **taints**: Node taints without matching tolerations
  - **affinity**: Node or pod affinity rules cannot be satisfied
  - **antiAffinity**: Pod anti-affinity conflicts preventing scheduling
  - **nodeSelector**: No nodes match the required selector
  - **scheduling**: Other scheduling failures

Examples:
```bash
# Analyze all pending pods across the cluster
k8s_pending_pod_analyzer.py

# Analyze pending pods in production namespace
k8s_pending_pod_analyzer.py -n production

# Verbose output with detailed failure reasons from events
k8s_pending_pod_analyzer.py --verbose

# Compact table view for quick review
k8s_pending_pod_analyzer.py --format table

# JSON output for monitoring integration
k8s_pending_pod_analyzer.py --format json

# Combine options: specific namespace, verbose, JSON format
k8s_pending_pod_analyzer.py -n production -v -f json
```

Use Cases:
  - **Scheduling Troubleshooting**: Quickly diagnose why pods cannot be scheduled
  - **Resource Capacity Planning**: Identify when clusters need more capacity
  - **Taint/Toleration Debugging**: Find mismatched taint configurations
  - **PVC Issues**: Detect storage provisioning failures blocking deployments
  - **Affinity Conflicts**: Identify when affinity rules prevent pod placement
  - **Deployment Validation**: Verify new deployments can schedule successfully
  - **Baremetal Operations**: Critical for on-premises clusters with limited node pools
  - **Monitoring Integration**: Export pending pod data for alerting systems

### k8s_pod_topology_analyzer.py
```
python3 k8s_pod_topology_analyzer.py [options]
  -n, --namespace: Analyze specific namespace (default: all namespaces)
  -f, --format: Output format - 'plain', 'table', or 'json' (default: table)
  -w, --warn-only: Only show workloads with topology issues
  -v, --verbose: Show detailed topology information
  -h, --help: Show help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No topology issues detected
  - 1: Topology issues or risks found
  - 2: Usage error or kubectl not available

Features:
  - Analyzes TopologySpreadConstraints configuration on deployments and statefulsets
  - Detects missing zone-level topology spread constraints
  - Monitors pod affinity and anti-affinity rules
  - Identifies required vs preferred anti-affinity configurations
  - Analyzes actual pod distribution across nodes and zones
  - Detects single points of failure (all pods on one node/zone)
  - Flags workloads with high pod concentration on single nodes
  - Multiple output formats for integration with monitoring systems

Output Formats:
  - **table**: Human-readable columnar format showing workloads and distribution issues (default)
  - **plain**: Space-separated values for scripting/shell integration
  - **json**: Machine-parseable JSON with detailed topology analysis

Examples:
```bash
# Analyze all workloads for topology issues
k8s_pod_topology_analyzer.py

# Check specific namespace
k8s_pod_topology_analyzer.py -n production

# Show only workloads with issues
k8s_pod_topology_analyzer.py --warn-only

# Get table output for human review
k8s_pod_topology_analyzer.py --format table

# Get JSON output for monitoring integration
k8s_pod_topology_analyzer.py --format json

# Combine options: production namespace, warn-only, JSON format
k8s_pod_topology_analyzer.py -n production -w -f json
```

Use Cases:
  - **High Availability Validation**: Ensure critical workloads have proper topology constraints
  - **Single Point of Failure Detection**: Identify when all replicas are on one node or zone
  - **Pre-deployment Validation**: Check workload configurations before deploying to production
  - **Cluster Topology Planning**: Understand how pods are distributed across infrastructure
  - **Baremetal Deployments**: Critical for on-premises clusters where node failures are costly
  - **Zone Failure Preparedness**: Ensure workloads can survive zone failures
  - **Monitoring Integration**: Export topology analysis via JSON for alerting systems

### k8s_node_restart_monitor.py
```
python3 k8s_node_restart_monitor.py [options]
  --format, -f: Output format - 'plain', 'table', or 'json' (default: table)
  --warn-only, -w: Only show nodes with excessive restarts or issues
  -h, --help: Show help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No restart issues detected
  - 1: Nodes with excessive restarts or recent crashes detected
  - 2: Usage error or kubectl not available

Features:
  - Monitors node uptime and identifies recently booted nodes
  - Tracks pod restart counts per node
  - Detects nodes with excessive pod restarts (potential hardware/software issues)
  - Monitors node conditions (MemoryPressure, DiskPressure, PIDPressure)
  - Identifies nodes not in Ready state
  - Generates alerts for stability issues
  - Multiple output formats for integration with monitoring systems

Output Formats:
  - **table**: Human-readable columnar format with node status, uptime, and restart counts (default)
  - **plain**: Space-separated values for scripting/shell integration
  - **json**: Machine-parseable JSON with detailed restart information per pod

Examples:
```bash
# Check all nodes with default table output
k8s_node_restart_monitor.py

# Show only nodes with issues
k8s_node_restart_monitor.py --warn-only

# Monitor for recent reboots with JSON output
k8s_node_restart_monitor.py -f json

# Integrate with monitoring: show problems in plain format
k8s_node_restart_monitor.py -w -f plain

# Get detailed restart information in JSON
k8s_node_restart_monitor.py --format json
```

Use Cases:
  - **Hardware Failure Detection**: Identify nodes with excessive restarts indicating hardware problems
  - **Kernel Panic Monitoring**: Detect cluster-wide instability from kernel issues
  - **Infrastructure Health**: Monitor baremetal hardware for reliability issues
  - **Incident Response**: Quickly identify problematic nodes during cluster issues
  - **Maintenance Tracking**: Monitor impact of updates and patches on node stability
  - **Capacity Planning**: Identify aging hardware with increasing restart rates
  - **Baremetal Operations**: Critical for on-premises clusters where hardware monitoring is essential
  - **Monitoring Integration**: Export node stability metrics for dashboards and alerting

### k8s_pod_count_analyzer.py
```
python3 k8s_pod_count_analyzer.py [options]
  -n, --namespace: Analyze specific namespace only (default: all namespaces)
  --format, -f: Output format - 'table', 'plain', or 'json' (default: table)
  --warn-only, -w: Only show resources with issues
  --deployments-only: Only analyze Deployments
  --statefulsets-only: Only analyze StatefulSets
  -h, --help: Show help message
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No scaling issues detected
  - 1: Scaling issues found (warnings)
  - 2: Usage error or kubectl not available

Features:
  - Analyzes Deployment and StatefulSet scaling configuration
  - Identifies deployments/statefulsets scaled to 0 replicas
  - Detects replica mismatches (desired vs. ready/available)
  - Warns about excessive replica counts (>50 replicas)
  - Tracks HPA configuration and correlation with replicas
  - Monitors resource quota usage and pod limits
  - Multiple output formats for integration with monitoring systems

Examples:
```bash
# Analyze all pod scaling across cluster
k8s_pod_count_analyzer.py

# Show only resources with issues (table format)
k8s_pod_count_analyzer.py --warn-only

# Analyze specific namespace
k8s_pod_count_analyzer.py -n production

# Get JSON output for monitoring integration
k8s_pod_count_analyzer.py --format json

# Only check Deployments (exclude StatefulSets)
k8s_pod_count_analyzer.py --deployments-only

# Combine options: production namespace, only problematic, plain format
k8s_pod_count_analyzer.py -n production -w -f plain
```

Use Cases:
  - **Scaling Configuration Audit**: Verify all deployments have correct replica configurations
  - **Capacity Planning**: Identify under-scaled or over-scaled workloads in baremetal clusters
  - **Resource Quota Monitoring**: Track namespace-level pod quotas to prevent quota exhaustion
  - **Deployment Health**: Detect deployments with replicas not becoming ready (potential issues)
  - **HPA Correlation**: Identify HPAs without proper minimum replica configuration
  - **Cluster Consolidation**: Find deployments with excessive replicas for consolidation opportunities
  - **Baremetal Operations**: Critical for on-premises clusters where pod density directly impacts resource utilization
  - **Incident Prevention**: Catch scaling misconfigurations before they impact availability

### k8s_orphaned_resources_finder.py
```
python3 k8s_orphaned_resources_finder.py [--namespace NAMESPACE] [--format FORMAT] [options]
  --namespace, -n: Check specific namespace only (default: all namespaces)
  --format, -f: Output format - 'plain' or 'json' (default: plain)
  --skip-empty-namespaces: Skip checking for empty namespaces
  --skip-configmaps: Skip checking for orphaned ConfigMaps
  --skip-secrets: Skip checking for orphaned Secrets
  --skip-pvcs: Skip checking for orphaned PersistentVolumeClaims
  --skip-services: Skip checking for unused Services with no endpoints
  --skip-service-accounts: Skip checking for unused ServiceAccounts
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No orphaned resources found
  - 1: Orphaned or unused resources detected
  - 2: Usage error or kubectl not available

Features:
  - Identifies empty namespaces (no pods or workloads)
  - Finds orphaned ConfigMaps not referenced by any pod
  - Detects orphaned Secrets not used by pod volumes or env variables
  - Identifies unused PersistentVolumeClaims not mounted by pods
  - Discovers Services with no endpoints (no backing pod replicas)
  - Finds unused ServiceAccounts not referenced by pods
  - Skips system namespaces (kube-*, olm*) automatically unless explicitly requested
  - Skips default-token Secrets (automatically managed by Kubernetes)
  - Multiple output formats for scripting and monitoring integration

Examples:
```bash
# Find all orphaned resources cluster-wide
k8s_orphaned_resources_finder.py

# Check specific namespace
k8s_orphaned_resources_finder.py -n production

# Show only ConfigMaps and Secrets
k8s_orphaned_resources_finder.py --skip-pvcs --skip-services --skip-service-accounts

# Get JSON output for processing
k8s_orphaned_resources_finder.py --format json

# Find only empty namespaces
k8s_orphaned_resources_finder.py --skip-configmaps --skip-secrets --skip-pvcs --skip-services --skip-service-accounts

# Combine namespace and format options
k8s_orphaned_resources_finder.py -n production -f json --skip-empty-namespaces
```

Use Cases:
  - **Resource Cleanup**: Identify and remove unused resources to reduce cluster overhead
  - **Cost Optimization**: Find and delete orphaned resources consuming storage/memory in baremetal clusters
  - **Cluster Health Auditing**: Regularly audit for orphaned configurations indicating stale deployments
  - **Storage Management**: Identify unused PVCs consuming storage space
  - **Configuration Cleanup**: Find orphaned ConfigMaps and Secrets from deleted workloads
  - **Security Hardening**: Identify and remove unused ServiceAccounts
  - **Operational Efficiency**: Catch configuration mistakes before they accumulate
  - **Baremetal Operations**: Critical for on-premises clusters where resources are limited and expensive

### k8s_configmap_secret_size_analyzer.py
```
python3 k8s_configmap_secret_size_analyzer.py [--namespace NAMESPACE] [--format FORMAT] [options]
  --namespace, -n: Check specific namespace only (default: all namespaces)
  --format, -f: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show objects above warning threshold
  --verbose, -v: Show detailed information including largest keys
  --warn-threshold: Warning threshold (default: 100KB)
  --crit-threshold: Critical threshold (default: 500KB)
  --skip-system: Skip kube-* system namespaces
  --configmaps-only: Only analyze ConfigMaps
  --secrets-only: Only analyze Secrets
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No oversized objects found
  - 1: Oversized objects detected (above warning threshold)
  - 2: Usage error or kubectl not available

Features:
  - Analyzes ConfigMap and Secret sizes across all or specific namespaces
  - Identifies objects that stress etcd performance (etcd stores all K8s objects)
  - Configurable thresholds for warning (100KB) and critical (500KB) sizes
  - Shows individual key sizes to identify largest contributors
  - Detects objects approaching Kubernetes 1MB hard limit
  - Skips service account tokens automatically (managed by K8s)
  - Multiple output formats for scripting and monitoring integration
  - Calculates actual decoded size for base64-encoded secret data

Examples:
```bash
# Analyze all ConfigMaps and Secrets cluster-wide
k8s_configmap_secret_size_analyzer.py

# Check specific namespace
k8s_configmap_secret_size_analyzer.py -n production

# Show only oversized objects
k8s_configmap_secret_size_analyzer.py --warn-only

# Custom thresholds for stricter monitoring
k8s_configmap_secret_size_analyzer.py --warn-threshold 50KB --crit-threshold 200KB

# Get JSON output for automation
k8s_configmap_secret_size_analyzer.py --format json

# Verbose output showing largest keys in oversized objects
k8s_configmap_secret_size_analyzer.py -v -w

# Only analyze Secrets (skip ConfigMaps)
k8s_configmap_secret_size_analyzer.py --secrets-only

# Table format for quick review
k8s_configmap_secret_size_analyzer.py --format table --warn-only
```

Use Cases:
  - **etcd Health**: Large objects stress etcd, causing slow API responses and increased memory usage
  - **API Server Performance**: Large object transfers slow down watch streams and API latency
  - **Kubelet Memory**: Large ConfigMaps/Secrets mounted as volumes consume kubelet memory
  - **Cluster Capacity Planning**: Monitor total configuration data size before it impacts cluster
  - **Configuration Best Practices**: Identify configs that should be externalized or split
  - **Baremetal Operations**: Critical for resource-constrained clusters where etcd runs on limited hardware
  - **Incident Prevention**: Catch objects approaching 1MB limit before they fail to save

### k8s_finalizer_analyzer.py
```
python3 k8s_finalizer_analyzer.py [--namespace NAMESPACE] [--format FORMAT] [options]
  --namespace, -n: Check specific namespace only (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --namespaces-only: Only check for terminating namespaces
  --resource-type: Specific resource type to check (default: all)
  --verbose, -v: Show detailed information including conditions
  --warn-only, -w: Only show resources stuck for more than 5 minutes
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No stuck resources found
  - 1: Stuck resources detected
  - 2: Usage error or kubectl not available

Features:
  - Detects namespaces stuck in Terminating state due to finalizers
  - Finds resources (pods, deployments, PVCs, etc.) that cannot be deleted
  - Reports how long resources have been stuck (age since deletion requested)
  - Identifies specific finalizers blocking deletion
  - Checks cluster-scoped resources like PersistentVolumes
  - Provides common finalizer documentation and remediation hints
  - Multiple output formats for scripting and monitoring integration

Examples:
```bash
# Check all namespaces for stuck resources
k8s_finalizer_analyzer.py

# Check specific namespace
k8s_finalizer_analyzer.py -n my-stuck-namespace

# Show only terminating namespaces
k8s_finalizer_analyzer.py --namespaces-only

# Get JSON output for automation
k8s_finalizer_analyzer.py --format json

# Check only pods
k8s_finalizer_analyzer.py --resource-type pods

# Show only resources stuck for more than 5 minutes
k8s_finalizer_analyzer.py --warn-only

# Verbose output with conditions
k8s_finalizer_analyzer.py -v
```

Use Cases:
  - **Namespace Deletion Issues**: Diagnose why namespace deletions are hanging
  - **Custom Controller Debugging**: Identify resources stuck due to failing custom controllers
  - **Cluster Maintenance**: Find and resolve stuck resources before maintenance windows
  - **PV/PVC Issues**: Detect PersistentVolumes stuck due to protection finalizers
  - **CRD Cleanup**: Find custom resources that cannot be deleted
  - **Incident Response**: Quickly identify the cause of stuck deletion operations
  - **Baremetal Operations**: Critical for on-premises clusters where manual intervention is often needed

### k8s_container_restart_analyzer.py
```
python3 k8s_container_restart_analyzer.py [--namespace NAMESPACE] [--timeframe MINUTES] [options]
  --namespace, -n: Analyze restarts in specific namespace (default: all namespaces)
  --timeframe MINUTES: Only analyze restarts within last N minutes
  --verbose, -v: Show detailed analysis with remediation suggestions
  --warn-only: Only show warnings (flapping containers with 5+ restarts)
  --output: Output format - 'plain' or 'json' (default: plain)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No restarts or only informational findings
  - 1: Restarts detected with warnings
  - 2: Usage error or kubectl not available

Features:
  - Analyzes container restart patterns across all pods in the cluster
  - Categorizes restart causes (OOMKilled, CrashLoopBackOff, ApplicationError, ProbeFailure, Evicted, SIGTERM, SIGKILL)
  - Identifies "flapping" containers with excessive restarts (5+ restarts)
  - Provides actionable remediation suggestions based on restart category
  - Checks resource limits for containers experiencing OOMKills
  - Shows restart distribution by namespace and category
  - Detects containers without memory limits that may be causing issues
  - Time-based filtering to focus on recent restart activity
  - Multiple output formats for scripting and monitoring integration

Examples:
```bash
# Analyze all container restarts
k8s_container_restart_analyzer.py

# Analyze restarts in specific namespace
k8s_container_restart_analyzer.py -n kube-system

# Show verbose output with remediation suggestions
k8s_container_restart_analyzer.py --verbose

# Only show flapping containers (5+ restarts)
k8s_container_restart_analyzer.py --warn-only

# Analyze restarts in last 24 hours
k8s_container_restart_analyzer.py --timeframe 1440

# Output as JSON for monitoring integration
k8s_container_restart_analyzer.py --output json

# Combine filters: production namespace, verbose, only flapping
k8s_container_restart_analyzer.py -n production --verbose --warn-only

# Recent restarts in JSON for alerting
k8s_container_restart_analyzer.py --timeframe 60 --output json
```

Use Cases:
  - **Incident Response**: Quickly identify root causes of container restarts during incidents
  - **Proactive Monitoring**: Detect chronic restart issues before they impact availability
  - **Resource Right-Sizing**: Identify OOMKills and adjust memory limits accordingly
  - **Application Debugging**: Categorize restart reasons to prioritize troubleshooting efforts
  - **Pattern Detection**: Find flapping containers that may indicate configuration issues
  - **Capacity Planning**: Identify resource pressure patterns causing evictions
  - **MTTR Reduction**: Get immediate remediation suggestions to reduce mean time to resolution
  - **Health Probe Tuning**: Detect probe failures and tune liveness/readiness probe configurations
  - **Baremetal Operations**: Critical for large-scale environments where restart patterns indicate hardware or network issues
  - **Production Stability**: Regular analysis prevents cascading failures from unstable containers

### k8s_job_failure_analyzer.py
```
python3 k8s_job_failure_analyzer.py [--namespace NAMESPACE] [--timeframe HOURS] [options]
  --namespace, -n: Analyze failures in specific namespace (default: all namespaces)
  --timeframe HOURS: Only analyze failures within last N hours
  --verbose, -v: Show detailed analysis with remediation suggestions
  --warn-only: Only show warnings (skip summary sections)
  --include-cronjobs: Include CronJob health analysis
  --format: Output format - 'plain' or 'json' (default: plain)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No job failures or CronJob issues detected
  - 1: Job failures or CronJob issues detected
  - 2: Usage error or kubectl not available

Features:
  - Categorizes job failures by root cause (OOMKilled, DeadlineExceeded, BackoffLimitExceeded, ImagePullFailure, ConfigError, ApplicationError)
  - Analyzes pod statuses to determine actual failure reasons
  - Tracks failures by namespace for targeted troubleshooting
  - Optionally analyzes CronJob health (suspended, stale schedules, high failure rates)
  - Provides specific remediation suggestions for each failure type
  - Identifies owner CronJobs for failed jobs
  - Multiple output formats for monitoring integration

Examples:
```bash
# Analyze all job failures
k8s_job_failure_analyzer.py

# Analyze failures in specific namespace
k8s_job_failure_analyzer.py -n batch-jobs

# Show verbose output with remediation suggestions
k8s_job_failure_analyzer.py --verbose

# Only show summary sections (skip detailed job list)
k8s_job_failure_analyzer.py --warn-only

# Analyze failures in last 24 hours
k8s_job_failure_analyzer.py --timeframe 24

# Include CronJob health analysis
k8s_job_failure_analyzer.py --include-cronjobs

# Output as JSON for monitoring integration
k8s_job_failure_analyzer.py --format json

# Combine filters: specific namespace, verbose, with CronJob analysis
k8s_job_failure_analyzer.py -n production --verbose --include-cronjobs

# Recent failures in JSON for alerting
k8s_job_failure_analyzer.py --timeframe 6 --format json
```

Use Cases:
  - **Batch Workload Troubleshooting**: Identify why Jobs and CronJobs are failing
  - **Resource Planning**: Detect OOMKilled jobs that need increased memory limits
  - **Deadline Tuning**: Find jobs exceeding activeDeadlineSeconds
  - **Image Management**: Identify image pull failures affecting batch workloads
  - **CronJob Health**: Monitor suspended CronJobs and high failure rates
  - **Incident Response**: Quickly triage batch processing failures
  - **Configuration Validation**: Detect ConfigMap/Secret reference errors
  - **SLA Monitoring**: Track job success rates for batch processing SLAs
  - **Capacity Planning**: Identify resource constraints affecting batch jobs
  - **ETL Pipeline Health**: Monitor data processing job health in large-scale environments

### k8s_workload_restart_age_analyzer.py
```
python3 k8s_workload_restart_age_analyzer.py [--namespace NAMESPACE] [--format FORMAT] [options]
  --namespace, -n: Analyze pods in specific namespace (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --stale-days DAYS: Days after which a workload is considered stale (default: 30)
  --fresh-hours HOURS: Hours within which a workload is considered fresh (default: 1)
  --warn-only, -w: Only show stale workloads
  --verbose, -v: Show detailed information for all workloads
  --exclude-namespace NAMESPACE: Namespaces to exclude (can be repeated)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All workloads within acceptable age bounds
  - 1: Stale workloads found (older than threshold)
  - 2: Usage error or kubectl not available

Features:
  - Analyzes pod age to identify stale deployments that haven't been updated
  - Categorizes workloads as stale, normal, or fresh based on configurable thresholds
  - Tracks restart counts alongside age analysis
  - Identifies owner types (Deployment, StatefulSet, DaemonSet, etc.)
  - Multiple output formats for scripting and monitoring integration
  - Exclude specific namespaces from analysis

Examples:
```bash
# Analyze all pods across all namespaces
k8s_workload_restart_age_analyzer.py

# Analyze pods in specific namespace
k8s_workload_restart_age_analyzer.py -n production

# Only show stale workloads (older than 30 days)
k8s_workload_restart_age_analyzer.py --warn-only

# Custom stale threshold (14 days)
k8s_workload_restart_age_analyzer.py --stale-days 14

# Exclude system namespaces
k8s_workload_restart_age_analyzer.py --exclude-namespace kube-system --exclude-namespace kube-public

# JSON output for monitoring integration
k8s_workload_restart_age_analyzer.py --format json

# Table format with verbose output
k8s_workload_restart_age_analyzer.py --format table -v
```

Use Cases:
  - **Security Compliance**: Audit deployment freshness to ensure workloads are regularly updated
  - **Stale Deployment Detection**: Identify pods that haven't been redeployed in months
  - **Orphaned Workload Detection**: Find pods that survived multiple deployments
  - **Capacity Planning**: Understand workload age distribution across the cluster
  - **Change Management**: Track deployment cadence across namespaces
  - **Incident Response**: Identify long-running pods that may need attention
  - **Baremetal Operations**: Critical for large-scale clusters where stale workloads can accumulate

### k8s_workload_generation_analyzer.py
```
python3 k8s_workload_generation_analyzer.py [--namespace NAMESPACE] [--format FORMAT] [options]
  --namespace, -n: Analyze pods in specific namespace (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --verbose, -v: Show detailed information for all workloads
  --warn-only, -w: Only show workloads with issues (orphaned or standalone)
  --show-chain: Include full ownership chain in output
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: Analysis complete, no issues found
  - 1: Issues found (orphaned workloads or standalone pods without controllers)
  - 2: Usage error or kubectl not available

Features:
  - Traces pod ownership chains (Pod -> ReplicaSet -> Deployment -> etc.)
  - Identifies generator type (Helm, ArgoCD, Flux, direct creation)
  - Detects orphaned workloads with missing owner references
  - Detects standalone pods created without controllers
  - Groups workloads by generator type and root controller kind
  - Reports operator-managed resources with specific operator labels

Examples:
```bash
# Analyze all workloads in cluster
k8s_workload_generation_analyzer.py

# Analyze specific namespace
k8s_workload_generation_analyzer.py -n production

# Only show workloads with issues
k8s_workload_generation_analyzer.py --warn-only

# JSON output for automation
k8s_workload_generation_analyzer.py --format json

# Verbose with full ownership chains
k8s_workload_generation_analyzer.py -v --show-chain

# Table format
k8s_workload_generation_analyzer.py --format table
```

Use Cases:
  - **Compliance Auditing**: Track workload origins for security and governance
  - **Troubleshooting**: Understand what created unexpected pods in the cluster
  - **Operator Debugging**: Identify which operator manages specific workloads
  - **Orphan Detection**: Find pods with missing or deleted owner controllers
  - **Helm/ArgoCD Tracking**: Identify Helm chart and GitOps-deployed resources
  - **Baremetal Operations**: Critical for large multi-tenant clusters with complex ownership

### k8s_pod_startup_latency_analyzer.py
```
python3 k8s_pod_startup_latency_analyzer.py [--namespace NAMESPACE] [--format FORMAT] [options]
  --namespace, -n: Analyze pods in specific namespace (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --verbose, -v: Show detailed timing breakdown for each phase
  --warn-only, -w: Only show slow pods or pods with issues
  --slow-threshold SECONDS: Seconds above which a pod is considered slow (default: 60)
  --include-completed: Include completed (Succeeded/Failed) pods in analysis
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: Analysis complete, no slow pods detected (below threshold)
  - 1: Slow pods detected (above threshold)
  - 2: Usage error or kubectl not available

Features:
  - Measures total startup time from pod creation to ready state
  - Breaks down latency into phases: scheduling, init containers, container startup
  - Identifies slow-starting pods above configurable threshold
  - Detects image pull issues (ImagePullBackOff, ErrImagePull)
  - Tracks container restarts during startup
  - Identifies pods stuck in Pending state
  - Calculates latency statistics (min, max, avg, p50, p90) in JSON output
  - Multiple output formats for monitoring integration

Examples:
```bash
# Analyze all pods across all namespaces
k8s_pod_startup_latency_analyzer.py

# Analyze pods in specific namespace
k8s_pod_startup_latency_analyzer.py -n kube-system

# Show only slow pods (above 60s threshold)
k8s_pod_startup_latency_analyzer.py --warn-only

# Custom slow threshold (2 minutes)
k8s_pod_startup_latency_analyzer.py --slow-threshold 120

# Verbose output with timing breakdown
k8s_pod_startup_latency_analyzer.py -v

# JSON output for automation and monitoring
k8s_pod_startup_latency_analyzer.py --format json

# Table format for quick overview
k8s_pod_startup_latency_analyzer.py --format table

# Combine options: namespace, verbose, show only slow pods
k8s_pod_startup_latency_analyzer.py -n production -v --warn-only

# Strict threshold for CI/CD pipelines
k8s_pod_startup_latency_analyzer.py --slow-threshold 30 --format json
```

Use Cases:
  - **Performance Optimization**: Identify slow-starting pods that impact deployment velocity
  - **Image Pull Analysis**: Detect pods waiting on slow image pulls or registry issues
  - **Init Container Debugging**: Find init containers that take too long to complete
  - **Scheduling Bottlenecks**: Identify pods waiting for node scheduling
  - **Capacity Planning**: Detect resource constraints causing scheduling delays
  - **CI/CD Integration**: Verify deployment startup times meet SLA requirements
  - **Incident Response**: Quickly identify pods stuck in startup phases during incidents
  - **Baremetal Operations**: Critical for large-scale clusters where startup latency indicates node or storage issues

### k8s_network_policy_audit.py
```
python3 k8s_network_policy_audit.py [--namespace NAMESPACE] [--format FORMAT] [--warn-only]
  --namespace, -n: Audit specific namespace (default: all namespaces)
  --format, -f: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show issues and warnings
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: Network policies properly configured
  - 1: Security issues or missing policies detected
  - 2: Usage error or kubectl not available

Features:
  - Identifies namespaces without network policies (default allow-all behavior)
  - Detects pods not covered by any network policy
  - Flags overly permissive policies (allowing all ingress/egress)
  - Finds deny-all policies that may block legitimate traffic
  - Validates network policy configuration and syntax
  - Analyzes pod label matching against policy selectors
  - Multiple output formats for monitoring integration

Examples:
```bash
# Audit all namespaces
k8s_network_policy_audit.py

# Audit specific namespace
k8s_network_policy_audit.py -n production

# Show only issues
k8s_network_policy_audit.py --warn-only

# JSON output for monitoring systems
k8s_network_policy_audit.py --format json

# Table format for overview
k8s_network_policy_audit.py --format table

# Combine options: production namespace, only issues, JSON format
k8s_network_policy_audit.py -n production -w -f json
```

Use Cases:
  - **Security Auditing**: Identify namespaces and pods without network policy protection
  - **Zero Trust Networking**: Validate that all workloads have appropriate network restrictions
  - **Compliance**: Ensure network policies meet security requirements and best practices
  - **Troubleshooting**: Identify overly restrictive policies blocking legitimate traffic
  - **Migration Planning**: Audit existing policies before implementing zero-trust architecture
  - **Multi-tenant Security**: Verify namespace isolation in shared clusters
  - **Policy Validation**: Detect misconfigured policies that don't match any pods
  - **Baremetal Deployments**: Critical for on-premises clusters where network segmentation is required
  - **Incident Prevention**: Catch security gaps before they're exploited

### k8s_node_taint_analyzer.py
```
python3 k8s_node_taint_analyzer.py [--format FORMAT] [--verbose] [--warn-only]
  --format, -f: Output format - 'plain', 'json', or 'table' (default: plain)
  --verbose, -v: Show detailed information about all taints
  --warn-only, -w: Only show nodes with blocking taints or orphaned taints
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No taint-related issues detected
  - 1: Issues found (nodes with blocking taints, imbalanced scheduling)
  - 2: Usage error or kubectl not available

Features:
  - Identifies nodes with NoSchedule and NoExecute taints that block pod scheduling
  - Detects nodes with PreferNoSchedule taints (soft constraints)
  - Analyzes pod tolerations to determine which pods can run on tainted nodes
  - Tracks workload distribution between tainted and untainted nodes
  - Identifies orphaned taints (taints with no matching tolerations)
  - Useful for managing baremetal clusters with specialized hardware or maintenance windows
  - Multiple output formats for monitoring integration

Examples:
```bash
# Show all tainted nodes
k8s_node_taint_analyzer.py

# Show only nodes with blocking taints
k8s_node_taint_analyzer.py --warn-only

# Show detailed information about all taints
k8s_node_taint_analyzer.py --verbose

# Output in JSON format for monitoring systems
k8s_node_taint_analyzer.py --format json

# Table format with warnings only
k8s_node_taint_analyzer.py --format table --warn-only

# Combined options
k8s_node_taint_analyzer.py -v -w -f json
```

Use cases:
  - Baremetal cluster maintenance: Track nodes tainted for hardware maintenance
  - Specialized workloads: Monitor GPU or high-memory node taints
  - Capacity planning: Understand how many nodes are unavailable due to taints
  - Troubleshooting: Identify why pods aren't scheduling (blocking taints)
  - Cleanup: Find orphaned taints that are no longer needed

### k8s_node_label_auditor.py
```
python3 k8s_node_label_auditor.py [--format FORMAT] [--verbose] [--warn-only] [--require-label LABEL] [--skip-deprecated] [--skip-consistency]
  --format, -f: Output format - 'plain', 'json', or 'table' (default: plain)
  --verbose, -v: Show detailed information including info messages
  --warn-only, -w: Only show nodes with issues or warnings
  --require-label, -l: Label that must be present on all nodes (can be specified multiple times)
  --skip-deprecated: Skip checking for deprecated labels
  --skip-consistency: Skip label consistency checks across similar nodes
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All nodes pass audit checks
  - 1: Audit issues detected (missing labels, inconsistencies, format violations)
  - 2: Usage error or kubectl not available

Features:
  - Checks for required custom labels (via --require-label)
  - Validates standard Kubernetes labels (hostname, os, arch)
  - Warns about missing topology labels (zone, region)
  - Detects deprecated labels (beta.kubernetes.io/*, failure-domain.*)
  - Validates label key/value format per Kubernetes naming conventions
  - Monitors annotation sizes (warns at 100KB, errors at 256KB limit)
  - Checks label consistency across nodes with the same role
  - Identifies nodes without role labels

Examples:
```bash
# Basic audit of all nodes
k8s_node_label_auditor.py

# Require specific labels for compliance
k8s_node_label_auditor.py --require-label env --require-label team

# Show only nodes with issues
k8s_node_label_auditor.py --warn-only

# JSON output for automation
k8s_node_label_auditor.py --format json

# Table format with verbose info
k8s_node_label_auditor.py --format table -v

# Skip deprecated label warnings
k8s_node_label_auditor.py --skip-deprecated

# Full audit with multiple required labels
k8s_node_label_auditor.py -l env -l team -l region --format table
```

Use cases:
  - **Compliance Auditing**: Ensure all nodes have required labels for cost allocation, environment tracking
  - **Migration Planning**: Identify deprecated labels that need updating before cluster upgrades
  - **Scheduling Verification**: Confirm topology labels are set for proper pod distribution
  - **Fleet Consistency**: Detect label drift across similar nodes (e.g., workers with different labels)
  - **Capacity Planning**: Verify node roles are properly labeled for resource planning
  - **Security Auditing**: Ensure nodes in production have required security labels

### k8s_node_kernel_config_audit.py
```
python3 k8s_node_kernel_config_audit.py [--format FORMAT] [--verbose] [--warn-only] [--consistency-only] [--node-selector SELECTOR]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --verbose, -v: Show detailed kernel configuration for each node
  --warn-only, -w: Only show warnings and critical issues
  --consistency-only: Only check for consistency across nodes, skip compliance checks
  --node-selector: Label selector to filter nodes (e.g., 'node-role.kubernetes.io/worker=')
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All nodes have consistent and compliant kernel configuration
  - 1: Inconsistencies or non-compliant settings detected
  - 2: Usage error or kubectl not available

Features:
  - Checks kernel parameter consistency across all cluster nodes
  - Validates recommended settings for Kubernetes networking (bridge-nf-call-iptables, ip_forward)
  - Audits security-related parameters (ASLR, dmesg_restrict, kptr_restrict)
  - Monitors memory/VM settings affecting container workloads
  - Checks conntrack settings critical for high-traffic clusters
  - Supports node filtering via label selector

Examples:
```bash
# Audit all nodes
k8s_node_kernel_config_audit.py

# Show detailed configuration for each node
k8s_node_kernel_config_audit.py -v

# Only show warnings and critical issues
k8s_node_kernel_config_audit.py --warn-only

# JSON output for monitoring integration
k8s_node_kernel_config_audit.py --format json

# Only check consistency, skip compliance
k8s_node_kernel_config_audit.py --consistency-only

# Audit only worker nodes
k8s_node_kernel_config_audit.py --node-selector 'node-role.kubernetes.io/worker='

# Combined options
k8s_node_kernel_config_audit.py -w -v --format table
```

Use cases:
  - **Cluster Consistency**: Ensure all nodes have identical kernel tuning for predictable behavior
  - **Security Compliance**: Verify security-related kernel parameters across the fleet
  - **Performance Tuning**: Audit network and memory parameters for high-performance workloads
  - **Troubleshooting**: Identify nodes with misconfigured kernel parameters causing issues
  - **Baremetal Operations**: Critical for baremetal Kubernetes where kernel config varies between hardware

### k8s_resource_quota_auditor.py
```
python3 k8s_resource_quota_auditor.py [--namespace NAMESPACE] [--format FORMAT] [--warn-only] [--verbose] [--warn-threshold PERCENT]
  --namespace, -n: Audit specific namespace (default: all namespaces except kube-system)
  --format, -f: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show namespaces with issues
  --verbose, -v: Show detailed quota utilization information
  --warn-threshold: Quota utilization warning threshold in percent (default: 80)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All namespaces have proper quotas and no issues detected
  - 1: Issues found (missing quotas, high utilization, missing limit ranges)
  - 2: Usage error or kubectl not available

Features:
  - Identifies namespaces without ResourceQuota (unlimited resource risk)
  - Detects namespaces without LimitRange (pods may lack default limits)
  - Monitors quota utilization and warns when approaching limits
  - Checks for meaningful default resource limits in LimitRanges
  - Parses Kubernetes quantity formats (CPU millicores, memory Ki/Mi/Gi/Ti)
  - Multiple output formats for monitoring integration
  - Automatically skips system namespaces (kube-system, kube-public, kube-node-lease)

Examples:
```bash
# Audit all namespaces
k8s_resource_quota_auditor.py

# Audit specific namespace
k8s_resource_quota_auditor.py -n production

# Show only namespaces with issues
k8s_resource_quota_auditor.py --warn-only

# Verbose output with quota utilization details
k8s_resource_quota_auditor.py --verbose

# JSON output for monitoring systems
k8s_resource_quota_auditor.py --format json

# Table format for quick overview
k8s_resource_quota_auditor.py --format table

# Custom warning threshold (warn at 90% instead of 80%)
k8s_resource_quota_auditor.py --warn-threshold 90

# Combine options: production namespace, only issues, verbose JSON
k8s_resource_quota_auditor.py -n production -w -v -f json
```

Use Cases:
  - **Multi-tenant Clusters**: Ensure fair resource distribution across teams/projects
  - **Resource Governance**: Prevent resource exhaustion from runaway pods
  - **Capacity Planning**: Identify namespaces approaching quota limits before issues occur
  - **Compliance**: Validate that all namespaces have appropriate resource constraints
  - **Cost Control**: Ensure teams stay within allocated resource budgets
  - **Security**: Prevent resource-based DoS attacks from compromised workloads
  - **Best Practices**: Enforce default resource limits for all pods
  - **Baremetal Clusters**: Critical for shared infrastructure without cloud auto-scaling
  - **Development Environments**: Ensure dev/test namespaces don't consume prod resources
  - **Incident Prevention**: Detect quota issues before they cause application failures

### k8s_namespace_resource_analyzer.py
```
python3 k8s_namespace_resource_analyzer.py [--format FORMAT] [--warn-only] [--top N] [--verbose]
  --format, -f: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show namespaces with issues
  --top, -t: Show only top N namespaces by CPU requests
  --verbose, -v: Show additional details including limits
```

Analyzes resource utilization across all namespaces in a Kubernetes cluster, providing:
- Aggregate CPU and memory requests/limits per namespace
- Percentage of cluster resources consumed by each namespace
- Pod and container counts by namespace
- Resource quota utilization percentages
- Identification of namespaces without resource quotas
- Detection of pods missing requests or limits

Examples:
```bash
# Analyze all namespaces
k8s_namespace_resource_analyzer.py

# Tabular output for quick overview
k8s_namespace_resource_analyzer.py --format table

# Show top 10 resource consumers
k8s_namespace_resource_analyzer.py --top 10

# Only show namespaces with governance issues
k8s_namespace_resource_analyzer.py --warn-only

# JSON output for automation/chargeback systems
k8s_namespace_resource_analyzer.py --format json

# Verbose output with limits info
k8s_namespace_resource_analyzer.py -v

# Top 5 consumers with issues, verbose
k8s_namespace_resource_analyzer.py -t 5 -w -v
```

Use Cases:
  - **Chargeback/Showback**: Generate reports of resource consumption by team/namespace for cost allocation
  - **Capacity Planning**: Identify resource distribution and plan for cluster growth
  - **Governance Auditing**: Find namespaces without resource quotas that could consume unlimited resources
  - **Multi-Tenant Clusters**: Monitor resource fairness across teams in shared clusters
  - **Resource Optimization**: Identify namespaces with pods missing requests/limits

### k8s_resource_right_sizer.py
```
python3 k8s_resource_right_sizer.py [--namespace NAMESPACE] [--format FORMAT] [--warn-only] [--verbose] [--cpu-threshold PCT] [--mem-threshold PCT] [--exclude-namespace NS]
  --namespace, -n: Analyze specific namespace (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show over/under-provisioned workloads
  --verbose, -v: Show detailed recommendations with suggested values
  --cpu-threshold: CPU efficiency % below which pod is over-provisioned (default: 30)
  --mem-threshold: Memory efficiency % below which pod is over-provisioned (default: 30)
  --exclude-namespace: Namespaces to exclude (can be specified multiple times)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster
  - metrics-server running in cluster for usage data

Exit codes:
  - 0: All workloads appropriately sized
  - 1: Right-sizing opportunities found
  - 2: Usage error or kubectl/metrics unavailable

Features:
  - Compares resource requests/limits against actual usage from metrics-server
  - Identifies over-provisioned pods wasting cluster resources
  - Detects under-provisioned pods at risk of OOM or throttling
  - Calculates potential resource savings from right-sizing
  - Groups analysis by namespace and owner (Deployment, StatefulSet, etc.)
  - Suggests concrete resource request values based on actual usage
  - Multiple output formats for monitoring integration
  - Configurable thresholds for different environments

Examples:
```bash
# Analyze all pods in cluster
k8s_resource_right_sizer.py

# Analyze specific namespace
k8s_resource_right_sizer.py -n production

# Show only over/under-provisioned workloads
k8s_resource_right_sizer.py --warn-only

# Verbose output with suggested new values
k8s_resource_right_sizer.py -v

# Custom thresholds (flag pods using <20% of requests)
k8s_resource_right_sizer.py --cpu-threshold 20 --mem-threshold 25

# JSON output for automation/cost analysis
k8s_resource_right_sizer.py --format json

# Table format for quick overview
k8s_resource_right_sizer.py --format table

# Exclude system namespaces
k8s_resource_right_sizer.py --exclude-namespace kube-system --exclude-namespace kube-public

# Combine options: production namespace, verbose, only issues
k8s_resource_right_sizer.py -n production -v -w
```

Use Cases:
  - **Cost Optimization**: Identify pods requesting far more resources than they use
  - **Capacity Planning**: Reclaim wasted resources for new workloads
  - **OOM Prevention**: Find pods at risk of OOMKilled due to tight limits
  - **Performance Tuning**: Detect CPU throttling from insufficient limits
  - **Resource Governance**: Audit pods missing resource requests/limits
  - **Baremetal Clusters**: Critical for maximizing utilization of fixed capacity
  - **Multi-Tenant Clusters**: Ensure fair resource allocation between teams
  - **FinOps**: Generate data for cost attribution and optimization reports

### k8s_image_pull_analyzer.py
```
python3 k8s_image_pull_analyzer.py [--namespace NAMESPACE] [--format FORMAT] [--verbose] [--warn-only] [--max-age MINUTES]
  --namespace, -n: Analyze specific namespace (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --verbose, -v: Show detailed information about each issue
  --warn-only, -w: Only show warnings and errors
  --max-age: Maximum age of events to analyze in minutes (default: 60)
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: No image pull issues detected
  - 1: Image pull issues found (ImagePullBackOff, slow pulls, auth failures)
  - 2: Usage error or kubectl not available

Features:
  - Detects ImagePullBackOff and ErrImagePull errors
  - Identifies registry authentication failures
  - Tracks image pull events and patterns
  - Aggregates issues by type, image, and namespace
  - Analyzes recent events for pull-related problems
  - Multiple output formats for monitoring integration
  - Filters by namespace for focused troubleshooting
  - Configurable event age window

Examples:
```bash
# Check all namespaces for image pull issues
k8s_image_pull_analyzer.py

# Check specific namespace with detailed output
k8s_image_pull_analyzer.py -n production -v

# Only show errors and warnings
k8s_image_pull_analyzer.py --warn-only

# Output in JSON format for automation
k8s_image_pull_analyzer.py --format json

# Analyze recent events (last 30 minutes)
k8s_image_pull_analyzer.py --max-age 30

# Table format for quick overview
k8s_image_pull_analyzer.py --format table

# Combine options: production namespace, verbose, table format
k8s_image_pull_analyzer.py -n production -v --format table
```

Use Cases:
  - **Troubleshooting Pod Failures**: Quickly diagnose why pods are stuck in ImagePullBackOff
  - **Registry Issues**: Identify connectivity problems to image registries
  - **Authentication Problems**: Detect ImagePullSecrets or registry credential issues
  - **Performance Analysis**: Find nodes or registries with slow image pull times
  - **Baremetal Clusters**: Critical for detecting registry cache misses in air-gapped environments
  - **Multi-Registry Environments**: Track which registries are experiencing issues
  - **CI/CD Pipeline Issues**: Identify image tagging or push problems affecting deployments
  - **Network Troubleshooting**: Detect network policies blocking registry access
  - **Capacity Planning**: Understand image pull patterns and registry load
  - **Incident Response**: First-line diagnostic tool for pod startup failures

### k8s_job_health_monitor.py
```
python3 k8s_job_health_monitor.py [--namespace NAMESPACE] [--format FORMAT] [--warn-only] [--skip-jobs] [--skip-cronjobs]
  --namespace, -n: Check specific namespace (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  --warn-only, -w: Only show jobs and cronjobs with issues
  --skip-jobs: Skip job analysis, only check cronjobs
  --skip-cronjobs: Skip cronjob analysis, only check jobs
```

Requirements:
  - kubectl command-line tool installed and configured
  - Access to a Kubernetes cluster

Exit codes:
  - 0: All jobs and cronjobs healthy
  - 1: Failed or stuck jobs detected
  - 2: Usage error or kubectl not available

Features:
  - Monitors Job completion status (successful, failed, active)
  - Tracks CronJob scheduling health and patterns
  - Detects long-running or stuck jobs (>24 hours)
  - Identifies jobs pending for too long (>1 hour)
  - Reports on jobs without TTL cleanup configuration
  - Finds CronJobs with consecutive failures
  - Detects suspended CronJobs
  - Identifies CronJobs with multiple concurrent jobs
  - Multiple output formats for monitoring integration
  - Filters by namespace for focused analysis

Examples:
```bash
# Check all jobs and cronjobs across all namespaces
k8s_job_health_monitor.py

# Check jobs in specific namespace
k8s_job_health_monitor.py -n production

# Show only problematic jobs
k8s_job_health_monitor.py --warn-only

# Output as JSON for monitoring systems
k8s_job_health_monitor.py --format json

# Show table format with issues only
k8s_job_health_monitor.py --format table --warn-only

# Check only jobs, skip cronjobs
k8s_job_health_monitor.py --skip-cronjobs

# Check only cronjobs, skip jobs
k8s_job_health_monitor.py --skip-jobs

# Combine options: production namespace, table format, issues only
k8s_job_health_monitor.py -n production --format table --warn-only
```

Use Cases:
  - **Batch Workload Monitoring**: Track health of batch jobs and scheduled tasks
  - **Failed Job Detection**: Quickly identify and troubleshoot failing jobs
  - **Resource Cleanup**: Find jobs without TTL configuration accumulating in cluster
  - **CronJob Reliability**: Monitor scheduled job execution patterns and failures
  - **Baremetal Clusters**: Critical for managing batch workloads on capacity-constrained infrastructure
  - **Stuck Job Detection**: Identify jobs running longer than expected
  - **Cluster Hygiene**: Detect abandoned or orphaned jobs consuming resources
  - **Scheduling Issues**: Find CronJobs that haven't run recently or are suspended
  - **Concurrent Job Analysis**: Detect CronJobs spawning too many simultaneous jobs
  - **Capacity Planning**: Understand batch workload resource consumption patterns

### k8s_endpointslice_health_monitor.py
```
k8s_endpointslice_health_monitor.py [-n namespace] [--format {plain,json}] [-w] [--include-headless] [--frag-threshold N] [--skip-coverage-check]
  -n, --namespace: Namespace to check (default: all namespaces)
  --format: Output format - 'plain' or 'json' (default: plain)
  -w, --warn-only: Only show EndpointSlices with issues
  --include-headless: Include headless services in coverage check
  --frag-threshold: EndpointSlice count threshold for fragmentation warning (default: 10)
  --skip-coverage-check: Skip checking for services missing EndpointSlices
```

Monitor EndpointSlice health for service discovery issues. EndpointSlices are the modern replacement for Endpoints resources, providing better scalability for large clusters. This script identifies:
- EndpointSlices with no ready endpoints (service down)
- High not-ready endpoint ratio (>50% not ready)
- Services missing EndpointSlices entirely
- EndpointSlice fragmentation (too many slices per service)
- Stale terminating endpoints

Examples:
```bash
# Check all EndpointSlices in all namespaces
k8s_endpointslice_health_monitor.py

# Check EndpointSlices in specific namespace
k8s_endpointslice_health_monitor.py -n production

# Only show unhealthy EndpointSlices
k8s_endpointslice_health_monitor.py --warn-only

# JSON output for automation
k8s_endpointslice_health_monitor.py --format json

# Include headless services in missing service check
k8s_endpointslice_health_monitor.py --include-headless

# Flag services with more than 5 EndpointSlices
k8s_endpointslice_health_monitor.py --frag-threshold 5

# Skip service coverage check (faster)
k8s_endpointslice_health_monitor.py --skip-coverage-check
```

Use Cases:
  - **Service Discovery Debugging**: Identify why services aren't receiving traffic
  - **Pre-deployment Validation**: Verify EndpointSlice health before rolling out changes
  - **Large Cluster Operations**: Detect fragmentation issues affecting kube-proxy performance
  - **Service Mesh Debugging**: Troubleshoot service mesh data plane issues

### k8s_service_health_monitor.py
```
k8s_service_health_monitor.py [-n namespace] [--format {plain,json,table}] [-v] [-w]
  -n, --namespace: Namespace to check (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show healthy services in addition to issues
  -w, --warn-only: Only show warnings (exclude errors)
```

Monitor Kubernetes Service health by correlating Services with their Endpoints to identify:
- Services with zero endpoints (no backing pods)
- Services with all endpoints not ready
- Services with partially ready endpoints
- Service type and configuration issues

Examples:
```bash
# Check all services in all namespaces
k8s_service_health_monitor.py

# Check services in specific namespace
k8s_service_health_monitor.py -n production

# Show detailed output including healthy services
k8s_service_health_monitor.py -v

# JSON output for automation
k8s_service_health_monitor.py --format json

# Table format for better readability
k8s_service_health_monitor.py --format table

# Only show warnings (services with some ready endpoints)
k8s_service_health_monitor.py --warn-only

# Combine options: production namespace, table format, verbose
k8s_service_health_monitor.py -n production --format table -v
```

Use Cases:

### k8s_rbac_auditor.py
```
k8s_rbac_auditor.py [-n namespace] [--format {plain,json,table}] [-v] [-w]
  -n, --namespace: Namespace to audit (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information for each issue
  -w, --warn-only: Only show warnings and issues
```

Audit Kubernetes RBAC roles and bindings for security issues. Identifies:
- Cluster-admin access bindings (highest severity)
- Wildcard permissions (*, all resources/verbs/apiGroups)
- Dangerous verbs (create, delete, exec, proxy, impersonate, bind, escalate)
- Access to sensitive resources (secrets, configmaps)
- Anonymous user access (system:anonymous, system:unauthenticated)
- Service account bindings to admin roles
- Overly permissive role configurations

Examples:
```bash
# Audit all RBAC roles and bindings in the cluster
k8s_rbac_auditor.py

# Audit specific namespace
k8s_rbac_auditor.py -n production

# Detailed output with full issue descriptions
k8s_rbac_auditor.py -v

# JSON output for automation/alerting
k8s_rbac_auditor.py --format json

# Table format for better readability
k8s_rbac_auditor.py --format table

# Only show issues (hide success message)
k8s_rbac_auditor.py --warn-only

# Combine options: specific namespace, table format, verbose
k8s_rbac_auditor.py -n kube-system --format table -v
```

Security Use Cases:
  - **Service Connectivity Troubleshooting**: Quickly identify why services aren't routing traffic
  - **Deployment Validation**: Verify services have healthy backends after deployments
  - **Pod Selector Issues**: Detect mismatched selectors causing services to have zero endpoints
  - **Rolling Update Monitoring**: Track endpoint readiness during deployments
  - **Network Issue Diagnosis**: Identify services affected by pod networking problems
  - **Cluster Health Checks**: Ensure all critical services have available endpoints
  - **Automated Monitoring**: JSON output for integration with monitoring systems
  - **Large-Scale Clusters**: Filter by namespace for focused troubleshooting

### k8s_serviceaccount_auditor.py
```
k8s_serviceaccount_auditor.py [-n namespace] [--format {plain,json,table}] [-v] [-w] [--skip-unused]
  -n, --namespace: Namespace to audit (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information for each issue
  -w, --warn-only: Only show warnings and issues
  --skip-unused: Skip checking for unused ServiceAccounts
```

Audit Kubernetes ServiceAccounts for security issues. Identifies:
- automountServiceAccountToken enabled when not needed (MEDIUM) - unnecessary token exposure
- Default ServiceAccount usage by application pods (LOW) - security anti-pattern
- ServiceAccounts bound to cluster-admin role (HIGH) - excessive privileges
- ServiceAccounts bound to admin roles (MEDIUM) - elevated privileges
- Unused ServiceAccounts (LOW) - potential stale accounts
- Non-standard kube-system ServiceAccounts with ClusterRoleBindings (MEDIUM)

```bash
# Audit all ServiceAccounts in the cluster
k8s_serviceaccount_auditor.py

# Audit specific namespace
k8s_serviceaccount_auditor.py -n production

# Detailed output with full issue descriptions
k8s_serviceaccount_auditor.py -v

# JSON output for automation/alerting
k8s_serviceaccount_auditor.py --format json

# Table format for better readability
k8s_serviceaccount_auditor.py --format table

# Skip unused ServiceAccount detection (faster)
k8s_serviceaccount_auditor.py --skip-unused

# Combine options: specific namespace, table format, verbose
k8s_serviceaccount_auditor.py -n kube-system --format table -v
```

Use Cases:
  - **Security Hardening**: Identify ServiceAccounts with unnecessary token automounting
  - **Privilege Auditing**: Find ServiceAccounts with cluster-admin or admin bindings
  - **Compliance Checks**: Ensure pods use dedicated ServiceAccounts, not default
  - **Cleanup**: Identify unused ServiceAccounts for removal
  - **Pre-deployment Review**: Validate ServiceAccount configurations before production
  - **Incident Response**: Quickly identify overly privileged accounts during security events

### k8s_pod_security_audit.py
```
k8s_pod_security_audit.py [-n namespace] [--format {plain,json,table}] [-v] [-w]
  -n, --namespace: Namespace to audit (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information for each issue
  -w, --warn-only: Only show warnings (exclude LOW severity)
```

Audit pod security contexts and Linux capabilities to identify security risks. Identifies:
- Privileged containers (CRITICAL) - full host access, container escape risk
- Host namespace sharing: hostPID, hostIPC, hostNetwork (CRITICAL/HIGH)
- Running as root user UID 0 (HIGH)
- Dangerous Linux capabilities: CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE, etc. (CRITICAL/HIGH/MEDIUM)
- Privilege escalation enabled (HIGH/LOW)
- Sensitive hostPath volume mounts (HIGH/MEDIUM)
- Missing readOnlyRootFilesystem (LOW)
- No AppArmor or Seccomp security profiles (LOW)

Exit codes:
  - 0: No critical or high security issues detected
  - 1: Security issues found
  - 2: Usage error or kubectl not available

Examples:
```bash
# Audit all pods in all namespaces
k8s_pod_security_audit.py

# Audit specific namespace
k8s_pod_security_audit.py -n production

# Show only warnings (exclude LOW severity)
k8s_pod_security_audit.py --warn-only

# JSON output for monitoring/alerting
k8s_pod_security_audit.py --format json

# Verbose output with full details
k8s_pod_security_audit.py -v

# Table format for quick overview
k8s_pod_security_audit.py --format table

# Combine: production namespace, only warnings, JSON format
k8s_pod_security_audit.py -n production -w --format json
```

Security Use Cases:
  - **Compliance Auditing**: Validate pod security against CIS Kubernetes Benchmark, PCI-DSS, HIPAA
  - **Container Escape Prevention**: Identify containers that could break out to the host
  - **Zero Trust Security**: Verify pods follow least-privilege principles
  - **Pre-deployment Review**: Audit security contexts before promoting to production
  - **Incident Response**: Quickly identify over-privileged containers during security events
  - **Security Posture**: Baseline and track security improvements over time
  - **Multi-tenant Clusters**: Ensure tenant workloads don't have dangerous privileges
  - **Baremetal Deployments**: Critical for on-prem clusters where container escapes are especially damaging

### k8s_control_plane_health.py
```
k8s_control_plane_health.py [-n namespace] [--format {plain,json,table}] [-v] [-w]
  -n, --namespace: Namespace for control plane components (default: kube-system)
  -f, --format: Output format - 'plain', 'json', or 'table' (default: table)
  -v, --verbose: Show detailed information
  -w, --warn-only: Only show output if issues or warnings detected
```

Monitor Kubernetes control plane health. Checks:
- API server availability and response latency
- API server health endpoints (/healthz, /readyz, /livez)
- etcd cluster health and quorum status
- Controller-manager and scheduler leader election leases
- Control plane pod health and restart counts

Exit codes:
  - 0: All control plane components healthy
  - 1: Control plane issues detected
  - 2: Usage error or kubectl not available

Examples:
```bash
# Check control plane health (default table format)
k8s_control_plane_health.py

# Plain text output
k8s_control_plane_health.py --format plain

# JSON output for monitoring systems
k8s_control_plane_health.py --format json

# Only show if there are problems
k8s_control_plane_health.py --warn-only

# Check control plane in custom namespace
k8s_control_plane_health.py -n kube-system

# Verbose with all details
k8s_control_plane_health.py -v

# Combine: only warnings in JSON format
k8s_control_plane_health.py -w --format json
```

Operational Use Cases:
  - **Cluster Health Monitoring**: Continuous health checks for alerting
  - **Upgrade Validation**: Verify control plane health after upgrades
  - **Disaster Recovery**: Quick assessment of control plane availability
  - **Performance Debugging**: Identify API server latency issues
  - **etcd Quorum Monitoring**: Detect etcd degradation before data loss
  - **Leader Election Tracking**: Monitor controller-manager and scheduler failovers
  - **Baremetal Deployments**: Critical for self-managed control planes

### k8s_kubelet_health_monitor.py
```
k8s_kubelet_health_monitor.py [--node NODE] [-l LABEL] [--format {plain,json,table}] [-w] [-v] [--skip-events]
  -n, --node: Check specific node by name
  -l, --label: Filter nodes by label selector (e.g., node-role.kubernetes.io/worker=)
  -f, --format: Output format - 'plain', 'json', or 'table' (default: table)
  -w, --warn-only: Only show nodes with issues
  -v, --verbose: Show detailed information
  --skip-events: Skip event collection (faster but less info)
```

Monitor kubelet health on Kubernetes nodes. The kubelet is the primary node agent that runs on each node and is responsible for:
- Registering the node with the API server
- Watching for PodSpecs and ensuring containers are running
- Reporting node and pod status to the API server
- Running container health checks (liveness/readiness probes)

This script checks:
- Node conditions (Ready, MemoryPressure, DiskPressure, PIDPressure)
- Kubelet heartbeat staleness (detects connectivity issues)
- Kubelet restart frequency via node events
- Kubelet version consistency across the cluster
- Cordoned/unschedulable node status

Exit codes:
  - 0: All kubelets healthy and versions consistent
  - 1: Kubelet issues detected or version mismatch
  - 2: Usage error or kubectl not available

Examples:
```bash
# Check all nodes (default table format)
k8s_kubelet_health_monitor.py

# Check specific node
k8s_kubelet_health_monitor.py --node worker-1

# Check worker nodes only
k8s_kubelet_health_monitor.py -l node-role.kubernetes.io/worker=

# Show only unhealthy kubelets
k8s_kubelet_health_monitor.py --warn-only

# JSON output for monitoring integration
k8s_kubelet_health_monitor.py --format json

# Quick check without event collection
k8s_kubelet_health_monitor.py --skip-events

# Plain text output
k8s_kubelet_health_monitor.py --format plain
```

Operational Use Cases:
  - **Node Health Monitoring**: Proactive detection of kubelet issues before pods fail
  - **Upgrade Validation**: Verify kubelet version consistency after rolling upgrades
  - **Connectivity Issues**: Detect nodes with stale heartbeats (network partitions)
  - **Capacity Planning**: Identify nodes under resource pressure
  - **Maintenance Windows**: Verify kubelet health before/after node maintenance
  - **Baremetal Clusters**: Critical for self-managed nodes without cloud provider integration

### k8s_api_latency_analyzer.py
```
k8s_api_latency_analyzer.py [-n namespace] [--format {plain,json,table}] [-v] [-w] [--samples N] [--warn-threshold MS] [--critical-threshold MS]
  -n, --namespace: Namespace for scoped operations (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information about each test
  -w, --warn-only: Only show output if issues or warnings are detected
  --samples N: Number of samples per operation (default: 3)
  --warn-threshold MS: Warning latency threshold in milliseconds (default: 500)
  --critical-threshold MS: Critical latency threshold in milliseconds (default: 2000)
```

Analyze Kubernetes API server response times to detect performance degradation. Performs a series of kubectl operations and measures their latency:
- LIST namespaces (cluster-wide, lightweight)
- LIST nodes (includes node status)
- LIST pods (potentially large, tests pagination)
- GET cluster-info (tests connectivity)
- LIST events (time-series data, often large)
- GET api-resources (discovery endpoint)

Exit codes:
  - 0: All API operations within acceptable latency thresholds
  - 1: Latency issues detected (operations exceeding thresholds)
  - 2: Usage error or kubectl not available

Examples:
```bash
# Basic latency check with plain output
k8s_api_latency_analyzer.py

# JSON output for monitoring integration
k8s_api_latency_analyzer.py --format json

# Check with lower thresholds for sensitive environments
k8s_api_latency_analyzer.py --warn-threshold 200 --critical-threshold 1000

# More samples for accurate measurement
k8s_api_latency_analyzer.py --samples 5

# Only show problems (for alerting)
k8s_api_latency_analyzer.py --warn-only

# Table format for easy reading
k8s_api_latency_analyzer.py --format table

# Namespace-scoped operations only
k8s_api_latency_analyzer.py -n production

# Combine options
k8s_api_latency_analyzer.py -n production --samples 5 --warn-threshold 300 --format json
```

Operational Use Cases:
  - **Early Warning System**: Detect API server degradation before cluster becomes unresponsive
  - **Performance Baseline**: Establish normal latency ranges for your cluster
  - **Upgrade Validation**: Compare API latency before and after control plane upgrades
  - **Capacity Planning**: Identify when cluster size is affecting API performance
  - **Troubleshooting**: Correlate slow cluster behavior with API latency
  - **etcd Performance**: High latency often indicates etcd or storage issues
  - **Baremetal Clusters**: Monitor self-managed control plane performance

### k8s_secret_expiry_monitor.py
```
k8s_secret_expiry_monitor.py [-n namespace] [--format {plain,json,table}] [-v] [-w] [--tls-only]
  -n, --namespace: Namespace to check (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed information including service account tokens
  -w, --warn-only: Only show secrets with issues
  --expiry-warn DAYS: Days before certificate expiry to warn (default: 30)
  --expiry-critical DAYS: Days before certificate expiry is critical (default: 7)
  --stale-days DAYS: Days after which a secret is considered stale (default: 365)
  --tls-only: Only check TLS secrets (kubernetes.io/tls type)
```

Monitor Kubernetes Secret age and TLS certificate expiration. Checks:
- TLS certificate expiration dates for kubernetes.io/tls secrets
- Expired certificates and approaching expiration thresholds
- Stale secrets that haven't been updated in a configurable time period
- Invalid or malformed TLS certificates
- Service account tokens are skipped by default (auto-managed)

Exit codes:
  - 0: All secrets healthy
  - 1: Expiring/expired secrets or issues detected
  - 2: Usage error or kubectl not available

Examples:
```bash
# Check all secrets across all namespaces
k8s_secret_expiry_monitor.py

# Check secrets in specific namespace
k8s_secret_expiry_monitor.py -n production

# Show only expiring/problematic secrets
k8s_secret_expiry_monitor.py --warn-only

# Check only TLS secrets with custom thresholds
k8s_secret_expiry_monitor.py --tls-only --expiry-warn 60 --expiry-critical 14

# JSON output for monitoring integration
k8s_secret_expiry_monitor.py --format json

# Table format for easy reading
k8s_secret_expiry_monitor.py --format table

# Include service account tokens in output
k8s_secret_expiry_monitor.py --verbose

# Combine options: production TLS secrets only with warnings
k8s_secret_expiry_monitor.py -n production --tls-only -w --format table
```

Operational Use Cases:
  - **Certificate Lifecycle Management**: Track TLS certificate expiration across cluster
  - **Outage Prevention**: Alert before certificates expire and cause service failures
  - **Security Hygiene**: Identify stale secrets that may indicate rotation issues
  - **Compliance Auditing**: Ensure secrets are rotated within policy timeframes
  - **Ingress/Service Mesh**: Monitor TLS secrets used by ingress controllers
  - **Cert-Manager Integration**: Validate cert-manager is renewing certificates properly

### k8s_csr_health_monitor.py
```
k8s_csr_health_monitor.py [--format {plain,json,table}] [-v] [-w] [--pending-warn MINUTES] [--pending-critical MINUTES]
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed CSR information
  -w, --warn-only: Only show CSRs with issues
  --pending-warn MINUTES: Minutes pending before warning (default: 10)
  --pending-critical MINUTES: Minutes pending before critical (default: 60)
```

Monitor Kubernetes CertificateSigningRequest (CSR) health and approval status. CSRs are the mechanism for requesting certificates from the cluster's certificate authority. This script monitors:
- Pending CSRs that haven't been approved/denied (potential stuck requests)
- Denied CSRs that may indicate configuration issues
- Failed CSRs that need investigation
- CSR approval latency (time from creation to approval)
- Approved CSRs without issued certificates

CSRs are critical for:
- **Node Bootstrap**: kubelet certificate requests during node registration
- **cert-manager**: Certificate issuance and renewal workflows
- **Service Mesh**: mTLS certificate rotation for sidecars
- **Custom Workflows**: Application-specific certificate management

Exit codes:
  - 0: All CSRs healthy, no pending beyond threshold
  - 1: Issues detected (long-pending, denied, or failed CSRs)
  - 2: Usage error or kubectl not available

Examples:
```bash
# Check all CSRs in the cluster
k8s_csr_health_monitor.py

# Show only CSRs with issues
k8s_csr_health_monitor.py --warn-only

# Custom pending thresholds (5 min warn, 30 min critical)
k8s_csr_health_monitor.py --pending-warn 5 --pending-critical 30

# JSON output for monitoring systems
k8s_csr_health_monitor.py --format json

# Table output with details
k8s_csr_health_monitor.py --format table --verbose

# Combine options for alerting
k8s_csr_health_monitor.py -w --format json --pending-critical 15
```

Operational Use Cases:
  - **Node Bootstrap Monitoring**: Detect stuck kubelet CSRs during node addition
  - **cert-manager Health**: Verify cert-manager CSR workflow is functioning
  - **Certificate Rotation**: Monitor CSR approval during certificate renewals
  - **Security Auditing**: Track CSR approval patterns and denied requests
  - **Capacity Planning**: Analyze CSR approval latency trends
  - **Troubleshooting**: Identify why nodes aren't joining (CSR not approved)

### k8s_lease_monitor.py
```
k8s_lease_monitor.py [-n namespace] [--format {plain,json,table}] [-v] [-w] [--stale-threshold SECONDS] [--skip-node-leases] [--check-orphans]
  -n, --namespace: Namespace to check (default: all namespaces)
  --format: Output format - 'plain', 'json', or 'table' (default: plain)
  -v, --verbose: Show detailed lease information
  -w, --warn-only: Only show leases with issues
  --stale-threshold SECONDS: Seconds without renewal before lease is stale (default: 60)
  --skip-node-leases: Skip node heartbeat leases in kube-node-lease namespace
  --check-orphans: Check if lease holders still exist (requires extra API calls)
```

Monitor Kubernetes Lease objects for leader election health. Leases are the modern mechanism for leader election in Kubernetes. This script monitors all leases across the cluster to detect:
- Stale leases (not renewed within threshold)
- Orphaned leases (holder no longer exists)
- Leader election contention or instability (high transition counts)
- Missing expected leases for critical components

Lease types detected:
- **control-plane**: kube-controller-manager, kube-scheduler
- **node-heartbeat**: Node heartbeat leases (kube-node-lease namespace)
- **controller**: Various Kubernetes controllers
- **operator**: Operator framework leases
- **ingress**: Ingress controller leader election
- **storage**: CSI and storage controller leases
- **service-mesh**: Istio, Linkerd, etc.
- **monitoring**: Prometheus, Grafana, etc.

Exit codes:
  - 0: All leases healthy
  - 1: Stale or problematic leases detected
  - 2: Usage error or kubectl not available

Examples:
```bash
# Check all leases across all namespaces
k8s_lease_monitor.py

# Check leases in kube-system only
k8s_lease_monitor.py -n kube-system

# Show only leases with issues
k8s_lease_monitor.py --warn-only

# Output as JSON for automation
k8s_lease_monitor.py --format json

# Custom stale threshold (default: 60 seconds)
k8s_lease_monitor.py --stale-threshold 120

# Skip node heartbeat leases (can be noisy in large clusters)
k8s_lease_monitor.py --skip-node-leases

# Check for orphaned lease holders
k8s_lease_monitor.py --check-orphans

# Combine options: kube-system namespace, table format, issues only
k8s_lease_monitor.py -n kube-system --format table --warn-only
```

Operational Use Cases:
  - **HA Health Monitoring**: Verify leader election is working across all controllers
  - **Controller Troubleshooting**: Detect controllers that have crashed or lost leadership
  - **Node Health**: Monitor node heartbeat leases to detect node failures
  - **Operator Health**: Ensure operator leader election is stable
  - **Cluster Upgrades**: Verify control plane components maintain leadership during rolling updates
  - **Service Mesh Health**: Monitor Istio/Linkerd controller leader election

### k8s_operator_health_monitor.py
```
k8s_operator_health_monitor.py [--format {plain,json}] [-v] [-w] [--list-known]
  --format, -f: Output format - 'plain' or 'json' (default: plain)
  -v, --verbose: Show detailed pod-level information
  -w, --warn-only: Only show operators with issues or warnings
  --list-known: List all known operators this tool can detect
```

Monitor Kubernetes operator health and status. Automatically detects installed operators by scanning for known namespaces and CRDs. For each detected operator, it checks:
- Controller deployment health (ready replicas, availability)
- Pod status and restart counts
- CRD availability and completeness
- Recent error events in operator namespaces

Supported operators:
- **prometheus-operator**: Prometheus Operator for Kubernetes-native monitoring
- **cert-manager**: Certificate management controller
- **argocd**: GitOps continuous delivery tool (server, repo-server, application-controller)
- **flux**: GitOps toolkit (source-controller, kustomize-controller, helm-controller)
- **istio**: Service mesh (istiod, ingressgateway, egressgateway)
- **nginx-ingress**: NGINX Ingress Controller
- **traefik**: Traefik Ingress Controller
- **external-dns**: Automatic DNS record management
- **sealed-secrets**: Sealed Secrets for Kubernetes
- **metallb**: Bare metal load balancer
- **keda**: Kubernetes Event-driven Autoscaling
- **crossplane**: Cloud infrastructure provisioning

Exit codes:
  - 0: All detected operators healthy
  - 1: One or more operators unhealthy or have warnings
  - 2: Usage error or kubectl not available

Examples:
```bash
# Check all detected operators
k8s_operator_health_monitor.py

# Show only unhealthy operators
k8s_operator_health_monitor.py --warn-only

# JSON output for monitoring integration
k8s_operator_health_monitor.py --format json

# Verbose output with pod details
k8s_operator_health_monitor.py -v

# List all operators this tool can detect
k8s_operator_health_monitor.py --list-known

# Combine options: JSON format, issues only, verbose
k8s_operator_health_monitor.py -f json -w -v
```

Operational Use Cases:
  - **Production Monitoring**: Integrate with alerting to detect operator failures
  - **Cluster Health Checks**: Verify all operators are healthy before deployments
  - **Troubleshooting**: Quickly identify which operators have issues
  - **Capacity Planning**: Monitor operator pod resource usage and restarts
  - **Post-Upgrade Validation**: Verify operators survived cluster upgrades
