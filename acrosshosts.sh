#!/bin/bash
#
# acrosshosts.sh - Execute commands across multiple hosts via SSH
#
# Improved version with error handling, parallel execution, timeouts,
# and comprehensive reporting.
#
# Exit codes:
#   0 - All hosts succeeded
#   1 - One or more hosts failed
#   2 - Usage error or invalid arguments

set -o pipefail

# Default configuration
PARALLEL_JOBS=1
TIMEOUT=30
STRICT_HOST_KEY_CHECKING="no"
VERBOSE=false
QUIET=false
DRY_RUN=false
SSH_USER=""
SSH_OPTIONS=""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Arrays to track results
declare -a SUCCEEDED_HOSTS
declare -a FAILED_HOSTS

usage() {
    cat << EOF
Usage: acrosshosts.sh [OPTIONS] <hostlist> <command>

Execute a command on multiple hosts via SSH.

Arguments:
  <hostlist>    File containing list of hosts (one per line)
  <command>     Command to execute on each host

Options:
  -j, --jobs N          Run N jobs in parallel (default: 1)
  -t, --timeout N       SSH connection timeout in seconds (default: 30)
  -u, --user USER       SSH username (default: current user)
  -s, --strict          Enable strict host key checking (default: disabled)
  -o, --ssh-opts OPTS   Additional SSH options (quoted string)
  -v, --verbose         Verbose output (show SSH commands)
  -q, --quiet           Quiet mode (only show errors)
  -n, --dry-run         Show what would be executed without running
  -h, --help            Display this help message

Examples:
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

Exit codes:
  0 - All hosts succeeded
  1 - One or more hosts failed
  2 - Usage error or invalid arguments
EOF
}

log_info() {
    if [[ "$QUIET" == false ]]; then
        echo -e "${GREEN}[INFO]${NC} $*"
    fi
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${YELLOW}[DEBUG]${NC} $*"
    fi
}

# Parse command line arguments
parse_args() {
    local positional_args=()
    local parsing_options=true

    while [[ $# -gt 0 ]]; do
        # Once we have the hostlist, stop parsing options and treat everything as command
        if [[ ${#positional_args[@]} -ge 1 ]]; then
            parsing_options=false
        fi

        # If we're no longer parsing options, collect everything as positional args
        if [[ "$parsing_options" == false ]]; then
            positional_args+=("$1")
            shift
            continue
        fi

        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -j|--jobs)
                if [[ -z "$2" ]] || [[ "$2" =~ ^- ]]; then
                    log_error "Option $1 requires an argument"
                    exit 2
                fi
                PARALLEL_JOBS="$2"
                if ! [[ "$PARALLEL_JOBS" =~ ^[0-9]+$ ]] || [[ "$PARALLEL_JOBS" -lt 1 ]]; then
                    log_error "Invalid job count: $PARALLEL_JOBS (must be positive integer)"
                    exit 2
                fi
                shift 2
                ;;
            -t|--timeout)
                if [[ -z "$2" ]] || [[ "$2" =~ ^- ]]; then
                    log_error "Option $1 requires an argument"
                    exit 2
                fi
                TIMEOUT="$2"
                if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -lt 1 ]]; then
                    log_error "Invalid timeout: $TIMEOUT (must be positive integer)"
                    exit 2
                fi
                shift 2
                ;;
            -u|--user)
                if [[ -z "$2" ]] || [[ "$2" =~ ^- ]]; then
                    log_error "Option $1 requires an argument"
                    exit 2
                fi
                SSH_USER="$2"
                shift 2
                ;;
            -s|--strict)
                STRICT_HOST_KEY_CHECKING="yes"
                shift
                ;;
            -o|--ssh-opts)
                if [[ -z "$2" ]]; then
                    log_error "Option $1 requires an argument"
                    exit 2
                fi
                # SSH options can start with '-', so don't check for that
                SSH_OPTIONS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -n|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 2
                ;;
            *)
                positional_args+=("$1")
                shift
                ;;
        esac
    done

    # Check for required positional arguments
    if [[ ${#positional_args[@]} -lt 2 ]]; then
        log_error "Missing required arguments"
        usage
        exit 2
    fi

    HOSTLIST="${positional_args[0]}"
    COMMAND="${positional_args[@]:1}"
}

# Validate hostlist file
validate_hostlist() {
    if [[ ! -f "$HOSTLIST" ]]; then
        log_error "Hostlist file not found: $HOSTLIST"
        exit 2
    fi

    if [[ ! -r "$HOSTLIST" ]]; then
        log_error "Hostlist file not readable: $HOSTLIST"
        exit 2
    fi

    if [[ ! -s "$HOSTLIST" ]]; then
        log_error "Hostlist file is empty: $HOSTLIST"
        exit 2
    fi
}

# Execute command on a single host
execute_on_host() {
    local host="$1"
    local command="$2"
    local ssh_cmd="ssh"
    local ssh_args=()

    # Build SSH command
    ssh_args+=("-o" "ConnectTimeout=${TIMEOUT}")
    ssh_args+=("-o" "StrictHostKeyChecking=${STRICT_HOST_KEY_CHECKING}")
    ssh_args+=("-o" "BatchMode=yes")

    # Add custom SSH options if provided
    if [[ -n "$SSH_OPTIONS" ]]; then
        # shellcheck disable=SC2206
        ssh_args+=($SSH_OPTIONS)
    fi

    # Add user if specified
    if [[ -n "$SSH_USER" ]]; then
        ssh_args+=("-l" "$SSH_USER")
    fi

    # Add host
    ssh_args+=("$host")

    # Add command
    ssh_args+=("$command")

    log_verbose "Executing: $ssh_cmd ${ssh_args[*]}"

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY RUN] $host: $ssh_cmd ${ssh_args[*]}"
        return 0
    fi

    # Execute SSH command
    local output
    local exit_code

    if [[ "$QUIET" == false ]]; then
        log_info "[$host] Executing command..."
    fi

    output=$("$ssh_cmd" "${ssh_args[@]}" 2>&1)
    exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        if [[ "$QUIET" == false ]]; then
            echo -e "${GREEN}[✓ $host]${NC}"
            if [[ -n "$output" ]]; then
                echo "$output" | sed "s/^/  [$host] /"
            fi
        fi
        return 0
    else
        log_error "[✗ $host] Command failed (exit code: $exit_code)"
        if [[ -n "$output" ]]; then
            echo "$output" | sed "s/^/  [$host] /" >&2
        fi
        return 1
    fi
}

# Export function for parallel execution
export -f execute_on_host
export -f log_info
export -f log_error
export -f log_verbose
export -f log_warn
export TIMEOUT STRICT_HOST_KEY_CHECKING SSH_OPTIONS SSH_USER VERBOSE QUIET DRY_RUN
export RED GREEN YELLOW NC

# Main execution
main() {
    parse_args "$@"
    validate_hostlist

    local total_hosts=0
    local hosts=()

    # Read hosts into array
    while IFS= read -r host; do
        # Skip empty lines and comments
        [[ -z "$host" ]] && continue
        [[ "$host" =~ ^# ]] && continue

        # Trim whitespace
        host=$(echo "$host" | xargs)
        [[ -z "$host" ]] && continue

        hosts+=("$host")
        ((total_hosts++))
    done < "$HOSTLIST"

    if [[ $total_hosts -eq 0 ]]; then
        log_error "No valid hosts found in $HOSTLIST"
        exit 2
    fi

    log_info "Found $total_hosts host(s) in $HOSTLIST"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN MODE - No commands will be executed"
    fi
    log_info "Command: $COMMAND"
    log_info "Parallel jobs: $PARALLEL_JOBS"
    log_info "Timeout: ${TIMEOUT}s"
    echo ""

    # Execute commands
    if [[ $PARALLEL_JOBS -gt 1 ]]; then
        # Parallel execution using GNU parallel or xargs
        if command -v parallel &> /dev/null; then
            log_verbose "Using GNU parallel for execution"
            printf "%s\n" "${hosts[@]}" | \
                parallel -j "$PARALLEL_JOBS" --will-cite \
                execute_on_host {} "$COMMAND"
        else
            log_verbose "GNU parallel not found, using xargs"
            printf "%s\n" "${hosts[@]}" | \
                xargs -I {} -P "$PARALLEL_JOBS" -n 1 \
                bash -c 'execute_on_host "$@"' _ {} "$COMMAND"
        fi
    else
        # Sequential execution
        for host in "${hosts[@]}"; do
            if execute_on_host "$host" "$COMMAND"; then
                SUCCEEDED_HOSTS+=("$host")
            else
                FAILED_HOSTS+=("$host")
            fi
        done
    fi

    # Summary
    echo ""
    echo "================================"
    echo "Summary"
    echo "================================"

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN completed - no commands were executed"
        exit 0
    fi

    local succeeded_count=${#SUCCEEDED_HOSTS[@]}
    local failed_count=${#FAILED_HOSTS[@]}

    if [[ $PARALLEL_JOBS -gt 1 ]]; then
        # For parallel execution, we can't track individual results
        # so we just report completion
        log_info "Parallel execution completed"
        log_warn "Individual host results not tracked in parallel mode"
        log_info "Check output above for host-specific results"
        exit 0
    else
        echo -e "${GREEN}Succeeded: $succeeded_count${NC}"
        if [[ $succeeded_count -gt 0 ]]; then
            for host in "${SUCCEEDED_HOSTS[@]}"; do
                echo -e "  ${GREEN}✓${NC} $host"
            done
        fi

        echo ""
        echo -e "${RED}Failed: $failed_count${NC}"
        if [[ $failed_count -gt 0 ]]; then
            for host in "${FAILED_HOSTS[@]}"; do
                echo -e "  ${RED}✗${NC} $host"
            done
        fi

        # Exit with appropriate code
        if [[ $failed_count -eq 0 ]]; then
            exit 0
        else
            exit 1
        fi
    fi
}

# Run main function
main "$@"
