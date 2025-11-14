#!/usr/bin/env python3
"""
Test script for acrosshosts.sh functionality.
Tests argument parsing and error handling without requiring SSH access.
"""

import subprocess
import sys
import os
import tempfile
import shutil

def run_command(cmd_args):
    """Helper function to run a command and return result"""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)

def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(['bash', 'acrosshosts.sh', '--help'])

    if return_code == 0 and 'Usage:' in stdout and 'Execute a command' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False

def test_short_help():
    """Test that -h flag works"""
    return_code, stdout, stderr = run_command(['bash', 'acrosshosts.sh', '-h'])

    if return_code == 0 and 'Usage:' in stdout:
        print("[PASS] Short help (-h) test passed")
        return True
    else:
        print(f"[FAIL] Short help test failed")
        return False

def test_no_arguments():
    """Test that script fails with usage error when no arguments provided"""
    return_code, stdout, stderr = run_command(['bash', 'acrosshosts.sh'])

    if return_code == 2 and 'Missing required arguments' in stderr:
        print("[PASS] No arguments test passed")
        return True
    else:
        print(f"[FAIL] No arguments test failed")
        print(f"  Expected exit code 2, got: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False

def test_missing_hostlist():
    """Test that script fails when hostlist file doesn't exist"""
    return_code, stdout, stderr = run_command(
        ['bash', 'acrosshosts.sh', '/nonexistent/hosts.txt', 'uptime']
    )

    if return_code == 2 and 'not found' in stderr:
        print("[PASS] Missing hostlist test passed")
        return True
    else:
        print(f"[FAIL] Missing hostlist test failed")
        print(f"  Expected exit code 2, got: {return_code}")
        return False

def test_empty_hostlist():
    """Test that script fails when hostlist file is empty"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', temp_file, 'uptime']
        )

        if return_code == 2 and 'empty' in stderr.lower():
            print("[PASS] Empty hostlist test passed")
            return True
        else:
            print(f"[FAIL] Empty hostlist test failed")
            print(f"  Expected exit code 2, got: {return_code}")
            print(f"  Stderr: {stderr[:200]}")
            return False
    finally:
        os.unlink(temp_file)

def test_invalid_parallel_jobs():
    """Test that invalid parallel job count is rejected"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        # Test negative number
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-j', '0', temp_file, 'uptime']
        )

        if return_code == 2 and 'Invalid job count' in stderr:
            print("[PASS] Invalid parallel jobs test passed")
            return True
        else:
            print(f"[FAIL] Invalid parallel jobs test failed")
            print(f"  Expected exit code 2, got: {return_code}")
            return False
    finally:
        os.unlink(temp_file)

def test_invalid_timeout():
    """Test that invalid timeout is rejected"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        # Test negative timeout
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-t', '-5', temp_file, 'uptime']
        )

        if return_code == 2:
            print("[PASS] Invalid timeout test passed")
            return True
        else:
            print(f"[FAIL] Invalid timeout test failed")
            print(f"  Expected exit code 2, got: {return_code}")
            return False
    finally:
        os.unlink(temp_file)

def test_unknown_option():
    """Test that unknown options are rejected"""
    return_code, stdout, stderr = run_command(
        ['bash', 'acrosshosts.sh', '--invalid-option', 'hosts.txt', 'uptime']
    )

    if return_code == 2 and 'Unknown option' in stderr:
        print("[PASS] Unknown option test passed")
        return True
    else:
        print(f"[FAIL] Unknown option test failed")
        print(f"  Expected exit code 2, got: {return_code}")
        return False

def test_dry_run_mode():
    """Test that dry-run mode doesn't execute commands"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-n', temp_file, 'echo test']
        )

        if return_code == 0 and 'DRY RUN' in stdout:
            print("[PASS] Dry-run mode test passed")
            return True
        else:
            print(f"[FAIL] Dry-run mode test failed")
            print(f"  Expected exit code 0, got: {return_code}")
            print(f"  Output: {stdout[:200]}")
            return False
    finally:
        os.unlink(temp_file)

def test_verbose_flag():
    """Test that verbose flag is accepted"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-v', '-n', temp_file, 'uptime']
        )

        # Verbose + dry-run should work (exit 0)
        if return_code == 0:
            print("[PASS] Verbose flag test passed")
            return True
        else:
            print(f"[FAIL] Verbose flag test failed")
            print(f"  Expected exit code 0, got: {return_code}")
            return False
    finally:
        os.unlink(temp_file)

def test_quiet_flag():
    """Test that quiet flag is accepted"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-q', '-n', temp_file, 'uptime']
        )

        # Quiet + dry-run should work (exit 0)
        # In quiet mode, there should be less output
        if return_code == 0:
            print("[PASS] Quiet flag test passed")
            return True
        else:
            print(f"[FAIL] Quiet flag test failed")
            print(f"  Expected exit code 0, got: {return_code}")
            return False
    finally:
        os.unlink(temp_file)

def test_parallel_jobs_flag():
    """Test that parallel jobs flag is accepted"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-j', '2', '-n', temp_file, 'uptime']
        )

        if return_code == 0 and 'Parallel jobs: 2' in stdout:
            print("[PASS] Parallel jobs flag test passed")
            return True
        else:
            print(f"[FAIL] Parallel jobs flag test failed")
            print(f"  Expected exit code 0, got: {return_code}")
            return False
    finally:
        os.unlink(temp_file)

def test_timeout_flag():
    """Test that timeout flag is accepted"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-t', '10', '-n', temp_file, 'uptime']
        )

        if return_code == 0 and 'Timeout: 10s' in stdout:
            print("[PASS] Timeout flag test passed")
            return True
        else:
            print(f"[FAIL] Timeout flag test failed")
            print(f"  Expected exit code 0, got: {return_code}")
            print(f"  Output: {stdout[:200]}")
            return False
    finally:
        os.unlink(temp_file)

def test_user_flag():
    """Test that user flag is accepted"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-u', 'testuser', '-n', temp_file, 'uptime']
        )

        if return_code == 0:
            print("[PASS] User flag test passed")
            return True
        else:
            print(f"[FAIL] User flag test failed")
            print(f"  Expected exit code 0, got: {return_code}")
            return False
    finally:
        os.unlink(temp_file)

def test_strict_flag():
    """Test that strict host key checking flag is accepted"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-s', '-n', temp_file, 'uptime']
        )

        if return_code == 0:
            print("[PASS] Strict flag test passed")
            return True
        else:
            print(f"[FAIL] Strict flag test failed")
            print(f"  Expected exit code 0, got: {return_code}")
            return False
    finally:
        os.unlink(temp_file)

def test_ssh_options_flag():
    """Test that SSH options flag is accepted"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-o', '-p 2222', '-n', temp_file, 'uptime']
        )

        if return_code == 0:
            print("[PASS] SSH options flag test passed")
            return True
        else:
            print(f"[FAIL] SSH options flag test failed")
            print(f"  Expected exit code 0, got: {return_code}")
            return False
    finally:
        os.unlink(temp_file)

def test_comments_in_hostlist():
    """Test that comments in hostlist are skipped"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("# This is a comment\n")
        f.write("localhost\n")
        f.write("# Another comment\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-n', temp_file, 'uptime']
        )

        if return_code == 0 and 'Found 1 host(s)' in stdout:
            print("[PASS] Comments in hostlist test passed")
            return True
        else:
            print(f"[FAIL] Comments in hostlist test failed")
            print(f"  Expected exit code 0 and '1 host', got: {return_code}")
            print(f"  Output: {stdout[:200]}")
            return False
    finally:
        os.unlink(temp_file)

def test_empty_lines_in_hostlist():
    """Test that empty lines in hostlist are skipped"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("\n")
        f.write("localhost\n")
        f.write("\n")
        f.write("127.0.0.1\n")
        f.write("\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-n', temp_file, 'uptime']
        )

        if return_code == 0 and 'Found 2 host(s)' in stdout:
            print("[PASS] Empty lines in hostlist test passed")
            return True
        else:
            print(f"[FAIL] Empty lines in hostlist test failed")
            print(f"  Expected '2 host(s)', got: {stdout[:200]}")
            return False
    finally:
        os.unlink(temp_file)

def test_multi_word_command():
    """Test that multi-word commands are handled correctly"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-n', temp_file, 'ls', '-la', '/tmp']
        )

        # Multi-word command should be captured correctly
        if return_code == 0 and 'Command: ls -la /tmp' in stdout:
            print("[PASS] Multi-word command test passed")
            return True
        else:
            print(f"[FAIL] Multi-word command test failed")
            print(f"  Output: {stdout[:300]}")
            return False
    finally:
        os.unlink(temp_file)

def test_option_requires_argument():
    """Test that options requiring arguments fail properly"""
    return_code, stdout, stderr = run_command(
        ['bash', 'acrosshosts.sh', '-j']
    )

    if return_code == 2 and 'requires an argument' in stderr:
        print("[PASS] Option requires argument test passed")
        return True
    else:
        print(f"[FAIL] Option requires argument test failed")
        print(f"  Expected exit code 2, got: {return_code}")
        return False

def test_long_options():
    """Test that long options work"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '--jobs', '3', '--timeout', '15',
             '--dry-run', temp_file, 'uptime']
        )

        if return_code == 0 and 'Parallel jobs: 3' in stdout and 'Timeout: 15s' in stdout:
            print("[PASS] Long options test passed")
            return True
        else:
            print(f"[FAIL] Long options test failed")
            print(f"  Output: {stdout[:300]}")
            return False
    finally:
        os.unlink(temp_file)

def test_teleport_flag():
    """Test that Teleport flag is accepted"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-T', '-n', temp_file, 'uptime']
        )

        if return_code == 0 and 'Using Teleport (tsh ssh)' in stdout:
            print("[PASS] Teleport flag test passed")
            return True
        else:
            print(f"[FAIL] Teleport flag test failed")
            print(f"  Expected exit code 0, got: {return_code}")
            print(f"  Output: {stdout[:300]}")
            return False
    finally:
        os.unlink(temp_file)

def test_teleport_long_option():
    """Test that --teleport long option works"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '--teleport', '--dry-run', temp_file, 'uptime']
        )

        if return_code == 0 and 'Using Teleport (tsh ssh)' in stdout:
            print("[PASS] Teleport long option test passed")
            return True
        else:
            print(f"[FAIL] Teleport long option test failed")
            print(f"  Output: {stdout[:300]}")
            return False
    finally:
        os.unlink(temp_file)

def test_teleport_with_user():
    """Test that Teleport flag works with user option"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("testhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-T', '-u', 'admin', '-n', temp_file, 'uptime']
        )

        if return_code == 0 and 'Using Teleport (tsh ssh)' in stdout:
            print("[PASS] Teleport with user test passed")
            return True
        else:
            print(f"[FAIL] Teleport with user test failed")
            print(f"  Expected exit code 0, got: {return_code}")
            return False
    finally:
        os.unlink(temp_file)

def test_without_teleport_shows_ssh():
    """Test that without Teleport flag, it shows standard SSH"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("localhost\n")
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command(
            ['bash', 'acrosshosts.sh', '-n', temp_file, 'uptime']
        )

        if return_code == 0 and 'Using standard SSH' in stdout:
            print("[PASS] Without Teleport shows SSH test passed")
            return True
        else:
            print(f"[FAIL] Without Teleport shows SSH test failed")
            print(f"  Output: {stdout[:300]}")
            return False
    finally:
        os.unlink(temp_file)

if __name__ == "__main__":
    print("Testing acrosshosts.sh...")
    print("")

    tests = [
        test_help_message,
        test_short_help,
        test_no_arguments,
        test_missing_hostlist,
        test_empty_hostlist,
        test_invalid_parallel_jobs,
        test_invalid_timeout,
        test_unknown_option,
        test_dry_run_mode,
        test_verbose_flag,
        test_quiet_flag,
        test_parallel_jobs_flag,
        test_timeout_flag,
        test_user_flag,
        test_strict_flag,
        test_ssh_options_flag,
        test_comments_in_hostlist,
        test_empty_lines_in_hostlist,
        test_multi_word_command,
        test_option_requires_argument,
        test_long_options,
        test_teleport_flag,
        test_teleport_long_option,
        test_teleport_with_user,
        test_without_teleport_shows_ssh,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("")
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
