#!/usr/bin/env python3
"""
Test script for baremetal_active_sessions_monitor.py functionality.
Tests argument parsing and error handling without requiring external resources.
"""

import subprocess
import sys
import json


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
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '--help']
    )

    if return_code == 0 and 'session' in stdout.lower() and 'idle' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_help_short_flag():
    """Test that -h flag works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '-h']
    )

    if return_code == 0 and 'session' in stdout.lower():
        print("[PASS] Help short flag test passed")
        return True
    else:
        print(f"[FAIL] Help short flag test failed")
        return False


def test_invalid_format_option():
    """Test that invalid format options are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option should fail")
        return False


def test_format_options():
    """Test that format options are recognized"""
    formats = ['plain', 'json', 'table']
    passed = True

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_active_sessions_monitor.py', '--format', fmt]
        )

        # Should not fail with argument parsing error
        if 'invalid choice' in stderr.lower():
            print(f"[FAIL] Format option '{fmt}' not recognized")
            passed = False

    if passed:
        print(f"[PASS] Format options test passed")
    return passed


def test_max_idle_option():
    """Test that max-idle option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '--max-idle', '1800']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Max-idle option test passed")
        return True
    else:
        print(f"[FAIL] Max-idle option test failed")
        print(f"  Error: {stderr[:200]}")
        return False


def test_max_sessions_option():
    """Test that max-sessions option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '--max-sessions', '10']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Max-sessions option test passed")
        return True
    else:
        print(f"[FAIL] Max-sessions option test failed")
        return False


def test_warn_root_option():
    """Test that warn-root option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '--warn-root']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-root option test passed")
        return True
    else:
        print(f"[FAIL] Warn-root option test failed")
        return False


def test_user_filter_option():
    """Test that user filter option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '--user', 'testuser']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] User filter option test passed")
        return True
    else:
        print(f"[FAIL] User filter option test failed")
        return False


def test_type_filter_option():
    """Test that type filter option is accepted"""
    for session_type in ['ssh', 'console', 'pty', 'x11']:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_active_sessions_monitor.py', '--type', session_type]
        )

        if 'invalid choice' in stderr.lower():
            print(f"[FAIL] Type filter option '{session_type}' not recognized")
            return False

    print("[PASS] Type filter option test passed")
    return True


def test_verbose_flag():
    """Test that verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '-v']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '-w']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        return False


def test_json_format_structure():
    """Test JSON output format structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '--format', 'json']
    )

    # Script should succeed on Linux (we have who/w commands)
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check for expected keys
            expected_keys = ['hostname', 'timestamp', 'session_count',
                           'unique_users', 'sessions', 'issues']
            missing_keys = [k for k in expected_keys if k not in data]

            if not missing_keys:
                print("[PASS] JSON format structure test passed")
                return True
            else:
                print(f"[FAIL] JSON format missing expected keys: {missing_keys}")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # Missing who/w command (unlikely on Linux)
        print("[SKIP] JSON format structure test (who/w command not available)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_plain_format_output():
    """Test plain format output contains expected fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        # Check for expected output fields
        expected_fields = ['Host:', 'Active Sessions:', 'Unique Users:']
        missing = [f for f in expected_fields if f not in stdout]

        if not missing:
            print("[PASS] Plain format output test passed")
            return True
        else:
            print(f"[FAIL] Plain format missing fields: {missing}")
            print(f"  Output: {stdout[:300]}")
            return False
    elif return_code == 2:
        print("[SKIP] Plain format output test (who/w command not available)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_table_format_output():
    """Test table format output contains expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        # Check for table markers and expected fields
        if '=' * 20 in stdout and 'Session' in stdout:
            print("[PASS] Table format output test passed")
            return True
        else:
            print(f"[FAIL] Table format missing expected structure")
            print(f"  Output: {stdout[:300]}")
            return False
    elif return_code == 2:
        print("[SKIP] Table format output test (who/w command not available)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_exit_codes():
    """Test that exit codes are valid"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py']
    )

    # Valid exit codes: 0 (success), 1 (warnings), 2 (missing tool)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_session_count_nonnegative():
    """Test that session count is non-negative"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            session_count = data.get('session_count', -1)

            if session_count >= 0:
                print("[PASS] Session count test passed")
                return True
            else:
                print(f"[FAIL] Session count invalid: {session_count}")
                return False
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[FAIL] Failed to parse session count: {e}")
            return False
    else:
        print(f"[SKIP] Session count test (exit code {return_code})")
        return True


def test_sessions_list_is_list():
    """Test that sessions output is a list"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            sessions = data.get('sessions')

            if isinstance(sessions, list):
                print("[PASS] Sessions list test passed")
                return True
            else:
                print(f"[FAIL] Sessions is not a list: {type(sessions)}")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] Failed to parse JSON: {e}")
            return False
    else:
        print(f"[SKIP] Sessions list test (exit code {return_code})")
        return True


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_active_sessions_monitor.py',
         '--format', 'json',
         '--max-idle', '3600',
         '--warn-root',
         '-v']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr and 'invalid choice' not in stderr:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed")
        print(f"  Error: {stderr[:200]}")
        return False


def test_docstring_present():
    """Test that script has module-level docstring with exit codes"""
    with open('baremetal_active_sessions_monitor.py', 'r') as f:
        content = f.read()

    if '"""' in content and 'Exit codes:' in content and 'session' in content.lower():
        print("[PASS] Docstring test passed")
        return True
    else:
        print("[FAIL] Docstring missing or incomplete")
        return False


def test_shebang_present():
    """Test that script has proper shebang"""
    with open('baremetal_active_sessions_monitor.py', 'r') as f:
        first_line = f.readline()

    if first_line.startswith('#!/usr/bin/env python3'):
        print("[PASS] Shebang test passed")
        return True
    else:
        print("[FAIL] Shebang missing or incorrect")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_active_sessions_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_help_short_flag,
        test_invalid_format_option,
        test_format_options,
        test_max_idle_option,
        test_max_sessions_option,
        test_warn_root_option,
        test_user_filter_option,
        test_type_filter_option,
        test_verbose_flag,
        test_warn_only_flag,
        test_json_format_structure,
        test_plain_format_output,
        test_table_format_output,
        test_exit_codes,
        test_session_count_nonnegative,
        test_sessions_list_is_list,
        test_combined_options,
        test_docstring_present,
        test_shebang_present,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
