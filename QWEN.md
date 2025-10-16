# tildebin Project Context

## Project Overview

This directory, `tildebin`, contains a collection of small shell and Python utility scripts intended for personal use, typically placed in a `~/bin` directory for easy access from the command line. The scripts automate common tasks related to system administration, AWS EC2 management, and SSH operations across multiple hosts.

## Key Scripts

*   **`acrosshosts.sh`**: Executes a specified command on multiple hosts listed in a file using SSH.
*   **`emptysgs.py`**: Uses the `boto` library to find unused AWS EC2 Security Groups in the `us-east-1` region.
*   **`generate_fstab.sh`**: Generates a basic `/etc/fstab` file content by parsing `/proc/mounts` and converting device names to UUIDs.
*   **`grephosts.sh`**: Filters the output of `listec2hosts.py` based on a search query, printing matching hostnames.
*   **`listec2hosts.py`**: Retrieves and lists EC2 instances from AWS, primarily from `us-west-2`, showing details like name, ID, type, placement, and IP addresses. Requires AWS credentials.
*   **`useradd.sh`**: Creates a new user account with SSH access and sudo privileges on multiple hosts listed in a file.

## Dependencies

*   **Python Scripts**: `emptysgs.py` and `listec2hosts.py` rely on the `boto` library for AWS interactions.
*   **Shell Scripts**: Standard POSIX shell tools (`ssh`, `grep`, `awk`, `blkid`, etc.) are used.

## Usage

These scripts are designed to be run directly from the command line. Each script typically prints a usage message if executed without the required arguments. For AWS-dependent scripts, ensure your environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `EC2_REGION`, or `EC2_URL`) are configured.