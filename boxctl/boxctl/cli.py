"""Command-line interface for boxctl."""

import sys


def main(argv=None):
    """Main entry point."""
    print("boxctl - Unified CLI for baremetal and Kubernetes utility scripts")
    print("Use --help for usage information")
    return 0


if __name__ == "__main__":
    sys.exit(main())
