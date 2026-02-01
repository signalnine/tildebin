"""Command-line interface for boxctl."""

import argparse
import sys
from pathlib import Path

from boxctl import __version__
from boxctl.core import discover_scripts, filter_scripts, run_script, needs_privilege


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="boxctl",
        description="Unified CLI for baremetal and Kubernetes utility scripts",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"boxctl {__version__}",
    )
    parser.add_argument(
        "--scripts-dir",
        type=Path,
        default=Path.cwd(),
        help="Directory containing scripts (default: current directory)",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # list command
    list_parser = subparsers.add_parser("list", help="List available scripts")
    list_parser.add_argument(
        "--category",
        "-c",
        help="Filter by category (e.g., baremetal/disk)",
    )
    list_parser.add_argument(
        "--tag",
        "-t",
        action="append",
        dest="tags",
        help="Filter by tag (can be specified multiple times)",
    )

    # run command
    run_parser = subparsers.add_parser("run", help="Run a script")
    run_parser.add_argument("script", help="Script name to run")
    run_parser.add_argument(
        "args",
        nargs="*",
        help="Arguments to pass to the script",
    )
    run_parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout in seconds (default: 60)",
    )
    run_parser.add_argument(
        "--sudo",
        action="store_true",
        help="Run with sudo (auto-enabled for privileged scripts)",
    )

    # show command
    show_parser = subparsers.add_parser("show", help="Show script details")
    show_parser.add_argument("script", help="Script name to show")

    # search command
    search_parser = subparsers.add_parser("search", help="Search scripts")
    search_parser.add_argument("query", help="Search query")

    return parser


def cmd_list(args: argparse.Namespace) -> int:
    """List available scripts."""
    scripts = discover_scripts(args.scripts_dir)
    scripts = filter_scripts(scripts, category=args.category, tags=args.tags)

    if not scripts:
        print("No scripts found.")
        return 0

    for script in sorted(scripts, key=lambda s: s.name):
        if args.format == "json":
            import json
            print(json.dumps({
                "name": script.name,
                "category": script.category,
                "tags": script.tags,
                "brief": script.brief,
            }))
        else:
            print(f"{script.name:30} {script.brief}")

    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run a script."""
    scripts = discover_scripts(args.scripts_dir)
    matches = [s for s in scripts if s.name == args.script or s.name == f"{args.script}.py"]

    if not matches:
        print(f"Script not found: {args.script}", file=sys.stderr)
        return 2

    script = matches[0]
    use_sudo = args.sudo or needs_privilege(script.path)

    result = run_script(
        script.path,
        args=args.args,
        timeout=args.timeout,
        use_sudo=use_sudo,
    )

    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")

    if result.timed_out:
        print("Script timed out", file=sys.stderr)
        return 1

    return result.returncode or 0


def cmd_show(args: argparse.Namespace) -> int:
    """Show script details."""
    scripts = discover_scripts(args.scripts_dir)
    matches = [s for s in scripts if s.name == args.script or s.name == f"{args.script}.py"]

    if not matches:
        print(f"Script not found: {args.script}", file=sys.stderr)
        return 2

    script = matches[0]

    if args.format == "json":
        import json
        print(json.dumps({
            "name": script.name,
            "path": str(script.path),
            "category": script.category,
            "tags": script.tags,
            "brief": script.brief,
            "requires": script.requires,
            "privilege": script.privilege,
            "related": script.related,
        }, indent=2))
    else:
        print(f"Name:     {script.name}")
        print(f"Path:     {script.path}")
        print(f"Category: {script.category}")
        print(f"Tags:     {', '.join(script.tags)}")
        print(f"Brief:    {script.brief}")
        if script.requires:
            print(f"Requires: {', '.join(script.requires)}")
        if script.privilege:
            print(f"Privilege: {script.privilege}")
        if script.related:
            print(f"Related:  {', '.join(script.related)}")

    return 0


def cmd_search(args: argparse.Namespace) -> int:
    """Search scripts."""
    scripts = discover_scripts(args.scripts_dir)
    query = args.query.lower()

    matches = [
        s for s in scripts
        if query in s.name.lower()
        or query in s.brief.lower()
        or any(query in tag.lower() for tag in s.tags)
        or query in s.category.lower()
    ]

    if not matches:
        print(f"No scripts matching: {args.query}")
        return 0

    for script in sorted(matches, key=lambda s: s.name):
        if args.format == "json":
            import json
            print(json.dumps({
                "name": script.name,
                "category": script.category,
                "brief": script.brief,
            }))
        else:
            print(f"{script.name:30} {script.brief}")

    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    commands = {
        "list": cmd_list,
        "run": cmd_run,
        "show": cmd_show,
        "search": cmd_search,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
