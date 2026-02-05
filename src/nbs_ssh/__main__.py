"""
CLI interface for nbs-ssh.

Usage:
    python -m nbs_ssh user@host              # Interactive shell
    python -m nbs_ssh user@host command      # Execute command
    python -m nbs_ssh -p 2222 user@host command
    python -m nbs_ssh -i keyfile user@host command
    python -m nbs_ssh --password user@host command
    python -m nbs_ssh --events user@host command
    python -m nbs_ssh --help
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from pathlib import Path


def parse_target(target: str) -> tuple[str, str | None]:
    """
    Parse user@host target string.

    Returns:
        Tuple of (host, username) where username may be None.
    """
    if "@" in target:
        username, host = target.rsplit("@", 1)
        return host, username
    return target, None


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for nbs-ssh CLI."""
    parser = argparse.ArgumentParser(
        prog="nbs-ssh",
        description="AI-inspectable SSH client",
        epilog="Example: python -m nbs_ssh user@host 'echo hello'",
    )

    parser.add_argument(
        "target",
        metavar="[user@]host",
        help="Target host (optionally with username)",
    )

    parser.add_argument(
        "command",
        nargs="?",
        help="Command to execute on remote host",
    )

    parser.add_argument(
        "-p", "--port",
        type=int,
        default=22,
        help="SSH port (default: 22)",
    )

    parser.add_argument(
        "-l", "--login",
        metavar="USER",
        help="Login username (alternative to user@host)",
    )

    parser.add_argument(
        "-i", "--identity",
        metavar="FILE",
        help="Private key file for authentication",
    )

    parser.add_argument(
        "--password",
        action="store_true",
        help="Prompt for password authentication",
    )

    parser.add_argument(
        "--events",
        action="store_true",
        help="Print JSONL events to stderr",
    )

    parser.add_argument(
        "--no-host-check",
        action="store_true",
        help="Disable host key verification (insecure)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Connection timeout in seconds (default: 30)",
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    return parser


async def run_command(args: argparse.Namespace) -> int:
    """
    Execute SSH command and return exit code.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code from remote command (or 1 on error)
    """
    from nbs_ssh import SSHConnection, create_key_auth, create_password_auth
    from nbs_ssh.events import EventCollector

    # Parse target
    host, target_user = parse_target(args.target)
    username = args.login or target_user

    if not username:
        # Default to current user
        import os
        username = os.environ.get("USER", os.environ.get("USERNAME", "root"))

    # Build auth config
    auth_configs = []

    if args.identity:
        key_path = Path(args.identity).expanduser()
        if not key_path.exists():
            print(f"Error: Key file not found: {key_path}", file=sys.stderr)
            return 1
        auth_configs.append(create_key_auth(key_path))

    if args.password:
        password = getpass.getpass(f"Password for {username}@{host}: ")
        auth_configs.append(create_password_auth(password))

    # If no explicit auth, try password prompt
    if not auth_configs:
        password = getpass.getpass(f"Password for {username}@{host}: ")
        auth_configs.append(create_password_auth(password))

    # Set up event collection if --events
    event_collector = EventCollector() if args.events else None
    known_hosts = None if args.no_host_check else ()

    try:
        async with SSHConnection(
            host=host,
            port=args.port,
            username=username,
            auth=auth_configs,
            known_hosts=known_hosts,
            event_collector=event_collector,
            connect_timeout=args.timeout,
        ) as conn:
            if args.command:
                result = await conn.exec(args.command)

                # Output stdout to stdout, stderr to stderr
                if result.stdout:
                    sys.stdout.write(result.stdout)
                if result.stderr:
                    sys.stderr.write(result.stderr)

                exit_code = result.exit_code
            else:
                # No command - open interactive shell
                try:
                    exit_code = await conn.shell()
                except RuntimeError as e:
                    # Not a TTY - just connect and print message
                    print(f"Connected to {username}@{host}:{args.port}", file=sys.stderr)
                    print(f"(Interactive shell not available: {e})", file=sys.stderr)
                    exit_code = 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        exit_code = 1

    finally:
        # Print events if requested
        if event_collector and args.events:
            for event in event_collector.events:
                print(event.to_json(), file=sys.stderr)

    return exit_code


def main() -> int:
    """CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    return asyncio.run(run_command(args))


if __name__ == "__main__":
    sys.exit(main())
