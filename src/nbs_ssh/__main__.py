"""
CLI interface for nbs-ssh.

Usage:
    python -m nbs_ssh user@host              # Interactive shell
    python -m nbs_ssh user@host command      # Execute command
    python -m nbs_ssh -p 2222 user@host command
    python -m nbs_ssh -i keyfile user@host command
    python -m nbs_ssh --password user@host command
    python -m nbs_ssh --keyboard-interactive user@host command
    python -m nbs_ssh --events user@host command
    python -m nbs_ssh --help
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from pathlib import Path


def cli_kbdint_callback(
    name: str,
    instructions: str,
    prompts: list[tuple[str, bool]],
) -> list[str]:
    """
    Prompt user for keyboard-interactive responses.

    This callback is used when keyboard-interactive auth is requested.
    It displays the challenge name and instructions, then prompts the user
    for each response.

    Args:
        name: Challenge name (may be empty)
        instructions: Instructions to display (may be empty)
        prompts: List of (prompt_text, echo_enabled) tuples

    Returns:
        List of responses from user.
    """
    # Display name if provided
    if name:
        print(name, file=sys.stderr)

    # Display instructions if provided
    if instructions:
        print(instructions, file=sys.stderr)

    # Collect responses for each prompt
    responses = []
    for prompt_text, echo_enabled in prompts:
        if echo_enabled:
            # Echo input back to user
            response = input(prompt_text)
        else:
            # Hide input (for passwords)
            response = getpass.getpass(prompt_text)
        responses.append(response)

    return responses


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
        "--keyboard-interactive",
        action="store_true",
        help="Force keyboard-interactive authentication (for 2FA/MFA)",
    )

    parser.add_argument(
        "-J", "--proxy-jump",
        metavar="HOST",
        help="Jump host(s) for connection tunnelling (like ssh -J). "
             "Use comma-separated hosts for chaining: host1,host2",
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
    from nbs_ssh import (
        SSHConnection,
        check_gssapi_available,
        create_agent_auth,
        create_gssapi_auth,
        create_key_auth,
        create_keyboard_interactive_auth,
        create_password_auth,
        get_agent_available,
        get_default_key_paths,
    )
    from nbs_ssh.events import EventCollector

    # Parse target
    host, target_user = parse_target(args.target)
    username = args.login or target_user

    if not username:
        # Default to current user
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

    if getattr(args, 'keyboard_interactive', False):
        # Use keyboard-interactive with CLI callback for prompts
        auth_configs.append(
            create_keyboard_interactive_auth(response_callback=cli_kbdint_callback)
        )

    # If no explicit auth, try GSSAPI, agent, default keys, then password
    if not auth_configs:
        # Try GSSAPI/Kerberos first (if available)
        if check_gssapi_available():
            auth_configs.append(create_gssapi_auth())

        # Try SSH agent
        if get_agent_available():
            auth_configs.append(create_agent_auth())

        # Try default key paths (only if readable)
        for key_path in get_default_key_paths():
            if key_path.exists() and os.access(key_path, os.R_OK):
                auth_configs.append(create_key_auth(key_path))

        # If still nothing, fall back to password (with keyboard-interactive as backup)
        if not auth_configs:
            password = getpass.getpass(f"Password for {username}@{host}: ")
            auth_configs.append(create_password_auth(password))
            # Also add keyboard-interactive for 2FA scenarios
            auth_configs.append(
                create_keyboard_interactive_auth(response_callback=cli_kbdint_callback)
            )

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
            proxy_jump=getattr(args, 'proxy_jump', None),
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
