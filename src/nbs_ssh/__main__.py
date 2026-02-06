"""
CLI interface for nbs-ssh.

Usage:
    python -m nbs_ssh user@host              # Interactive shell
    python -m nbs_ssh user@host command      # Execute command
    python -m nbs_ssh -p 2222 user@host command
    python -m nbs_ssh -i keyfile user@host command
    python -m nbs_ssh --password user@host command
    python -m nbs_ssh --keyboard-interactive user@host command
    python -m nbs_ssh -I /usr/lib/opensc-pkcs11.so user@host command  # PKCS#11
    python -m nbs_ssh --events user@host command
    python -m nbs_ssh -L 8080:localhost:80 user@host  # Local forward
    python -m nbs_ssh -R 9090:localhost:3000 user@host  # Remote forward
    python -m nbs_ssh -D 1080 user@host  # Dynamic SOCKS
    python -m nbs_ssh -N -L 8080:localhost:80 user@host  # Forwarding only
    python -m nbs_ssh --help
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import os
import re
import signal
import sys
from pathlib import Path

from nbs_ssh.secure_string import SecureString


def cli_unknown_host_callback(host: str, port: int, key) -> bool:
    """
    Prompt user to accept an unknown host key.

    Called when ASK policy encounters an unknown host.

    Args:
        host: Server hostname
        port: Server port
        key: Server's public key (asyncssh.SSHKey)

    Returns:
        True if user accepts the key, False to reject.
    """
    from nbs_ssh import get_key_fingerprint

    fingerprint = get_key_fingerprint(key)
    key_type = key.get_algorithm()

    print(
        f"The authenticity of host '{host}' ({port}) can't be established.",
        file=sys.stderr,
    )
    print(f"{key_type} key fingerprint is {fingerprint}.", file=sys.stderr)

    while True:
        try:
            response = input("Are you sure you want to continue connecting (yes/no)? ")
            response = response.strip().lower()
            if response in ("yes", "y"):
                print(
                    f"Warning: Permanently added '{host}' ({key_type}) to the list of "
                    "known hosts.",
                    file=sys.stderr,
                )
                return True
            elif response in ("no", "n"):
                print("Host key verification failed.", file=sys.stderr)
                return False
            else:
                print("Please type 'yes' or 'no': ", end="", file=sys.stderr)
        except (EOFError, KeyboardInterrupt):
            print("\nHost key verification failed.", file=sys.stderr)
            return False


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


def parse_local_forward(spec: str) -> tuple[str | None, int, str, int]:
    """
    Parse local forward specification.

    Formats:
        port:host:hostport          → (None, port, host, hostport)
        bind_addr:port:host:hostport → (bind_addr, port, host, hostport)
        *:port:host:hostport        → ("", port, host, hostport)

    Args:
        spec: Forward specification string

    Returns:
        Tuple of (bind_host, bind_port, dest_host, dest_port)

    Raises:
        ValueError: If spec format is invalid
    """
    # Handle IPv6 addresses in brackets
    # Pattern: [bind_addr]:port:host:hostport or port:host:hostport
    ipv6_pattern = r'^\[([^\]]+)\]:(\d+):(.+):(\d+)$'
    match = re.match(ipv6_pattern, spec)
    if match:
        bind_host, bind_port, dest_host, dest_port = match.groups()
        return bind_host, int(bind_port), dest_host, int(dest_port)

    parts = spec.split(":")
    if len(parts) == 3:
        # port:host:hostport
        return None, int(parts[0]), parts[1], int(parts[2])
    elif len(parts) == 4:
        # bind_addr:port:host:hostport
        bind_host = "" if parts[0] == "*" else parts[0]
        return bind_host, int(parts[1]), parts[2], int(parts[3])
    else:
        raise ValueError(
            f"Invalid local forward spec: {spec!r}. "
            "Expected [bind_addr:]port:host:hostport"
        )


def parse_remote_forward(spec: str) -> tuple[str | None, int, str, int]:
    """
    Parse remote forward specification.

    Formats:
        port:host:hostport          → (None, port, host, hostport)
        bind_addr:port:host:hostport → (bind_addr, port, host, hostport)
        *:port:host:hostport        → ("", port, host, hostport)

    Args:
        spec: Forward specification string

    Returns:
        Tuple of (bind_host, bind_port, dest_host, dest_port)

    Raises:
        ValueError: If spec format is invalid
    """
    # Same parsing as local forward
    return parse_local_forward(spec)


def parse_dynamic_forward(spec: str) -> tuple[str | None, int]:
    """
    Parse dynamic (SOCKS) forward specification.

    Formats:
        port            → (None, port)
        bind_addr:port  → (bind_addr, port)
        *:port          → ("", port)

    Args:
        spec: Forward specification string

    Returns:
        Tuple of (bind_host, bind_port)

    Raises:
        ValueError: If spec format is invalid
    """
    # Handle IPv6 addresses in brackets
    ipv6_pattern = r'^\[([^\]]+)\]:(\d+)$'
    match = re.match(ipv6_pattern, spec)
    if match:
        bind_host, bind_port = match.groups()
        return bind_host, int(bind_port)

    parts = spec.split(":")
    if len(parts) == 1:
        # port only
        return None, int(parts[0])
    elif len(parts) == 2:
        # bind_addr:port
        bind_host = "" if parts[0] == "*" else parts[0]
        return bind_host, int(parts[1])
    else:
        raise ValueError(
            f"Invalid dynamic forward spec: {spec!r}. "
            "Expected [bind_addr:]port"
        )


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
        "-I", "--pkcs11-provider",
        metavar="LIB",
        help="PKCS#11 shared library for smart card/HSM authentication "
             "(e.g., /usr/lib/opensc-pkcs11.so, /usr/lib/libykcs11.so)",
    )

    parser.add_argument(
        "-J", "--proxy-jump",
        metavar="HOST",
        help="Jump host(s) for connection tunnelling (like ssh -J). "
             "Use comma-separated hosts for chaining: host1,host2",
    )

    parser.add_argument(
        "-o", "--proxy-command",
        metavar="COMMAND",
        help="Command whose stdin/stdout becomes the SSH transport "
             "(like ssh -o ProxyCommand=...). Tokens %%h, %%p are expanded. "
             "Takes precedence over --proxy-jump.",
    )

    parser.add_argument(
        "--events",
        action="store_true",
        help="Print JSONL events to stderr",
    )

    parser.add_argument(
        "--no-host-check",
        action="store_true",
        help="Disable host key verification (insecure). Equivalent to "
             "--strict-host-key-checking=no",
    )

    parser.add_argument(
        "--strict-host-key-checking",
        metavar="MODE",
        choices=["yes", "ask", "no", "accept-new"],
        default="ask",
        help="Host key verification mode (default: ask). "
             "yes: reject unknown hosts (scripts). "
             "ask: prompt for unknown hosts. "
             "accept-new: accept and save unknown, reject changed. "
             "no: accept all (INSECURE, testing only).",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Connection timeout in seconds (default: 30)",
    )

    # Port forwarding options (OpenSSH parity)
    parser.add_argument(
        "-L", "--local-forward",
        metavar="[BIND:]PORT:HOST:HOSTPORT",
        action="append",
        dest="local_forward",
        help="Forward local port to remote host:port. "
             "Can be specified multiple times.",
    )

    parser.add_argument(
        "-R", "--remote-forward",
        metavar="[BIND:]PORT:HOST:HOSTPORT",
        action="append",
        dest="remote_forward",
        help="Forward remote port to local host:port. "
             "Can be specified multiple times.",
    )

    parser.add_argument(
        "-D", "--dynamic-forward",
        metavar="[BIND:]PORT",
        action="append",
        dest="dynamic_forward",
        help="Dynamic SOCKS port forwarding. "
             "Can be specified multiple times.",
    )

    parser.add_argument(
        "-N", "--no-command",
        action="store_true",
        dest="no_command",
        help="Do not execute remote command (forwarding only mode)",
    )

    parser.add_argument(
        "--verbose",
        action="count",
        default=0,
        help="Verbose mode (use multiple times for more verbosity: "
             "--verbose, --verbose --verbose, etc.)",
    )

    # Extended OpenSSH-compatible options
    parser.add_argument(
        "-A", "--forward-agent",
        action="store_true",
        dest="forward_agent",
        help="Enable SSH agent forwarding",
    )

    parser.add_argument(
        "-C", "--compress",
        action="store_true",
        help="Enable compression",
    )

    parser.add_argument(
        "-X", "--forward-x11",
        action="store_true",
        dest="forward_x11",
        help="Enable X11 forwarding",
    )

    parser.add_argument(
        "-Y", "--forward-x11-trusted",
        action="store_true",
        dest="forward_x11_trusted",
        help="Enable trusted X11 forwarding",
    )

    parser.add_argument(
        "-t", "--force-tty",
        action="store_true",
        dest="force_tty",
        help="Force pseudo-tty allocation",
    )

    parser.add_argument(
        "-T", "--disable-tty",
        action="store_true",
        dest="disable_tty",
        help="Disable pseudo-tty allocation",
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (suppress warnings)",
    )

    parser.add_argument(
        "-V", "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    # SSH config file options
    parser.add_argument(
        "-F", "--config-file",
        metavar="FILE",
        dest="config_file",
        help="Use specified config file instead of ~/.ssh/config",
    )

    parser.add_argument(
        "-G", "--print-config",
        action="store_true",
        dest="print_config",
        help="Print resolved configuration and exit (like ssh -G)",
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
        ForwardManager,
        SSHConnection,
        check_gssapi_available,
        check_pkcs11_available,
        create_agent_auth,
        create_gssapi_auth,
        create_key_auth,
        create_keyboard_interactive_auth,
        create_password_auth,
        create_pkcs11_auth,
        get_agent_available,
        get_default_key_paths,
    )
    from nbs_ssh.config import SSHConfig
    from nbs_ssh.events import EventCollector

    # Set up logging based on verbosity and quiet mode
    quiet = getattr(args, 'quiet', False)
    verbose = getattr(args, 'verbose', 0) if not quiet else 0

    if quiet:
        # Suppress warnings - only show errors
        logging.basicConfig(
            level=logging.ERROR,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            stream=sys.stderr,
        )
        logging.getLogger("asyncssh").setLevel(logging.ERROR)
    elif verbose > 0:
        level = logging.DEBUG if verbose >= 2 else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            stream=sys.stderr,
        )
        # Also enable asyncssh logging at appropriate level
        if verbose >= 3:
            logging.getLogger("asyncssh").setLevel(logging.DEBUG)
        elif verbose >= 2:
            logging.getLogger("asyncssh").setLevel(logging.INFO)

    # Parse target to get host alias and optional user
    host_alias, target_user = parse_target(args.target)

    # Load SSH config file(s)
    # Precedence: CLI args > user config > system config
    config_file = getattr(args, 'config_file', None)
    if config_file:
        # Use only the specified config file
        ssh_config = SSHConfig(config_files=[config_file], load_system_config=False)
    else:
        # Use default ~/.ssh/config and /etc/ssh/ssh_config
        ssh_config = SSHConfig()

    # Look up host configuration
    host_config = ssh_config.lookup(host_alias)

    # Handle -G (print config and exit)
    if getattr(args, 'print_config', False):
        # Print resolved configuration like ssh -G
        print(f"host {host_alias}")
        print(f"hostname {host_config.get_hostname(host_alias)}")
        print(f"port {host_config.get_port(args.port)}")
        user = args.login or target_user or host_config.user
        if user:
            print(f"user {user}")
        if host_config.identity_file:
            for identity in host_config.identity_file:
                print(f"identityfile {identity}")
        if host_config.forward_agent:
            print("forwardagent yes")
        if host_config.proxy_command:
            print(f"proxycommand {host_config.proxy_command}")
        if host_config.proxy_jump:
            print(f"proxyjump {host_config.proxy_jump}")
        if host_config.identities_only:
            print("identitiesonly yes")
        if host_config.connect_timeout:
            print(f"connecttimeout {host_config.connect_timeout}")
        return 0

    # Resolve actual hostname (HostName directive or original)
    host = host_config.get_hostname(host_alias)

    # Resolve username: CLI args > config > current user
    # -l option takes precedence, then user@host, then config
    username = args.login or target_user
    if not username:
        username = host_config.get_user()

    # Resolve port: CLI arg (if non-default) > config > default
    # Only use config port if CLI port wasn't explicitly set
    port = args.port
    if port == 22 and host_config.port is not None:
        port = host_config.port

    # Resolve timeout: CLI arg > config > default
    timeout = args.timeout
    if timeout == 30.0 and host_config.connect_timeout is not None:
        timeout = float(host_config.connect_timeout)

    # Resolve proxy settings: CLI > config
    proxy_jump = getattr(args, 'proxy_jump', None) or host_config.proxy_jump
    proxy_command = getattr(args, 'proxy_command', None) or host_config.proxy_command

    # Resolve ForwardAgent: CLI > config
    forward_agent = getattr(args, 'forward_agent', False) or host_config.forward_agent

    # Track secrets for eradication after use
    secrets_to_eradicate: list[SecureString] = []

    # Build auth config
    auth_configs = []

    # CLI identity file takes priority
    if args.identity:
        key_path = Path(args.identity).expanduser()
        if not key_path.exists():
            print(f"Error: Key file not found: {key_path}", file=sys.stderr)
            return 1
        auth_configs.append(create_key_auth(key_path))
    elif host_config.identity_file:
        # Use identity files from config if no CLI identity specified
        for key_path in host_config.identity_file:
            if key_path.exists() and os.access(key_path, os.R_OK):
                auth_configs.append(create_key_auth(key_path))

    if args.password:
        password = SecureString(getpass.getpass(f"Password for {username}@{host}: "))
        secrets_to_eradicate.append(password)
        auth_configs.append(create_password_auth(password))

    if getattr(args, 'keyboard_interactive', False):
        # Use keyboard-interactive with CLI callback for prompts
        auth_configs.append(
            create_keyboard_interactive_auth(response_callback=cli_kbdint_callback)
        )

    if getattr(args, 'pkcs11_provider', None):
        # PKCS#11 smart card/hardware token authentication
        if not check_pkcs11_available():
            print(
                "Error: PKCS#11 support not available. Install python-pkcs11: "
                "pip install python-pkcs11",
                file=sys.stderr,
            )
            # Eradicate any secrets collected so far
            for secret in secrets_to_eradicate:
                secret.eradicate()
            return 1
        # Prompt for PIN if not provided
        pin_str = getpass.getpass("PKCS#11 PIN (or press Enter for no PIN): ")
        if pin_str:
            pin = SecureString(pin_str)
            secrets_to_eradicate.append(pin)
        else:
            pin = None
        auth_configs.append(
            create_pkcs11_auth(
                provider=args.pkcs11_provider,
                pin=pin,
            )
        )

    # If no explicit auth, try GSSAPI, agent, default keys, then password
    if not auth_configs:
        # Try GSSAPI/Kerberos first (if available)
        if check_gssapi_available():
            auth_configs.append(create_gssapi_auth())

        # Try SSH agent (unless IdentitiesOnly is set in config)
        if get_agent_available() and not host_config.identities_only:
            auth_configs.append(create_agent_auth())

        # Try default key paths (only if readable, and only if not IdentitiesOnly)
        if not host_config.identities_only:
            for key_path in get_default_key_paths():
                if key_path.exists() and os.access(key_path, os.R_OK):
                    auth_configs.append(create_key_auth(key_path))

        # If still nothing, fall back to password (with keyboard-interactive as backup)
        if not auth_configs:
            password = SecureString(getpass.getpass(f"Password for {username}@{host}: "))
            secrets_to_eradicate.append(password)
            auth_configs.append(create_password_auth(password))
            # Also add keyboard-interactive for 2FA scenarios
            auth_configs.append(
                create_keyboard_interactive_auth(response_callback=cli_kbdint_callback)
            )

    # Set up event collection if --events
    event_collector = EventCollector() if args.events else None

    # Host key verification policy
    # --no-host-check takes precedence and is equivalent to --strict-host-key-checking=no
    from nbs_ssh import HostKeyPolicy

    if args.no_host_check:
        host_key_policy = HostKeyPolicy.INSECURE
    else:
        mode = getattr(args, 'strict_host_key_checking', 'ask')
        policy_map = {
            "yes": HostKeyPolicy.STRICT,
            "ask": HostKeyPolicy.ASK,
            "no": HostKeyPolicy.INSECURE,
            "accept-new": HostKeyPolicy.ACCEPT_NEW,
        }
        host_key_policy = policy_map.get(mode, HostKeyPolicy.ASK)

    # Set up callback for ASK policy
    on_unknown_host_key = cli_unknown_host_callback if host_key_policy == HostKeyPolicy.ASK else None

    # Expand tokens in proxy_command if provided (already resolved from CLI or config)
    if proxy_command:
        # Expand %h and %p tokens
        proxy_command = proxy_command.replace("%h", host)
        proxy_command = proxy_command.replace("%p", str(port))
        proxy_command = proxy_command.replace("%%", "%")

    try:
        async with SSHConnection(
            host=host,
            port=port,
            username=username,
            auth=auth_configs,
            host_key_policy=host_key_policy,
            on_unknown_host_key=on_unknown_host_key,
            event_collector=event_collector,
            connect_timeout=timeout,
            proxy_jump=proxy_jump,
            proxy_command=proxy_command,
            agent_forwarding=forward_agent,
            x11_forwarding=getattr(args, 'forward_x11', False) or getattr(args, 'forward_x11_trusted', False),
            compression=getattr(args, 'compress', False),
        ) as conn:
            # Set up port forwarding if requested
            forward_manager = ForwardManager(emitter=event_collector)
            forward_manager.set_connection(conn._conn)  # Access underlying asyncssh connection

            forward_handles = []

            # Set up local forwards (-L)
            for spec in getattr(args, 'local_forward', None) or []:
                try:
                    bind_host, bind_port, dest_host, dest_port = parse_local_forward(spec)
                    handle = await forward_manager.forward_local(
                        local_port=bind_port,
                        remote_host=dest_host,
                        remote_port=dest_port,
                        local_host=bind_host or "localhost",
                    )
                    forward_handles.append(handle)
                    if verbose > 0:
                        print(
                            f"Local forward: {bind_host or 'localhost'}:{handle.local_port} -> "
                            f"{dest_host}:{dest_port}",
                            file=sys.stderr,
                        )
                except ValueError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    return 1

            # Set up remote forwards (-R)
            for spec in getattr(args, 'remote_forward', None) or []:
                try:
                    bind_host, bind_port, dest_host, dest_port = parse_remote_forward(spec)
                    handle = await forward_manager.forward_remote(
                        remote_port=bind_port,
                        local_host=dest_host,
                        local_port=dest_port,
                        remote_host=bind_host or "localhost",
                    )
                    forward_handles.append(handle)
                    if verbose > 0:
                        print(
                            f"Remote forward: {bind_host or 'localhost'}:{handle.local_port} -> "
                            f"{dest_host}:{dest_port}",
                            file=sys.stderr,
                        )
                except ValueError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    return 1

            # Set up dynamic forwards (-D)
            for spec in getattr(args, 'dynamic_forward', None) or []:
                try:
                    bind_host, bind_port = parse_dynamic_forward(spec)
                    handle = await forward_manager.forward_dynamic(
                        local_port=bind_port,
                        local_host=bind_host or "localhost",
                    )
                    forward_handles.append(handle)
                    if verbose > 0:
                        print(
                            f"Dynamic SOCKS forward: {bind_host or 'localhost'}:{handle.local_port}",
                            file=sys.stderr,
                        )
                except ValueError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    return 1

            # Handle -N (no command, forwarding only)
            no_command = getattr(args, 'no_command', False)
            if no_command:
                # Just keep connection alive for forwarding
                if verbose > 0:
                    print(
                        f"Forwarding mode active. Press Ctrl+C to exit.",
                        file=sys.stderr,
                    )
                # Set up signal handler for clean exit
                stop_event = asyncio.Event()

                def signal_handler():
                    stop_event.set()

                loop = asyncio.get_event_loop()
                for sig in (signal.SIGINT, signal.SIGTERM):
                    try:
                        loop.add_signal_handler(sig, signal_handler)
                    except NotImplementedError:
                        # Windows doesn't support add_signal_handler
                        pass

                try:
                    await stop_event.wait()
                except asyncio.CancelledError:
                    pass
                finally:
                    # Close all forwards
                    for handle in forward_handles:
                        await handle.close()
                exit_code = 0
            elif args.command:
                # Determine terminal type based on -t/-T flags
                force_tty = getattr(args, 'force_tty', False)
                disable_tty = getattr(args, 'disable_tty', False)

                if force_tty:
                    # -t: Force PTY allocation
                    term_type = os.environ.get("TERM", "xterm-256color")
                elif disable_tty:
                    # -T: Explicitly disable PTY
                    term_type = None
                else:
                    # Default: no PTY for command execution
                    term_type = None

                result = await conn.exec(args.command, term_type=term_type)

                # Output stdout to stdout, stderr to stderr
                if result.stdout:
                    sys.stdout.write(result.stdout)
                if result.stderr:
                    sys.stderr.write(result.stderr)

                exit_code = result.exit_code

                # Close all forwards
                for handle in forward_handles:
                    await handle.close()
            else:
                # No command - open interactive shell
                try:
                    exit_code = await conn.shell()
                except RuntimeError as e:
                    # Not a TTY - just connect and print message
                    print(f"Connected to {username}@{host}:{args.port}", file=sys.stderr)
                    print(f"(Interactive shell not available: {e})", file=sys.stderr)
                    exit_code = 0

                # Close all forwards
                for handle in forward_handles:
                    await handle.close()

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        exit_code = 1

    finally:
        # Eradicate all secrets (passwords, PINs) from memory
        for secret in secrets_to_eradicate:
            secret.eradicate()

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
