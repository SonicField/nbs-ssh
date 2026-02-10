"""
SSH config file parsing matching OpenSSH behaviour.

Provides:
- SSHConfig: Parser for ~/.ssh/config and /etc/ssh/ssh_config
- SSHHostConfig: Resolved configuration for a specific host

Supports:
- Host pattern matching with wildcards (*, ?)
- Option inheritance and overrides
- All auth-related options
"""
from __future__ import annotations

import fnmatch
import getpass
import logging
import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from nbs_ssh.platform import expand_path, get_config_path, get_system_config_path

log = logging.getLogger("nbs_ssh.config")


@dataclass
class SSHHostConfig:
    """
    Resolved SSH configuration for a specific host.

    Contains all options that apply to a host after processing
    Host blocks and pattern matching.
    """
    # Connection options
    hostname: str | None = None
    port: int | None = None
    user: str | None = None
    connect_timeout: int | None = None

    # Keepalive options (ServerAliveInterval / ServerAliveCountMax)
    server_alive_interval: int | None = None
    server_alive_count_max: int | None = None

    # Authentication options
    identity_file: list[Path] = field(default_factory=list)
    identity_agent: str | None = None  # Path to agent socket (IdentityAgent)
    identities_only: bool = False
    preferred_authentications: list[str] | None = None
    pubkey_accepted_algorithms: list[str] | None = None
    pkcs11_provider: str | None = None  # PKCS#11 shared library path

    # Connection multiplexing (ControlMaster)
    control_master: str | None = None    # yes/no/auto/autoask
    control_path: str | None = None      # Socket path template
    control_persist: str | None = None   # yes/no/time

    # Other useful options
    forward_agent: bool = False
    proxy_command: str | None = None
    proxy_jump: str | None = None

    def get_hostname(self, original_host: str) -> str:
        """Get the real hostname to connect to."""
        assert original_host and isinstance(original_host, str), (
            f"get_hostname() requires a non-empty original_host, got {original_host!r}"
        )
        return self.hostname if self.hostname else original_host

    def get_port(self, default: int = 22) -> int:
        """Get the port to connect to."""
        return self.port if self.port is not None else default

    def get_user(self, default: str | None = None) -> str | None:
        """Get the username for authentication."""
        if self.user:
            return self.user
        if default:
            return default
        return getpass.getuser()


@dataclass
class _HostBlock:
    """Internal representation of a Host block in config."""
    patterns: list[str]
    options: dict[str, str | list[str]]
    is_match: bool = False  # True for Match blocks


class SSHConfig:
    """
    Parser for SSH config files.

    Matches OpenSSH behaviour:
    - Reads user config (~/.ssh/config) then system config (/etc/ssh/ssh_config)
    - First match wins for most options
    - Host patterns support * and ? wildcards
    - Token expansion (%h, %u, %r, etc.)

    Usage:
        config = SSHConfig()  # Auto-loads user and system configs
        host_config = config.lookup("myserver.example.com")

        # Or load from specific files
        config = SSHConfig(config_files=["/path/to/config"])
    """

    # Options that accumulate (multiple values allowed)
    MULTI_VALUE_OPTIONS = frozenset({
        "identityfile",
        "sendenv",
        "setenv",
    })

    # Case-insensitive option name mapping to canonical form
    OPTION_ALIASES: dict[str, str] = {
        "hostname": "hostname",
        "port": "port",
        "user": "user",
        "identityfile": "identityfile",
        "identitiesonly": "identitiesonly",
        "preferredauthentications": "preferredauthentications",
        "pubkeyacceptedalgorithms": "pubkeyacceptedalgorithms",
        "pubkeyacceptedkeytypes": "pubkeyacceptedalgorithms",  # Deprecated alias
        "connecttimeout": "connecttimeout",
        "serveraliveinterval": "serveraliveinterval",
        "serveralivecountmax": "serveralivecountmax",
        "connectionattempts": "connectionattempts",
        "forwardagent": "forwardagent",
        "identityagent": "identityagent",
        "proxycommand": "proxycommand",
        "proxyjump": "proxyjump",
        "pkcs11provider": "pkcs11provider",
        # Connection multiplexing
        "controlmaster": "controlmaster",
        "controlpath": "controlpath",
        "controlpersist": "controlpersist",
    }

    def __init__(
        self,
        config_files: list[Path | str] | None = None,
        load_system_config: bool = True,
    ) -> None:
        """
        Initialise SSH config parser.

        Args:
            config_files: Specific config files to load (overrides default)
            load_system_config: Whether to also load /etc/ssh/ssh_config
        """
        self._host_blocks: list[_HostBlock] = []
        self._global_options: dict[str, str | list[str]] = {}

        if config_files is not None:
            for config_file in config_files:
                self._load_file(Path(config_file))
        else:
            # Load user config first (takes precedence)
            user_config = get_config_path()
            self._load_file(user_config)

            # Then system config
            if load_system_config:
                system_config = get_system_config_path()
                self._load_file(system_config)

    def _load_file(self, config_path: Path) -> None:
        """Load and parse a config file."""
        if not config_path.exists():
            log.debug("Config file not found: %s", config_path)
            return

        log.debug("Reading configuration data %s", config_path)
        try:
            with open(config_path, "r", encoding="utf-8", errors="replace") as f:
                self._parse(f.read(), config_path)
        except (OSError, IOError):
            log.warning("Could not read config file: %s", config_path)

    def _parse(self, content: str, source_path: Path | None = None) -> None:
        """Parse SSH config content."""
        current_block: _HostBlock | None = None

        for line_no, line in enumerate(content.splitlines(), 1):
            # Strip whitespace and skip empty lines
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Handle inline comments (only # preceded by whitespace)
            comment_idx = line.find(" #")
            if comment_idx >= 0:
                line = line[:comment_idx].rstrip()

            # Parse option name and value
            # SSH config allows both "Option Value" and "Option=Value"
            if "=" in line and " " not in line.split("=", 1)[0]:
                option, value = line.split("=", 1)
            else:
                parts = line.split(None, 1)
                if len(parts) < 2:
                    log.warning(
                        "Malformed config line %d in %s: '%s' (expected 'Option Value')",
                        line_no,
                        source_path or "<unknown>",
                        line,
                    )
                    continue
                option, value = parts

            option = option.strip().lower()
            value = value.strip()

            # Remove surrounding quotes if present
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            elif value.startswith("'") and value.endswith("'"):
                value = value[1:-1]

            # Handle Include directive
            if option == "include":
                # Close current block if any (Include always starts new context)
                if current_block:
                    self._host_blocks.append(current_block)
                    current_block = None

                # Resolve and load included files
                self._handle_include(value, source_path)
                continue

            # Handle Host and Match blocks
            if option == "host":
                # Save previous block if any
                if current_block:
                    self._host_blocks.append(current_block)

                # Start new block
                patterns = self._parse_patterns(value)
                current_block = _HostBlock(patterns=patterns, options={})

            elif option == "match":
                # Save previous block if any
                if current_block:
                    self._host_blocks.append(current_block)

                # Parse Match criteria
                match_patterns, is_host_match = self._parse_match_criteria(value)

                if is_host_match:
                    current_block = _HostBlock(
                        patterns=match_patterns,
                        options={},
                        is_match=True,
                    )
                else:
                    # Unsupported Match criteria — create block but it won't match
                    import sys
                    print(f"Warning: Unsupported Match criteria: {value}", file=sys.stderr)
                    current_block = _HostBlock(
                        patterns=[],
                        options={},
                        is_match=True,
                    )

            else:
                # Regular option
                canonical = self.OPTION_ALIASES.get(option, option)

                if current_block is not None:
                    self._set_option(current_block.options, canonical, value)
                else:
                    self._set_option(self._global_options, canonical, value)

        # Save final block
        if current_block:
            self._host_blocks.append(current_block)

    def _parse_patterns(self, value: str) -> list[str]:
        """Parse Host pattern value into list of patterns."""
        # Patterns are space-separated, but can be quoted
        patterns = []
        in_quotes = False
        current = []
        quote_char = None

        for char in value:
            if char in ('"', "'") and not in_quotes:
                in_quotes = True
                quote_char = char
            elif char == quote_char and in_quotes:
                in_quotes = False
                quote_char = None
            elif char == " " and not in_quotes:
                if current:
                    patterns.append("".join(current))
                    current = []
            else:
                current.append(char)

        if current:
            patterns.append("".join(current))

        return patterns

    def _handle_include(self, pattern: str, source_path: Path | None = None) -> None:
        """Handle Include directive by loading matching config files."""
        import glob as glob_module

        # Expand ~ to home directory
        expanded = os.path.expanduser(pattern)

        # If relative path, resolve relative to the config file's directory
        if not os.path.isabs(expanded) and source_path is not None:
            expanded = str(source_path.parent / expanded)

        # Glob to find matching files
        matches = sorted(glob_module.glob(expanded))
        log.debug("Include %s → %d file(s)", pattern, len(matches))

        for match_path in matches:
            path = Path(match_path)
            if path.is_file():
                self._load_file(path)

    def _parse_match_criteria(self, value: str) -> tuple[list[str], bool]:
        """Parse Match block criteria.

        Currently supports:
        - Match host <pattern>[,<pattern>,...] (comma-separated, per OpenSSH)
        - Match all (matches everything)

        Other criteria (user, exec, localuser, etc.) are not supported
        and will be silently skipped with a warning.

        Note: OpenSSH uses comma-separated patterns for Match host
        (unlike Host blocks which are space-separated).

        Returns:
            Tuple of (patterns, is_host_match) where is_host_match indicates
            whether this is a supported Match block.
        """
        parts = value.strip().split()
        if not parts:
            return [], False

        keyword = parts[0].lower()

        if keyword == "all":
            return ["*"], True

        if keyword == "host":
            # Remaining parts are host patterns — comma-separated per OpenSSH
            # e.g. "Match host *.facebook.com,*.fbinfra.net,dev*"
            raw = " ".join(parts[1:]) if len(parts) > 1 else ""
            patterns = [p.strip() for p in raw.split(",") if p.strip()]
            return patterns, bool(patterns)

        # Unsupported criteria
        return [], False

    def _set_option(
        self,
        options: dict[str, str | list[str]],
        name: str,
        value: str,
    ) -> None:
        """Set an option, handling multi-value options correctly."""
        if name in self.MULTI_VALUE_OPTIONS:
            if name not in options:
                options[name] = []
            # Type assertion for mypy
            option_list = options[name]
            assert isinstance(option_list, list), (
                f"Expected list for multi-value option '{name}', "
                f"got {type(option_list).__name__}. "
                f"This indicates _set_option was called after a single-value "
                f"option was already stored for '{name}'."
            )
            option_list.append(value)
        else:
            # First match wins for single-value options
            if name not in options:
                options[name] = value

    def _matches_host_block(self, host: str, patterns: list[str]) -> bool:
        """Check if host matches a Host block's patterns.

        OpenSSH behaviour:
        - Multiple patterns on one Host line are OR'd together
        - But negated patterns (!) exclude hosts even if they match positive patterns
        - A host must match at least one positive pattern AND no negated patterns
        """
        matched_positive = False
        excluded = False

        for pattern in patterns:
            if pattern.startswith("!"):
                # Negated pattern - check if it excludes this host
                actual_pattern = pattern[1:]
                if fnmatch.fnmatch(host.lower(), actual_pattern.lower()):
                    excluded = True
            else:
                # Positive pattern
                if fnmatch.fnmatch(host.lower(), pattern.lower()):
                    matched_positive = True

        # Must match at least one positive and not be excluded
        return matched_positive and not excluded

    def _matches_pattern(self, host: str, pattern: str) -> bool:
        """Check if host matches a pattern.

        Patterns support:
        - * matches any sequence of characters
        - ? matches exactly one character
        - ! prefix negates the match
        """
        negated = pattern.startswith("!")
        if negated:
            pattern = pattern[1:]

        # Convert SSH wildcard pattern to fnmatch pattern
        # SSH uses same wildcards as fnmatch
        match = fnmatch.fnmatch(host.lower(), pattern.lower())

        return not match if negated else match

    def _expand_tokens(
        self,
        value: str,
        host: str,
        user: str | None = None,
        local_user: str | None = None,
        port: int = 22,
    ) -> str:
        """Expand SSH config tokens in a value.

        Tokens:
        - %h: target hostname
        - %p: port (default 22)
        - %r: remote username
        - %u: local username
        - %n: original hostname
        - %%: literal %
        """
        if local_user is None:
            local_user = getpass.getuser()
        if user is None:
            user = local_user

        result = value
        result = result.replace("%%", "\x00")  # Temporary placeholder
        result = result.replace("%h", host)
        result = result.replace("%p", str(port))
        result = result.replace("%n", host)
        result = result.replace("%r", user)
        result = result.replace("%u", local_user)
        result = result.replace("\x00", "%")

        return result

    def lookup(self, host: str) -> SSHHostConfig:
        """
        Look up configuration for a specific host.

        Two-pass evaluation matching OpenSSH behaviour:
        1. First pass: evaluate Host blocks against the original hostname
        2. Second pass: evaluate Match host blocks against the resolved
           hostname (post-HostName aliasing)

        First match wins for single-value options.

        Args:
            host: The hostname to look up (as specified by user)

        Returns:
            SSHHostConfig with all applicable options
        """
        # Precondition: host must be a non-empty string
        assert host and isinstance(host, str), (
            f"lookup() requires a non-empty host string, got {host!r}"
        )

        # Start with empty config
        merged: dict[str, str | list[str]] = {}

        # Apply global options first
        for key, value in self._global_options.items():
            if isinstance(value, list):
                for v in value:
                    self._set_option(merged, key, v)
            else:
                self._set_option(merged, key, value)

        # First pass: Apply matching Host blocks (skip Match blocks)
        for block in self._host_blocks:
            if block.is_match:
                continue

            if self._matches_host_block(host, block.patterns):
                for key, value in block.options.items():
                    if isinstance(value, list):
                        for v in value:
                            self._set_option(merged, key, v)
                    else:
                        self._set_option(merged, key, value)

        # Second pass: Apply matching Match host blocks
        # Use resolved hostname (post-HostName aliasing)
        resolved_host = str(merged.get("hostname", host))

        for block in self._host_blocks:
            if not block.is_match:
                continue
            if not block.patterns:
                continue  # Unsupported Match criteria

            if self._matches_host_block(resolved_host, block.patterns):
                for key, value in block.options.items():
                    if isinstance(value, list):
                        for v in value:
                            self._set_option(merged, key, v)
                    else:
                        self._set_option(merged, key, value)

        # Build SSHHostConfig from merged options
        return self._build_host_config(merged, host)

    def _build_host_config(
        self,
        options: dict[str, str | list[str]],
        host: str,
    ) -> SSHHostConfig:
        """Build SSHHostConfig from merged options dict."""
        config = SSHHostConfig()

        # Get user first (needed for token expansion)
        if "user" in options:
            config.user = str(options["user"])

        # Port (needed for token expansion)
        if "port" in options:
            try:
                port_val = int(options["port"])
                if not (1 <= port_val <= 65535):
                    log.warning(
                        "Port value %d out of valid range (1-65535), ignoring",
                        port_val,
                    )
                else:
                    config.port = port_val
            except ValueError:
                log.warning(
                    "Invalid port value '%s', expected integer",
                    options["port"],
                )

        # Get port for token expansion (use configured or default)
        port_for_tokens = config.port if config.port is not None else 22

        # HostName (with token expansion)
        if "hostname" in options:
            hostname = str(options["hostname"])
            config.hostname = self._expand_tokens(
                hostname, host, config.user, port=port_for_tokens
            )

        # ConnectTimeout
        if "connecttimeout" in options:
            try:
                config.connect_timeout = int(options["connecttimeout"])
            except ValueError:
                log.warning(
                    "Invalid ConnectTimeout value '%s', expected integer",
                    options["connecttimeout"],
                )

        # ServerAliveInterval
        if "serveraliveinterval" in options:
            try:
                val = int(options["serveraliveinterval"])
                if val >= 0:
                    config.server_alive_interval = val
                else:
                    log.warning(
                        "ServerAliveInterval must be non-negative, got %d", val
                    )
            except ValueError:
                log.warning(
                    "Invalid ServerAliveInterval value '%s', expected integer",
                    options["serveraliveinterval"],
                )

        # ServerAliveCountMax
        if "serveralivecountmax" in options:
            try:
                val = int(options["serveralivecountmax"])
                if val > 0:
                    config.server_alive_count_max = val
                else:
                    log.warning(
                        "ServerAliveCountMax must be positive, got %d", val
                    )
            except ValueError:
                log.warning(
                    "Invalid ServerAliveCountMax value '%s', expected integer",
                    options["serveralivecountmax"],
                )

        # IdentityFile (multi-value, with expansion)
        if "identityfile" in options:
            identity_files = options["identityfile"]
            if isinstance(identity_files, str):
                identity_files = [identity_files]
            for path_str in identity_files:
                expanded = self._expand_tokens(
                    path_str, host, config.user, port=port_for_tokens
                )
                config.identity_file.append(expand_path(expanded))

        # IdentitiesOnly
        if "identitiesonly" in options:
            val = str(options["identitiesonly"]).lower()
            config.identities_only = val in ("yes", "true", "1")

        # IdentityAgent (path to agent socket, with ~ expansion)
        if "identityagent" in options:
            agent_path = str(options["identityagent"])
            if agent_path.lower() != "none":
                config.identity_agent = os.path.expanduser(agent_path)

        # PreferredAuthentications
        if "preferredauthentications" in options:
            val = str(options["preferredauthentications"])
            config.preferred_authentications = [
                m.strip() for m in val.split(",")
            ]

        # PubkeyAcceptedAlgorithms
        if "pubkeyacceptedalgorithms" in options:
            val = str(options["pubkeyacceptedalgorithms"])
            config.pubkey_accepted_algorithms = [
                a.strip() for a in val.split(",")
            ]

        # ForwardAgent
        if "forwardagent" in options:
            val = str(options["forwardagent"]).lower()
            config.forward_agent = val in ("yes", "true", "1")

        # ProxyCommand (with token expansion including %p)
        if "proxycommand" in options:
            cmd = str(options["proxycommand"])
            if cmd.lower() != "none":
                config.proxy_command = self._expand_tokens(
                    cmd, host, config.user, port=port_for_tokens
                )

        # ProxyJump
        if "proxyjump" in options:
            jump = str(options["proxyjump"])
            if jump.lower() != "none":
                config.proxy_jump = jump

        # PKCS11Provider
        if "pkcs11provider" in options:
            provider = str(options["pkcs11provider"])
            if provider.lower() != "none":
                config.pkcs11_provider = provider

        # ControlMaster
        if "controlmaster" in options:
            config.control_master = str(options["controlmaster"]).lower()

        # ControlPath (with token expansion)
        if "controlpath" in options:
            path = str(options["controlpath"])
            if path.lower() != "none":
                # Don't expand tokens here - will be done at connection time
                # when we know the full connection details
                config.control_path = path

        # ControlPersist
        if "controlpersist" in options:
            config.control_persist = str(options["controlpersist"])

        # Postcondition: if port is set, it must be in valid range
        assert config.port is None or (1 <= config.port <= 65535), (
            f"Port postcondition violated: port {config.port} not in range 1-65535. "
            f"This should have been caught during port parsing above."
        )

        return config

    def get_hosts(self) -> list[str]:
        """Get all explicitly defined host patterns (not wildcards).

        Useful for tab completion and listing configured hosts.
        """
        hosts = []
        for block in self._host_blocks:
            for pattern in block.patterns:
                # Skip wildcards and negations
                if "*" not in pattern and "?" not in pattern and not pattern.startswith("!"):
                    hosts.append(pattern)
        return hosts


def get_ssh_config() -> SSHConfig:
    """
    Get the default SSH config (user + system configs).

    This is a convenience function for common use cases.
    """
    return SSHConfig()
