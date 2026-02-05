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
import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from nbs_ssh.platform import expand_path, get_config_path, get_system_config_path


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

    # Authentication options
    identity_file: list[Path] = field(default_factory=list)
    identities_only: bool = False
    preferred_authentications: list[str] | None = None
    pubkey_accepted_algorithms: list[str] | None = None
    pkcs11_provider: str | None = None  # PKCS#11 shared library path

    # Other useful options
    forward_agent: bool = False
    proxy_command: str | None = None
    proxy_jump: str | None = None

    def get_hostname(self, original_host: str) -> str:
        """Get the real hostname to connect to."""
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
        "connectionattempts": "connectionattempts",
        "forwardagent": "forwardagent",
        "proxycommand": "proxycommand",
        "proxyjump": "proxyjump",
        "pkcs11provider": "pkcs11provider",
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
            return

        try:
            with open(config_path, "r", encoding="utf-8", errors="replace") as f:
                self._parse(f.read(), config_path)
        except (OSError, IOError):
            pass  # Skip unreadable configs

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
                    continue  # Skip malformed lines
                option, value = parts

            option = option.strip().lower()
            value = value.strip()

            # Remove surrounding quotes if present
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            elif value.startswith("'") and value.endswith("'"):
                value = value[1:-1]

            # Handle Host and Match blocks
            if option == "host":
                # Save previous block if any
                if current_block:
                    self._host_blocks.append(current_block)

                # Start new block
                patterns = self._parse_patterns(value)
                current_block = _HostBlock(patterns=patterns, options={})

            elif option == "match":
                # Match blocks are more complex - for now, skip them
                if current_block:
                    self._host_blocks.append(current_block)
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
            assert isinstance(option_list, list)
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

        Applies Host blocks in order, with first match winning
        for single-value options.

        Args:
            host: The hostname to look up (as specified by user)

        Returns:
            SSHHostConfig with all applicable options
        """
        # Start with empty config
        merged: dict[str, str | list[str]] = {}

        # Apply global options first
        for key, value in self._global_options.items():
            self._set_option(merged, key, value if isinstance(value, str) else value[0])

        # Apply matching Host blocks
        for block in self._host_blocks:
            if block.is_match:
                continue  # Skip Match blocks for now

            # Check if the host matches this block's patterns
            if self._matches_host_block(host, block.patterns):
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
                config.port = int(options["port"])
            except ValueError:
                pass

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
                pass

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
