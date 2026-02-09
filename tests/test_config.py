"""
Tests for SSH config file parsing.

Tests cover:
- Host pattern matching (wildcards, negation)
- Option inheritance and first-match-wins
- Token expansion (%h, %u, %r)
- All supported options
- SSHConnection integration
"""
from __future__ import annotations

import getpass
from pathlib import Path
from unittest.mock import patch

import pytest

from nbs_ssh.config import SSHConfig, SSHHostConfig, get_ssh_config


# ---------------------------------------------------------------------------
# SSHHostConfig Tests
# ---------------------------------------------------------------------------

class TestSSHHostConfig:
    """Test SSHHostConfig dataclass methods."""

    def test_get_hostname_returns_alias(self) -> None:
        """get_hostname returns configured hostname when set."""
        config = SSHHostConfig(hostname="real.example.com")
        assert config.get_hostname("alias") == "real.example.com"

    def test_get_hostname_returns_original_when_not_set(self) -> None:
        """get_hostname returns original when no hostname configured."""
        config = SSHHostConfig()
        assert config.get_hostname("original.example.com") == "original.example.com"

    def test_get_port_returns_configured(self) -> None:
        """get_port returns configured port when set."""
        config = SSHHostConfig(port=2222)
        assert config.get_port() == 2222

    def test_get_port_returns_default(self) -> None:
        """get_port returns default when not configured."""
        config = SSHHostConfig()
        assert config.get_port() == 22
        assert config.get_port(default=2222) == 2222

    def test_get_user_returns_configured(self) -> None:
        """get_user returns configured user when set."""
        config = SSHHostConfig(user="testuser")
        assert config.get_user() == "testuser"

    def test_get_user_returns_default(self) -> None:
        """get_user returns default when not configured."""
        config = SSHHostConfig()
        assert config.get_user(default="myuser") == "myuser"

    def test_get_user_falls_back_to_current_user(self) -> None:
        """get_user returns current username when no default."""
        config = SSHHostConfig()
        assert config.get_user() == getpass.getuser()


# ---------------------------------------------------------------------------
# SSHConfig Parsing Tests
# ---------------------------------------------------------------------------

class TestSSHConfigParsing:
    """Test SSH config file parsing."""

    def test_empty_config(self, tmp_path: Path) -> None:
        """Empty config returns default SSHHostConfig."""
        config_file = tmp_path / "config"
        config_file.write_text("")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("example.com")

        assert host_config.hostname is None
        assert host_config.port is None
        assert host_config.user is None

    def test_global_options(self, tmp_path: Path) -> None:
        """Options before any Host block apply globally."""
        config_file = tmp_path / "config"
        config_file.write_text("""
User globaluser
Port 2222

Host example.com
    HostName real.example.com
""")

        ssh_config = SSHConfig(config_files=[config_file])

        # example.com should have global user and its own hostname
        host_config = ssh_config.lookup("example.com")
        assert host_config.user == "globaluser"
        assert host_config.hostname == "real.example.com"
        assert host_config.port == 2222

        # Other hosts should also get global options
        other_config = ssh_config.lookup("other.com")
        assert other_config.user == "globaluser"
        assert other_config.port == 2222

    def test_host_block_options(self, tmp_path: Path) -> None:
        """Options in Host block apply to matching hosts."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host myserver
    HostName server.example.com
    User admin
    Port 2222
    ConnectTimeout 10
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("myserver")

        assert host_config.hostname == "server.example.com"
        assert host_config.user == "admin"
        assert host_config.port == 2222
        assert host_config.connect_timeout == 10

    def test_first_match_wins(self, tmp_path: Path) -> None:
        """First matching Host block's value wins for single-value options."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host myserver
    User firstuser

Host myserver
    User seconduser
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("myserver")

        assert host_config.user == "firstuser"

    def test_wildcard_matching(self, tmp_path: Path) -> None:
        """Host patterns support * wildcard."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host *.example.com
    User exampleuser
    Port 2222

Host dev.*
    User devuser
""")

        ssh_config = SSHConfig(config_files=[config_file])

        # Should match *.example.com
        host_config = ssh_config.lookup("server.example.com")
        assert host_config.user == "exampleuser"
        assert host_config.port == 2222

        # Should match dev.*
        dev_config = ssh_config.lookup("dev.mycompany.com")
        assert dev_config.user == "devuser"

        # Should not match either
        other_config = ssh_config.lookup("other.com")
        assert other_config.user is None

    def test_question_mark_wildcard(self, tmp_path: Path) -> None:
        """Host patterns support ? wildcard for single character."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host server?
    User singlechar
""")

        ssh_config = SSHConfig(config_files=[config_file])

        # Should match server followed by single char
        assert ssh_config.lookup("server1").user == "singlechar"
        assert ssh_config.lookup("serverA").user == "singlechar"

        # Should not match
        assert ssh_config.lookup("server12").user is None
        assert ssh_config.lookup("server").user is None

    def test_negated_pattern(self, tmp_path: Path) -> None:
        """Host patterns support ! for negation."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host * !*.internal.com
    User externaluser
""")

        ssh_config = SSHConfig(config_files=[config_file])

        # Should match (not internal)
        host_config = ssh_config.lookup("external.com")
        assert host_config.user == "externaluser"

        # Should not match (is internal)
        internal_config = ssh_config.lookup("server.internal.com")
        assert internal_config.user is None

    def test_multiple_patterns_in_host(self, tmp_path: Path) -> None:
        """Host can have multiple space-separated patterns."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host server1 server2 server3
    User multiuser
""")

        ssh_config = SSHConfig(config_files=[config_file])

        assert ssh_config.lookup("server1").user == "multiuser"
        assert ssh_config.lookup("server2").user == "multiuser"
        assert ssh_config.lookup("server3").user == "multiuser"
        assert ssh_config.lookup("server4").user is None

    def test_case_insensitive_options(self, tmp_path: Path) -> None:
        """Option names are case-insensitive."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host test
    hostname real.test.com
    HOSTNAME ignored.com
    HostName alsoignored.com
    USER testuser
    port 2222
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("test")

        # First match wins regardless of case
        assert host_config.hostname == "real.test.com"
        assert host_config.user == "testuser"
        assert host_config.port == 2222

    def test_comment_handling(self, tmp_path: Path) -> None:
        """Comments are properly ignored."""
        config_file = tmp_path / "config"
        config_file.write_text("""
# This is a comment
Host test
    # Comment in block
    User testuser # inline comment
    Port 2222  # another inline comment
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("test")

        assert host_config.user == "testuser"
        assert host_config.port == 2222

    def test_equals_syntax(self, tmp_path: Path) -> None:
        """Options can use = instead of space."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host test
    HostName=real.test.com
    User=testuser
    Port=2222
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("test")

        assert host_config.hostname == "real.test.com"
        assert host_config.user == "testuser"
        assert host_config.port == 2222

    def test_quoted_values(self, tmp_path: Path) -> None:
        """Values can be quoted."""
        config_file = tmp_path / "config"
        config_file.write_text('''
Host test
    User "quoted user"
    ProxyCommand "ssh -W %h:%p jumphost"
''')

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("test")

        assert host_config.user == "quoted user"
        assert host_config.proxy_command == "ssh -W test:22 jumphost"


# ---------------------------------------------------------------------------
# Token Expansion Tests
# ---------------------------------------------------------------------------

class TestTokenExpansion:
    """Test SSH config token expansion."""

    def test_hostname_token(self, tmp_path: Path) -> None:
        """%h expands to target hostname."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host myserver
    ProxyCommand ssh -W %h:22 jumphost
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("myserver")

        assert "%h" not in (host_config.proxy_command or "")
        assert "myserver" in (host_config.proxy_command or "")

    def test_user_tokens(self, tmp_path: Path) -> None:
        """%u expands to local username, %r to remote."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host myserver
    User remoteuser
    ProxyCommand ssh -l %u %r@jumphost
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("myserver")

        current_user = getpass.getuser()
        assert "%u" not in (host_config.proxy_command or "")
        assert current_user in (host_config.proxy_command or "")
        assert "remoteuser" in (host_config.proxy_command or "")


# ---------------------------------------------------------------------------
# Multi-Value Options Tests
# ---------------------------------------------------------------------------

class TestMultiValueOptions:
    """Test options that can have multiple values."""

    def test_identity_file_accumulates(self, tmp_path: Path) -> None:
        """Multiple IdentityFile directives accumulate."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host test
    IdentityFile ~/.ssh/key1
    IdentityFile ~/.ssh/key2
    IdentityFile /absolute/key3
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("test")

        assert len(host_config.identity_file) == 3
        names = [p.name for p in host_config.identity_file]
        assert "key1" in names
        assert "key2" in names
        assert "key3" in names


# ---------------------------------------------------------------------------
# Authentication Options Tests
# ---------------------------------------------------------------------------

class TestAuthOptions:
    """Test authentication-related options."""

    def test_identities_only(self, tmp_path: Path) -> None:
        """IdentitiesOnly is parsed correctly."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host test1
    IdentitiesOnly yes

Host test2
    IdentitiesOnly no
""")

        ssh_config = SSHConfig(config_files=[config_file])

        assert ssh_config.lookup("test1").identities_only is True
        assert ssh_config.lookup("test2").identities_only is False

    def test_preferred_authentications(self, tmp_path: Path) -> None:
        """PreferredAuthentications is parsed as list."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host test
    PreferredAuthentications publickey,keyboard-interactive,password
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("test")

        assert host_config.preferred_authentications == [
            "publickey", "keyboard-interactive", "password"
        ]

    def test_pubkey_accepted_algorithms(self, tmp_path: Path) -> None:
        """PubkeyAcceptedAlgorithms is parsed as list."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host test
    PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("test")

        assert host_config.pubkey_accepted_algorithms == [
            "ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"
        ]


# ---------------------------------------------------------------------------
# Other Options Tests
# ---------------------------------------------------------------------------

class TestOtherOptions:
    """Test other SSH config options."""

    def test_forward_agent(self, tmp_path: Path) -> None:
        """ForwardAgent is parsed correctly."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host test
    ForwardAgent yes
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("test")

        assert host_config.forward_agent is True

    def test_proxy_jump(self, tmp_path: Path) -> None:
        """ProxyJump is parsed correctly."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host test
    ProxyJump jumphost.example.com
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("test")

        assert host_config.proxy_jump == "jumphost.example.com"

    def test_proxy_jump_none(self, tmp_path: Path) -> None:
        """ProxyJump none disables jumping when specific host comes first."""
        config_file = tmp_path / "config"
        # NOTE: In OpenSSH, first match wins. To override a wildcard setting,
        # the specific host must come BEFORE the wildcard.
        config_file.write_text("""
Host direct
    ProxyJump none

Host *
    ProxyJump jumphost.example.com
""")

        ssh_config = SSHConfig(config_files=[config_file])

        # direct has none (disabled) - comes first so wins
        assert ssh_config.lookup("direct").proxy_jump is None

        # Other hosts get the wildcard's jump host
        assert ssh_config.lookup("other").proxy_jump == "jumphost.example.com"


# ---------------------------------------------------------------------------
# Multiple Config Files Tests
# ---------------------------------------------------------------------------

class TestMultipleConfigs:
    """Test loading multiple config files."""

    def test_user_config_takes_precedence(self, tmp_path: Path) -> None:
        """User config options take precedence over system config."""
        user_config = tmp_path / "user_config"
        user_config.write_text("""
Host test
    User userconfig
""")

        system_config = tmp_path / "system_config"
        system_config.write_text("""
Host test
    User systemconfig
    Port 2222
""")

        ssh_config = SSHConfig(config_files=[user_config, system_config])
        host_config = ssh_config.lookup("test")

        # User wins for User option
        assert host_config.user == "userconfig"
        # System provides Port (user didn't set it)
        assert host_config.port == 2222


# ---------------------------------------------------------------------------
# get_hosts Tests
# ---------------------------------------------------------------------------

class TestGetHosts:
    """Test getting list of configured hosts."""

    def test_get_hosts_returns_explicit(self, tmp_path: Path) -> None:
        """get_hosts returns explicitly defined hosts (not wildcards)."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host myserver
    HostName server.example.com

Host *.example.com
    User exampleuser

Host dev staging prod
    User deploy
""")

        ssh_config = SSHConfig(config_files=[config_file])
        hosts = ssh_config.get_hosts()

        assert "myserver" in hosts
        assert "dev" in hosts
        assert "staging" in hosts
        assert "prod" in hosts
        # Wildcards excluded
        assert "*.example.com" not in hosts


# ---------------------------------------------------------------------------
# SSHConnection Integration Tests
# ---------------------------------------------------------------------------

class TestSSHConnectionIntegration:
    """Test SSHConnection integration with SSHConfig."""

    def test_connection_resolves_hostname(self, tmp_path: Path) -> None:
        """SSHConnection resolves HostName from config."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host myalias
    HostName real.server.com
    User testuser
    Port 2222
""")

        ssh_config = SSHConfig(config_files=[config_file])

        # Mock to avoid actual connection attempt and auth discovery
        with patch("nbs_ssh.connection.check_gssapi_available", return_value=False):
            with patch("nbs_ssh.connection.check_agent_available", return_value=True):
                from nbs_ssh.connection import SSHConnection
                from nbs_ssh.auth import create_agent_auth
                conn = SSHConnection(
                    host="myalias",
                    ssh_config=ssh_config,
                    use_ssh_config=True,
                    auth=create_agent_auth(),  # Provide explicit auth to avoid discovery
                )

                # Host should be resolved
                assert conn._host == "real.server.com"
                assert conn._port == 2222
                assert conn._username == "testuser"
                assert conn._original_host == "myalias"

    def test_explicit_params_override_config(self, tmp_path: Path) -> None:
        """Explicit SSHConnection parameters override config."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host myalias
    HostName config.server.com
    User configuser
    Port 2222
""")

        ssh_config = SSHConfig(config_files=[config_file])

        with patch("nbs_ssh.connection.check_gssapi_available", return_value=False):
            with patch("nbs_ssh.connection.check_agent_available", return_value=True):
                from nbs_ssh.connection import SSHConnection
                from nbs_ssh.auth import create_agent_auth
                conn = SSHConnection(
                    host="myalias",
                    port=3333,  # Explicit override
                    username="explicituser",  # Explicit override
                    ssh_config=ssh_config,
                    auth=create_agent_auth(),
                )

                # HostName from config (no explicit hostname param)
                assert conn._host == "config.server.com"
                # Explicit values override config
                assert conn._port == 3333
                assert conn._username == "explicituser"

    def test_use_ssh_config_false(self, tmp_path: Path) -> None:
        """use_ssh_config=False disables config loading."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host myalias
    HostName config.server.com
    Port 2222
""")

        with patch("nbs_ssh.config.get_config_path", return_value=config_file):
            with patch("nbs_ssh.connection.check_gssapi_available", return_value=False):
                with patch("nbs_ssh.connection.check_agent_available", return_value=True):
                    from nbs_ssh.connection import SSHConnection
                    from nbs_ssh.auth import create_agent_auth
                    conn = SSHConnection(
                        host="myalias",
                        use_ssh_config=False,
                        auth=create_agent_auth(),
                    )

                    # Should NOT resolve from config
                    assert conn._host == "myalias"
                    assert conn._port == 22
                    assert conn._host_config is None


# ---------------------------------------------------------------------------
# Real-World Config Examples
# ---------------------------------------------------------------------------

class TestRealWorldConfigs:
    """Test with realistic SSH config examples."""

    def test_github_config(self, tmp_path: Path) -> None:
        """Parse a typical GitHub SSH config."""
        config_file = tmp_path / "config"
        config_file.write_text("""
# GitHub configuration
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/github_ed25519
    IdentitiesOnly yes
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("github.com")

        assert host_config.user == "git"
        assert host_config.identities_only is True
        assert len(host_config.identity_file) == 1

    def test_bastion_config(self, tmp_path: Path) -> None:
        """Parse a bastion/jump host config."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host bastion
    HostName bastion.example.com
    User admin
    IdentityFile ~/.ssh/bastion_key
    ForwardAgent yes

Host internal-*
    ProxyJump bastion
    User developer
""")

        ssh_config = SSHConfig(config_files=[config_file])

        bastion = ssh_config.lookup("bastion")
        assert bastion.hostname == "bastion.example.com"
        assert bastion.forward_agent is True

        internal = ssh_config.lookup("internal-server1")
        assert internal.proxy_jump == "bastion"
        assert internal.user == "developer"

    def test_wildcard_with_specific_override(self, tmp_path: Path) -> None:
        """Specific host overrides wildcard settings."""
        config_file = tmp_path / "config"
        config_file.write_text("""
# Specific host first
Host special.example.com
    User specialuser
    Port 2222

# Wildcard for all example.com
Host *.example.com
    User defaultuser
    ConnectTimeout 30
""")

        ssh_config = SSHConfig(config_files=[config_file])

        # Special host gets its specific settings
        special = ssh_config.lookup("special.example.com")
        assert special.user == "specialuser"
        assert special.port == 2222
        # Also gets wildcard settings not overridden
        assert special.connect_timeout == 30

        # Regular host gets wildcard settings
        regular = ssh_config.lookup("regular.example.com")
        assert regular.user == "defaultuser"
        assert regular.connect_timeout == 30


# ---------------------------------------------------------------------------
# Convenience Function Tests
# ---------------------------------------------------------------------------

class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_get_ssh_config(self) -> None:
        """get_ssh_config returns an SSHConfig instance."""
        config = get_ssh_config()
        assert isinstance(config, SSHConfig)

        # Should be able to lookup hosts
        host_config = config.lookup("example.com")
        assert isinstance(host_config, SSHHostConfig)


# ---------------------------------------------------------------------------
# Include Directive Tests
# ---------------------------------------------------------------------------

class TestIncludeDirective:
    """Test SSH config Include directive support."""

    def test_include_loads_subconfig(self, tmp_path: Path) -> None:
        """Include directive loads files from sub-config."""
        # Create sub-config
        config_d = tmp_path / "config.d"
        config_d.mkdir()
        sub_config = config_d / "devgpu.conf"
        sub_config.write_text("""
Host devgpu*
    ProxyJump bastion.example.com
    User developer
""")

        # Create main config with Include
        main_config = tmp_path / "config"
        main_config.write_text(f"""
Include {config_d}/*

Host *
    ConnectTimeout 30
""")

        ssh_config = SSHConfig(config_files=[main_config])
        host_config = ssh_config.lookup("devgpu009")

        assert host_config.proxy_jump == "bastion.example.com"
        assert host_config.user == "developer"
        assert host_config.connect_timeout == 30

    def test_include_glob_pattern(self, tmp_path: Path) -> None:
        """Include with glob pattern loads multiple files."""
        config_d = tmp_path / "config.d"
        config_d.mkdir()

        (config_d / "a.conf").write_text("""
Host server-a
    User usera
""")
        (config_d / "b.conf").write_text("""
Host server-b
    User userb
""")

        main_config = tmp_path / "config"
        main_config.write_text(f"""
Include {config_d}/*.conf
""")

        ssh_config = SSHConfig(config_files=[main_config])

        assert ssh_config.lookup("server-a").user == "usera"
        assert ssh_config.lookup("server-b").user == "userb"

    def test_include_tilde_expansion(self, tmp_path: Path) -> None:
        """Include expands ~ to home directory."""
        # This test verifies the expansion happens without error.
        # We can't easily test with actual ~ without mocking.
        main_config = tmp_path / "config"
        # Include a non-existent path - should not error
        main_config.write_text("""
Include ~/.ssh/config.d/*
""")

        # Should not raise
        ssh_config = SSHConfig(config_files=[main_config])
        host_config = ssh_config.lookup("example.com")
        assert host_config is not None

    def test_include_nonexistent_path(self, tmp_path: Path) -> None:
        """Include with non-existent path is silently skipped."""
        main_config = tmp_path / "config"
        main_config.write_text(f"""
Include {tmp_path}/nonexistent/*

Host test
    User testuser
""")

        ssh_config = SSHConfig(config_files=[main_config])
        assert ssh_config.lookup("test").user == "testuser"

    def test_include_position_dependent(self, tmp_path: Path) -> None:
        """Include is position-dependent (first match wins)."""
        config_d = tmp_path / "config.d"
        config_d.mkdir()
        (config_d / "first.conf").write_text("""
Host myhost
    User firstuser
""")

        main_config = tmp_path / "config"
        main_config.write_text(f"""
Include {config_d}/*

Host myhost
    User seconduser
""")

        ssh_config = SSHConfig(config_files=[main_config])
        # First match wins - included file comes first
        assert ssh_config.lookup("myhost").user == "firstuser"


# ---------------------------------------------------------------------------
# Match Host Block Tests
# ---------------------------------------------------------------------------

class TestMatchHostBlocks:
    """Test SSH config Match host block support."""

    def test_match_host_pattern(self, tmp_path: Path) -> None:
        """Match host applies options based on resolved hostname."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host devgpu009
    HostName devgpu009.ncg6.facebook.com

Match host *.facebook.com
    User specialuser
    ProxyJump bastion.facebook.com
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("devgpu009")

        assert host_config.hostname == "devgpu009.ncg6.facebook.com"
        assert host_config.user == "specialuser"
        assert host_config.proxy_jump == "bastion.facebook.com"

    def test_match_host_wildcard(self, tmp_path: Path) -> None:
        """Match host with wildcard pattern."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Match host *.example.com
    User matchuser
""")

        ssh_config = SSHConfig(config_files=[config_file])

        assert ssh_config.lookup("server.example.com").user == "matchuser"
        assert ssh_config.lookup("other.org").user is None

    def test_match_all(self, tmp_path: Path) -> None:
        """Match all applies to all hosts."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Match all
    ConnectTimeout 60
""")

        ssh_config = SSHConfig(config_files=[config_file])

        assert ssh_config.lookup("anything.com").connect_timeout == 60
        assert ssh_config.lookup("other.org").connect_timeout == 60

    def test_match_host_after_hostname_resolution(self, tmp_path: Path) -> None:
        """Match host evaluates against resolved hostname (post-HostName)."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host myalias
    HostName real.server.facebook.com

Match host *.facebook.com
    ProxyJump bastion
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("myalias")

        # Match should work against resolved hostname
        assert host_config.proxy_jump == "bastion"

    def test_unsupported_match_criteria_skipped(self, tmp_path: Path) -> None:
        """Unsupported Match criteria are silently skipped."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Match user *
    Port 2222

Host test
    User testuser
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("test")

        # Match user should be skipped (unsupported)
        assert host_config.port is None
        assert host_config.user == "testuser"

    def test_host_block_wins_over_match_for_first_set(self, tmp_path: Path) -> None:
        """Host block options (set first) take precedence over Match block."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Host myserver
    User hostuser

Match host myserver
    User matchuser
    Port 2222
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("myserver")

        # First match wins: Host block set User first
        assert host_config.user == "hostuser"
        # Match block can still add new options
        assert host_config.port == 2222

    def test_match_host_comma_separated_patterns(self, tmp_path: Path) -> None:
        """Match host with comma-separated patterns (OpenSSH format)."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Match host *.facebook.com,*.thefacebook.com,*.fbinfra.net,dev,dev*
    ProxyCommand x2ssh -fallback -tunnel %h
""")

        ssh_config = SSHConfig(config_files=[config_file])

        # Should match *.facebook.com
        cfg = ssh_config.lookup("devgpu009.ncg6.facebook.com")
        assert cfg.proxy_command is not None
        assert "x2ssh" in cfg.proxy_command

        # Should match *.fbinfra.net
        cfg2 = ssh_config.lookup("server.fbinfra.net")
        assert cfg2.proxy_command is not None

        # Should match dev*
        cfg3 = ssh_config.lookup("devserver")
        assert cfg3.proxy_command is not None

        # Should NOT match
        cfg4 = ssh_config.lookup("other.example.com")
        assert cfg4.proxy_command is None

    def test_match_host_negated_comma_patterns(self, tmp_path: Path) -> None:
        """Match host with negated patterns in comma-separated list."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Match host !*.thefacebook.com,*-arvrusr*,*-fbuser*
    Port 2222
""")

        ssh_config = SSHConfig(config_files=[config_file])

        # Should match *-arvrusr* but not *.thefacebook.com
        cfg = ssh_config.lookup("host-arvrusr-01")
        assert cfg.port == 2222

        # Should NOT match — matches negated pattern
        cfg2 = ssh_config.lookup("host-arvrusr-01.thefacebook.com")
        assert cfg2.port is None

        # Should NOT match — no positive pattern matches
        cfg3 = ssh_config.lookup("devgpu009.facebook.com")
        assert cfg3.port is None

    def test_match_host_real_world_meta_config(self, tmp_path: Path) -> None:
        """Test against real-world Meta /etc/ssh/ssh_config structure."""
        config_file = tmp_path / "config"
        config_file.write_text("""
Match host !*.thefacebook.com,*-arvrusr*,*-fbuser*
    Port 2222

Match host *.od,*.sb
    ConnectTimeout 10

Match host *.facebook.com,*.thefacebook.com,*.fbinfra.net,dev,dev*
    ProxyCommand x2ssh -fallback -tunnel %h

Match all
    ConnectTimeout 30
""")

        ssh_config = SSHConfig(config_files=[config_file])

        # devgpu009.ncg6.facebook.com should get ProxyCommand from line 42
        cfg = ssh_config.lookup("devgpu009.ncg6.facebook.com")
        assert cfg.proxy_command is not None
        assert "x2ssh" in cfg.proxy_command
        assert "devgpu009.ncg6.facebook.com" in cfg.proxy_command
        # Should also get ConnectTimeout from Match all
        assert cfg.connect_timeout == 30

        # An fbinfra.net host should also get the proxy
        cfg2 = ssh_config.lookup("server.od.fbinfra.net")
        assert cfg2.proxy_command is not None
