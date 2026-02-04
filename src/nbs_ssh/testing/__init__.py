"""
Testing utilities for nbs-ssh.

Provides MockSSHServer for falsifiable integration testing without Docker.
"""
from nbs_ssh.testing.mock_server import MockSSHServer, MockServerConfig

__all__ = ["MockSSHServer", "MockServerConfig"]
