"""Interactive SSH event handler.

Provides SSHInteractionHandler — a base class for handling SSH events
that require user input. Consumers subclass and override the methods
they need; unoverridden methods use safe defaults.

Usage:
    class MyHandler(SSHInteractionHandler):
        def on_kbdint(self, name, instructions, prompts):
            return [input(p) for p, echo in prompts]

    SSHConnection(host, interaction_handler=MyHandler())
"""
from __future__ import annotations


class SSHInteractionHandler:
    """Handle interactive SSH events that require user input.

    Implement the methods you need. Unimplemented methods use safe defaults:
    - on_host_key: reject unknown hosts (safe)
    - on_kbdint: return empty responses (auth fails gracefully)
    - on_password_needed: return None (skip password auth)

    The handler is called synchronously from the SSH connection thread.
    Implementations that need GUI interaction (Tk, Qt) must bridge
    to the GUI thread themselves.
    """

    def on_host_key(self, host, port, key_info):
        """Called when the server's host key is unknown or changed.

        Args:
            host: SSH server hostname.
            port: SSH server port.
            key_info: Human-readable key description (algorithm + fingerprint).

        Returns:
            True to accept the key and continue connecting.
            False to reject and abort the connection.
        """
        return False

    def on_kbdint(self, name, instructions, prompts):
        """Called when the server sends a keyboard-interactive challenge.

        This handles 2FA (Duo), password change prompts, and any other
        server-driven interactive authentication.

        Args:
            name: Challenge name from the server (often empty).
            instructions: Instructions to display (often empty).
            prompts: List of (prompt_text, echo_enabled) tuples.
                     echo_enabled=True: input can be shown (e.g. Duo options).
                     echo_enabled=False: input should be masked (e.g. password).

        Returns:
            List of response strings, one per prompt. Length must match prompts.
            Return empty list to cancel authentication.
        """
        return []

    def on_password_needed(self, host, username):
        """Called when password authentication is needed but no password was provided.

        Args:
            host: SSH server hostname.
            username: Username being authenticated.

        Returns:
            Password string, or None to skip password auth.
        """
        return None
