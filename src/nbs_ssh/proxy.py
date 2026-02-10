"""
ProxyCommand support for SSH connections.

Provides:
- ProxyCommandProcess: Runs a command and bridges stdin/stdout to asyncssh

OpenSSH's ProxyCommand runs a shell command and uses its stdin/stdout as the
SSH transport. This enables connecting through HTTP CONNECT proxies, SOCKS
proxies, or custom tunnel scripts.

Examples:
    # SOCKS proxy
    ProxyCommand nc -X 5 -x socks-proxy:1080 %h %p

    # HTTP CONNECT proxy
    ProxyCommand corkscrew http-proxy 8080 %h %p

    # Custom script
    ProxyCommand /usr/local/bin/my-tunnel %h %p
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
from typing import Any

log = logging.getLogger("nbs_ssh.proxy")


class ProxyCommandError(Exception):
    """Error running ProxyCommand."""

    def __init__(
        self,
        message: str,
        command: str | None = None,
        exit_code: int | None = None,
        stderr: str | None = None,
    ) -> None:
        super().__init__(message)
        self.command = command
        self.exit_code = exit_code
        self.stderr = stderr


class ProxyCommandProcess:
    """
    Manages a ProxyCommand subprocess for SSH transport.

    This class runs a shell command and provides a socket pair where:
    - One end connects to the subprocess stdin/stdout
    - The other end can be used by asyncssh as the transport

    Usage:
        async with ProxyCommandProcess("nc proxy.example.com 22") as proxy:
            # proxy.get_socket() returns the socket for asyncssh
            conn = await asyncssh.connect(..., sock=proxy.get_socket())
    """

    def __init__(self, command: str) -> None:
        """
        Initialise ProxyCommand process.

        Args:
            command: Shell command to run (tokens should already be expanded)
        """
        if not command or not command.strip():
            raise ProxyCommandError("Empty ProxyCommand", command=command)

        self._command = command
        self._process: asyncio.subprocess.Process | None = None
        self._local_sock: socket.socket | None = None
        self._remote_sock: socket.socket | None = None
        self._bridge_task: asyncio.Task | None = None
        self._closed = False

    @property
    def command(self) -> str:
        """Return the command being run."""
        return self._command

    async def start(self) -> None:
        """Start the ProxyCommand subprocess."""
        # Precondition: not already closed
        assert not self._closed, (
            f"Cannot start ProxyCommand after close() has been called. "
            f"Command: {self._command}"
        )

        if self._process is not None:
            raise RuntimeError("ProxyCommand already started")

        # Create a socket pair for bidirectional communication.
        # asyncssh expects a socket, so we use a socket pair.
        # On Unix: AF_UNIX.  On Windows: socketpair() defaults to AF_INET.
        if hasattr(socket, "AF_UNIX"):
            self._local_sock, self._remote_sock = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_STREAM
            )
        else:
            self._local_sock, self._remote_sock = socket.socketpair(
                socket.AF_INET, socket.SOCK_STREAM
            )

        # Make sockets non-blocking
        self._local_sock.setblocking(False)
        self._remote_sock.setblocking(False)

        # Start the subprocess
        try:
            self._process = await asyncio.create_subprocess_shell(
                self._command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as e:
            self._cleanup_sockets()
            raise ProxyCommandError(
                f"Failed to start ProxyCommand: {e}",
                command=self._command,
            ) from e

        # Check for immediate failure (e.g., command not found)
        # Give it a brief moment to fail
        await asyncio.sleep(0.05)

        if self._process.returncode is not None:
            stderr = ""
            if self._process.stderr:
                try:
                    stderr = (await self._process.stderr.read()).decode(
                        "utf-8", errors="replace"
                    )
                except OSError as e:
                    stderr = f"<stderr read failed: {e}>"
                    log.debug("Failed to read stderr from ProxyCommand: %s", e)
            self._cleanup_sockets()
            raise ProxyCommandError(
                f"ProxyCommand exited immediately with code {self._process.returncode}",
                command=self._command,
                exit_code=self._process.returncode,
                stderr=stderr,
            )

        # Start the bridge task to forward data between socket and subprocess
        self._bridge_task = asyncio.create_task(self._bridge())

        # Postconditions: all state must be initialised after successful start
        assert self._process is not None, (
            "Postcondition violated: _process is not None after start()"
        )
        assert self._local_sock is not None, (
            "Postcondition violated: _local_sock is not None after start()"
        )
        assert self._remote_sock is not None, (
            "Postcondition violated: _remote_sock is not None after start()"
        )
        assert self._bridge_task is not None, (
            "Postcondition violated: _bridge_task is not None after start()"
        )

    async def _bridge(self) -> None:
        """Bridge data between the socket pair and subprocess stdin/stdout."""
        # Precondition: process and socket must exist when bridge is called
        assert self._process is not None, (
            "_bridge called but _process is None — bridge requires a running process"
        )
        assert self._local_sock is not None, (
            "_bridge called but _local_sock is None — bridge requires a connected socket"
        )

        loop = asyncio.get_event_loop()
        assert self._process.stdin is not None, (
            "Process stdin is None — subprocess was not created with stdin=PIPE"
        )
        assert self._process.stdout is not None, (
            "Process stdout is None — subprocess was not created with stdout=PIPE"
        )

        async def socket_to_subprocess() -> None:
            """Forward data from socket to subprocess stdin."""
            while not self._closed:
                try:
                    # Read from socket (using executor for blocking read)
                    data = await loop.sock_recv(self._local_sock, 65536)
                    if not data:
                        # Socket closed
                        break
                    # Write to subprocess stdin
                    self._process.stdin.write(data)
                    await self._process.stdin.drain()
                except (OSError, asyncio.CancelledError, ConnectionError):
                    break

            # Close subprocess stdin when socket closes
            try:
                self._process.stdin.close()
            except OSError as e:
                log.debug("Error closing subprocess stdin: %s", e)

        async def subprocess_to_socket() -> None:
            """Forward data from subprocess stdout to socket."""
            while not self._closed:
                try:
                    # Read from subprocess stdout
                    data = await self._process.stdout.read(65536)
                    if not data:
                        # Subprocess stdout closed
                        break
                    # Write to socket
                    await loop.sock_sendall(self._local_sock, data)
                except (OSError, asyncio.CancelledError, ConnectionError):
                    break

        async def monitor_process() -> None:
            """Monitor subprocess for unexpected exit."""
            await self._process.wait()
            if not self._closed:
                # Process exited unexpectedly
                self._closed = True

        # Run all bridge tasks concurrently
        try:
            await asyncio.gather(
                socket_to_subprocess(),
                subprocess_to_socket(),
                monitor_process(),
            )
        except (OSError, ConnectionError, asyncio.CancelledError) as e:
            log.debug("Bridge terminated: %s", e)

    def get_socket(self) -> socket.socket:
        """
        Get the socket for asyncssh to use.

        Returns:
            Socket connected to the ProxyCommand's stdin/stdout
        """
        if self._remote_sock is None:
            raise RuntimeError("ProxyCommand not started")
        return self._remote_sock

    def _cleanup_sockets(self) -> None:
        """Clean up socket resources."""
        if self._local_sock is not None:
            try:
                self._local_sock.close()
            except OSError as e:
                log.debug("Error closing local socket: %s", e)
            self._local_sock = None

        if self._remote_sock is not None:
            try:
                self._remote_sock.close()
            except OSError as e:
                log.debug("Error closing remote socket: %s", e)
            self._remote_sock = None

    async def close(self) -> None:
        """Close the ProxyCommand subprocess and cleanup."""
        if self._closed:
            return

        self._closed = True

        # Cancel bridge task
        if self._bridge_task is not None:
            self._bridge_task.cancel()
            try:
                await self._bridge_task
            except asyncio.CancelledError:
                pass
            self._bridge_task = None

        # Terminate subprocess
        if self._process is not None:
            try:
                self._process.terminate()
                # Give it a moment to terminate gracefully
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    # Force kill if it doesn't respond
                    self._process.kill()
                    await self._process.wait()
            except (OSError, ProcessLookupError) as e:
                log.debug("Error terminating ProxyCommand process: %s", e)
            self._process = None

        # Clean up sockets
        self._cleanup_sockets()

    async def __aenter__(self) -> "ProxyCommandProcess":
        """Start the ProxyCommand process."""
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Close the ProxyCommand process."""
        await self.close()
