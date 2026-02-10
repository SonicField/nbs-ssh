"""
OpenSSH-style connection multiplexing (ControlMaster).

Provides:
- ControlMaster: Server that holds an SSH connection and accepts multiplexed clients
- MultiplexClient: Client that connects via an existing master
- ControlSocket: Socket path management with token expansion

This allows multiple SSH sessions to share a single TCP connection,
avoiding repeated authentication.

Usage:
    # Master mode (-M):
    master = ControlMaster(socket_path)
    async with SSHConnection(...) as conn:
        await master.start(conn)
        await master.wait_closed()

    # Client mode (-S):
    client = MultiplexClient(socket_path)
    if await client.check_master():
        exit_code = await client.exec("command")
    else:
        # Fall back to direct connection
        ...
"""
from __future__ import annotations

import asyncio
import enum
import getpass
import json
import logging
import os
import re
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import asyncssh

from nbs_ssh.platform import expand_path


logger = logging.getLogger(__name__)


class ControlMasterMode(enum.Enum):
    """ControlMaster option values (matching OpenSSH)."""
    NO = "no"            # Disable multiplexing
    YES = "yes"          # Always be master
    AUTO = "auto"        # Become master if no existing socket
    AUTOASK = "autoask"  # Like auto, but ask before becoming master


class ControlCommand(enum.Enum):
    """Control commands for -O option."""
    CHECK = "check"      # Check if master is running
    FORWARD = "forward"  # Request forwardings only (not implemented)
    CANCEL = "cancel"    # Cancel forwardings (not implemented)
    EXIT = "exit"        # Request master to exit
    STOP = "stop"        # Request master to stop accepting new sessions


class MessageType(enum.Enum):
    """IPC message types for master-client protocol."""
    # Client -> Master
    HELLO = "hello"           # Initial handshake
    EXEC = "exec"             # Execute command
    SHELL = "shell"           # Open interactive shell
    CHECK = "check"           # Check if master alive
    EXIT = "exit"             # Request master exit
    STOP = "stop"             # Stop accepting new connections
    FORWARD_LOCAL = "fwd_l"   # Request local forward
    FORWARD_REMOTE = "fwd_r"  # Request remote forward
    FORWARD_CANCEL = "fwd_c"  # Cancel forward

    # Master -> Client
    OK = "ok"                 # Success response
    ERROR = "error"           # Error response
    STDOUT = "stdout"         # Stdout data
    STDERR = "stderr"         # Stderr data
    EXIT_STATUS = "exit"      # Command exit status


@dataclass
class ControlMessage:
    """Message exchanged between master and client."""
    msg_type: MessageType
    data: dict[str, Any] = field(default_factory=dict)

    def encode(self) -> bytes:
        """Encode message for transmission."""
        payload = json.dumps({
            "type": self.msg_type.value,
            "data": self.data,
        }).encode("utf-8")
        # Length-prefixed framing (4 bytes, big-endian)
        return struct.pack(">I", len(payload)) + payload

    @classmethod
    def decode(cls, data: bytes) -> "ControlMessage":
        """Decode message from received data."""
        obj = json.loads(data.decode("utf-8"))
        return cls(
            msg_type=MessageType(obj["type"]),
            data=obj.get("data", {}),
        )


def expand_control_path(
    template: str,
    host: str,
    port: int = 22,
    remote_user: str | None = None,
    local_user: str | None = None,
    local_host: str | None = None,
) -> Path:
    """
    Expand OpenSSH tokens in control socket path.

    Tokens:
        %h - target host
        %p - port
        %r - remote username
        %u - local username
        %L - local hostname (short)
        %l - local hostname (FQDN)
        %C - hash of connection parameters (simplified)
        %n - original host name (same as %h here)
        %% - literal %

    Args:
        template: Path template with tokens
        host: Target hostname
        port: SSH port
        remote_user: Remote username
        local_user: Local username (defaults to current user)
        local_host: Local hostname (defaults to socket.gethostname())

    Returns:
        Expanded Path object
    """
    import hashlib
    import socket

    if local_user is None:
        local_user = getpass.getuser()
    if remote_user is None:
        remote_user = local_user
    if local_host is None:
        local_host = socket.gethostname()

    # Get short and FQDN local hostname
    local_host_short = local_host.split(".")[0]
    try:
        local_host_fqdn = socket.getfqdn()
    except Exception:
        local_host_fqdn = local_host

    # Generate connection hash (simplified version of OpenSSH's %C)
    conn_str = f"{local_host}:{remote_user}@{host}:{port}"
    conn_hash = hashlib.sha256(conn_str.encode()).hexdigest()[:16]

    # Perform substitutions
    result = template
    result = result.replace("%%", "\x00")  # Temporary placeholder
    result = result.replace("%h", host)
    result = result.replace("%p", str(port))
    result = result.replace("%r", remote_user)
    result = result.replace("%u", local_user)
    result = result.replace("%L", local_host_short)
    result = result.replace("%l", local_host_fqdn)
    result = result.replace("%C", conn_hash)
    result = result.replace("%n", host)
    result = result.replace("\x00", "%")

    return expand_path(result)


class ControlMaster:
    """
    SSH connection multiplexing master.

    Holds an SSH connection and accepts requests from clients via Unix socket.
    Each client request is executed using the shared connection.
    """

    def __init__(
        self,
        socket_path: Path | str,
        persist_time: float | None = None,
    ) -> None:
        """
        Initialise control master.

        Args:
            socket_path: Path for the Unix control socket
            persist_time: Seconds to keep running after last client disconnects.
                         None means run until explicitly stopped.
                         0 means exit immediately when last client disconnects.
        """
        self._socket_path = Path(socket_path)
        self._persist_time = persist_time
        self._server: asyncio.Server | None = None
        self._connection: asyncssh.SSHClientConnection | None = None
        self._stopping = False
        self._accepting = True
        self._active_clients = 0
        self._last_client_time: float | None = None
        self._persist_task: asyncio.Task | None = None
        self._closed = asyncio.Event()

    @property
    def socket_path(self) -> Path:
        """Get the control socket path."""
        return self._socket_path

    @property
    def is_running(self) -> bool:
        """Check if master is running."""
        return self._server is not None and not self._stopping

    async def start(self, connection: asyncssh.SSHClientConnection) -> None:
        """
        Start the control master server.

        Args:
            connection: The SSH connection to multiplex

        Raises:
            OSError: If socket creation fails
        """
        self._connection = connection
        self._stopping = False
        self._closed.clear()

        # Ensure parent directory exists
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove stale socket if exists
        if self._socket_path.exists():
            try:
                self._socket_path.unlink()
            except OSError:
                pass

        # Create Unix socket server
        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(self._socket_path),
        )

        # Set restrictive permissions (owner only)
        os.chmod(self._socket_path, 0o600)

        logger.info(f"ControlMaster listening on {self._socket_path}")

    async def wait_closed(self) -> None:
        """Wait for the master to close."""
        await self._closed.wait()

    async def stop(self) -> None:
        """Stop the control master."""
        if self._stopping:
            return

        self._stopping = True
        self._accepting = False

        if self._persist_task:
            self._persist_task.cancel()
            try:
                await self._persist_task
            except asyncio.CancelledError:
                pass

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Clean up socket file
        try:
            if self._socket_path.exists():
                self._socket_path.unlink()
        except OSError:
            pass

        self._closed.set()
        logger.info("ControlMaster stopped")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a client connection."""
        if not self._accepting:
            # Not accepting new connections
            await self._send_message(
                writer,
                ControlMessage(MessageType.ERROR, {"error": "Master not accepting connections"}),
            )
            writer.close()
            await writer.wait_closed()
            return

        self._active_clients += 1
        logger.debug(f"Client connected (active: {self._active_clients})")

        try:
            while True:
                try:
                    msg = await self._recv_message(reader)
                    if msg is None:
                        break

                    await self._handle_message(msg, reader, writer)

                    # Exit after single request (non-persistent session)
                    if msg.msg_type in (MessageType.EXEC, MessageType.SHELL):
                        break

                except (asyncio.IncompleteReadError, ConnectionResetError):
                    break
                except Exception as e:
                    logger.exception(f"Error handling client: {e}")
                    await self._send_message(
                        writer,
                        ControlMessage(MessageType.ERROR, {"error": str(e)}),
                    )
                    break
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            self._active_clients -= 1
            self._last_client_time = time.time()
            logger.debug(f"Client disconnected (active: {self._active_clients})")

            # Check if we should exit due to persist timeout
            if self._active_clients == 0 and self._persist_time is not None:
                if self._persist_time == 0:
                    # Exit immediately
                    asyncio.create_task(self.stop())
                else:
                    # Schedule exit after persist time
                    self._schedule_persist_exit()

    async def _handle_message(
        self,
        msg: ControlMessage,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single message from client."""
        assert self._connection is not None

        if msg.msg_type == MessageType.HELLO:
            await self._send_message(
                writer,
                ControlMessage(MessageType.OK, {"version": 1}),
            )

        elif msg.msg_type == MessageType.CHECK:
            await self._send_message(
                writer,
                ControlMessage(MessageType.OK, {"status": "running"}),
            )

        elif msg.msg_type == MessageType.EXIT:
            await self._send_message(
                writer,
                ControlMessage(MessageType.OK, {"status": "exiting"}),
            )
            asyncio.create_task(self.stop())

        elif msg.msg_type == MessageType.STOP:
            self._accepting = False
            await self._send_message(
                writer,
                ControlMessage(MessageType.OK, {"status": "stopped"}),
            )

        elif msg.msg_type == MessageType.EXEC:
            await self._handle_exec(msg, reader, writer)

        elif msg.msg_type == MessageType.SHELL:
            await self._handle_shell(msg, reader, writer)

        else:
            await self._send_message(
                writer,
                ControlMessage(MessageType.ERROR, {"error": f"Unknown message type: {msg.msg_type}"}),
            )

    async def _handle_exec(
        self,
        msg: ControlMessage,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle command execution request."""
        assert self._connection is not None

        command = msg.data.get("command", "")
        env = msg.data.get("env")
        term_type = msg.data.get("term_type")

        try:
            # Execute command on the multiplexed connection
            result = await self._connection.run(
                command,
                check=False,
                term_type=term_type,
                env=env,
            )

            # Send stdout
            if result.stdout:
                await self._send_message(
                    writer,
                    ControlMessage(MessageType.STDOUT, {"data": result.stdout}),
                )

            # Send stderr
            if result.stderr:
                await self._send_message(
                    writer,
                    ControlMessage(MessageType.STDERR, {"data": result.stderr}),
                )

            # Send exit status
            exit_code = result.exit_status if result.exit_status is not None else -1
            await self._send_message(
                writer,
                ControlMessage(MessageType.EXIT_STATUS, {"exit_code": exit_code}),
            )

        except Exception as e:
            await self._send_message(
                writer,
                ControlMessage(MessageType.ERROR, {"error": str(e)}),
            )

    async def _handle_shell(
        self,
        msg: ControlMessage,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle interactive shell request."""
        assert self._connection is not None

        term_type = msg.data.get("term_type", "xterm")
        term_width = msg.data.get("term_width", 80)
        term_height = msg.data.get("term_height", 24)

        try:
            # Create shell process
            process = await self._connection.create_process(
                None,
                term_type=term_type,
                term_size=(term_width, term_height),
            )

            # Proxy I/O between client and shell
            await self._proxy_shell(process, reader, writer)

            exit_code = process.exit_status or 0
            await self._send_message(
                writer,
                ControlMessage(MessageType.EXIT_STATUS, {"exit_code": exit_code}),
            )

        except Exception as e:
            await self._send_message(
                writer,
                ControlMessage(MessageType.ERROR, {"error": str(e)}),
            )

    async def _proxy_shell(
        self,
        process: asyncssh.SSHClientProcess,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Proxy I/O between client socket and SSH shell."""
        done = False

        async def read_client() -> None:
            """Read from client and send to shell."""
            nonlocal done
            while not done:
                try:
                    msg = await self._recv_message(reader)
                    if msg is None:
                        process.stdin.write_eof()
                        break
                    if msg.msg_type == MessageType.STDOUT:
                        data = msg.data.get("data", "")
                        process.stdin.write(data)
                except Exception:
                    break

        async def read_shell() -> None:
            """Read from shell and send to client."""
            nonlocal done
            while not done:
                try:
                    data = await process.stdout.read(4096)
                    if data:
                        await self._send_message(
                            writer,
                            ControlMessage(MessageType.STDOUT, {"data": data}),
                        )
                    else:
                        break
                except Exception:
                    break

        client_task = asyncio.create_task(read_client())
        shell_task = asyncio.create_task(read_shell())
        wait_task = asyncio.create_task(process.wait())

        try:
            await asyncio.wait(
                {client_task, shell_task, wait_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            done = True
        finally:
            for task in [client_task, shell_task]:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    def _schedule_persist_exit(self) -> None:
        """Schedule exit after persist timeout."""
        assert self._persist_time is not None and self._persist_time > 0, \
            f"_schedule_persist_exit called with invalid persist_time: {self._persist_time}"

        if self._persist_task:
            self._persist_task.cancel()

        async def check_exit() -> None:
            await asyncio.sleep(self._persist_time)
            if self._active_clients == 0:
                await self.stop()

        self._persist_task = asyncio.create_task(check_exit())

    async def _send_message(
        self,
        writer: asyncio.StreamWriter,
        msg: ControlMessage,
    ) -> None:
        """Send a message to the client."""
        writer.write(msg.encode())
        await writer.drain()

    async def _recv_message(
        self,
        reader: asyncio.StreamReader,
    ) -> ControlMessage | None:
        """Receive a message from the client."""
        try:
            # Read length prefix
            length_data = await reader.readexactly(4)
            length = struct.unpack(">I", length_data)[0]

            # Read payload
            if length > 10 * 1024 * 1024:  # 10MB limit
                raise ValueError(f"Message too large: {length}")

            payload = await reader.readexactly(length)
            return ControlMessage.decode(payload)

        except asyncio.IncompleteReadError:
            return None


class MultiplexClient:
    """
    Client for connecting via an existing ControlMaster.

    Connects to the control socket and sends requests to the master,
    which executes them using the shared SSH connection.
    """

    def __init__(self, socket_path: Path | str) -> None:
        """
        Initialise multiplex client.

        Args:
            socket_path: Path to the control socket
        """
        self._socket_path = Path(socket_path)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    @property
    def socket_path(self) -> Path:
        """Get the control socket path."""
        return self._socket_path

    async def connect(self) -> bool:
        """
        Connect to the control master.

        Returns:
            True if connected successfully, False otherwise
        """
        if not self._socket_path.exists():
            return False

        try:
            self._reader, self._writer = await asyncio.open_unix_connection(
                str(self._socket_path)
            )

            # Send hello and wait for response
            await self._send_message(ControlMessage(MessageType.HELLO))
            response = await self._recv_message()

            if response and response.msg_type == MessageType.OK:
                return True

            await self.close()
            return False

        except (OSError, ConnectionRefusedError):
            return False

    async def close(self) -> None:
        """Close the connection to master."""
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

    async def check(self) -> bool:
        """
        Check if master is running.

        Returns:
            True if master is alive, False otherwise
        """
        if not await self.connect():
            return False

        try:
            await self._send_message(ControlMessage(MessageType.CHECK))
            response = await self._recv_message()
            return response is not None and response.msg_type == MessageType.OK
        finally:
            await self.close()

    async def request_exit(self) -> bool:
        """
        Request master to exit.

        Returns:
            True if exit request sent successfully
        """
        if not await self.connect():
            return False

        try:
            await self._send_message(ControlMessage(MessageType.EXIT))
            response = await self._recv_message()
            return response is not None and response.msg_type == MessageType.OK
        finally:
            await self.close()

    async def request_stop(self) -> bool:
        """
        Request master to stop accepting new connections.

        Returns:
            True if stop request sent successfully
        """
        if not await self.connect():
            return False

        try:
            await self._send_message(ControlMessage(MessageType.STOP))
            response = await self._recv_message()
            return response is not None and response.msg_type == MessageType.OK
        finally:
            await self.close()

    async def exec(
        self,
        command: str,
        env: dict[str, str] | None = None,
        term_type: str | None = None,
    ) -> tuple[str, str, int]:
        """
        Execute a command via the master.

        Args:
            command: Command to execute
            env: Optional environment variables
            term_type: Optional terminal type for PTY

        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        if not await self.connect():
            raise ConnectionError(f"Cannot connect to master at {self._socket_path}")

        try:
            await self._send_message(
                ControlMessage(MessageType.EXEC, {
                    "command": command,
                    "env": env,
                    "term_type": term_type,
                })
            )

            stdout = ""
            stderr = ""
            exit_code = -1

            while True:
                response = await self._recv_message()
                if response is None:
                    break

                if response.msg_type == MessageType.STDOUT:
                    stdout += response.data.get("data", "")
                elif response.msg_type == MessageType.STDERR:
                    stderr += response.data.get("data", "")
                elif response.msg_type == MessageType.EXIT_STATUS:
                    exit_code = response.data.get("exit_code", -1)
                    break
                elif response.msg_type == MessageType.ERROR:
                    raise RuntimeError(response.data.get("error", "Unknown error"))

            return stdout, stderr, exit_code

        finally:
            await self.close()

    async def _send_message(self, msg: ControlMessage) -> None:
        """Send a message to the master."""
        assert self._writer is not None
        self._writer.write(msg.encode())
        await self._writer.drain()

    async def _recv_message(self) -> ControlMessage | None:
        """Receive a message from the master."""
        assert self._reader is not None
        try:
            length_data = await self._reader.readexactly(4)
            length = struct.unpack(">I", length_data)[0]

            if length > 10 * 1024 * 1024:
                raise ValueError(f"Message too large: {length}")

            payload = await self._reader.readexactly(length)
            return ControlMessage.decode(payload)

        except asyncio.IncompleteReadError:
            return None


def parse_control_persist(value: str) -> float | None:
    """
    Parse ControlPersist value.

    Args:
        value: "yes", "no", or a time specification (e.g., "10m", "1h", "30s")

    Returns:
        None for infinite persistence, 0 for no persistence,
        or seconds for timed persistence
    """
    value = value.strip().lower()

    if value in ("yes", "true", "1"):
        return None  # Infinite

    if value in ("no", "false", "0"):
        return 0.0  # Exit when last client disconnects

    # Parse time specification
    match = re.match(r"^(\d+)([smhd]?)$", value)
    if not match:
        raise ValueError(f"Invalid ControlPersist value: {value}")

    num = int(match.group(1))
    unit = match.group(2) or "s"

    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return float(num * multipliers[unit])
