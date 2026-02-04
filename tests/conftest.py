"""
Pytest fixtures for nbs-ssh integration tests.

Provides:
- SSH server fixture (Docker-based)
- Event capture fixture for asserting event sequences
- Known hosts fixture for test environment
"""
from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, AsyncGenerator, Generator

import pytest

if TYPE_CHECKING:
    from nbs_ssh.events import Event, EventCollector


# Path to docker directory relative to this file
DOCKER_DIR = Path(__file__).parent.parent / "docker"
TEST_KEY_PATH = DOCKER_DIR / "keys" / "test_key"


@dataclass
class SSHServerInfo:
    """Connection details for the test SSH server."""
    host: str
    port: int
    username: str
    password: str
    key_path: Path
    known_hosts_path: Path


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def wait_for_port(host: str, port: int, timeout: float = 30.0) -> bool:
    """Wait for a port to become available."""
    import time
    start = time.time()
    while time.time() - start < timeout:
        if is_port_open(host, port):
            return True
        time.sleep(0.5)
    return False


@pytest.fixture(scope="session")
def docker_available() -> bool:
    """Check if Docker is available."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@pytest.fixture(scope="session")
def ssh_server(docker_available: bool) -> Generator[SSHServerInfo | None, None, None]:
    """
    Start the Docker SSH test server for the session.

    Yields SSHServerInfo with connection details, or None if Docker unavailable.
    """
    if not docker_available:
        pytest.skip("Docker not available - skipping SSH integration tests")
        yield None
        return

    # Check if container already running
    host = "localhost"
    port = 2222

    # Try to start the container
    compose_file = DOCKER_DIR / "docker-compose.yml"
    if not compose_file.exists():
        pytest.skip(f"docker-compose.yml not found at {compose_file}")
        yield None
        return

    try:
        # Build and start
        subprocess.run(
            ["docker-compose", "-f", str(compose_file), "up", "-d", "--build"],
            capture_output=True,
            timeout=120,
            check=True,
            cwd=DOCKER_DIR,
        )
    except subprocess.CalledProcessError as e:
        pytest.skip(f"Failed to start Docker SSH server: {e.stderr.decode()}")
        yield None
        return
    except FileNotFoundError:
        pytest.skip("docker-compose not found")
        yield None
        return

    # Wait for SSH to be ready
    if not wait_for_port(host, port, timeout=30):
        pytest.skip(f"SSH server did not become ready on {host}:{port}")
        yield None
        return

    # Get host key and create known_hosts file
    known_hosts_fd, known_hosts_path = tempfile.mkstemp(prefix="known_hosts_")
    try:
        # Scan host key
        result = subprocess.run(
            ["ssh-keyscan", "-p", str(port), host],
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0:
            os.write(known_hosts_fd, result.stdout)
        os.close(known_hosts_fd)

        yield SSHServerInfo(
            host=host,
            port=port,
            username="testuser",
            password="testpass123",
            key_path=TEST_KEY_PATH,
            known_hosts_path=Path(known_hosts_path),
        )
    finally:
        # Cleanup known_hosts file
        Path(known_hosts_path).unlink(missing_ok=True)

        # Stop container (optional - leave running for faster iteration)
        # subprocess.run(
        #     ["docker-compose", "-f", str(compose_file), "down"],
        #     capture_output=True,
        #     cwd=DOCKER_DIR,
        # )


@pytest.fixture
def event_collector() -> Generator["EventCollector", None, None]:
    """
    Fixture for capturing and asserting event sequences.

    Usage:
        def test_example(event_collector):
            # Run code that emits events
            connection = SSHConnection(event_collector=event_collector)
            ...

            # Assert event sequence
            events = event_collector.events
            assert events[0].event_type == "CONNECT"
    """
    from nbs_ssh.events import EventCollector

    collector = EventCollector()
    yield collector
    collector.clear()


@pytest.fixture
def temp_jsonl_path(tmp_path: Path) -> Path:
    """Provide a temporary path for JSONL event log output."""
    return tmp_path / "events.jsonl"
