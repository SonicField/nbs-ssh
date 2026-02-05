# Getting Started with nbs-ssh

This guide will get you up and running with nbs-ssh in a few minutes.

## Installation

Clone the repository and install in development mode:

```bash
git clone <repository-url>
cd nbs-ssh

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install with development dependencies
pip install -e ".[dev]"
```

## Quick Start: Connect and Run a Command

Here's the simplest way to connect to an SSH server and run a command:

```python
import asyncio
from pathlib import Path
from nbs_ssh import SSHConnection, create_key_auth

async def main():
    # Create authentication config
    auth = create_key_auth(Path.home() / ".ssh" / "id_ed25519")

    # Connect and execute a command
    async with SSHConnection(
        "example.com",
        username="alice",
        auth=auth,
    ) as conn:
        result = await conn.exec("uname -a")
        print(result.stdout)
        print(f"Exit code: {result.exit_code}")

asyncio.run(main())
```

### Using Password Authentication

```python
from nbs_ssh import SSHConnection, create_password_auth

async def main():
    auth = create_password_auth("your-password")

    async with SSHConnection(
        "example.com",
        username="alice",
        auth=auth,
    ) as conn:
        result = await conn.exec("whoami")
        print(result.stdout)

asyncio.run(main())
```

## CLI Usage

nbs-ssh includes a command-line interface for quick operations:

```bash
# Run a command on a remote host
python -m nbs_ssh alice@example.com "ls -la"

# Use a specific private key
python -m nbs_ssh -i ~/.ssh/id_ed25519 alice@example.com "whoami"

# Custom port
python -m nbs_ssh -p 2222 alice@example.com "date"

# Password authentication (will prompt)
python -m nbs_ssh --password alice@example.com "echo hello"

# Enable event logging to stderr
python -m nbs_ssh --events alice@example.com "uptime" 2>events.jsonl
```

## Streaming Output

For long-running commands or when you need real-time output, use streaming execution:

```python
import asyncio
from nbs_ssh import SSHConnection, create_key_auth

async def main():
    auth = create_key_auth("~/.ssh/id_ed25519")

    async with SSHConnection(
        "example.com",
        username="alice",
        auth=auth,
    ) as conn:
        # Stream output as it arrives
        async for event in conn.stream_exec("tail -f /var/log/syslog"):
            if event.stream == "stdout":
                print(event.data, end="", flush=True)
            elif event.stream == "stderr":
                print(f"[stderr] {event.data}", end="", flush=True)
            elif event.stream == "exit":
                print(f"\nCommand exited with code: {event.exit_code}")
                break

asyncio.run(main())
```

Each `StreamEvent` contains:
- `timestamp`: When the event occurred (Unix milliseconds)
- `stream`: Either `"stdout"`, `"stderr"`, or `"exit"`
- `data`: The output text (empty for exit events)
- `exit_code`: Only set when `stream == "exit"`

## What's Next?

Now that you have the basics working, explore these features:

- **[User Guide](user-guide.md)**: Complete documentation of all features
  - SSHSupervisor for automatic reconnection
  - Port forwarding (local, remote, dynamic/SOCKS)
  - Automation engine for interactive commands (expect/respond)
  - Event logging and evidence bundles

- **[Debugging Guide](debugging.md)**: How to diagnose issues
  - Enable JSONL event logging
  - Analyse evidence bundles
  - Common problems and solutions

- **[API Reference](api-reference.md)**: Complete class and method documentation
  - All constructor parameters
  - Method signatures
  - Usage examples

## Error Handling

nbs-ssh provides specific exception types for different failure modes:

```python
from nbs_ssh import (
    SSHConnection,
    ConnectionRefused,
    ConnectionTimeout,
    AuthFailed,
    HostKeyMismatch,
    SSHError,
)

try:
    async with SSHConnection("host", username="user", auth=auth) as conn:
        await conn.exec("command")
except ConnectionRefused:
    print("Server refused the connection")
except ConnectionTimeout:
    print("Connection timed out")
except AuthFailed:
    print("Authentication failed - check credentials")
except HostKeyMismatch:
    print("Host key mismatch - potential security issue")
except SSHError as e:
    print(f"SSH error: {e}")
```

## Requirements

- Python 3.12+
- AsyncSSH library (installed automatically)
- For testing: Docker (for integration tests with real SSH server)
