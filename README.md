# nbs-ssh

AI-inspectable SSH client library and CLI built on AsyncSSH.

## Features

- **Interactive shell**: Full PTY support, just like `ssh`
- **Command execution**: Run commands, get structured results
- **Streaming output**: Async iterator for real-time output
- **Port forwarding**: Local (-L), remote (-R), dynamic SOCKS (-D)
- **Supervisor runtime**: Liveness metrics, freeze detection, auto-reconnection
- **Automated interaction**: Expect/respond patterns without terminal emulation
- **Evidence-first diagnostics**: JSONL event logs, reproducible failure bundles
- **Pure-Python testing**: MockSSHServer for testing without Docker

## Installation

```bash
git clone https://github.com/SonicField/nbs-ssh.git
cd nbs-ssh
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## CLI Usage

```bash
# Interactive shell (like ssh)
python -m nbs_ssh user@host

# Execute command
python -m nbs_ssh user@host "echo hello"

# With options
python -m nbs_ssh -p 2222 user@host              # Custom port
python -m nbs_ssh -i ~/.ssh/id_ed25519 user@host # Specific key
python -m nbs_ssh --events user@host "cmd"       # JSONL event logging
```

Add to your shell for convenience:
```bash
# In ~/.bashrc or ~/.zshrc
py-ssh() {
  PYTHONPATH=~/path/to/nbs-ssh/src ~/path/to/nbs-ssh/venv/bin/python -m nbs_ssh "$@"
}
```

## Library Usage

```python
import asyncio
from nbs_ssh import SSHConnection

async def main():
    async with SSHConnection(
        host="example.com",
        username="user",
        known_hosts=None,  # Or path to known_hosts
    ) as conn:
        # Simple command execution
        result = await conn.exec("echo hello")
        print(result.stdout)  # "hello\n"
        print(result.exit_code)  # 0

        # Streaming output
        async for event in await conn.stream_exec("long-running-command"):
            if event.stream == "stdout":
                print(event.data, end="")

asyncio.run(main())
```

## Authentication

nbs-ssh tries authentication methods in order:

1. **SSH agent** (if `SSH_AUTH_SOCK` is set)
2. **Default keys** (`~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, etc.)
3. **Password prompt** (only if nothing else works)

Explicit authentication:
```python
from nbs_ssh import SSHConnection, create_key_auth, create_password_auth

async with SSHConnection(
    host="example.com",
    username="user",
    auth=[create_key_auth("~/.ssh/my_key")],
) as conn:
    ...
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [User Guide](docs/user-guide.md)
- [Debugging Guide](docs/debugging.md)
- [API Reference](docs/api-reference.md)
- [Testing Guide](docs/testing.md)

## Testing

nbs-ssh uses a **pure-Python testing approach** with no Docker required.

```bash
# Run all tests
source venv/bin/activate
PYTHONPATH=src pytest tests/ -v

# Run specific test file
PYTHONPATH=src pytest tests/test_connection.py -v
```

### Key Testing Features

- **MockSSHServer**: A real AsyncSSH server that binds to port 0 for parallel test execution
- **Falsifiable security tests**: Tests that actively attempt attacks (weak ciphers, downgrade attacks) and verify they fail
- **No Docker dependency**: All 261 tests run against MockSSHServer
- **Real command execution**: MockSSHServer can execute actual shell commands when needed

See [Testing Guide](docs/testing.md) for the full testing philosophy and how to write tests.

## Development

```bash
# Run tests (no Docker required)
source venv/bin/activate
PYTHONPATH=src pytest tests/ -v

# Tests use MockSSHServer - a pure-Python SSH server for testing
```

## Licence

MIT
