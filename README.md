# nbs-ssh

AI-inspectable SSH client library and CLI built on AsyncSSH.

> **⚠️ Security Notice:** nbs-ssh is designed for development, testing, and AI-assisted debugging - not for production deployment in adversarial network conditions. See [Known Security Issues](docs/known-security-issues.md) for details.

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

Requires Python 3.12+.

```bash
pip install git+https://github.com/SonicField/nbs-ssh.git
```

This installs the `nbs-ssh` command into your Python environment's `bin/` directory. It's available directly if you're in an activated venv, or via `pipx` which manages PATH for you.

### Using pipx (recommended for CLI use)

[pipx](https://pipx.pypa.io/) installs the tool in an isolated environment and puts `nbs-ssh` on your PATH automatically.

**Linux (Debian/Ubuntu):**
```bash
sudo apt install pipx
pipx install git+https://github.com/SonicField/nbs-ssh.git
```

**macOS:**
```bash
brew install pipx
pipx install git+https://github.com/SonicField/nbs-ssh.git
```

**Windows:**
```powershell
winget install Python.Python.3.12
pip install pipx
pipx install git+https://github.com/SonicField/nbs-ssh.git
```

### Optional Extras

```bash
pip install "nbs-ssh[fido2] @ git+https://github.com/SonicField/nbs-ssh.git"   # FIDO2/YubiKey
pip install "nbs-ssh[pkcs11] @ git+https://github.com/SonicField/nbs-ssh.git"  # Smart cards
pip install "nbs-ssh[all] @ git+https://github.com/SonicField/nbs-ssh.git"     # Everything
```

## CLI Usage

```bash
# Interactive shell (like ssh)
nbs-ssh user@host

# Execute command
nbs-ssh user@host "echo hello"

# With options
nbs-ssh -p 2222 user@host              # Custom port
nbs-ssh -i ~/.ssh/id_ed25519 user@host # Specific key
nbs-ssh --events user@host "cmd"       # JSONL event logging
```

If `nbs-ssh` isn't on your PATH, use `python -m nbs_ssh` instead.

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

nbs-ssh supports all common SSH authentication methods, matching OpenSSH behaviour:

### Supported Methods

| Method | Description | Helper Function |
|--------|-------------|-----------------|
| **SSH Agent** | Keys from ssh-agent | `create_agent_auth()` |
| **Private Key** | Key files (~/.ssh/id_*) | `create_key_auth(path)` |
| **Password** | Password authentication | `create_password_auth(pw)` |
| **GSSAPI/Kerberos** | Enterprise SSO | `create_gssapi_auth()` |
| **Keyboard-Interactive** | 2FA/MFA challenges | `create_keyboard_interactive_auth()` |
| **Certificate** | CA-signed certificates | `create_cert_auth(key, cert)` |
| **PKCS#11** | Smart cards/HSMs | `create_pkcs11_auth(provider)` |
| **FIDO2/U2F** | YubiKey, security keys | `create_security_key_auth()` |

### Automatic Discovery

By default, nbs-ssh automatically discovers authentication methods:

1. **GSSAPI/Kerberos** (if available and configured)
2. **SSH agent** (if `SSH_AUTH_SOCK` is set)
3. **Keys from SSH config** (`IdentityFile` entries)
4. **Default keys** (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, etc.)
5. **Password prompt** (CLI only, as fallback)

### SSH Agent

The SSH agent is the preferred authentication method:

```bash
# Check if agent is available
echo $SSH_AUTH_SOCK
ssh-add -l
```

**Common issue:** Some environments (tmux, screen, cron) don't inherit `SSH_AUTH_SOCK`.

### FIDO2/U2F Security Keys (YubiKey)

For hardware security keys:

```python
from nbs_ssh import SSHConnection, create_security_key_auth

# Resident keys (stored on device)
auth = create_security_key_auth(pin="123456")

# File-based sk-* keys
auth = create_security_key_auth(key_path="~/.ssh/id_ed25519_sk")
```

Requires: `pip install nbs-ssh[fido2]`

### PKCS#11 Smart Cards

For smart cards and hardware security modules:

```python
from nbs_ssh import create_pkcs11_auth

auth = create_pkcs11_auth(
    provider="/usr/lib/opensc-pkcs11.so",
    pin="123456",
)
```

Requires: `pip install nbs-ssh[pkcs11]`

### Certificates

For CA-signed SSH certificates:

```python
from nbs_ssh import create_cert_auth

auth = create_cert_auth(
    key_path="~/.ssh/id_ed25519",
    certificate_path="~/.ssh/id_ed25519-cert.pub",
)
```

### Explicit Authentication

For programmatic control:

```python
from nbs_ssh import SSHConnection, create_key_auth, create_agent_auth

# Try multiple methods in order
async with SSHConnection(
    host="example.com",
    username="user",
    auth=[
        create_agent_auth(),
        create_key_auth("~/.ssh/backup_key"),
    ],
) as conn:
    ...
```

### Not Implemented: Host-Based Authentication

Host-based authentication (where the client machine's identity is trusted) is deliberately **not implemented**. This method:

- Relies on trusting entire machines rather than users
- Creates transitive trust vulnerabilities (compromising one host compromises all)
- Requires privileged access to host keys
- Has been superseded by safer alternatives (certificates, agent forwarding)

If you have a legacy environment requiring host-based auth, we recommend migrating to certificate-based authentication instead.

## Proxy Support

nbs-ssh supports connecting through jump hosts and proxies:

### ProxyJump (-J)

```python
# Single jump host
async with SSHConnection(
    host="target.internal",
    proxy_jump="bastion.example.com",
) as conn:
    ...

# Chained jump hosts
async with SSHConnection(
    host="target.internal",
    proxy_jump="jump1.example.com,jump2.example.com",
) as conn:
    ...
```

CLI: `nbs-ssh -J bastion user@target`

### ProxyCommand

```python
# Custom proxy command
async with SSHConnection(
    host="target.internal",
    proxy_command="nc -X 5 -x socks-proxy:1080 %h %p",
) as conn:
    ...
```

CLI: `nbs-ssh -o "nc proxy %h %p" user@target`

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
pip install -e ".[dev]"
pytest tests/ -v

# Run specific test file
pytest tests/test_connection.py -v
```

### Key Testing Features

- **MockSSHServer**: A real AsyncSSH server that binds to port 0 for parallel test execution
- **Falsifiable security tests**: Tests that actively attempt attacks (weak ciphers, downgrade attacks) and verify they fail
- **No Docker dependency**: All 736 tests run against MockSSHServer
- **Real command execution**: MockSSHServer can execute actual shell commands when needed

See [Testing Guide](docs/testing.md) for the full testing philosophy and how to write tests.

## Development

```bash
git clone https://github.com/SonicField/nbs-ssh.git
cd nbs-ssh
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Run tests (no Docker required)
pytest tests/ -v

# Tests use MockSSHServer - a pure-Python SSH server for testing
```

## Licence

MIT
