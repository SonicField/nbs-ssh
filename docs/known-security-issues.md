# Known Security Issues

**Last Updated:** 2026-02-05

## Disclaimer

**nbs-ssh is designed for development, testing, and AI-assisted debugging - not for production deployment in adversarial network conditions.**

nbs-ssh exhibits a fundamentally different security philosophy from OpenSSH. Where OpenSSH minimises information disclosure, nbs-ssh maximises diagnostic richness for AI-inspectable workflows. This is an intentional design choice, not a deficiency.

| Aspect | OpenSSH | nbs-ssh |
|--------|---------|---------|
| Error verbosity | Minimal | Verbose (for diagnostics) |
| Default security | Strict | Permissive |
| Attack surface | Minimal dependencies | Python + AsyncSSH + transitive |
| Memory handling | Explicit scrubbing | GC-dependent (with SecureString mitigation) |
| Host verification | Required | Optional |

If you require OpenSSH-level security, use OpenSSH.

---

## Security Audit Response

This document responds to the security audit in [Issue #4](https://github.com/SonicField/nbs-ssh/issues/4). Each finding is categorised as:

- **FIXED** - Implemented in the codebase
- **ACCEPTED** - Intentional design decision, documented here
- **MITIGATED** - Partially addressed with documented limitations
- **FUTURE** - Planned for future implementation

---

## Critical Findings

### CRIT-1: known_hosts=None Bypasses Host Key Verification

**Status: ACCEPTED**

When `known_hosts=None` is passed, host key verification is disabled. This enables MITM attacks.

**Rationale:** nbs-ssh is designed for testing and development where:
- Mock servers have dynamically generated keys
- Test environments don't have stable host keys
- The user explicitly opts out of verification

**Recommendation:** For production use, always specify a `known_hosts` path:
```python
async with SSHConnection(host, known_hosts="~/.ssh/known_hosts") as conn:
    ...
```

---

### CRIT-2: No SOCKS Proxy Authentication

**Status: ACCEPTED**

Dynamic SOCKS forwarding provides no authentication.

**Rationale:** OpenSSH also lacks built-in SOCKS authentication. The mitigation is binding to localhost only, which nbs-ssh also does by default.

**Recommendation:** Only use dynamic forwarding on trusted networks. Do not expose SOCKS ports to untrusted clients.

---

### CRIT-3: Memory Clearing of Secrets

**Status: MITIGATED**

Python strings are immutable and cannot be reliably cleared from memory.

**Mitigation implemented:**
- `SecureString` class stores secrets in ctypes-controlled memory
- `eradicate()` method overwrites with cryptographically secure random bytes
- `str()`/`bytes()` return `<hidden>`, preventing accidental logging
- `reveal()` required for explicit access
- CLI calls `eradicate()` in finally block

**Limitation:** When `reveal()` is called to pass secrets to asyncssh, the returned Python string is in Python's managed memory. This is fundamental - asyncssh requires Python strings. SecureString prevents accidental leakage and provides explicit eradication of the controlled copy.

**Usage:**
```python
from nbs_ssh import SecureString

password = SecureString(getpass.getpass())
try:
    async with SSHConnection(host, auth=create_password_auth(password)):
        ...
finally:
    password.eradicate()
```

---

### CRIT-4: Filesystem Paths in Error Messages

**Status: ACCEPTED**

Error messages include full paths for diagnostic purposes.

**Rationale:** nbs-ssh's primary purpose is AI-inspectable diagnostics. Detailed error messages enable:
- Automated troubleshooting
- Clear debugging information
- Evidence bundles for support

**Recommendation:** Do not expose nbs-ssh error messages to untrusted users. Log them internally only.

---

## High Severity Findings

### HIGH-1: No Explicit Cipher/KEX/MAC Restrictions

**Status: ACCEPTED**

nbs-ssh relies on AsyncSSH defaults.

**Rationale:** AsyncSSH maintains modern secure defaults. Explicit restrictions would require tracking OpenSSH's evolving recommendations and could break legitimate use cases.

**Recommendation:** Pin `asyncssh>=2.14.2` (see HIGH-8).

---

### HIGH-2: Remote Forwarding Defaults

**Status: FIXED**

Remote forwarding now defaults to binding on localhost only, matching OpenSSH's `GatewayPorts=no` behaviour. To bind to all interfaces, explicitly pass `remote_host=""` or `remote_host="0.0.0.0"`.

```python
# Default: binds to localhost only (secure)
handle = await manager.forward_remote(8080, "localhost", 3000)

# Explicit all-interface binding (use with caution)
handle = await manager.forward_remote(8080, "localhost", 3000, remote_host="")
```

---

### HIGH-3: No Forwarding Restriction Mechanism

**Status: ACCEPTED**

No equivalent to OpenSSH's `AllowTcpForwarding`, `PermitOpen`, `PermitListen`.

**Rationale:** nbs-ssh is a client library, not a server. Forwarding restrictions are a server-side concern. The SSH server you connect to enforces its own policies.

---

### HIGH-4: Hostname Validation

**Status: FIXED**

Hostnames are now validated in `SSHConnection.__init__`:
- RFC 952/1123 compliant
- Max 253 characters total, labels max 63 characters
- Alphanumeric + hyphens only (no leading/trailing hyphens)
- Shell metacharacters, newlines, null bytes rejected
- Normalised to lowercase

```python
from nbs_ssh import validate_hostname

# Explicit validation (also called automatically in SSHConnection)
hostname = validate_hostname("Example.COM")  # Returns "example.com"
```

---

### HIGH-5: Password Persistence in SSHSupervisor

**Status: ACCEPTED**

SSHSupervisor stores passwords for reconnection.

**Rationale:** This is intentional - the supervisor's purpose is maintaining persistent connections with automatic reconnection. Without stored credentials, reconnection would be impossible.

**Recommendation:** Use SSH agent authentication with SSHSupervisor instead of passwords. The agent handles credential lifecycle.

---

### HIGH-6: Detailed Authentication Method Disclosure

**Status: ACCEPTED**

Auth failure messages reveal which methods were tried.

**Rationale:** Essential for debugging authentication issues. OpenSSH's opaque "Permission denied" requires `-v` flags to diagnose; nbs-ssh provides this information by default.

---

### HIGH-7: Username Existence Enumeration

**Status: ACCEPTED**

Different auth failures may produce distinguishable errors.

**Rationale:** See HIGH-6. Diagnostic value outweighs enumeration risk in development/testing contexts.

---

### HIGH-8: AsyncSSH Version Constraint

**Status: FIXED**

**Action:** Pin minimum to `asyncssh>=2.14.2` in `pyproject.toml` to exclude CVE-2023-46445, CVE-2023-46446, CVE-2023-48795.

---

### HIGH-9: JSONL Event Timing Information

**Status: ACCEPTED**

Millisecond-precision timing in event logs.

**Rationale:** Timing information is essential for performance analysis and debugging. JSONL events are opt-in (`--events` flag or `event_collector` parameter).

**Recommendation:** Do not expose JSONL event logs to untrusted parties.

---

## Medium Severity Findings

| ID | Issue | Status | Notes |
|----|-------|--------|-------|
| MED-1 | AuthConfig `__repr__` exposes secrets | **FIXED** | `to_dict()` excludes secrets; `__repr__` should be added |
| MED-2 | No username validation | **FIXED** | `validate_username()` - POSIX-style, max 32 chars |
| MED-3 | Path traversal | ACCEPTED | Key paths come from user/config, not untrusted input |
| MED-4 | Regex pattern injection (ReDoS) | ACCEPTED | Automation patterns from user code, not untrusted input |
| MED-5 | Incomplete evidence redaction | FUTURE | Evidence bundles are for debugging, not external sharing |
| MED-6 | Transcript captures passwords | ACCEPTED | Automation is for controlled scripts, not untrusted input |
| MED-7 | No renegotiation config | ACCEPTED | AsyncSSH handles renegotiation |
| MED-8 | No port validation | **FIXED** | `validate_port()` - Range 1-65535 |
| MED-9 | No resource exhaustion protection | ACCEPTED | OS/SSH server limits apply |
| MED-10 | Intent replay | ACCEPTED | Fresh connection per session |

---

## Test Coverage Gaps

The following are known testing limitations:

| Gap | Reason | Impact |
|-----|--------|--------|
| Host key verification | Tests use mock server with dynamic keys | MITM scenarios untested |
| Malformed protocol data | Mock server is well-behaved | Parser robustness untested |
| Fuzzing | Not implemented | Unknown edge cases |
| Rekeying attacks | Not implemented | Session security untested |
| Terrapin attack | AsyncSSH handles; not tested | CVE-2023-48795 mitigation untested |

**Mitigation:** We rely on AsyncSSH's protocol implementation, which has its own test suite and security track record.

---

## Dependency Attack Surface

nbs-ssh has a larger attack surface than OpenSSH due to the Python dependency chain:

| Component | OpenSSH | nbs-ssh |
|-----------|---------|---------|
| Lines of dependency code | ~100k | ~1M+ |
| Cryptographic implementations | 1 (system OpenSSL) | 2 (asyncssh + bundled) |
| Supply chain attack surface | OS package manager | PyPI |
| Protocol implementation | Reference (30+ years) | Third-party |

**Mitigation:** Pin dependencies, use `pip-audit` or similar tools, consider vendoring critical dependencies.

---

## Authentication Methods

### Supported (OpenSSH Compatible)

| Method | Status |
|--------|--------|
| Password | ✅ Supported |
| Public key (files) | ✅ Supported |
| SSH Agent | ✅ Supported |
| GSSAPI/Kerberos | ✅ Supported |
| Keyboard-interactive | ✅ Supported |
| Certificate-based | ✅ Supported |
| PKCS#11/Smart cards | ✅ Supported |
| FIDO2/U2F (sk-* keys) | ✅ Supported |

### Not Implemented

| Method | Reason |
|--------|--------|
| Host-based | Security concerns: relies on trusting entire machines, creates transitive trust vulnerabilities, superseded by certificates |

---

## Recommendations for Production Use

If you must use nbs-ssh in a security-sensitive context:

1. **Always specify `known_hosts`** - Never use `known_hosts=None`
2. **Use SSH agent** - Avoid password storage; let the agent manage credentials
3. **Pin dependencies** - Use `pip freeze` and audit regularly
4. **Don't expose events/errors** - Keep JSONL logs and error messages internal
5. **Validate inputs** - Validate hostnames, usernames, ports before passing to nbs-ssh
6. **Use SecureString** - Wrap secrets and call `eradicate()` when done
7. **Consider OpenSSH** - For adversarial networks, use the reference implementation

---

## Reporting Security Issues

See [SECURITY.md](../SECURITY.md) for responsible disclosure procedures.
