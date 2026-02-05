# Security Policy

## Scope

nbs-ssh is an SSH client library. Security is critical to its design and implementation.

## Supported Versions

Only the latest version on the `master` branch is actively maintained.

## Reporting a Vulnerability

If you discover a security vulnerability in nbs-ssh, please report it by:

1. **Opening a GitHub issue** if the vulnerability is not sensitive
2. **Emailing the maintainer directly** for sensitive security issues (see GitHub profile for contact)

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- Acknowledgment: Within 1 week
- Initial assessment: Within 2 weeks
- Fix timeline: Depends on severity and complexity

## Security Considerations

nbs-ssh is built on top of AsyncSSH, which provides:
- Strong cipher support (AES-GCM, ChaCha20-Poly1305)
- Modern key exchange algorithms
- Host key verification
- Certificate support

**Security-sensitive features:**
- **Known hosts**: Host key verification is enabled by default
- **Weak ciphers**: Weak/legacy ciphers are not enabled
- **Password handling**: Passwords are not logged or stored
- **FIDO2/U2F**: Hardware security key support (requires fido2 package)
- **PKCS#11**: Smart card/HSM support (requires python-pkcs11 package)

## Dependency Security

nbs-ssh depends on:
- **asyncssh**: Core SSH implementation (well-maintained, security-focused)
- **cryptography**: Cryptographic primitives (widely audited)

Keep dependencies updated to receive security patches.
