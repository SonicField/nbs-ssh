#!/bin/bash
PTY=/home/alexturner/.nbs/bin/pty-session

# Worker 018: SSH Config Parsing
$PTY create worker-018 'cd /home/alexturner/local/nbs-ssh && claude'
sleep 6
$PTY send worker-018 'Read .nbs/workers/worker-018-ssh-config.md and execute the task. Update the Status and Log sections when complete. Remember to checkout the feature branch first and run the FULL test suite before finishing.'
$PTY send worker-018 ''

# Worker 019: Certificate Support
$PTY create worker-019 'cd /home/alexturner/local/nbs-ssh && claude'
sleep 6
$PTY send worker-019 'Read .nbs/workers/worker-019-certificate.md and execute the task. Update the Status and Log sections when complete. Remember to checkout the feature branch first and run the FULL test suite before finishing.'
$PTY send worker-019 ''

# Worker 020: Proxy Support
$PTY create worker-020 'cd /home/alexturner/local/nbs-ssh && claude'
sleep 6
$PTY send worker-020 'Read .nbs/workers/worker-020-proxy.md and execute the task. Update the Status and Log sections when complete. Remember to checkout the feature branch first and run the FULL test suite before finishing.'
$PTY send worker-020 ''

# Worker 021: PKCS#11
$PTY create worker-021 'cd /home/alexturner/local/nbs-ssh && claude'
sleep 6
$PTY send worker-021 'Read .nbs/workers/worker-021-pkcs11.md and execute the task. Update the Status and Log sections when complete. Remember to checkout the feature branch first and run the FULL test suite before finishing.'
$PTY send worker-021 ''

echo "All 4 workers spawned"
