# nbs-ssh

AI-inspectable SSH client library built on AsyncSSH.

## Features

- **exec**: Run command, return {stdout, stderr, exit_status, timings}
- **stream_exec**: Stream output events with cancellation support
- **Port forwarding**: Local (-L), remote (-R), dynamic SOCKS (-D)
- **Supervisor runtime**: Liveness metrics, freeze detection, reconnection
- **Automated interaction**: Expect/respond without terminal emulation
- **Evidence-first**: JSONL event logs, reproducible failure bundles

## Installation

```bash
source venv/bin/activate
pip install -e .
```

## Development

```bash
# Run tests
pytest tests/

# Run with Docker SSH server
docker-compose up -d
pytest tests/ --ssh-host=localhost --ssh-port=2222
```

## Architecture

See `.nbs/plan.md` for the full architecture and slice plan.

## Licence

MIT
