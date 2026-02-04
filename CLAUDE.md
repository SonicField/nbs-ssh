# nbs-ssh Project Configuration

## Developer

The developer working with you is **Dr Alex Turner** (she/her).

## Terminal Goal

Build an AI-inspectable SSH client library using AsyncSSH that provides exec, streaming exec, port forwarding, automated interaction (expect/respond), supervisor-managed reconnection, and evidence-first diagnostics (JSONL event logs, failure bundles) - all with falsifiable tests against a Docker-based chaos testing rig.

## Engineering Standards

Follow the standards defined in:
`/home/alexturner/local/soma/docs/concepts/engineering-standards.md`

Key principles:
- Falsifiability as foundation
- The Cycle of Verified Construction: Design → Plan → Deconstruct → [Test → Code → Document]
- Integration-first testing
- Assertions at all levels

## Build

```bash
# Activate venv
source ~/local/nbs-ssh/venv/bin/activate

# Install in dev mode
pip install -e ".[dev]"

# Run tests
pytest tests/
```

## Testing

Tests require a Docker-based OpenSSH server. See `docker/` for setup.

```bash
docker-compose -f docker/docker-compose.yml up -d
pytest tests/
```

## Architecture

See `.nbs/plan.md` for the slice plan and architecture overview.

## NBS Teams

This project uses NBS teams. See `.nbs/` for:
- `supervisor.md` - Terminal goal and progress
- `decisions.log` - Decision record
- `workers/` - Worker task files

## Language

British English for all documentation.
