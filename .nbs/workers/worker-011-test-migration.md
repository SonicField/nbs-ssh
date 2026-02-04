# Worker: Complete Test Migration

## Task

Finish migrating all Docker-dependent tests to use MockSSHServer with execute_commands=True. Target: 0 skipped tests.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for tests
- MockSSHServer now has execute_commands=True option for real shell execution
- conftest.py has streaming_ssh_server fixture (partially added)
- test_streaming.py partially updated but may have issues
- test_automation.py and test_hello_ssh.py still use docker_ssh_server

## Instructions

1. Verify conftest.py has streaming_ssh_server fixture with execute_commands=True
2. Update test_streaming.py header comment to remove Docker references
3. Update test_automation.py to use streaming_ssh_server instead of docker_ssh_server
4. Update test_hello_ssh.py key-based auth test (may need to skip or implement key auth in mock server)
5. Run full test suite: `PYTHONPATH=src python -m pytest tests/ -v`
6. Fix any failures
7. Target: 0 skipped tests (or document why any must remain skipped)

## Success Criteria

1. Does `pytest tests/` show 0 skipped?
2. Do all tests pass?
3. Is there no reference to docker_ssh_server in test assertions?

## Status

State: pending
Started:
Completed:

## Log

[Worker will append findings here]
