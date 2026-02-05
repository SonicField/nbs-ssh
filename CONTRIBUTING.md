# Contributing to nbs-ssh

Thank you for your interest in nbs-ssh (AI-inspectable SSH library)!

## Project Status

nbs-ssh is a Python SSH library designed to be a drop-in replacement for OpenSSH with enhanced observability for AI-assisted automation.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- A clear, descriptive title
- Steps to reproduce the behavior
- Expected vs actual behavior
- nbs-ssh version and environment details

### Suggesting Features

Feature requests are welcome! Please open an issue describing:
- The use case or problem you're trying to solve
- How the feature would work
- Whether OpenSSH supports the feature (since our goal is OpenSSH compatibility)

### Pull Requests

Pull requests are welcome, especially for:
- Bug fixes
- Documentation improvements
- Test coverage
- OpenSSH compatibility improvements

Before submitting a large PR, consider opening an issue first to discuss the approach.

**PR Guidelines:**
- All tests must pass (`PYTHONPATH=src python -m pytest tests/ -v`)
- Add tests for new functionality
- Update documentation as needed
- Follow existing code style

## Development Setup

```bash
# Clone the repository
git clone https://github.com/SonicField/nbs-ssh.git
cd nbs-ssh

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Run tests
PYTHONPATH=src python -m pytest tests/ -v
```

## Questions?

Open an issue for questions about nbs-ssh's design, implementation, or usage.

## License

By contributing, you agree that your contributions will be licensed under the MIT license.
