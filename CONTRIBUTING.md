# Contributing to Catalyst Networks

Thanks for your interest in contributing! This guide will help you get started.

## Reporting Bugs

Open a [GitHub Issue](../../issues) with:
- Steps to reproduce the problem
- What you expected to happen
- What actually happened
- Your environment (OS, Docker version, browser)

## Suggesting Features

Open a [GitHub Issue](../../issues) with the `enhancement` label. Describe the use case and why it would be useful.

## Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `docker compose exec web python manage.py test`
5. Commit with a clear message
6. Push and open a pull request

### Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) for Python code
- Use the existing code patterns in the project as a guide
- Keep changes focused — one feature or fix per PR

### Testing

- Add tests for new features
- Ensure existing tests pass before submitting

## Development Setup

See the [README](README.md) for setup instructions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
