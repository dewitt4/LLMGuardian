# Contributing to LLMGuardian

First off, thank you for considering contributing to LLMGuardian! It's people like you who make LLMGuardian a great tool for protecting LLM applications. This document provides guidelines and steps for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. We are committed to providing a welcoming and inclusive environment for everyone. Key points:

- Be respectful and inclusive
- Use welcoming and inclusive language
- Be collaborative
- Focus on what is best for the community
- Show empathy towards other community members

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- A clear and descriptive title
- Exact steps to reproduce the problem
- Expected behavior vs actual behavior
- Code samples and test cases if applicable
- Your environment details (OS, Python version, etc.)

### Suggesting Enhancements

If you have ideas for new features or improvements:

1. Check existing issues and discussions first
2. Provide a clear and detailed explanation of the feature
3. Include examples of how the feature would be used
4. Explain why this enhancement would be useful to LLMGuardian users

### Pull Requests

1. Fork the repository
2. Create a new branch for your feature or fix
3. Write clear, documented, and tested code
4. Follow our coding conventions (detailed below)
5. Submit a pull request with a clear description of the changes

## Development Guidelines

### Code Style

- Follow PEP 8 style guide
- Use type hints
- Write docstrings for all public methods and classes
- Keep functions focused and single-purpose
- Use descriptive variable names

### Testing Requirements

- Write unit tests for all new functionality
- Maintain or improve test coverage
- Tests must pass in CI pipeline
- Include both positive and negative test cases
- Test edge cases and potential security implications

### Security Considerations

As LLMGuardian is a security tool, we have strict requirements:

1. No malicious code or backdoors
2. All dependencies must be vetted and approved
3. Security-sensitive code requires additional review
4. Follow secure coding practices
5. Document security implications of changes
6. Regular security testing and validation

### Documentation

- Update README.md if adding new features
- Include docstrings in code
- Update relevant documentation files
- Provide examples for new functionality
- Document security considerations

### Commit Messages

- Use clear and descriptive commit messages
- Reference issue numbers when applicable
- Use present tense ("Add feature" not "Added feature")
- Keep commits focused and atomic

## Getting Started

1. Set up your development environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or `venv\Scripts\activate` on Windows
   pip install -r requirements-dev.txt
   ```

2. Run tests locally:
   ```bash
   pytest
   ```

3. Check code style:
   ```bash
   flake8
   black .
   isort .
   ```

## Pull Request Process

1. Update documentation to reflect changes
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Get at least one code review
6. Squash commits if requested
7. Address review feedback

## Release Process

Releases are handled by maintainers following the semantic versioning (SemVer) system.

## Additional Notes

### Attribution

We use the Apache License 2.0 - see the LICENSE file for details. When you contribute code, you agree to license your contribution under the same terms.

### Support

If you need help with your contribution:

- Check the documentation
- Open a discussion on GitHub
- Join our community chat
- Ask questions in issues

### Future Plans

Check our roadmap and project board for planned features and enhancements. This can help you find areas where your contributions would be most valuable.

Thank you for contributing to LLMGuardian! Together we can make LLM applications more secure for everyone.
