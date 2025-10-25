# GitHub Actions Workflows

This directory contains GitHub Actions workflow configurations for CI/CD automation.

## Active Workflows

### 1. CI (ci.yml)
**Trigger:** Push and Pull Requests to `main` and `develop` branches

The main continuous integration workflow with three sequential jobs:

#### Lint Job
- Runs code quality checks with:
  - **Black**: Code formatting validation
  - **Flake8**: Style guide enforcement
  - **isort**: Import statement organization
  - **mypy**: Static type checking
- Uses Python 3.8

#### Test Job
- Runs after lint job passes
- Tests across Python versions: 3.8, 3.9, 3.10, 3.11
- Executes pytest with coverage reporting
- Uploads test results as artifacts
- Sends coverage reports to Codecov (Python 3.9 only)

#### Build Job
- Runs after all tests pass
- Only executes on `main` branch
- Builds Python distribution packages (sdist and wheel)
- Uploads build artifacts

### 2. File Size Check (filesize.yml)
**Trigger:** Pull Requests to `main` branch, Manual dispatch

- Checks for large files (>10MB) to ensure compatibility with HuggingFace Spaces
- Helps prevent repository bloat

### 3. HuggingFace Sync (huggingface.yml)
**Trigger:** Push to `main` branch, Manual dispatch

- Syncs repository to HuggingFace Spaces
- Requires `HF_TOKEN` secret to be configured

## Migration from CircleCI

This project has migrated from CircleCI to GitHub Actions. The new CI workflow provides:

- ✅ Multi-version Python testing (3.8-3.11)
- ✅ Comprehensive linting and code quality checks
- ✅ Test coverage reporting with Codecov
- ✅ Automated package building
- ✅ Better integration with GitHub ecosystem
- ✅ Faster feedback with parallel job execution

## Required Secrets

- `HF_TOKEN`: HuggingFace token for syncing to Spaces (optional, only needed if using HuggingFace sync)

## Local Testing

To run the same checks locally before pushing:

```bash
# Install development dependencies
pip install -e ".[dev,test]"

# Run linting
black --check src tests
flake8 src tests
isort --check-only src tests
mypy src

# Run tests
pytest tests/ --cov=src --cov-report=term

# Build package
python -m build
```