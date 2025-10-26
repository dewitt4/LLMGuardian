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

### 2. Security Scan (security-scan.yml)
**Trigger:** Push and Pull Requests to `main` and `develop` branches, Daily schedule (2 AM UTC), Manual dispatch

Comprehensive security scanning with multiple jobs:

#### Trivy Repository Scan
- Scans filesystem for vulnerabilities in dependencies
- Checks for CRITICAL, HIGH, and MEDIUM severity issues
- Uploads results to GitHub Security tab (SARIF format)

#### Trivy Config Scan
- Scans configuration files for security misconfigurations
- Checks Dockerfiles, GitHub Actions, and other config files

#### Dependency Review
- Reviews dependency changes in pull requests
- Fails on high severity vulnerabilities
- Posts summary comments on PRs

#### Python Safety Check
- Runs safety check on Python dependencies
- Identifies known security vulnerabilities in packages

### 3. Docker Build & Publish (docker-publish.yml)
**Trigger:** Push to `main`, Version tags (v*.*.*), Pull Requests to `main`, Releases, Manual dispatch

Builds and publishes Docker images to GitHub Container Registry (ghcr.io):

#### Build and Push Job
- Builds Docker image using BuildKit
- Pushes to GitHub Container Registry (ghcr.io/dewitt4/llmguardian)
- Supports multi-architecture builds (linux/amd64, linux/arm64)
- Tags images with:
  - Branch name (e.g., `main`)
  - Semantic version (e.g., `v1.0.0`, `1.0`, `1`)
  - Git SHA (e.g., `main-abc1234`)
  - `latest` for main branch
- For PRs: Only builds, doesn't push
- Runs Trivy vulnerability scan on published images
- Generates artifact attestation for supply chain security

#### Test Image Job
- Pulls published image
- Validates image can run
- Checks image size

### 4. File Size Check (filesize.yml)
**Trigger:** Pull Requests to `main` branch, Manual dispatch

- Checks for large files (>10MB) to ensure compatibility with HuggingFace Spaces
- Helps prevent repository bloat
- Posts warnings on PRs for large files

### 5. HuggingFace Sync (huggingface.yml)
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

### GitHub Container Registry
- No additional secrets needed - uses `GITHUB_TOKEN` automatically provided by GitHub Actions

### HuggingFace (Optional)
- `HF_TOKEN`: HuggingFace token for syncing to Spaces (only needed if using HuggingFace sync)

### Codecov (Optional)
- Coverage reports will upload anonymously, but you can configure `CODECOV_TOKEN` for private repos

## Permissions

The workflows use the following permissions:

- **CI Workflow**: `contents: read`
- **Security Scan**: `contents: read`, `security-events: write`
- **Docker Publish**: `contents: read`, `packages: write`, `id-token: write`
- **File Size Check**: `contents: read`, `pull-requests: write`

## Local Testing

To run the same checks locally before pushing:

### Code Quality & Tests
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

### Security Scanning
```bash
# Install Trivy (macOS)
brew install trivy

# Install Trivy (Linux)
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

# Run Trivy scans
trivy fs . --severity CRITICAL,HIGH,MEDIUM
trivy config .

# Run Safety check
pip install safety
safety check
```

### Docker Build & Test
```bash
# Build Docker image
docker build -f docker/dockerfile -t llmguardian:local .

# Run container
docker run -p 8000:8000 -p 8501:8501 llmguardian:local

# Scan Docker image with Trivy
trivy image llmguardian:local

# Test image
docker run --rm llmguardian:local python -c "import llmguardian; print(llmguardian.__version__)"
```

## Using Published Docker Images

Pull and run the latest published image:

```bash
# Pull latest image
docker pull ghcr.io/dewitt4/llmguardian:latest

# Run API server
docker run -p 8000:8000 ghcr.io/dewitt4/llmguardian:latest

# Run dashboard
docker run -p 8501:8501 ghcr.io/dewitt4/llmguardian:latest streamlit run src/llmguardian/dashboard/app.py

# Run with environment variables
docker run -p 8000:8000 \
  -e LOG_LEVEL=DEBUG \
  -e SECURITY_RISK_THRESHOLD=8 \
  ghcr.io/dewitt4/llmguardian:latest
```

See `docker/README.md` for more Docker usage examples.