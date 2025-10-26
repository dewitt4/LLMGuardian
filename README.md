# LLMGuardian

[![CI](https://github.com/dewitt4/LLMGuardian/actions/workflows/ci.yml/badge.svg)](https://github.com/dewitt4/LLMGuardian/actions/workflows/ci.yml)
[![Security Scan](https://github.com/dewitt4/LLMGuardian/actions/workflows/security-scan.yml/badge.svg)](https://github.com/dewitt4/LLMGuardian/actions/workflows/security-scan.yml)
[![Docker Build](https://github.com/dewitt4/LLMGuardian/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/dewitt4/LLMGuardian/actions/workflows/docker-publish.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Comprehensive LLM AI Model protection toolset aligned to addressing OWASP vulnerabilities in Large Language Models

**Author:** [DeWitt Gibson](https://www.linkedin.com/in/dewitt-gibson/)

**Full Documentation and Usage Instructions: [DOCS](docs/README.md)**

## 🚀 Quick Start

### Installation

```bash
# Install from PyPI (when available)
pip install llmguardian

# Or install from source
git clone https://github.com/dewitt4/LLMGuardian.git
cd LLMGuardian
pip install -e .
```

### Using Docker

```bash
# Pull the latest image
docker pull ghcr.io/dewitt4/llmguardian:latest

# Run the API server
docker run -p 8000:8000 ghcr.io/dewitt4/llmguardian:latest

# Run the dashboard
docker run -p 8501:8501 ghcr.io/dewitt4/llmguardian:latest streamlit run src/llmguardian/dashboard/app.py
```

See [docker/README.md](docker/README.md) for detailed Docker usage.

### Running the Dashboard

```bash
# Install dashboard dependencies
pip install -e ".[dashboard]"

# Run the Streamlit dashboard
streamlit run src/llmguardian/dashboard/app.py
```

## ✨ Features

### 🛡️ Comprehensive Security Protection

- **Prompt Injection Detection**: Advanced scanning for injection attacks
- **Data Leakage Prevention**: Sensitive data exposure protection
- **Output Validation**: Ensure safe and appropriate model outputs
- **Rate Limiting**: Protect against abuse and DoS attacks
- **Token Validation**: Secure authentication and authorization

### 🔍 Security Scanning & Monitoring

- **Automated Vulnerability Scanning**: Daily security scans with Trivy
- **Dependency Review**: Automated checks for vulnerable dependencies
- **Real-time Threat Detection**: Monitor and detect anomalous behavior
- **Audit Logging**: Comprehensive security event logging
- **Performance Monitoring**: Track system health and performance

### 🐳 Docker & Deployment

- **Pre-built Docker Images**: Available on GitHub Container Registry
- **Multi-architecture Support**: AMD64 and ARM64 builds
- **Automated CI/CD**: GitHub Actions for testing and deployment
- **Security Attestations**: Supply chain security with provenance
- **Health Checks**: Built-in container health monitoring

### 📊 Interactive Dashboard

- **Streamlit Interface**: User-friendly web dashboard
- **Real-time Visualization**: Monitor threats and metrics
- **Configuration Management**: Easy setup and customization
- **Alert Management**: Configure and manage security alerts

## 🏗️ Project Structure

LLMGuardian follows a modular and secure architecture designed to provide comprehensive protection for LLM applications. Below is the detailed project structure with explanations for each component:

## Directory Structure

```
LLMGuardian/
├── .github/                      # GitHub specific configurations
│   ├── workflows/                # GitHub Actions workflows for CI/CD
│   ├── CODEOWNERS               # Repository ownership rules
│   ├── ISSUE_TEMPLATE/          # Issue reporting templates
│   └── PULL_REQUEST_TEMPLATE.md # PR guidelines
│
├── src/                         # Source code
│   └── llmguardian/            # Main package directory
│       ├── cli/                # Command-line interface
│       ├── dashboard/          # Streamlit dashboard
│       ├── core/               # Core functionality
│       ├── scanners/           # Security scanning modules
│       ├── defenders/          # Defense mechanisms
│       ├── monitors/           # Monitoring components
│       ├── api/                # API integration
|       ├── vectors/            # Embeddings protection / supply chain vulnerabilities
|       ├── data/               # Sensive data exposure / data poisoning
|       ├── agency/             # Excessive agency protection
│       └── utils/              # Utility functions
│
├── tests/                      # Test suite
│   ├── unit/                  # Unit tests
│   ├── integration/           # Integration tests
│   └── security/              # Security-specific tests
│
├── docs/                      # Documentation
├── scripts/                   # Utility scripts
├── page/                      # Files for GitHub pages
├── requirements/              # Dependencies
├── docker/                    # Docker configurations
├── config/                    # Various config files
└── app.py                     # Huggingface Space deployment
```

## Component Details

### 🔒 Security Components

1. **Scanners (`src/llmguardian/scanners/`)**
   - Prompt injection detection
   - Data leakage scanning
   - Model security validation
   - Output validation checks

2. **Defenders (`src/llmguardian/defenders/`)**
   - Input sanitization
   - Output filtering
   - Content validation
   - Token validation

3. **Monitors (`src/llmguardian/monitors/`)**
   - Real-time usage tracking
   - Threat detection
   - Anomaly monitoring
   - Performance tracking
   - Audit logging

4. **Vectors (`src/llmguardian/vectors/`)**
   - Embedding weaknesses detection
   - Supply chain vulnerabilities
   - Vector store monitoring
   - Retrieval guard

5. **Data (`src/llmguardian/data/`)**
   - Sensitive information disclosure prevention
   - Protection from data poisoning
   - Data sanitizing
   - Privacy enforcement

6. **Agency (`src/llmguardian/agency/`)**
   - Permission management
   - Scope limitation
   - Action validation
   - Safe execution

### 🛠️ Core Components

7. **CLI (`src/llmguardian/cli/`)**
   - Command-line interface
   - Interactive tools
   - Configuration management

8. **API (`src/llmguardian/api/`)**
   - RESTful endpoints
   - FastAPI integration
   - Security middleware
   - Health check endpoints

9. **Core (`src/llmguardian/core/`)**
   - Configuration management
   - Logging setup
   - Event handling
   - Rate limiting
   - Security utilities

### 🧪 Testing & Quality Assurance

10. **Tests (`tests/`)**
    - Unit tests for individual components
    - Integration tests for system functionality
    - Security-specific test cases
    - Vulnerability testing
    - Automated CI/CD testing

### 📚 Documentation & Support

11. **Documentation (`docs/`)**
    - API documentation
    - Implementation guides
    - Security best practices
    - Usage examples

12. **Docker (`docker/`)**
    - Production-ready Dockerfile
    - Multi-architecture support
    - Container health checks
    - Security optimized

### 🔧 Development Tools

13. **Scripts (`scripts/`)**
    - Setup utilities
    - Development tools
    - Security checking scripts

### 📊 Dashboard

14. **Dashboard (`src/llmguardian/dashboard/`)**
    - Streamlit application
    - Real-time visualization
    - Monitoring and control
    - Alert management

## 🔐 Security Features

### Automated Security Scanning

LLMGuardian includes comprehensive automated security scanning:

- **Daily Vulnerability Scans**: Automated Trivy scans run daily at 2 AM UTC
- **Dependency Review**: All pull requests are automatically checked for vulnerable dependencies
- **Container Scanning**: Docker images are scanned before publication
- **Configuration Validation**: Automated checks for security misconfigurations

### CI/CD Integration

Our GitHub Actions workflows provide:

- **Continuous Integration**: Automated testing on Python 3.8, 3.9, 3.10, and 3.11
- **Code Quality**: Black, Flake8, isort, and mypy checks
- **Security Gates**: Vulnerabilities are caught before merge
- **Automated Deployment**: Docker images published to GitHub Container Registry

### Supply Chain Security

- **SBOM Generation**: Software Bill of Materials for all builds
- **Provenance Attestations**: Cryptographically signed build provenance
- **Multi-architecture Builds**: Support for AMD64 and ARM64

## 🐳 Docker Deployment

### Quick Start with Docker

```bash
# Pull the latest image
docker pull ghcr.io/dewitt4/llmguardian:latest

# Run API server
docker run -p 8000:8000 ghcr.io/dewitt4/llmguardian:latest

# Run with environment variables
docker run -p 8000:8000 \
  -e LOG_LEVEL=DEBUG \
  -e SECURITY_RISK_THRESHOLD=8 \
  ghcr.io/dewitt4/llmguardian:latest
```

### Available Tags

- `latest` - Latest stable release from main branch
- `main` - Latest commit on main branch
- `v*.*.*` - Specific version tags (e.g., v1.0.0)
- `sha-*` - Specific commit SHA tags

### Volume Mounts

```bash
# Persist logs and data
docker run -p 8000:8000 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/data:/app/data \
  ghcr.io/dewitt4/llmguardian:latest
```

See [docker/README.md](docker/README.md) for complete Docker documentation.

## ☁️ Cloud Deployment

LLMGuardian can be deployed on all major cloud platforms. Below are quick start guides for each provider. For detailed step-by-step instructions, see [PROJECT.md - Cloud Deployment Guides](PROJECT.md#cloud-deployment-guides).

### AWS Deployment

**Option 1: ECS with Fargate (Recommended)**
```bash
# Push to ECR and deploy
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com
aws ecr create-repository --repository-name llmguardian
docker tag llmguardian:latest YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/llmguardian:latest
docker push YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/llmguardian:latest
```

**Other AWS Options:**
- AWS Lambda with Docker containers
- Elastic Beanstalk for PaaS deployment
- EKS for Kubernetes orchestration

### Google Cloud Platform

**Cloud Run (Recommended)**
```bash
# Build and deploy to Cloud Run
gcloud auth configure-docker
docker tag llmguardian:latest gcr.io/YOUR_PROJECT_ID/llmguardian:latest
docker push gcr.io/YOUR_PROJECT_ID/llmguardian:latest

gcloud run deploy llmguardian \
  --image gcr.io/YOUR_PROJECT_ID/llmguardian:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 2Gi \
  --port 8000
```

**Other GCP Options:**
- Google Kubernetes Engine (GKE)
- App Engine for PaaS deployment

### Microsoft Azure

**Azure Container Instances**
```bash
# Create resource group and deploy
az group create --name llmguardian-rg --location eastus
az acr create --resource-group llmguardian-rg --name llmguardianacr --sku Basic
az acr login --name llmguardianacr

docker tag llmguardian:latest llmguardianacr.azurecr.io/llmguardian:latest
docker push llmguardianacr.azurecr.io/llmguardian:latest

az container create \
  --resource-group llmguardian-rg \
  --name llmguardian-container \
  --image llmguardianacr.azurecr.io/llmguardian:latest \
  --cpu 2 --memory 4 --ports 8000
```

**Other Azure Options:**
- Azure App Service (Web App for Containers)
- Azure Kubernetes Service (AKS)
- Azure Functions

### Vercel

**Serverless Deployment**
```bash
# Install Vercel CLI and deploy
npm i -g vercel
vercel login
vercel --prod
```

Create `vercel.json`:
```json
{
  "version": 2,
  "builds": [{"src": "src/llmguardian/api/app.py", "use": "@vercel/python"}],
  "routes": [{"src": "/(.*)", "dest": "src/llmguardian/api/app.py"}]
}
```

### DigitalOcean

**App Platform (Easiest)**
```bash
# Using doctl CLI
doctl auth init
doctl apps create --spec .do/app.yaml
```

**Other DigitalOcean Options:**
- DigitalOcean Kubernetes (DOKS)
- Droplets with Docker

### Platform Comparison

| Platform | Best For | Ease of Setup | Estimated Cost |
|----------|----------|---------------|----------------|
| **GCP Cloud Run** | Startups, Auto-scaling | ⭐⭐⭐⭐⭐ Easy | $30-150/mo |
| **AWS ECS** | Enterprise, Flexibility | ⭐⭐⭐ Medium | $50-200/mo |
| **Azure ACI** | Microsoft Ecosystem | ⭐⭐⭐⭐ Easy | $50-200/mo |
| **Vercel** | API Routes, Serverless | ⭐⭐⭐⭐⭐ Very Easy | $20-100/mo |
| **DigitalOcean** | Simple, Predictable | ⭐⭐⭐⭐ Easy | $24-120/mo |

### Prerequisites for Cloud Deployment

Before deploying to any cloud:

1. **Prepare Environment Variables**: Copy `.env.example` to `.env` and configure
2. **Build Docker Image**: `docker build -t llmguardian:latest -f docker/dockerfile .`
3. **Set Up Cloud CLI**: Install and authenticate with your chosen provider
4. **Configure Secrets**: Use cloud secret managers (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)
5. **Enable HTTPS**: Configure SSL/TLS certificates
6. **Set Up Monitoring**: Enable cloud-native monitoring and logging

For complete deployment guides with step-by-step instructions, configuration examples, and best practices, see **[PROJECT.md - Cloud Deployment Guides](PROJECT.md#cloud-deployment-guides)**.

## ⚙️ Configuration

### Environment Variables

LLMGuardian can be configured using environment variables. Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

Key configuration options:

- `SECURITY_RISK_THRESHOLD`: Risk threshold (1-10)
- `SECURITY_CONFIDENCE_THRESHOLD`: Detection confidence (0.0-1.0)
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `API_SERVER_PORT`: API server port (default: 8000)
- `DASHBOARD_PORT`: Dashboard port (default: 8501)

See `.env.example` for all available options.

## 🚦 GitHub Actions Workflows

### Available Workflows

1. **CI Workflow** (`ci.yml`)
   - Runs on push and PR to main/develop
   - Linting (Black, Flake8, isort, mypy)
   - Testing on multiple Python versions
   - Code coverage reporting

2. **Security Scan** (`security-scan.yml`)
   - Daily automated scans
   - Trivy vulnerability scanning
   - Dependency review on PRs
   - Python Safety checks

3. **Docker Build & Publish** (`docker-publish.yml`)
   - Builds on push to main
   - Multi-architecture builds
   - Security scanning of images
   - Publishes to GitHub Container Registry

4. **File Size Check** (`filesize.yml`)
   - Prevents large files (>10MB)
   - Ensures HuggingFace compatibility

See [.github/workflows/README.md](.github/workflows/README.md) for detailed documentation.

## 📦 Installation Options

### From Source

```bash
git clone https://github.com/dewitt4/LLMGuardian.git
cd LLMGuardian
pip install -e .
```

### Development Installation

```bash
pip install -e ".[dev,test]"
```

### Dashboard Installation

```bash
pip install -e ".[dashboard]"
```

## 🧑‍💻 Development

### Running Tests

```bash
# Install test dependencies
pip install -e ".[dev,test]"

# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=term
```

### Code Quality Checks

```bash
# Format code
black src tests

# Sort imports
isort src tests

# Check style
flake8 src tests

# Type checking
mypy src
```

### Local Security Scanning

```bash
# Install Trivy
brew install trivy  # macOS
# or use package manager for Linux

# Scan repository
trivy fs . --severity CRITICAL,HIGH,MEDIUM

# Scan dependencies
pip install safety
safety check
```

## 🌟 Key Files

- `pyproject.toml`: Project metadata and dependencies
- `setup.py`: Package setup configuration
- `requirements/*.txt`: Environment-specific dependencies
- `.env.example`: Environment variable template
- `.dockerignore`: Docker build optimization
- `CONTRIBUTING.md`: Contribution guidelines
- `LICENSE`: Apache 2.0 license terms

## 🎯 Design Principles

The structure follows these key principles:

1. **Modularity**: Each component is self-contained and independently maintainable
2. **Security-First**: Security considerations are built into the architecture
3. **Scalability**: Easy to extend and add new security features
4. **Testability**: Comprehensive test coverage and security validation
5. **Usability**: Clear organization and documentation
6. **Automation**: CI/CD pipelines for testing, security, and deployment

## 🚀 Getting Started with Development

To start working with this structure:

1. **Fork the repository**
   ```bash
   git clone https://github.com/dewitt4/LLMGuardian.git
   cd LLMGuardian
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -e ".[dev,test]"
   ```

4. **Run the test suite**
   ```bash
   pytest tests/
   ```

5. **Follow the contribution guidelines**
   - See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines

## 🤗 HuggingFace Space

LLMGuardian is available as a HuggingFace Space for easy testing and demonstration:

**[https://huggingface.co/spaces/Safe-Harbor/LLMGuardian](https://huggingface.co/spaces/Safe-Harbor/LLMGuardian)**

### Features

1. **FastAPI Backend**
   - Model scanning endpoints
   - Prompt injection detection
   - Input/output validation
   - Rate limiting middleware
   - Authentication checks

2. **Gradio UI Frontend**
   - Model security testing interface
   - Vulnerability scanning dashboard
   - Real-time attack detection
   - Configuration settings

### Deployment

The HuggingFace Space is automatically synced from the main branch via GitHub Actions. See `.github/workflows/huggingface.yml` for the sync workflow.

## 📊 Status & Monitoring

### GitHub Actions Status

Monitor the health of the project:

- **[CI Pipeline](https://github.com/dewitt4/LLMGuardian/actions/workflows/ci.yml)**: Continuous integration status
- **[Security Scans](https://github.com/dewitt4/LLMGuardian/actions/workflows/security-scan.yml)**: Latest security scan results
- **[Docker Builds](https://github.com/dewitt4/LLMGuardian/actions/workflows/docker-publish.yml)**: Container build status

### Security Advisories

Check the [Security tab](https://github.com/dewitt4/LLMGuardian/security) for:
- Vulnerability reports
- Dependency alerts
- Security advisories

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Code of conduct
- Development setup
- Pull request process
- Coding standards

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 📝 Citation

If you use LLMGuardian in your research or project, please cite:

```bibtex
@misc{llmguardian2025,
      title={LLMGuardian: Comprehensive LLM AI Model Protection}, 
      author={DeWitt Gibson},
      year={2025},
      url={https://github.com/dewitt4/LLMGuardian}, 
}
```

## 🔗 Links

- **Documentation**: [docs/README.md](docs/README.md)
- **Docker Hub**: [ghcr.io/dewitt4/llmguardian](https://github.com/dewitt4/LLMGuardian/pkgs/container/llmguardian)
- **HuggingFace Space**: [Safe-Harbor/LLMGuardian](https://huggingface.co/spaces/Safe-Harbor/LLMGuardian)
- **Issues**: [GitHub Issues](https://github.com/dewitt4/LLMGuardian/issues)
- **Pull Requests**: [GitHub PRs](https://github.com/dewitt4/LLMGuardian/pulls)

## 🙏 Acknowledgments

Built with alignment to [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)

---

**Built with ❤️ for secure AI development**
